// Copyright 2022 Praetorian Security, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package nfs

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

// NFSPlugin implements the plugins.Plugin interface for NFS detection
type NFSPlugin struct{}

// NFS is the protocol name constant
const NFS = "nfs"

// NFSProgramNumber is the Sun RPC program number for NFS
const NFSProgramNumber = 100003

func init() {
	plugins.RegisterPlugin(&NFSPlugin{})
}

// generateXID creates a random 32-bit transaction ID for RPC calls
func generateXID() uint32 {
	b := make([]byte, 4)
	_, err := rand.Read(b)
	if err != nil {
		// Fallback to predictable XID if random fails
		return 0x12345678
	}
	return binary.BigEndian.Uint32(b)
}

// buildNFSNullCall creates an RPC NULL procedure call packet for the specified NFS version.
// The packet follows Sun RPC (RFC 5531) format with XDR encoding (big-endian, 4-byte aligned).
//
// Packet structure (44 bytes total):
//   - Record marker: 4 bytes (0x80000028 = last fragment + 40 bytes)
//   - XID: 4 bytes (transaction ID)
//   - Message type: 4 bytes (0 = CALL)
//   - RPC version: 4 bytes (2)
//   - Program number: 4 bytes (100003 = NFS)
//   - Program version: 4 bytes (4, 3, or 2)
//   - Procedure: 4 bytes (0 = NULL)
//   - Credentials: 8 bytes (AUTH_NULL: flavor=0, len=0)
//   - Verifier: 8 bytes (AUTH_NULL: flavor=0, len=0)
func buildNFSNullCall(xid uint32, version uint32) []byte {
	buf := make([]byte, 44)

	// Record marker: last fragment (0x80000000) + length (40 bytes = 0x28)
	binary.BigEndian.PutUint32(buf[0:4], 0x80000028)

	// XID (transaction ID)
	binary.BigEndian.PutUint32(buf[4:8], xid)

	// Message type (CALL = 0)
	binary.BigEndian.PutUint32(buf[8:12], 0)

	// RPC version (2)
	binary.BigEndian.PutUint32(buf[12:16], 2)

	// Program number (NFS = 100003)
	binary.BigEndian.PutUint32(buf[16:20], NFSProgramNumber)

	// Program version
	binary.BigEndian.PutUint32(buf[20:24], version)

	// Procedure (NULL = 0)
	binary.BigEndian.PutUint32(buf[24:28], 0)

	// Credentials: AUTH_NULL (flavor=0, length=0)
	binary.BigEndian.PutUint32(buf[28:32], 0)
	binary.BigEndian.PutUint32(buf[32:36], 0)

	// Verifier: AUTH_NULL (flavor=0, length=0)
	binary.BigEndian.PutUint32(buf[36:40], 0)
	binary.BigEndian.PutUint32(buf[40:44], 0)

	return buf
}

// parseNFSReply validates an RPC reply message and checks if the NFS NULL procedure succeeded.
// Returns true if the response indicates the NFS version is supported.
//
// RPC Reply structure (minimum 28 bytes):
//   - Record marker: 4 bytes
//   - XID: 4 bytes (must match request)
//   - Message type: 4 bytes (1 = REPLY)
//   - Reply stat: 4 bytes (0 = MSG_ACCEPTED)
//   - Verifier: 8 bytes
//   - Accept stat: 4 bytes (0 = SUCCESS)
func parseNFSReply(response []byte, expectedXID uint32) bool {
	// Minimum response size: record marker (4) + XID (4) + msg_type (4) +
	// reply_stat (4) + verifier (8) + accept_stat (4) = 28 bytes
	if len(response) < 28 {
		return false
	}

	// Skip record marker (first 4 bytes)
	offset := 4

	// Check XID matches
	xid := binary.BigEndian.Uint32(response[offset : offset+4])
	if xid != expectedXID {
		return false
	}
	offset += 4

	// Check message type is REPLY (1)
	msgType := binary.BigEndian.Uint32(response[offset : offset+4])
	if msgType != 1 {
		return false
	}
	offset += 4

	// Check reply stat is MSG_ACCEPTED (0)
	replyStat := binary.BigEndian.Uint32(response[offset : offset+4])
	if replyStat != 0 {
		return false
	}
	offset += 4

	// Skip verifier (8 bytes: flavor + length)
	offset += 8

	// Check accept stat is SUCCESS (0)
	// Non-zero means: PROG_UNAVAIL(1), PROG_MISMATCH(2), PROC_UNAVAIL(3), etc.
	acceptStat := binary.BigEndian.Uint32(response[offset : offset+4])
	if acceptStat != 0 {
		return false
	}

	return true
}

// formatVersionString creates a version string from detected versions.
// Returns highest version as primary, e.g., "4" or "3".
func formatVersionString(versions []int) string {
	if len(versions) == 0 {
		return ""
	}
	// versions are added highest-first due to probe order
	return fmt.Sprintf("%d", versions[0])
}

// Run detects NFS service by sending RPC NULL procedure calls.
// It probes versions in descending order (v4 -> v3 -> v2) and reports
// the highest version that responds successfully.
func (p *NFSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	nfsService := plugins.ServiceNFS{}

	// Generate a random XID for this detection session
	xid := generateXID()

	// Probe versions in descending order: 4, 3, 2
	// This allows us to report the highest supported version
	versions := []uint32{4, 3, 2}

	for _, version := range versions {
		packet := buildNFSNullCall(xid, version)

		response, err := utils.SendRecv(conn, packet, timeout)
		if err != nil {
			// Write error - propagate
			return nil, err
		}

		// Empty response - server didn't respond to this version
		if len(response) == 0 {
			continue
		}

		// Check if response indicates successful NULL procedure
		if parseNFSReply(response, xid) {
			nfsService.DetectedVersions = append(nfsService.DetectedVersions, int(version))

			// Set highest version (first successful probe)
			if nfsService.Version == 0 {
				nfsService.Version = int(version)
			}
		}
	}

	// If no version responded successfully, not NFS
	if len(nfsService.DetectedVersions) == 0 {
		return nil, nil
	}

	versionStr := formatVersionString(nfsService.DetectedVersions)
	return plugins.CreateServiceFrom(target, nfsService, false, versionStr, plugins.TCP), nil
}

// PortPriority returns true if this is the default NFS port
func (p *NFSPlugin) PortPriority(i uint16) bool {
	return i == 2049
}

// Name returns the protocol name
func (p *NFSPlugin) Name() string {
	return NFS
}

// Type returns the transport protocol
func (p *NFSPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the scan priority (higher = later)
// NFS runs after RPC (300) since it uses RPC protocol
func (p *NFSPlugin) Priority() int {
	return 350
}
