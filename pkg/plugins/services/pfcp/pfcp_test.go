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

package pfcp

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/require"
)

// buildHeartbeatResponse constructs a PFCP Heartbeat Response with Recovery Time Stamp.
func buildHeartbeatResponse(recoveryTS uint32) []byte {
	return []byte{
		0x20,       // Flags: Version=1, S=0
		0x02,       // Message Type: Heartbeat Response
		0x00, 0x0c, // Message Length: 12
		0x00, 0x00, 0x01, // Sequence Number
		0x00,                                          // Spare
		0x00, 0x60,                                    // IE Type: Recovery Time Stamp (96)
		0x00, 0x04,                                    // IE Length: 4
		byte(recoveryTS >> 24), byte(recoveryTS >> 16), // Recovery TS high bytes
		byte(recoveryTS >> 8), byte(recoveryTS),        // Recovery TS low bytes
	}
}

// buildHeartbeatResponseWithNodeID constructs a response with both Recovery TS and Node ID.
func buildHeartbeatResponseWithNodeID(recoveryTS uint32, nodeIP net.IP) []byte {
	resp := []byte{
		0x20,       // Flags: Version=1, S=0
		0x02,       // Message Type: Heartbeat Response
		0x00, 0x19, // Message Length: 25 (Recovery TS IE 8 + Node ID IE 9 + header 8 = 25 after first 4)
		0x00, 0x00, 0x01, // Sequence Number
		0x00,                                          // Spare
		0x00, 0x60,                                    // IE Type: Recovery Time Stamp (96)
		0x00, 0x04,                                    // IE Length: 4
		byte(recoveryTS >> 24), byte(recoveryTS >> 16),
		byte(recoveryTS >> 8), byte(recoveryTS),
		0x00, 0x3c, // IE Type: Node ID (60)
		0x00, 0x05, // IE Length: 5 (1 type + 4 IPv4)
		0x00,       // Node ID Type: IPv4
	}
	resp = append(resp, nodeIP.To4()...)
	// Update message length
	msgLen := len(resp) - 4
	resp[2] = byte(msgLen >> 8)
	resp[3] = byte(msgLen)
	return resp
}

func setupMockUDPServer(t *testing.T, response []byte) string {
	t.Helper()
	addr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	require.NoError(t, err)

	conn, err := net.ListenUDP("udp", addr)
	require.NoError(t, err)

	serverAddr := conn.LocalAddr().String()

	go func() {
		defer conn.Close()
		buffer := make([]byte, 1024)
		_, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		_, _ = conn.WriteToUDP(response, clientAddr)
	}()

	time.Sleep(10 * time.Millisecond)
	return serverAddr
}

func TestPFCPValidResponse(t *testing.T) {
	response := buildHeartbeatResponse(0x12345678)
	serverAddr := setupMockUDPServer(t, response)

	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &Plugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "pfcp", result.Protocol)
}

func TestPFCPRecoveryTimestamp(t *testing.T) {
	response := buildHeartbeatResponse(0xAABBCCDD)
	serverAddr := setupMockUDPServer(t, response)

	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &Plugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify enrichment extracted the recovery timestamp
	recoveryTS, _ := enrichPFCP(response)
	require.Equal(t, uint32(0xAABBCCDD), recoveryTS)
}

func TestPFCPNodeIDExtraction(t *testing.T) {
	nodeIP := net.ParseIP("10.0.0.1").To4()
	response := buildHeartbeatResponseWithNodeID(0x12345678, nodeIP)

	recoveryTS, nodeID := enrichPFCP(response)
	require.Equal(t, uint32(0x12345678), recoveryTS)
	require.Equal(t, "10.0.0.1", nodeID)
}

func TestPFCPInvalidVersion(t *testing.T) {
	// Version=2 (bits 7-5 = 010 → 0x40) instead of 1
	response := []byte{0x40, 0x02, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x60, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01}
	serverAddr := setupMockUDPServer(t, response)

	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &Plugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	require.NoError(t, err)
	require.Nil(t, result)
}

func TestPFCPWrongMessageType(t *testing.T) {
	// Message Type = 0x06 (Association Setup Response) instead of 0x02
	response := []byte{0x20, 0x06, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x60, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01}
	serverAddr := setupMockUDPServer(t, response)

	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &Plugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	require.NoError(t, err)
	require.Nil(t, result)
}

func TestPFCPShortResponse(t *testing.T) {
	// Only 4 bytes - too short for valid PFCP
	response := []byte{0x20, 0x02, 0x00, 0x00}
	serverAddr := setupMockUDPServer(t, response)

	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &Plugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	require.NoError(t, err)
	require.Nil(t, result)
}

func TestPFCPPortPriority(t *testing.T) {
	plugin := &Plugin{}
	require.True(t, plugin.PortPriority(8805))
	require.False(t, plugin.PortPriority(80))
	require.False(t, plugin.PortPriority(443))
	require.False(t, plugin.PortPriority(3386))
	require.False(t, plugin.PortPriority(0))
}

func TestPFCPName(t *testing.T) {
	plugin := &Plugin{}
	require.Equal(t, "pfcp", plugin.Name())
}

func TestPFCPType(t *testing.T) {
	plugin := &Plugin{}
	require.Equal(t, plugins.UDP, plugin.Type())
}

func TestPFCPPriority(t *testing.T) {
	plugin := &Plugin{}
	require.Equal(t, 80, plugin.Priority())
}

func TestPFCPTruncatedIE(t *testing.T) {
	// Response with IE length exceeding actual data - tests the break path
	response := []byte{
		0x20, 0x02, 0x00, 0x0c, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x60, // IE Type: Recovery Time Stamp (96)
		0x00, 0x08, // IE Length: 8 (but only 4 bytes follow - truncated)
		0x00, 0x00, 0x00, 0x01,
	}
	recoveryTS, nodeID := enrichPFCP(response)
	// Should gracefully handle truncated IE without panic
	require.Equal(t, uint32(0), recoveryTS)
	require.Equal(t, "", nodeID)
}

func TestPFCPNodeIDIPv6(t *testing.T) {
	// Build response with IPv6 Node ID
	resp := []byte{
		0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		// Recovery Time Stamp IE
		0x00, 0x60, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x01,
		// Node ID IE: Type=60, Length=17 (1 type byte + 16 IPv6 bytes)
		0x00, 0x3c, 0x00, 0x11,
		0x01, // Node ID Type: IPv6
		// IPv6: 2001:db8::1
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}
	// Update message length
	msgLen := len(resp) - 4
	resp[2] = byte(msgLen >> 8)
	resp[3] = byte(msgLen)

	recoveryTS, nodeID := enrichPFCP(resp)
	require.Equal(t, uint32(1), recoveryTS)
	require.Equal(t, "2001:db8::1", nodeID)
}

func TestPFCPNodeIDFQDN(t *testing.T) {
	// Build response with FQDN Node ID (raw bytes, not DNS-encoded)
	fqdn := "smf.example.com"
	resp := []byte{
		0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		// Recovery Time Stamp IE
		0x00, 0x60, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x01,
		// Node ID IE: Type=60
		0x00, 0x3c,
		byte((1 + len(fqdn)) >> 8), byte(1 + len(fqdn)), // IE Length
		0x02, // Node ID Type: FQDN
	}
	resp = append(resp, []byte(fqdn)...)
	// Update message length
	msgLen := len(resp) - 4
	resp[2] = byte(msgLen >> 8)
	resp[3] = byte(msgLen)

	recoveryTS, nodeID := enrichPFCP(resp)
	require.Equal(t, uint32(1), recoveryTS)
	require.Equal(t, fqdn, nodeID)
}

func TestPFCPHeaderOnlyResponse(t *testing.T) {
	// Valid PFCP header (8 bytes) with no IEs following.
	// Exercises the "loop never enters" path in enrichPFCP when offset+4 > len(response) immediately.
	response := []byte{0x20, 0x02, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00}

	recoveryTS, nodeID := enrichPFCP(response)
	require.Equal(t, uint32(0), recoveryTS)
	require.Equal(t, "", nodeID)
}

func TestPFCPUnknownNodeIDType(t *testing.T) {
	// Node ID IE where the type byte is 0x03 (unknown, not IPv4/IPv6/FQDN).
	// Unknown type should be silently ignored.
	resp := []byte{
		0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		// Node ID IE: Type=60, Length=5
		0x00, 0x3c, 0x00, 0x05,
		0x03, // Unknown Node ID Type
		0x01, 0x02, 0x03, 0x04,
	}
	// Update message length
	msgLen := len(resp) - 4
	resp[2] = byte(msgLen >> 8)
	resp[3] = byte(msgLen)

	recoveryTS, nodeID := enrichPFCP(resp)
	require.Equal(t, "", nodeID)
	require.Equal(t, uint32(0), recoveryTS)
}

func TestPFCPNodeIDShortIPv6(t *testing.T) {
	// Node ID IE with type=1 (IPv6) but ieLen=10 (needs 17 for IPv6).
	// Insufficient length should result in empty nodeID.
	resp := []byte{
		0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		// Node ID IE: Type=60, Length=10 (too short for IPv6: need 17)
		0x00, 0x3c, 0x00, 0x0a,
		0x01, // Node ID Type: IPv6
		0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00,
	}
	// Update message length
	msgLen := len(resp) - 4
	resp[2] = byte(msgLen >> 8)
	resp[3] = byte(msgLen)

	_, nodeID := enrichPFCP(resp)
	require.Equal(t, "", nodeID)
}

func TestPFCPRecoveryTSShortIE(t *testing.T) {
	// Recovery TS IE (type=96) but ieLen=2 (needs >= 4).
	// Short IE should result in recoveryTS == 0.
	resp := []byte{
		0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		// Recovery TS IE: Type=96, Length=2 (too short, needs 4)
		0x00, 0x60, 0x00, 0x02,
		0xAA, 0xBB,
	}
	// Update message length
	msgLen := len(resp) - 4
	resp[2] = byte(msgLen >> 8)
	resp[3] = byte(msgLen)

	recoveryTS, _ := enrichPFCP(resp)
	require.Equal(t, uint32(0), recoveryTS)
}

func TestPFCPUnknownIESkipped(t *testing.T) {
	// An unknown IE type (type=999) followed by a valid Recovery TS IE.
	// Parser should skip the unknown IE and still find the Recovery TS.
	resp := []byte{
		0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		// Unknown IE: Type=999 (0x03E7), Length=2
		0x03, 0xe7, 0x00, 0x02,
		0xFF, 0xFF,
		// Recovery TS IE: Type=96, Length=4
		0x00, 0x60, 0x00, 0x04,
		0xDE, 0xAD, 0xBE, 0xEF,
	}
	// Update message length
	msgLen := len(resp) - 4
	resp[2] = byte(msgLen >> 8)
	resp[3] = byte(msgLen)

	recoveryTS, nodeID := enrichPFCP(resp)
	require.Equal(t, uint32(0xDEADBEEF), recoveryTS)
	require.Equal(t, "", nodeID)
}

func TestPFCPNodeIDOnlyNoRecoveryTS(t *testing.T) {
	// Response with only a Node ID IE (IPv4), no Recovery TS IE at all.
	resp := []byte{
		0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		// Node ID IE: Type=60, Length=5
		0x00, 0x3c, 0x00, 0x05,
		0x00,                   // IPv4
		0xC0, 0xA8, 0x01, 0x01, // 192.168.1.1
	}
	// Update message length
	msgLen := len(resp) - 4
	resp[2] = byte(msgLen >> 8)
	resp[3] = byte(msgLen)

	recoveryTS, nodeID := enrichPFCP(resp)
	require.Equal(t, uint32(0), recoveryTS)
	require.Equal(t, "192.168.1.1", nodeID)
}

func TestPFCPExactly7Bytes(t *testing.T) {
	// 7-byte response — right at the boundary of len(response) < 8 check in detectPFCP.
	// Should be rejected by the length check and return nil.
	response := []byte{0x20, 0x02, 0x00, 0x03, 0x00, 0x00, 0x01}
	serverAddr := setupMockUDPServer(t, response)

	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &Plugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	require.NoError(t, err)
	require.Nil(t, result)
}

func TestPFCPEmptyResponse(t *testing.T) {
	// Empty (0-byte) response from server should be rejected.
	serverAddr := setupMockUDPServer(t, []byte{})

	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &Plugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	require.NoError(t, err)
	require.Nil(t, result)
}

func TestPFCPNodeIDIPv4ShortIE(t *testing.T) {
	// Node ID IE with type=0 (IPv4) but ieLen=3 (needs >= 5).
	// Insufficient length should result in empty nodeID.
	resp := []byte{
		0x20, 0x02, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
		// Node ID IE: Type=60, Length=3 (too short for IPv4: need 5)
		0x00, 0x3c, 0x00, 0x03,
		0x00, // Node ID Type: IPv4
		0x0A, 0x00,
	}
	// Update message length
	msgLen := len(resp) - 4
	resp[2] = byte(msgLen >> 8)
	resp[3] = byte(msgLen)

	_, nodeID := enrichPFCP(resp)
	require.Equal(t, "", nodeID)
}

func TestPFCPRunEnrichmentInPayload(t *testing.T) {
	nodeIP := net.ParseIP("10.0.0.1").To4()
	response := buildHeartbeatResponseWithNodeID(0xAABBCCDD, nodeIP)
	serverAddr := setupMockUDPServer(t, response)

	clientConn, err := net.Dial("udp", serverAddr)
	require.NoError(t, err)
	defer clientConn.Close()

	plugin := &Plugin{}
	result, err := plugin.Run(clientConn, 2*time.Second, plugins.Target{})

	require.NoError(t, err)
	require.NotNil(t, result)
	require.Equal(t, "pfcp", result.Protocol)

	// Verify the raw JSON payload contains enrichment data
	var payload plugins.ServicePFCP
	err = json.Unmarshal(result.Raw, &payload)
	require.NoError(t, err)
	require.Equal(t, uint32(0xAABBCCDD), payload.RecoveryTimestamp)
	require.Equal(t, "10.0.0.1", payload.NodeID)
}
