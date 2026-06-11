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

package quic

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

// QUIC Version Negotiation detection plugin (RFC 9000, RFC 8999).
//
// Sends a QUIC long-header packet with an invalid version number to trigger
// a Version Negotiation response. This detects any QUIC service (HTTP/3,
// SMB-over-QUIC, etc.) without requiring TLS crypto.

const (
	quicPort     = 443
	quicPriority = 2100 // Low priority; runs after most other UDP plugins
	dcidLen      = 8    // Destination Connection ID length
	minDatagram  = 1200 // RFC 9000 Section 14.1: minimum UDP datagram size
)

// Well-known QUIC version numbers.
var knownVersions = map[uint32]string{
	0x00000001: "QUICv1",
	0x6B3343CF: "QUICv2",
	0xFF000000: "draft-00",
}

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return quicPriority
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == quicPort
}

func (p *Plugin) Name() string {
	return "quic"
}

// Run sends a QUIC Version Negotiation probe and parses the response.
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	dcid := make([]byte, dcidLen)
	if _, err := rand.Read(dcid); err != nil {
		return nil, err
	}

	probe := buildVersionNegotiationProbe(dcid)

	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	metadata, ok := parseVersionNegotiation(response, dcid)
	if !ok {
		return nil, nil
	}

	return plugins.CreateServiceFrom(target, metadata, false, "", plugins.UDP), nil
}

// buildVersionNegotiationProbe constructs a 1200-byte QUIC long-header packet
// with an invalid version to trigger a Version Negotiation response.
//
// Layout (RFC 8999):
//
//	Byte 0:         0x80 (long header form, fixed bit may be 0)
//	Bytes 1-4:      0xBABABABA (invalid version)
//	Byte 5:         DCID Length (8)
//	Bytes 6-13:     Destination Connection ID (random 8 bytes)
//	Byte 14:        SCID Length (0)
//	Bytes 15-1199:  Zero padding (to meet 1200-byte minimum)
func buildVersionNegotiationProbe(dcid []byte) []byte {
	probe := make([]byte, minDatagram)

	probe[0] = 0x80 // Long header form
	// Invalid version to trigger Version Negotiation
	probe[1] = 0xBA
	probe[2] = 0xBA
	probe[3] = 0xBA
	probe[4] = 0xBA
	probe[5] = byte(len(dcid)) // DCID Length
	copy(probe[6:6+len(dcid)], dcid)
	probe[6+len(dcid)] = 0x00 // SCID Length = 0
	// Remaining bytes are zero (padding)

	return probe
}

// parseVersionNegotiation validates a QUIC Version Negotiation response.
//
// A valid Version Negotiation packet (RFC 8999):
//
//	Byte 0:         High bit set (0x80+)
//	Bytes 1-4:      Version = 0x00000000 (identifies Version Negotiation)
//	Byte 5:         DCID Length (should echo back our SCID length = 0)
//	Bytes 6+:       DCID (should echo back our SCID = empty)
//	Next byte:      SCID Length (should echo back our DCID length)
//	Next N bytes:   SCID (should echo back our DCID)
//	Remaining:      List of 4-byte supported version numbers
func parseVersionNegotiation(data []byte, sentDCID []byte) (plugins.ServiceQUIC, bool) {
	// Minimum: 1 (header) + 4 (version) + 1 (dcid len) + 1 (scid len) + 4 (at least one version)
	if len(data) < 11 {
		return plugins.ServiceQUIC{}, false
	}

	// High bit must be set (long header form)
	if data[0]&0x80 == 0 {
		return plugins.ServiceQUIC{}, false
	}

	// Version field must be 0x00000000 for Version Negotiation
	version := binary.BigEndian.Uint32(data[1:5])
	if version != 0x00000000 {
		return plugins.ServiceQUIC{}, false
	}

	offset := 5

	// DCID Length and DCID (echoed SCID from our probe = empty since we sent SCID length 0)
	if offset >= len(data) {
		return plugins.ServiceQUIC{}, false
	}
	respDCIDLen := int(data[offset])
	offset++
	offset += respDCIDLen // Skip the echoed DCID

	// SCID Length and SCID (should echo back our DCID)
	if offset >= len(data) {
		return plugins.ServiceQUIC{}, false
	}
	respSCIDLen := int(data[offset])
	offset++

	// Verify the echoed SCID matches our sent DCID
	if offset+respSCIDLen > len(data) {
		return plugins.ServiceQUIC{}, false
	}
	if respSCIDLen == len(sentDCID) {
		echoed := data[offset : offset+respSCIDLen]
		match := true
		for i := range echoed {
			if echoed[i] != sentDCID[i] {
				match = false
				break
			}
		}
		if !match {
			return plugins.ServiceQUIC{}, false
		}
	}
	offset += respSCIDLen

	// Parse supported version list (each entry is 4 bytes)
	remaining := len(data) - offset
	if remaining < 4 || remaining%4 != 0 {
		return plugins.ServiceQUIC{}, false
	}

	var versions []string
	for offset+4 <= len(data) {
		v := binary.BigEndian.Uint32(data[offset : offset+4])
		offset += 4

		if name, ok := knownVersions[v]; ok {
			versions = append(versions, name)
		} else {
			versions = append(versions, fmt.Sprintf("0x%08X", v))
		}
	}

	if len(versions) == 0 {
		return plugins.ServiceQUIC{}, false
	}

	return plugins.ServiceQUIC{SupportedVersions: versions}, true
}
