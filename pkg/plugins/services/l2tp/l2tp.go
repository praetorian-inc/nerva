// Copyright 2025 Praetorian Security, Inc.
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

package l2tp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const L2TP = "l2tp"

// AVP types as defined in RFC 2661
const (
	avpMessageType       = 0
	avpProtocolVersion   = 2
	avpFirmwareRevision  = 6
	avpHostName          = 7
	avpVendorName        = 8
	avpAssignedTunnelID  = 9
	avpReceiveWindowSize = 10
	avpChallenge         = 11
	avpChallengeResponse = 13
)

// Message types
const (
	msgSCCRQ = 1 // Start-Control-Connection-Request
	msgSCCRP = 2 // Start-Control-Connection-Reply
	msgStopCCN = 4 // Stop-Control-Connection-Notification
)

type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// buildSCCRQ constructs an L2TP Start-Control-Connection-Request probe
func buildSCCRQ() ([]byte, []byte, error) {
	// Generate random tunnel ID for tracking response
	tunnelID := make([]byte, 2)
	if _, err := rand.Read(tunnelID); err != nil {
		return nil, nil, fmt.Errorf("failed to generate tunnel ID: %w", err)
	}

	// Start building control message header
	// Flags: T=1 (control), L=1 (length present), S=1 (Ns/Nr present), Ver=2
	flags := uint16(0xC802) // 1100 1000 0000 0010 in binary

	var packet bytes.Buffer

	// Write header (12 bytes for control message with Ns/Nr)
	binary.Write(&packet, binary.BigEndian, flags)

	// Length will be calculated and written later
	lengthPos := packet.Len()
	binary.Write(&packet, binary.BigEndian, uint16(0)) // Placeholder for length

	// Tunnel ID (recipient, set to 0 for new connection)
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Session ID (set to 0 for control connection)
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Ns (sequence number, starts at 0)
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Nr (next expected sequence number, starts at 0)
	binary.Write(&packet, binary.BigEndian, uint16(0))

	// Build AVPs
	// AVP: Message Type (SCCRQ=1) - Mandatory
	packet.Write(buildAVP(avpMessageType, []byte{0, msgSCCRQ}, true))

	// AVP: Protocol Version (1.0) - Mandatory
	versionData := []byte{0x01, 0x00, 0x01, 0x00} // Version 1, Revision 0
	packet.Write(buildAVP(avpProtocolVersion, versionData, true))

	// AVP: Host Name - Mandatory
	hostname := []byte("nerva")
	packet.Write(buildAVP(avpHostName, hostname, true))

	// AVP: Assigned Tunnel ID - Mandatory
	packet.Write(buildAVP(avpAssignedTunnelID, tunnelID, true))

	// AVP: Receive Window Size - Mandatory
	windowSize := make([]byte, 2)
	binary.BigEndian.PutUint16(windowSize, 4) // Window size of 4
	packet.Write(buildAVP(avpReceiveWindowSize, windowSize, true))

	// Update length field
	packetBytes := packet.Bytes()
	binary.BigEndian.PutUint16(packetBytes[lengthPos:], uint16(len(packetBytes)))

	return packetBytes, tunnelID, nil
}

// buildAVP constructs a single AVP (Attribute-Value Pair)
func buildAVP(avpType uint16, value []byte, mandatory bool) []byte {
	var avp bytes.Buffer

	// Flags and Length (2 bytes)
	// Bit 0: Mandatory (M) bit
	// Bit 1: Hidden (H) bit
	// Bits 2-15: Length including header
	flags := uint16(len(value) + 6) // 6 bytes for AVP header
	if mandatory {
		flags |= 0x8000 // Set mandatory bit
	}
	binary.Write(&avp, binary.BigEndian, flags)

	// Vendor ID (2 bytes) - 0 for IETF
	binary.Write(&avp, binary.BigEndian, uint16(0))

	// Attribute Type (2 bytes)
	binary.Write(&avp, binary.BigEndian, avpType)

	// Attribute Value
	avp.Write(value)

	return avp.Bytes()
}

// sanitizeString removes non-printable characters and enforces max length
func sanitizeString(s string) string {
	const maxLen = 256
	if len(s) > maxLen {
		s = s[:maxLen]
	}
	// Remove non-printable characters
	result := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		if s[i] >= 32 && s[i] < 127 {
			result = append(result, s[i])
		}
	}
	return string(result)
}

// parseResponse parses the L2TP response and extracts relevant information
func parseResponse(data []byte, target plugins.Target, sentTunnelID []byte) (*plugins.Service, error) {
	if len(data) < 12 {
		return nil, nil // Too short to be valid L2TP control message
	}

	// Parse header
	flags := binary.BigEndian.Uint16(data[0:2])

	// Check if this is a control message (T bit must be 1)
	if flags&0x8000 == 0 {
		return nil, nil // Not a control message
	}

	// Check version (should be 2)
	version := flags & 0x000F
	if version != 2 {
		return nil, nil // Wrong version
	}

	// Parse length if present (L bit)
	offset := 2
	var length uint16
	if flags&0x4000 != 0 {
		if len(data) < 4 {
			return nil, nil
		}
		length = binary.BigEndian.Uint16(data[offset : offset+2])
		offset += 2

		// Validate length
		if int(length) > len(data) || int(length) < 12 {
			return nil, nil
		}
	} else {
		length = uint16(len(data))
	}

	// Skip Tunnel ID (2 bytes)
	if len(data) < offset+2 {
		return nil, nil
	}
	offset += 2

	// Skip Session ID (2 bytes)
	if len(data) < offset+2 {
		return nil, nil
	}
	offset += 2

	// Skip Ns/Nr if present (4 bytes total)
	if flags&0x0800 != 0 {
		if len(data) < offset+4 {
			return nil, nil
		}
		offset += 4
	}

	// Parse AVPs
	avps := data[offset:length]

	var messageType uint16
	var hostname string
	var vendorName string
	var protocolVersion string
	var firmwareRevision uint16
	var assignedTunnelID uint16
	var framingCaps uint32
	var bearerCaps uint32

	avpCount := 0
	maxAVPs := 100
	for len(avps) >= 6 && avpCount < maxAVPs {
		avpCount++

		// Parse AVP header
		avpFlags := binary.BigEndian.Uint16(avps[0:2])
		avpLength := avpFlags & 0x03FF // Lower 10 bits

		if avpLength < 6 || int(avpLength) > len(avps) {
			break // Invalid AVP
		}

		vendorID := binary.BigEndian.Uint16(avps[2:4])
		if vendorID != 0 {
			// Skip vendor-specific AVPs
			avps = avps[avpLength:]
			continue
		}

		avpType := binary.BigEndian.Uint16(avps[4:6])
		avpValue := avps[6:avpLength]

		switch avpType {
		case avpMessageType:
			if len(avpValue) >= 2 {
				messageType = binary.BigEndian.Uint16(avpValue)
			}
		case avpProtocolVersion:
			if len(avpValue) >= 2 {
				ver := avpValue[0]
				rev := avpValue[1]
				protocolVersion = fmt.Sprintf("%d.%d", ver, rev)
			}
		case avpHostName:
			hostname = sanitizeString(string(avpValue))
		case avpVendorName:
			vendorName = sanitizeString(string(avpValue))
		case avpFirmwareRevision:
			if len(avpValue) >= 2 {
				firmwareRevision = binary.BigEndian.Uint16(avpValue)
			}
		case avpAssignedTunnelID:
			if len(avpValue) >= 2 {
				assignedTunnelID = binary.BigEndian.Uint16(avpValue)
			}
		case 3: // Framing Capabilities AVP
			if len(avpValue) >= 4 {
				framingCaps = binary.BigEndian.Uint32(avpValue)
			}
		case 4: // Bearer Capabilities AVP
			if len(avpValue) >= 4 {
				bearerCaps = binary.BigEndian.Uint32(avpValue)
			}
		}

		avps = avps[avpLength:]
	}

	// Verify this is a SCCRP (response to SCCRQ)
	if messageType != msgSCCRP {
		return nil, nil
	}

	// Build service payload
	payload := plugins.ServiceL2TP{
		ProtocolVersion:  protocolVersion,
		HostName:         hostname,
		VendorName:       vendorName,
		FirmwareRevision: firmwareRevision,
		AssignedTunnelID: assignedTunnelID,
		FramingCaps:      framingCaps,
		BearerCaps:       bearerCaps,
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP), nil
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Build SCCRQ probe
	probe, tunnelID, err := buildSCCRQ()
	if err != nil {
		return nil, err
	}

	// Send probe and receive response
	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}

	// Parse response
	return parseResponse(response, target, tunnelID)
}

func (p *Plugin) PortPriority(i uint16) bool {
	return i == 1701
}

func (p *Plugin) Name() string {
	return L2TP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *Plugin) Priority() int {
	return 200
}
