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

// Package pptp implements a PPTP (Point-to-Point Tunneling Protocol) service
// fingerprinting plugin. Detection sends a Start-Control-Connection-Request
// (SCCRQ, message type 1) to TCP port 1723 and validates the
// Start-Control-Connection-Reply (SCCRP, message type 2) by checking the
// magic cookie (0x1A2B3C4D) and control message type field. On success,
// hostname, vendor string, firmware revision, and protocol version are
// extracted from the response payload.
//
// PPTP control messages are defined in RFC 2637.
package pptp

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const PPTP = "pptp"

// PPTP wire format constants.
const (
	pptpPort        = 1723
	pptpMagicCookie = uint32(0x1A2B3C4D)
	pptpMsgTypeSCCRP = uint16(2)

	// Offsets within the SCCRP response.
	offsetMagicCookie      = 4
	offsetControlMsgType   = 8
	offsetProtocolVersion  = 12
	offsetResultCode       = 14
	offsetFramingCaps      = 16
	offsetBearerCaps       = 20
	offsetMaxChannels      = 24
	offsetFirmwareRevision = 26
	offsetHostname         = 28
	offsetVendorString     = 92

	// Field sizes.
	sizeHostname     = 64
	sizeVendorString = 64

	// Minimum valid SCCRP length must cover the vendor string field.
	minSCCRPLen = offsetVendorString + sizeVendorString // 156 bytes
)

// sccrqPacket is the 156-byte Start-Control-Connection-Request sent to the
// PPTP server. The host name and vendor string fields are set to "nerva"
// followed by null padding.
//
// SCCRQ packet layout (RFC 2637 section 3.1):
//
//	Bytes 0-1:   0x009C  Length = 156
//	Bytes 2-3:   0x0001  PPTP Message Type = 1 (Control)
//	Bytes 4-7:   0x1A2B3C4D  Magic Cookie
//	Bytes 8-9:   0x0001  Control Message Type = 1 (SCCRQ)
//	Bytes 10-11: 0x0000  Reserved0
//	Bytes 12-13: 0x0100  Protocol Version 1.0
//	Bytes 14-15: 0x0000  Reserved1
//	Bytes 16-19: 0x00000001  Framing Capabilities (Async)
//	Bytes 20-23: 0x00000001  Bearer Capabilities (Analog)
//	Bytes 24-25: 0x0001  Maximum Channels
//	Bytes 26-27: 0x0000  Firmware Revision
//	Bytes 28-91: Host Name (64 bytes, null-padded)
//	Bytes 92-155: Vendor String (64 bytes, null-padded)
var sccrqPacket = buildSCCRQ()

func buildSCCRQ() []byte {
	pkt := make([]byte, 156)

	// Length
	binary.BigEndian.PutUint16(pkt[0:2], 156)
	// PPTP Message Type = 1 (Control)
	binary.BigEndian.PutUint16(pkt[2:4], 1)
	// Magic Cookie
	binary.BigEndian.PutUint32(pkt[4:8], pptpMagicCookie)
	// Control Message Type = 1 (SCCRQ)
	binary.BigEndian.PutUint16(pkt[8:10], 1)
	// Reserved0
	binary.BigEndian.PutUint16(pkt[10:12], 0)
	// Protocol Version 1.0
	binary.BigEndian.PutUint16(pkt[12:14], 0x0100)
	// Reserved1
	binary.BigEndian.PutUint16(pkt[14:16], 0)
	// Framing Capabilities (Async = 1)
	binary.BigEndian.PutUint32(pkt[16:20], 1)
	// Bearer Capabilities (Analog = 1)
	binary.BigEndian.PutUint32(pkt[20:24], 1)
	// Maximum Channels
	binary.BigEndian.PutUint16(pkt[24:26], 1)
	// Firmware Revision
	binary.BigEndian.PutUint16(pkt[26:28], 0)
	// Host Name (64 bytes, null-padded)
	copy(pkt[28:92], "nerva")
	// Vendor String (64 bytes, null-padded)
	copy(pkt[92:156], "nerva")

	return pkt
}

// Plugin implements the fingerprintx Plugin interface for PPTP.
type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Run sends a SCCRQ to the connection and validates the SCCRP response.
// Returns nil, nil if the service is not PPTP.
// Returns nil, err for I/O or protocol errors.
// Returns a populated Service on successful detection.
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.SendRecv(conn, sccrqPacket, timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, nil
	}

	if len(response) < minSCCRPLen {
		return nil, nil
	}

	// Validate magic cookie.
	cookie := binary.BigEndian.Uint32(response[offsetMagicCookie : offsetMagicCookie+4])
	if cookie != pptpMagicCookie {
		return nil, nil
	}

	// Validate control message type is SCCRP (2).
	msgType := binary.BigEndian.Uint16(response[offsetControlMsgType : offsetControlMsgType+2])
	if msgType != pptpMsgTypeSCCRP {
		return nil, nil
	}

	// Extract metadata from SCCRP.
	protocolVersionRaw := binary.BigEndian.Uint16(response[offsetProtocolVersion : offsetProtocolVersion+2])
	resultCode := response[offsetResultCode]
	framingCaps := binary.BigEndian.Uint32(response[offsetFramingCaps : offsetFramingCaps+4])
	bearerCaps := binary.BigEndian.Uint32(response[offsetBearerCaps : offsetBearerCaps+4])
	maxChannels := binary.BigEndian.Uint16(response[offsetMaxChannels : offsetMaxChannels+2])
	firmwareRevision := binary.BigEndian.Uint16(response[offsetFirmwareRevision : offsetFirmwareRevision+2])

	hostnameRaw := response[offsetHostname : offsetHostname+sizeHostname]
	vendorRaw := response[offsetVendorString : offsetVendorString+sizeVendorString]

	hostname := extractNullTerminated(hostnameRaw)
	vendorString := extractNullTerminated(vendorRaw)

	// Format protocol version as "major.minor".
	major := protocolVersionRaw >> 8
	minor := protocolVersionRaw & 0xFF
	protocolVersion := formatVersion(major, minor)

	payload := plugins.ServicePPTP{
		Hostname:            hostname,
		VendorString:        vendorString,
		FirmwareRevision:    firmwareRevision,
		ProtocolVersion:     protocolVersion,
		FramingCapabilities: framingCaps,
		BearerCapabilities:  bearerCaps,
		MaxChannels:         maxChannels,
		ResultCode:          resultCode,
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

// extractNullTerminated returns the string before the first null byte,
// with trailing null bytes removed.
func extractNullTerminated(data []byte) string {
	idx := bytes.IndexByte(data, 0)
	if idx >= 0 {
		return string(data[:idx])
	}
	return strings.TrimRight(string(data), "\x00")
}

// formatVersion converts a major/minor byte pair into a "major.minor" string,
// returning an empty string when both values are zero.
func formatVersion(major, minor uint16) string {
	if major == 0 && minor == 0 {
		return ""
	}
	// Build "M.N" without importing fmt.
	return versionString(major) + "." + versionString(minor)
}

// versionString converts a small uint16 to its decimal string representation.
func versionString(n uint16) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 5)
	for n > 0 {
		buf = append([]byte{byte('0' + n%10)}, buf...)
		n /= 10
	}
	return string(buf)
}

func (p *Plugin) PortPriority(port uint16) bool {
	return port == pptpPort
}

func (p *Plugin) Name() string {
	return PPTP
}

func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *Plugin) Priority() int {
	return 175
}
