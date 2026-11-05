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

package clickhouse

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

/*
ClickHouse Native Protocol Fingerprinting

This plugin implements ClickHouse fingerprinting using the ClickHouse native
binary protocol (default port 9000, TLS port 9440) via a ClientHello/ServerHello
handshake.

Detection Strategy:

	PHASE 1 - DETECTION (determines if the service is ClickHouse):
	  - Send a ClientHello (packet type 0) advertising protocol version 54401
	  - Validate the ServerHello response: either packet type 0 (Hello) or
	    packet type 2 (Exception, e.g. authentication required)

	PHASE 2 - ENRICHMENT (extracts version and metadata):
	  - Parse ServerHello fields (server_name, version_major/minor, protocol_version)
	  - Parse optional fields gated by the negotiated protocol version
	    (timezone, display_name, version_patch)
	  - Build CPE using the extracted major.minor.patch version

Native Protocol Wire Format:

	Integers are encoded as VarUInt (LEB128): each byte's high bit is a
	continuation bit, remaining 7 bits are data, little-endian bit order.

	Strings are VarUInt-length-prefixed byte sequences with no null terminator
	and no additional framing.

	ClientHello (packet type 0):
	  [VarUInt: 0]              packet_type (Hello)
	  [String]                  client_name
	  [VarUInt]                 version_major
	  [VarUInt]                 version_minor
	  [VarUInt]                 protocol_version
	  [String]                  database
	  [String]                  user
	  [String]                  password

	ServerHello (packet type 0):
	  [VarUInt: 0]              packet_type (Hello)
	  [String]                  server_name
	  [VarUInt]                 version_major
	  [VarUInt]                 version_minor
	  [VarUInt]                 protocol_version
	  [String]                  timezone           (if negotiated >= 54058)
	  [String]                  display_name       (if negotiated >= 54372)
	  [VarUInt]                 version_patch      (if negotiated >= 54401)

	Server Exception (packet type 2):
	  Sent instead of Hello when the server rejects the handshake (e.g.
	  authentication required). This still confirms ClickHouse's native
	  protocol, but no version metadata is available.

Negotiated version = min(client_protocol_version, server_protocol_version).
*/

// ClickHousePlugin detects ClickHouse over the plaintext native protocol port (9000).
type ClickHousePlugin struct{}

// ClickHouseTLSPlugin detects ClickHouse over the TLS native protocol port (9440).
type ClickHouseTLSPlugin struct{}

const CLICKHOUSE = "clickhouse"

// ClickHouse native protocol packet types relevant to the handshake.
const (
	packetTypeHello     = 0
	packetTypeException = 2
)

// ClientHello parameters. protocolVersion is the minimum protocol version
// required for the server to include version_patch in its ServerHello.
const (
	clientName      = "nerva"
	clientVerMajor  = 24
	clientVerMinor  = 1
	protocolVersion = 54401
)

// Protocol version thresholds gating optional ServerHello fields.
const (
	minProtocolVersionTimezone     = 54058
	minProtocolVersionDisplayName  = 54372
	minProtocolVersionVersionPatch = 54401
)

// maxStringLen guards against unreasonably large VarUInt-prefixed strings
// (e.g. corrupted or adversarial responses) causing excessive allocation.
const maxStringLen = 1 << 20 // 1 MiB

// maxVarUIntBytes bounds VarUInt (LEB128) decoding to 9 bytes (63 bits),
// matching ClickHouse's own VarUInt implementation limit.
const maxVarUIntBytes = 9

// serverHelloFields holds the fields extracted from a ClickHouse ServerHello response.
type serverHelloFields struct {
	ServerName      string
	VersionMajor    uint64
	VersionMinor    uint64
	ProtocolVersion uint64
	Timezone        string
	DisplayName     string
	VersionPatch    uint64
	HasPatch        bool
}

func init() {
	plugins.RegisterPlugin(&ClickHousePlugin{})
	plugins.RegisterPlugin(&ClickHouseTLSPlugin{})
}

// readVarUInt decodes a LEB128-encoded VarUInt from buf starting at pos.
//
// Parameters:
//   - buf: Byte slice containing the encoded value
//   - pos: Starting position
//
// Returns:
//   - uint64: Decoded value
//   - int: New position after the VarUInt
//   - error: nil if successful, error if truncated or the value exceeds 63 bits
func readVarUInt(buf []byte, pos int) (uint64, int, error) {
	var result uint64

	for i := 0; i < maxVarUIntBytes; i++ {
		if pos >= len(buf) {
			return 0, pos, fmt.Errorf("truncated varuint at offset %d", pos)
		}

		b := buf[pos]
		pos++

		result |= uint64(b&0x7f) << (7 * i) // #nosec G115 -- i bounded to [0,8], shift max 56, no overflow

		if b&0x80 == 0 {
			return result, pos, nil
		}
	}

	return 0, pos, fmt.Errorf("varuint exceeds %d bytes at offset %d", maxVarUIntBytes, pos)
}

// readString decodes a VarUInt-length-prefixed string from buf starting at pos.
//
// Parameters:
//   - buf: Byte slice containing the encoded string
//   - pos: Starting position
//
// Returns:
//   - string: Decoded string value
//   - int: New position after the string
//   - error: nil if successful, error if truncated or the length exceeds maxStringLen
func readString(buf []byte, pos int) (string, int, error) {
	length, pos, err := readVarUInt(buf, pos)
	if err != nil {
		return "", pos, err
	}

	if length > maxStringLen {
		return "", pos, fmt.Errorf("string length %d exceeds max %d at offset %d", length, maxStringLen, pos)
	}

	end := pos + int(length) // #nosec G115 -- length bounded to maxStringLen (1 MiB) above
	if end > len(buf) {
		return "", pos, fmt.Errorf("truncated string at offset %d", pos)
	}

	return string(buf[pos:end]), end, nil
}

// writeVarUInt LEB128-encodes val and appends it to dst.
func writeVarUInt(dst []byte, val uint64) []byte {
	for val >= 0x80 {
		dst = append(dst, byte(val)|0x80)
		val >>= 7
	}
	return append(dst, byte(val))
}

// writeString appends a VarUInt-length-prefixed string to dst.
func writeString(dst []byte, s string) []byte {
	dst = writeVarUInt(dst, uint64(len(s)))
	return append(dst, s...)
}

// buildClientHello constructs a ClickHouse native protocol ClientHello (packet type 0)
// probe using minimal, non-privileged credentials ("default"/empty password).
//
// Returns:
//   - []byte: Complete ClientHello packet ready to send
func buildClientHello() []byte {
	buf := make([]byte, 0, 64)
	buf = writeVarUInt(buf, packetTypeHello)
	buf = writeString(buf, clientName)
	buf = writeVarUInt(buf, clientVerMajor)
	buf = writeVarUInt(buf, clientVerMinor)
	buf = writeVarUInt(buf, protocolVersion)
	buf = writeString(buf, "default")
	buf = writeString(buf, "default")
	buf = writeString(buf, "")
	return buf
}

// parseServerHello parses a ClickHouse ServerHello (packet type 0) response.
//
// Optional fields (timezone, display_name, version_patch) are only present
// when the negotiated protocol version meets the corresponding threshold.
//
// Parameters:
//   - data: Complete ServerHello response bytes, starting with the packet type VarUInt
//
// Returns:
//   - *serverHelloFields: Parsed ServerHello fields
//   - error: nil if successful, error if the packet type is not Hello or parsing fails
func parseServerHello(data []byte) (*serverHelloFields, error) {
	pos := 0

	packetType, pos, err := readVarUInt(data, pos)
	if err != nil {
		return nil, err
	}
	if packetType != packetTypeHello {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: CLICKHOUSE,
			Info:    fmt.Sprintf("expected Hello packet type (0), got %d", packetType),
		}
	}

	fields := &serverHelloFields{}

	fields.ServerName, pos, err = readString(data, pos)
	if err != nil {
		return nil, err
	}
	fields.VersionMajor, pos, err = readVarUInt(data, pos)
	if err != nil {
		return nil, err
	}
	fields.VersionMinor, pos, err = readVarUInt(data, pos)
	if err != nil {
		return nil, err
	}
	fields.ProtocolVersion, pos, err = readVarUInt(data, pos)
	if err != nil {
		return nil, err
	}

	negotiated := fields.ProtocolVersion
	if negotiated > protocolVersion {
		negotiated = protocolVersion
	}

	if negotiated >= minProtocolVersionTimezone {
		fields.Timezone, pos, err = readString(data, pos)
		if err != nil {
			return nil, err
		}
	}
	if negotiated >= minProtocolVersionDisplayName {
		fields.DisplayName, pos, err = readString(data, pos)
		if err != nil {
			return nil, err
		}
	}
	if negotiated >= minProtocolVersionVersionPatch {
		fields.VersionPatch, pos, err = readVarUInt(data, pos)
		if err != nil {
			return nil, err
		}
		fields.HasPatch = true
	}

	return fields, nil
}

// buildClickHouseCPE generates a CPE (Common Platform Enumeration) string for ClickHouse.
// CPE format: cpe:2.3:a:clickhouse:clickhouse:{version}:*:*:*:*:*:*:*
//
// Uses a wildcard "*" when version is empty (matches Cassandra/MySQL/Redis pattern).
//
// Parameters:
//   - version: ClickHouse version string (e.g., "24.1.5"), or empty for unknown
//
// Returns:
//   - string: CPE identifier
func buildClickHouseCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:clickhouse:clickhouse:%s:*:*:*:*:*:*:*", version)
}

// validateExceptionFrame checks that the response contains a structurally valid
// ClickHouse exception after the packet type byte: error_code (VarUInt) followed
// by a non-empty error_name (String). This prevents false positives from
// non-ClickHouse services that happen to respond with a leading 0x02 byte.
func validateExceptionFrame(data []byte) bool {
	pos := 0
	// Skip packet type (already read by caller).
	_, pos, err := readVarUInt(data, pos)
	if err != nil {
		return false
	}
	// Read error_code.
	_, pos, err = readVarUInt(data, pos)
	if err != nil {
		return false
	}
	// Read error_name — must be non-empty (e.g. "DB::Exception").
	name, _, err := readString(data, pos)
	if err != nil {
		return false
	}
	return len(name) > 0
}

// DetectClickHouse performs ClickHouse fingerprinting using the native protocol
// ClientHello/ServerHello handshake.
//
// Parameters:
//   - conn: Network connection to the candidate ClickHouse server
//   - timeout: Timeout for network operations
//
// Returns:
//   - *serverHelloFields: Parsed ServerHello fields (zero-value if the server
//     responded with an Exception rather than Hello)
//   - bool: true if ClickHouse was detected
//   - error: Error details if detection failed
func DetectClickHouse(conn net.Conn, timeout time.Duration) (*serverHelloFields, bool, error) {
	probe := buildClientHello()

	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, false, err
	}
	if len(response) == 0 {
		return nil, false, &utils.ServerNotEnable{}
	}

	packetType, _, err := readVarUInt(response, 0)
	if err != nil {
		return nil, false, &utils.InvalidResponseErrorInfo{
			Service: CLICKHOUSE,
			Info:    fmt.Sprintf("failed to parse packet type: %v", err),
		}
	}

	switch packetType {
	case packetTypeException:
		if !validateExceptionFrame(response) {
			return nil, false, &utils.InvalidResponseErrorInfo{
				Service: CLICKHOUSE,
				Info:    "exception packet failed structural validation",
			}
		}
		return &serverHelloFields{}, true, nil
	case packetTypeHello:
		fields, err := parseServerHello(response)
		if err != nil {
			return nil, false, err
		}
		return fields, true, nil
	default:
		return nil, false, &utils.InvalidResponseErrorInfo{
			Service: CLICKHOUSE,
			Info:    fmt.Sprintf("unexpected packet type %d, expected Hello(0) or Exception(2)", packetType),
		}
	}
}

// runClickHouse contains the Run logic shared by ClickHousePlugin and ClickHouseTLSPlugin.
//
// Parameters:
//   - conn: Network connection to the candidate ClickHouse server
//   - timeout: Timeout for network operations
//   - target: Scan target metadata
//   - isTLS: true if conn is a TLS connection (TCPTLS transport)
//
// Returns:
//   - *plugins.Service: Service metadata with CPE, or nil if not ClickHouse
//   - error: Error details, or nil
func runClickHouse(conn net.Conn, timeout time.Duration, target plugins.Target, isTLS bool) (*plugins.Service, error) {
	fields, detected, err := DetectClickHouse(conn, timeout)
	if !detected {
		return nil, err
	}

	version := ""
	if fields.HasPatch {
		version = fmt.Sprintf("%d.%d.%d", fields.VersionMajor, fields.VersionMinor, fields.VersionPatch)
	} else if fields.VersionMajor != 0 || fields.VersionMinor != 0 {
		version = fmt.Sprintf("%d.%d", fields.VersionMajor, fields.VersionMinor)
	}

	// Guard against CPE metacharacters in server-supplied version fields.
	if strings.ContainsAny(version, ":*?") {
		version = ""
	}

	cpe := buildClickHouseCPE(version)

	payload := plugins.ServiceClickHouse{
		ServerName:      fields.ServerName,
		Timezone:        fields.Timezone,
		DisplayName:     fields.DisplayName,
		ProtocolVersion: fields.ProtocolVersion,
		CPEs:            []string{cpe},
	}

	transport := plugins.TCP
	if isTLS {
		transport = plugins.TCPTLS
	}

	service := plugins.CreateServiceFrom(target, payload, isTLS, version, transport)
	return service, nil
}

// Run implements the Plugin interface for plaintext ClickHouse fingerprinting.
func (p *ClickHousePlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return runClickHouse(conn, timeout, target, false)
}

// Run implements the Plugin interface for TLS ClickHouse fingerprinting.
func (p *ClickHouseTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return runClickHouse(conn, timeout, target, true)
}

// PortPriority returns true if the port is the default ClickHouse native protocol port (9000).
func (p *ClickHousePlugin) PortPriority(port uint16) bool {
	return port == 9000
}

// PortPriority returns true if the port is the default ClickHouse native protocol TLS port (9440).
func (p *ClickHouseTLSPlugin) PortPriority(port uint16) bool {
	return port == 9440
}

// Name returns the protocol name.
func (p *ClickHousePlugin) Name() string {
	return CLICKHOUSE
}

// Name returns the protocol name.
func (p *ClickHouseTLSPlugin) Name() string {
	return CLICKHOUSE
}

// Type returns the protocol type (TCP).
func (p *ClickHousePlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Type returns the protocol type (TCPTLS).
func (p *ClickHouseTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

// Priority returns the plugin execution priority.
func (p *ClickHousePlugin) Priority() int {
	return 200
}

// Priority returns the plugin execution priority.
func (p *ClickHouseTLSPlugin) Priority() int {
	return 201
}
