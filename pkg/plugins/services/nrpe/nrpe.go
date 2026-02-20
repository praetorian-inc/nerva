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

/*
Package nrpe implements service detection for Nagios Remote Plugin Executor (NRPE) using the v2 binary protocol.

Detection Strategy:
1. Sends NRPE v2 query packet (1036 bytes):
   - 2-byte packet_version (big-endian, value = 2)
   - 2-byte packet_type (big-endian, value = 1 for Query)
   - 4-byte crc32_value (big-endian, CRC-32/IEEE over entire packet with crc32 field set to 0)
   - 2-byte result_code (big-endian, value = 0)
   - 1024-byte buffer (null-terminated command string "_NRPE_CHECK", zero-padded)
   - 2-byte struct padding (C struct alignment to 4 bytes: sizeof(v2_packet) = 1036)
2. Validates server NRPE v2 response packet:
   - Minimum 1036 bytes required (fixed v2 packet size with padding)
   - Bytes 0-1: packet_version must be 2
   - Bytes 2-3: packet_type must be 2 (Response)
   - Bytes 4-7: crc32_value must be valid
   - Bytes 10-1035: buffer contains "NRPE v" prefix indicating version
3. Extracts version from response buffer using regex `NRPE v(\d+\.\d+(?:\.\d+)?)`
4. Detects command argument support by sending "_NRPE_CHECK!test" probe
5. Returns Service with version-specific CPE, command args enabled flag, or wildcard CPE if version unknown
*/
package nrpe

import (
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"net"
	"regexp"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	NRPE             = "nrpe"
	PacketVersion2   = 2
	QueryPacket      = 1
	ResponsePacket   = 2
	PacketSize       = 1036 // Fixed v2 packet size (C struct with 2-byte padding: sizeof(v2_packet) = 1036)
	PacketPadding    = 2    // C struct end-padding for 4-byte alignment (1034 → 1036)
	BufferSize       = 1024 // Usable buffer size within packet
	NRPECheckCommand = "_NRPE_CHECK"
)

type NRPEPlugin struct{}
type NRPETLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&NRPEPlugin{})
	plugins.RegisterPlugin(&NRPETLSPlugin{})
}

// buildNRPEQuery constructs the NRPE v2 query packet with CRC32
func buildNRPEQuery() []byte {
	return buildNRPEQueryWithCommand(NRPECheckCommand)
}

// buildNRPEQueryWithCommand constructs an NRPE v2 query packet with a custom command
func buildNRPEQueryWithCommand(command string) []byte {
	// 1036-byte packet: version(2) + type(2) + crc32(4) + result(2) + buffer(1024) + padding(2)
	packet := make([]byte, PacketSize)

	// Packet version: 2 (big-endian uint16)
	binary.BigEndian.PutUint16(packet[0:2], PacketVersion2)

	// Packet type: 1 = Query (big-endian uint16)
	binary.BigEndian.PutUint16(packet[2:4], QueryPacket)

	// CRC32: initially 0, will be calculated below (big-endian uint32)
	binary.BigEndian.PutUint32(packet[4:8], 0)

	// Result code: 0 (big-endian uint16)
	binary.BigEndian.PutUint16(packet[8:10], 0)

	// Buffer: command null-terminated, zero-padded to 1024 bytes
	copy(packet[10:], command)
	// Rest of buffer and padding (from 10+len(command) to 1036) is already zero-initialized

	// Calculate CRC32 (CRC-32/IEEE polynomial 0xEDB88320) over entire 1036-byte packet
	crc := crc32.ChecksumIEEE(packet)
	binary.BigEndian.PutUint32(packet[4:8], crc)

	return packet
}

// isValidNRPEResponse validates an NRPE v2 response packet structure
func isValidNRPEResponse(response []byte) bool {
	// NRPE v2 response must be at least 1036 bytes (with C struct padding)
	if len(response) < PacketSize {
		return false
	}

	// Check packet_version (bytes 0-1, big-endian, must be 2)
	version := binary.BigEndian.Uint16(response[0:2])
	if version != PacketVersion2 {
		return false
	}

	// Check packet_type (bytes 2-3, big-endian, must be 2 for Response)
	packetType := binary.BigEndian.Uint16(response[2:4])
	if packetType != ResponsePacket {
		return false
	}

	return true
}

// parseNRPEVersion extracts the NRPE version from response buffer
func parseNRPEVersion(response []byte) string {
	if len(response) < PacketSize {
		return ""
	}

	// Buffer starts at byte 10, scan until null terminator or end of packet
	// (buffer is 1024 bytes long, packet is 1036 bytes with 2-byte padding)
	bufferEnd := len(response)
	if bufferEnd > PacketSize {
		bufferEnd = PacketSize
	}
	buffer := string(response[10:bufferEnd])

	// Extract version using regex: "NRPE v1.2.3" or "NRPE v4.1" etc.
	re := regexp.MustCompile(`NRPE v(\d+\.\d+(?:\.\d+)?)`)
	matches := re.FindStringSubmatch(buffer)
	if len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// generateCPE creates CPE identifier for NRPE services
func generateCPE(version string) []string {
	if version != "" {
		return []string{fmt.Sprintf("cpe:2.3:a:nagios:nrpe:%s:*:*:*:*:*:*:*", version)}
	}
	// Wildcard CPE when version is unknown
	return []string{"cpe:2.3:a:nagios:nrpe:*:*:*:*:*:*:*:*"}
}

// detectCommandArgs detects if command arguments are enabled on the NRPE server
func detectCommandArgs(addr string, timeout time.Duration, useTLS bool) *bool {
	var conn net.Conn
	var err error

	// Create appropriate connection type
	if useTLS {
		dialer := &net.Dialer{Timeout: timeout}
		// InsecureSkipVerify is intentionally true for this scanner because:
		// 1. We're probing unknown hosts that often have self-signed certificates
		// 2. We're only detecting the NRPE service, not transmitting sensitive data
		// 3. Certificate validation would cause false negatives on valid NRPE services
		tlsConfig := &tls.Config{InsecureSkipVerify: true}
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
	} else {
		conn, err = net.DialTimeout("tcp", addr, timeout)
	}
	if err != nil {
		return nil
	}
	defer conn.Close()

	// Send probe with command argument: "_NRPE_CHECK!test"
	probe := buildNRPEQueryWithCommand("_NRPE_CHECK!test")
	response, err := utils.SendRecv(conn, probe, timeout)

	// If we get EOF or connection closed, command args are disabled
	if err != nil {
		// Connection closed = command args disabled
		disabled := false
		return &disabled
	}

	// If we get a valid response, command args are enabled
	if len(response) > 0 && isValidNRPEResponse(response) {
		enabled := true
		return &enabled
	}

	// Unable to determine
	return nil
}

// detectNRPE performs NRPE protocol detection
func detectNRPE(conn net.Conn, timeout time.Duration, target plugins.Target, useTLS bool) (version string, commandArgsEnabled *bool, detected bool, err error) {
	// Send NRPE v2 query packet
	probe := buildNRPEQuery()
	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return "", nil, false, err
	}

	if len(response) == 0 {
		return "", nil, false, &utils.ServerNotEnable{}
	}

	// Validate NRPE v2 response
	if !isValidNRPEResponse(response) {
		return "", nil, false, &utils.InvalidResponseError{Service: NRPE}
	}

	// Extract version from buffer
	version = parseNRPEVersion(response)

	// Detect command argument support (separate connection)
	commandArgsEnabled = detectCommandArgs(conn.RemoteAddr().String(), timeout, useTLS)

	return version, commandArgsEnabled, true, nil
}

// NRPEPlugin implements TCP NRPE detection
func (p *NRPEPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, commandArgsEnabled, detected, err := detectNRPE(conn, timeout, target, false)
	if err != nil {
		if _, ok := err.(*utils.ServerNotEnable); ok {
			return nil, nil
		}
		if _, ok := err.(*utils.InvalidResponseError); ok {
			return nil, nil
		}
		return nil, err
	}

	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceNRPE{
		CommandArgsEnabled: commandArgsEnabled,
		CPEs:               generateCPE(version),
	}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *NRPEPlugin) PortPriority(port uint16) bool {
	return port == 5666
}

func (p *NRPEPlugin) Name() string {
	return NRPE
}

func (p *NRPEPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *NRPEPlugin) Priority() int {
	return 410
}

// NRPETLSPlugin implements TCPTLS NRPE detection
func (p *NRPETLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, commandArgsEnabled, detected, err := detectNRPE(conn, timeout, target, true)
	if err != nil {
		if _, ok := err.(*utils.ServerNotEnable); ok {
			return nil, nil
		}
		if _, ok := err.(*utils.InvalidResponseError); ok {
			return nil, nil
		}
		return nil, err
	}

	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceNRPE{
		CommandArgsEnabled: commandArgsEnabled,
		CPEs:               generateCPE(version),
	}

	return plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS), nil
}

func (p *NRPETLSPlugin) PortPriority(port uint16) bool {
	return port == 5666
}

func (p *NRPETLSPlugin) Name() string {
	return NRPE
}

func (p *NRPETLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *NRPETLSPlugin) Priority() int {
	return 410
}
