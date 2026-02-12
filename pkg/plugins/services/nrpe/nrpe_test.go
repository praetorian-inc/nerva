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

package nrpe

import (
	"encoding/binary"
	"hash/crc32"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// buildMockNRPEResponse constructs a mock NRPE v2 response for testing (1036 bytes)
func buildMockNRPEResponse(message string) []byte {
	response := make([]byte, 1036) // Updated to 1036 bytes

	// Packet version: 2
	binary.BigEndian.PutUint16(response[0:2], PacketVersion2)

	// Packet type: 2 (Response)
	binary.BigEndian.PutUint16(response[2:4], ResponsePacket)

	// CRC32: initially 0
	binary.BigEndian.PutUint32(response[4:8], 0)

	// Result code: 0 (OK)
	binary.BigEndian.PutUint16(response[8:10], 0)

	// Buffer: message null-terminated, zero-padded
	copy(response[10:], message)

	// Calculate and set CRC32
	crc := crc32.ChecksumIEEE(response)
	binary.BigEndian.PutUint32(response[4:8], crc)

	return response
}

// TestBuildNRPEQuery verifies the NRPE v2 query packet is correctly constructed
func TestBuildNRPEQuery(t *testing.T) {
	packet := buildNRPEQuery()

	// Verify total length
	if len(packet) != PacketSize {
		t.Errorf("Expected packet length %d, got %d", PacketSize, len(packet))
	}

	// Verify packet version (bytes 0-1, big-endian, value = 2)
	version := binary.BigEndian.Uint16(packet[0:2])
	if version != PacketVersion2 {
		t.Errorf("Expected packet version %d, got %d", PacketVersion2, version)
	}

	// Verify packet type (bytes 2-3, big-endian, value = 1 for Query)
	packetType := binary.BigEndian.Uint16(packet[2:4])
	if packetType != QueryPacket {
		t.Errorf("Expected packet type %d, got %d", QueryPacket, packetType)
	}

	// Verify result code (bytes 8-9, big-endian, value = 0)
	resultCode := binary.BigEndian.Uint16(packet[8:10])
	if resultCode != 0 {
		t.Errorf("Expected result code 0, got %d", resultCode)
	}

	// Verify buffer contains "_NRPE_CHECK"
	command := string(packet[10 : 10+len(NRPECheckCommand)])
	if command != NRPECheckCommand {
		t.Errorf("Expected command '%s', got '%s'", NRPECheckCommand, command)
	}

	// Verify CRC32 is valid
	storedCRC := binary.BigEndian.Uint32(packet[4:8])

	// Set CRC field to 0 and recalculate
	packetCopy := make([]byte, len(packet))
	copy(packetCopy, packet)
	binary.BigEndian.PutUint32(packetCopy[4:8], 0)
	calculatedCRC := crc32.ChecksumIEEE(packetCopy)

	if storedCRC != calculatedCRC {
		t.Errorf("CRC32 mismatch: stored=%d, calculated=%d", storedCRC, calculatedCRC)
	}
}

// TestIsValidNRPEResponse verifies validation of NRPE v2 responses
func TestIsValidNRPEResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected bool
	}{
		{
			name:     "valid response with version info",
			response: buildMockNRPEResponse("NRPE v4.1.3"),
			expected: true,
		},
		{
			name:     "valid response without version",
			response: buildMockNRPEResponse("OK"),
			expected: true,
		},
		{
			name:     "empty response",
			response: []byte{},
			expected: false,
		},
		{
			name:     "response too short (1035 bytes - one byte short)",
			response: buildMockNRPEResponse("NRPE v4.1.3")[0:1035],
			expected: false,
		},
		{
			name: "wrong packet version (3 instead of 2)",
			response: func() []byte {
				resp := buildMockNRPEResponse("NRPE v4.1.3")
				binary.BigEndian.PutUint16(resp[0:2], 3) // wrong version
				return resp
			}(),
			expected: false,
		},
		{
			name: "wrong packet type (1 instead of 2)",
			response: func() []byte {
				resp := buildMockNRPEResponse("NRPE v4.1.3")
				binary.BigEndian.PutUint16(resp[2:4], 1) // Query instead of Response
				return resp
			}(),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidNRPEResponse(tt.response)
			if result != tt.expected {
				t.Errorf("isValidNRPEResponse() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestParseNRPEVersion verifies extraction of version from response buffer
func TestParseNRPEVersion(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected string
	}{
		{
			name:     "version 4.1.3 (latest)",
			response: buildMockNRPEResponse("NRPE v4.1.3"),
			expected: "4.1.3",
		},
		{
			name:     "version 4.0.3",
			response: buildMockNRPEResponse("NRPE v4.0.3"),
			expected: "4.0.3",
		},
		{
			name:     "version 3.2.1",
			response: buildMockNRPEResponse("NRPE v3.2.1"),
			expected: "3.2.1",
		},
		{
			name:     "version 3.0",
			response: buildMockNRPEResponse("NRPE v3.0"),
			expected: "3.0",
		},
		{
			name:     "version 2.16",
			response: buildMockNRPEResponse("NRPE v2.16"),
			expected: "2.16",
		},
		{
			name:     "version 2.15 (ancient but common)",
			response: buildMockNRPEResponse("NRPE v2.15"),
			expected: "2.15",
		},
		{
			name:     "no version in buffer",
			response: buildMockNRPEResponse("OK: All checks passed"),
			expected: "",
		},
		{
			name:     "empty buffer",
			response: buildMockNRPEResponse(""),
			expected: "",
		},
		{
			name:     "response too short",
			response: []byte{0x00, 0x01, 0x02},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseNRPEVersion(tt.response)
			if result != tt.expected {
				t.Errorf("parseNRPEVersion() = '%s', want '%s'", result, tt.expected)
			}
		})
	}
}

// TestGenerateCPE verifies CPE generation for NRPE
func TestGenerateCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with version 4.1.3",
			version:  "4.1.3",
			expected: "cpe:2.3:a:nagios:nrpe:4.1.3:*:*:*:*:*:*:*",
		},
		{
			name:     "with version 3.0",
			version:  "3.0",
			expected: "cpe:2.3:a:nagios:nrpe:3.0:*:*:*:*:*:*:*",
		},
		{
			name:     "without version (empty string)",
			version:  "",
			expected: "cpe:2.3:a:nagios:nrpe:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpes := generateCPE(tt.version)
			if len(cpes) != 1 {
				t.Fatalf("Expected 1 CPE, got %d", len(cpes))
			}
			if cpes[0] != tt.expected {
				t.Errorf("Expected CPE '%s', got '%s'", tt.expected, cpes[0])
			}
		})
	}
}

// TestTCPPluginType verifies TCP plugin returns correct protocol type
func TestTCPPluginType(t *testing.T) {
	plugin := &NRPEPlugin{}
	if plugin.Type() != plugins.TCP {
		t.Errorf("Expected TCP protocol, got %v", plugin.Type())
	}
}

// TestTLSPluginType verifies TLS plugin returns correct protocol type
func TestTLSPluginType(t *testing.T) {
	plugin := &NRPETLSPlugin{}
	if plugin.Type() != plugins.TCPTLS {
		t.Errorf("Expected TCPTLS protocol, got %v", plugin.Type())
	}
}

// TestTCPPortPriority verifies TCP plugin prioritizes port 5666
func TestTCPPortPriority(t *testing.T) {
	plugin := &NRPEPlugin{}
	if !plugin.PortPriority(5666) {
		t.Error("Expected port 5666 to have priority")
	}
	if plugin.PortPriority(8080) {
		t.Error("Port 8080 should not have priority")
	}
}

// TestTLSPortPriority verifies TLS plugin prioritizes port 5666
func TestTLSPortPriority(t *testing.T) {
	plugin := &NRPETLSPlugin{}
	if !plugin.PortPriority(5666) {
		t.Error("Expected port 5666 to have priority")
	}
	if plugin.PortPriority(8080) {
		t.Error("Port 8080 should not have priority")
	}
}

// TestPluginPriority verifies both plugins have priority 410
func TestPluginPriority(t *testing.T) {
	tcpPlugin := &NRPEPlugin{}
	tlsPlugin := &NRPETLSPlugin{}

	if tcpPlugin.Priority() != 410 {
		t.Errorf("Expected priority 410, got %d", tcpPlugin.Priority())
	}
	if tlsPlugin.Priority() != 410 {
		t.Errorf("Expected priority 410, got %d", tlsPlugin.Priority())
	}
}

// TestPluginName verifies plugin names
func TestPluginName(t *testing.T) {
	tcpPlugin := &NRPEPlugin{}
	tlsPlugin := &NRPETLSPlugin{}

	if tcpPlugin.Name() != NRPE {
		t.Errorf("Expected name '%s', got '%s'", NRPE, tcpPlugin.Name())
	}
	if tlsPlugin.Name() != NRPE {
		t.Errorf("Expected name '%s', got '%s'", NRPE, tlsPlugin.Name())
	}
}

// TestBuildNRPEQueryWithArgument verifies NRPE query packet with command argument
func TestBuildNRPEQueryWithArgument(t *testing.T) {
	command := "_NRPE_CHECK!test"
	packet := buildNRPEQueryWithCommand(command)

	// Verify total length (should be 1036 bytes)
	if len(packet) != 1036 {
		t.Errorf("Expected packet length 1036, got %d", len(packet))
	}

	// Verify packet version
	version := binary.BigEndian.Uint16(packet[0:2])
	if version != PacketVersion2 {
		t.Errorf("Expected packet version %d, got %d", PacketVersion2, version)
	}

	// Verify packet type (Query)
	packetType := binary.BigEndian.Uint16(packet[2:4])
	if packetType != QueryPacket {
		t.Errorf("Expected packet type %d, got %d", QueryPacket, packetType)
	}

	// Verify buffer contains the command
	bufferEnd := 10 + len(command)
	extractedCommand := string(packet[10:bufferEnd])
	if extractedCommand != command {
		t.Errorf("Expected command '%s', got '%s'", command, extractedCommand)
	}

	// Verify CRC32 is valid
	storedCRC := binary.BigEndian.Uint32(packet[4:8])
	packetCopy := make([]byte, len(packet))
	copy(packetCopy, packet)
	binary.BigEndian.PutUint32(packetCopy[4:8], 0)
	calculatedCRC := crc32.ChecksumIEEE(packetCopy)

	if storedCRC != calculatedCRC {
		t.Errorf("CRC32 mismatch: stored=%d, calculated=%d", storedCRC, calculatedCRC)
	}
}
