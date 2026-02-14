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

package pulsar

import (
	"encoding/binary"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
	"github.com/stretchr/testify/assert"
)

// TestBuildConnectFrame verifies Connect frame structure
func TestBuildConnectFrame(t *testing.T) {
	frame := buildConnectFrame()

	// Verify frame is at least 20 bytes (8 byte header + minimal protobuf)
	assert.GreaterOrEqual(t, len(frame), 20, "Frame should be at least 20 bytes")

	// Extract totalSize and cmdSize
	totalSize := binary.BigEndian.Uint32(frame[0:4])
	cmdSize := binary.BigEndian.Uint32(frame[4:8])

	// Verify sizes are consistent
	assert.Equal(t, uint32(4+cmdSize), totalSize, "totalSize should equal 4 + cmdSize")
	assert.Equal(t, len(frame)-8, int(cmdSize), "cmdSize should match protobuf length")

	// Verify protobuf starts with BaseCommand.type = CONNECT (08 02)
	protobuf := frame[8:]
	assert.GreaterOrEqual(t, len(protobuf), 2, "Protobuf should have at least 2 bytes")
	assert.Equal(t, byte(0x08), protobuf[0], "First byte should be field tag 08 (type)")
	assert.Equal(t, byte(0x02), protobuf[1], "Second byte should be value 02 (CONNECT)")

	// Verify client_version string is present somewhere in frame
	clientVersion := "Pulsar-Client-Go-v0.14.0"
	frameStr := string(frame)
	assert.Contains(t, frameStr, clientVersion, "Frame should contain client version")

	// Verify protocol_version field (tag 20, value 06 or higher)
	// Tag 20 = field 4 (protocol_version), wire type 0
	foundProtocolVersion := false
	for i := 0; i < len(protobuf)-1; i++ {
		if protobuf[i] == 0x20 {
			// Found protocol_version tag
			foundProtocolVersion = true
			// Value should be 6 or higher (we use 6)
			assert.GreaterOrEqual(t, protobuf[i+1], byte(0x06), "Protocol version should be >= 6")
			break
		}
	}
	assert.True(t, foundProtocolVersion, "Frame should contain protocol_version field (tag 0x20)")
}

// TestDecodeVarint validates varint decoding
func TestDecodeVarint(t *testing.T) {
	tests := []struct {
		name      string
		input     []byte
		pos       int
		expected  uint64
		expectedPos int
	}{
		{
			name:        "single_byte_6",
			input:       []byte{0x06},
			pos:         0,
			expected:    6,
			expectedPos: 1,
		},
		{
			name:        "two_byte_128",
			input:       []byte{0x80, 0x01},
			pos:         0,
			expected:    128,
			expectedPos: 2,
		},
		{
			name:        "zero",
			input:       []byte{0x00},
			pos:         0,
			expected:    0,
			expectedPos: 1,
		},
		{
			name:        "max_single_byte_127",
			input:       []byte{0x7F},
			pos:         0,
			expected:    127,
			expectedPos: 1,
		},
		{
			name:        "empty_input",
			input:       []byte{},
			pos:         0,
			expected:    0,
			expectedPos: -1,
		},
		{
			name: "overflow_protection",
			// 11 bytes with high bit set will cause shift > 63
			input:       []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
			pos:         0,
			expected:    0,
			expectedPos: -1,
		},
		{
			name:        "truncated_varint",
			input:       []byte{0x80}, // High bit set but no next byte
			pos:         0,
			expected:    0,
			expectedPos: -1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, pos := decodeVarint(tt.input, tt.pos)
			assert.Equal(t, tt.expected, value, "Value mismatch")
			assert.Equal(t, tt.expectedPos, pos, "Position mismatch")
		})
	}
}

// TestExtractServerVersion validates server version extraction from Connected response
func TestExtractServerVersion(t *testing.T) {
	tests := []struct {
		name            string
		protobuf        []byte
		expectedVersion string
	}{
		{
			name: "valid_pulsar_3.0.0",
			// BaseCommand { type = 2 (CONNECTED), connected = CommandConnected {...} }
			protobuf: buildMockConnectedResponse("Pulsar-Broker-v3.0.0", 7),
			expectedVersion: "3.0.0",
		},
		{
			name: "valid_pulsar_2.10.4",
			protobuf: buildMockConnectedResponse("Pulsar-Broker-v2.10.4", 6),
			expectedVersion: "2.10.4",
		},
		{
			name: "pulsar_server_format_no_dash",
			// Pulsar 4.x format: "Pulsar Server4.1.2" (space, no dash, no "Broker-v")
			protobuf: buildMockConnectedResponse("Pulsar Server4.1.2", 6),
			expectedVersion: "4.1.2",
		},
		{
			name: "non_pulsar_version",
			// Server version without "Pulsar-Broker-v" prefix
			protobuf: buildMockConnectedResponse("SomeOther-v1.0", 6),
			expectedVersion: "SomeOther-v1.0",
		},
		{
			name: "empty_protobuf",
			protobuf: []byte{},
			expectedVersion: "",
		},
		{
			name: "truncated_protobuf",
			// Just tag byte, no value
			protobuf: []byte{0x08},
			expectedVersion: "",
		},
		{
			name: "no_connected_field",
			// BaseCommand with type = 2 but no field 3 (connected)
			protobuf: []byte{
				0x08, 0x02, // type = 2 (CONNECTED)
			},
			expectedVersion: "",
		},
		{
			name: "wrong_command_type",
			// BaseCommand with type = 3 (not CONNECTED)
			protobuf: []byte{
				0x08, 0x03, // type = 3 (PRODUCER)
			},
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := extractServerVersion(tt.protobuf)
			assert.Equal(t, tt.expectedVersion, version, "Version mismatch")
		})
	}
}

// TestParseServerVersionFromConnected validates version parsing from CommandConnected
func TestParseServerVersionFromConnected(t *testing.T) {
	tests := []struct {
		name            string
		protobuf        []byte
		expectedVersion string
	}{
		{
			name: "valid_version",
			// CommandConnected { server_version = "Pulsar-Broker-v4.0.3", protocol_version = 7 }
			protobuf: []byte{
				0x0a, 0x14, // field 1 (server_version), length 20
				0x50, 0x75, 0x6c, 0x73, 0x61, 0x72, 0x2d, 0x42, // "Pulsar-B"
				0x72, 0x6f, 0x6b, 0x65, 0x72, 0x2d, 0x76, 0x34, // "roker-v4"
				0x2e, 0x30, 0x2e, 0x33, // ".0.3" (total 20 bytes)
				0x10, 0x07, // field 2 (protocol_version), value 7
			},
			expectedVersion: "4.0.3",
		},
		{
			name: "no_prefix_version",
			// CommandConnected { server_version = "4.0.3" }
			protobuf: []byte{
				0x0a, 0x05, // field 1, length 5
				0x34, 0x2e, 0x30, 0x2e, 0x33, // "4.0.3"
			},
			expectedVersion: "4.0.3",
		},
		{
			name: "pulsar_server_space_format",
			// CommandConnected { server_version = "Pulsar Server4.1.2" }
			protobuf: func() []byte {
				var msg []byte
				version := "Pulsar Server4.1.2"
				msg = append(msg, 0x0a)                    // field 1 (server_version)
				msg = append(msg, byte(len(version)))      // length
				msg = append(msg, []byte(version)...)      // string
				msg = append(msg, 0x10, 0x06)              // field 2 (protocol_version = 6)
				return msg
			}(),
			expectedVersion: "4.1.2",
		},
		{
			name: "empty_protobuf",
			protobuf: []byte{},
			expectedVersion: "",
		},
		{
			name: "no_server_version_field",
			// CommandConnected { protocol_version = 7 }
			protobuf: []byte{
				0x10, 0x07, // field 2 (protocol_version), no field 1
			},
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := parseServerVersionFromConnected(tt.protobuf)
			assert.Equal(t, tt.expectedVersion, version, "Version mismatch")
		})
	}
}

// TestBuildCPE validates CPE generation
func TestBuildCPE(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectedCPE string
	}{
		{
			name:        "version_3.0.0",
			version:     "3.0.0",
			expectedCPE: "cpe:2.3:a:apache:pulsar:3.0.0:*:*:*:*:*:*:*",
		},
		{
			name:        "version_2.10.4",
			version:     "2.10.4",
			expectedCPE: "cpe:2.3:a:apache:pulsar:2.10.4:*:*:*:*:*:*:*",
		},
		{
			name:        "empty_version",
			version:     "",
			expectedCPE: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildCPE(tt.version)
			assert.Equal(t, tt.expectedCPE, cpe, "CPE mismatch")
		})
	}
}

// TestDetectPulsarAdmin validates HTTP admin API detection
func TestDetectPulsarAdmin(t *testing.T) {
	tests := []struct {
		name           string
		response       string
		shouldDetect   bool
		expectedError  bool
	}{
		{
			name: "valid_standalone_cluster",
			response: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`["standalone"]`,
			shouldDetect:  true,
			expectedError: false,
		},
		{
			name: "valid_multi_cluster",
			response: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`["us-east-1","eu-west-1"]`,
			shouldDetect:  true,
			expectedError: false,
		},
		{
			name: "invalid_not_json",
			response: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n" +
				`<html>Not Found</html>`,
			shouldDetect:  false,
			expectedError: true,
		},
		{
			name: "invalid_not_array",
			response: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`{"error":"not found"}`,
			shouldDetect:  false,
			expectedError: true,
		},
		{
			name: "invalid_404",
			response: "HTTP/1.1 404 Not Found\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`["standalone"]`,
			shouldDetect:  false,
			expectedError: true,
		},
		{
			name: "invalid_empty_response",
			response: "",
			shouldDetect:  false,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock connection
			mockConn := &mockConn{
				readData: []byte(tt.response),
			}

			// Run detection
			addr, _ := netip.ParseAddrPort("127.0.0.1:8080")
			target := plugins.Target{
				Address: addr,
				Host:    "localhost",
			}
			result, err := detectPulsarAdmin(mockConn, false, 5*time.Second, target)

			if tt.shouldDetect {
				assert.NoError(t, err, "Should not return error")
				assert.NotNil(t, result, "Should return service")
			} else if tt.expectedError {
				assert.Error(t, err, "Should return error")
				assert.Nil(t, result, "Should not return service")
			}
		})
	}
}

// TestDetectPulsarBinary validates binary protocol detection with mock responses
func TestDetectPulsarBinary(t *testing.T) {
	tests := []struct {
		name          string
		response      []byte
		shouldDetect  bool
		expectedError bool
	}{
		{
			name:          "valid_connected_response",
			response:      buildValidConnectedFrame("3.0.0"),
			shouldDetect:  true,
			expectedError: false,
		},
		{
			name: "wrong_command_type",
			// Frame with type = 1 (not CONNECTED=3)
			response:      buildFrameWithCommandType(1),
			shouldDetect:  false,
			expectedError: true,
		},
		{
			name:          "too_short_response",
			response:      []byte{0x00, 0x00, 0x00, 0x01},
			shouldDetect:  false,
			expectedError: true,
		},
		{
			name: "oversized_totalSize",
			// totalSize = 0xFFFFFFFF
			response:      []byte{0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x08},
			shouldDetect:  false,
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create mock connection
			mockConn := &mockConn{
				readData: tt.response,
			}

			// Run detection
			addr, _ := netip.ParseAddrPort("127.0.0.1:6650")
			target := plugins.Target{
				Address: addr,
				Host:    "localhost",
			}
			result, err := detectPulsarBinary(mockConn, false, 5*time.Second, target)

			if tt.shouldDetect {
				assert.NoError(t, err, "Should not return error")
				assert.NotNil(t, result, "Should return service")
			} else if tt.expectedError {
				assert.Error(t, err, "Should return error")
				assert.Nil(t, result, "Should not return service")
			}
		})
	}
}

// TestPulsarDocker runs Docker integration tests
func TestPulsarDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	testcases := []test.Testcase{
		{
			Description: "pulsar-binary",
			Port:        6650,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil && res.Protocol == plugins.ProtoPulsar
			},
			RunConfig: dockertest.RunOptions{
				Repository:   "apachepulsar/pulsar",
				Tag:          "3.0.9",
				Cmd:          []string{"bin/pulsar", "standalone"},
				ExposedPorts: []string{"6650/tcp"},
			},
		},
		{
			Description: "pulsar-admin",
			Port:        8080,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil && res.Protocol == plugins.ProtoPulsarAdmin
			},
			RunConfig: dockertest.RunOptions{
				Repository:   "apachepulsar/pulsar",
				Tag:          "3.0.9",
				Cmd:          []string{"bin/pulsar", "standalone"},
				ExposedPorts: []string{"8080/tcp"},
			},
		},
	}

	// Binary and admin tests use different plugin types
	pluginMap := map[string]plugins.Plugin{
		"pulsar-binary": &Plugin{},
		"pulsar-admin":  &AdminPlugin{},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, pluginMap[tc.Description])
			if err != nil {
				t.Errorf("%s", err.Error())
			}
		})
	}
}

// Helper: buildMockConnectedResponse creates a protobuf Connected response
func buildMockConnectedResponse(serverVersion string, protocolVersion int) []byte {
	// Build CommandConnected nested message
	var connectMsg []byte

	// Field 1: server_version (tag 0a = field 1, wire type 2)
	connectMsg = append(connectMsg, 0x0a)
	connectMsg = append(connectMsg, byte(len(serverVersion)))
	connectMsg = append(connectMsg, []byte(serverVersion)...)

	// Field 2: protocol_version (tag 10 = field 2, wire type 0)
	connectMsg = append(connectMsg, 0x10)
	connectMsg = append(connectMsg, byte(protocolVersion))

	// Build BaseCommand
	var baseCmd []byte

	// Field 1: type = 3 (CONNECTED)
	baseCmd = append(baseCmd, 0x08, 0x03)

	// Field 3: connected (tag 1a = field 3, wire type 2)
	baseCmd = append(baseCmd, 0x1a)
	baseCmd = append(baseCmd, byte(len(connectMsg)))
	baseCmd = append(baseCmd, connectMsg...)

	return baseCmd
}

// Helper: buildValidConnectedFrame creates a full Pulsar frame with Connected response
func buildValidConnectedFrame(version string) []byte {
	serverVersion := "Pulsar-Broker-v" + version
	pbData := buildMockConnectedResponse(serverVersion, 7)

	cmdSize := uint32(len(pbData))
	totalSize := 4 + cmdSize

	frame := make([]byte, 8+cmdSize)
	binary.BigEndian.PutUint32(frame[0:4], totalSize)
	binary.BigEndian.PutUint32(frame[4:8], cmdSize)
	copy(frame[8:], pbData)

	return frame
}

// Helper: buildFrameWithCommandType creates a frame with specific command type
func buildFrameWithCommandType(cmdType byte) []byte {
	pbData := []byte{0x08, cmdType}

	cmdSize := uint32(len(pbData))
	totalSize := 4 + cmdSize

	frame := make([]byte, 8+cmdSize)
	binary.BigEndian.PutUint32(frame[0:4], totalSize)
	binary.BigEndian.PutUint32(frame[4:8], cmdSize)
	copy(frame[8:], pbData)

	return frame
}

// mockConn implements net.Conn for testing
type mockConn struct {
	readData  []byte
	readPos   int
	written   []byte
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readPos >= len(m.readData) {
		return 0, io.EOF
	}
	n = copy(b, m.readData[m.readPos:])
	m.readPos += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.written = append(m.written, b...)
	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (m *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 8080} }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }
