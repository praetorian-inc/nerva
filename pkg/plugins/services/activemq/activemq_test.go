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

package activemq

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// buildMockWireFormatInfoResponse constructs a mock WIREFORMAT_INFO response for testing
func buildMockWireFormatInfoResponse(version uint32) []byte {
	response := make([]byte, 21)
	binary.BigEndian.PutUint32(response[0:4], 17)  // size
	response[4] = 0x01                              // type (WIREFORMAT_INFO)
	copy(response[5:13], "ActiveMQ")                // magic
	binary.BigEndian.PutUint32(response[13:17], version) // version
	binary.BigEndian.PutUint32(response[17:21], 0)  // empty properties
	return response
}

// TestBuildWireFormatInfo verifies the WIREFORMAT_INFO probe is correctly constructed
func TestBuildWireFormatInfo(t *testing.T) {
	probe := buildWireFormatInfo()

	// Verify total length
	if len(probe) != 21 {
		t.Errorf("Expected probe length 21, got %d", len(probe))
	}

	// Verify size prefix (bytes 0-3, big-endian, value = 17)
	sizePrefix := binary.BigEndian.Uint32(probe[0:4])
	if sizePrefix != 17 {
		t.Errorf("Expected size prefix 17, got %d", sizePrefix)
	}

	// Verify type byte (byte 4, value = 0x01)
	if probe[4] != 0x01 {
		t.Errorf("Expected type byte 0x01, got 0x%02x", probe[4])
	}

	// Verify magic "ActiveMQ" (bytes 5-12)
	magic := string(probe[5:13])
	if magic != "ActiveMQ" {
		t.Errorf("Expected magic 'ActiveMQ', got '%s'", magic)
	}

	// Verify protocol version (bytes 13-16, big-endian, value = 1)
	version := binary.BigEndian.Uint32(probe[13:17])
	if version != 1 {
		t.Errorf("Expected protocol version 1, got %d", version)
	}

	// Verify empty properties (bytes 17-20, big-endian, value = 0)
	properties := binary.BigEndian.Uint32(probe[17:21])
	if properties != 0 {
		t.Errorf("Expected empty properties 0, got %d", properties)
	}
}

// TestIsValidWireFormatInfo verifies validation of WIREFORMAT_INFO responses
func TestIsValidWireFormatInfo(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected bool
	}{
		{
			name:     "valid response with correct magic and type",
			response: buildMockWireFormatInfoResponse(1),
			expected: true,
		},
		{
			name:     "empty response",
			response: []byte{},
			expected: false,
		},
		{
			name:     "response too short (16 bytes - one byte short)",
			response: buildMockWireFormatInfoResponse(1)[0:16],
			expected: false,
		},
		{
			name:     "response exactly 17 bytes (minimum valid)",
			response: buildMockWireFormatInfoResponse(1)[0:17],
			expected: true,
		},
		{
			name: "wrong command type (0x02 instead of 0x01)",
			response: func() []byte {
				resp := buildMockWireFormatInfoResponse(1)
				resp[4] = 0x02 // wrong type
				return resp
			}(),
			expected: false,
		},
		{
			name: "wrong magic bytes (NotAMQP! instead of ActiveMQ)",
			response: func() []byte {
				resp := buildMockWireFormatInfoResponse(1)
				copy(resp[5:13], "NotAMQP!")
				return resp
			}(),
			expected: false,
		},
		{
			name: "correct magic but different surrounding bytes",
			response: func() []byte {
				resp := buildMockWireFormatInfoResponse(1)
				resp[3] = 0xFF // modify size prefix
				// type and magic still correct
				return resp
			}(),
			expected: true, // still valid because only type and magic are checked
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidWireFormatInfo(tt.response)
			if result != tt.expected {
				t.Errorf("isValidWireFormatInfo() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestParseProtocolVersion verifies extraction of protocol version from response
func TestParseProtocolVersion(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected int
	}{
		{
			name:     "valid version 1",
			response: buildMockWireFormatInfoResponse(1),
			expected: 1,
		},
		{
			name:     "valid version 12 (max)",
			response: buildMockWireFormatInfoResponse(12),
			expected: 12,
		},
		{
			name:     "version 0 (invalid - below min)",
			response: buildMockWireFormatInfoResponse(0),
			expected: 0,
		},
		{
			name:     "version 13 (invalid - above max)",
			response: buildMockWireFormatInfoResponse(13),
			expected: 0,
		},
		{
			name:     "very large version (invalid)",
			response: buildMockWireFormatInfoResponse(999999),
			expected: 0,
		},
		{
			name:     "response too short (16 bytes)",
			response: buildMockWireFormatInfoResponse(1)[0:16],
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseProtocolVersion(tt.response)
			if result != tt.expected {
				t.Errorf("parseProtocolVersion() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestGenerateCPE verifies CPE generation for ActiveMQ
func TestGenerateCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  int
		expected string
	}{
		{
			name:     "with version",
			version:  1,
			expected: ActiveMQCPEMatch,
		},
		{
			name:     "with different version",
			version:  12,
			expected: ActiveMQCPEMatch,
		},
		{
			name:     "without version (zero)",
			version:  0,
			expected: ActiveMQCPEMatch,
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
	plugin := &Plugin{}
	if plugin.Type() != plugins.TCP {
		t.Errorf("Expected TCP protocol, got %v", plugin.Type())
	}
}

// TestTLSPluginType verifies TLS plugin returns correct protocol type
func TestTLSPluginType(t *testing.T) {
	plugin := &TLSPlugin{}
	if plugin.Type() != plugins.TCPTLS {
		t.Errorf("Expected TCPTLS protocol, got %v", plugin.Type())
	}
}

// TestTCPPortPriority verifies TCP plugin prioritizes port 61616
func TestTCPPortPriority(t *testing.T) {
	plugin := &Plugin{}
	if !plugin.PortPriority(61616) {
		t.Error("Expected port 61616 to have priority")
	}
	if plugin.PortPriority(61617) {
		t.Error("Port 61617 should not have priority for TCP plugin")
	}
}

// TestTLSPortPriority verifies TLS plugin prioritizes port 61617
func TestTLSPortPriority(t *testing.T) {
	plugin := &TLSPlugin{}
	if !plugin.PortPriority(61617) {
		t.Error("Expected port 61617 to have priority")
	}
	if plugin.PortPriority(61616) {
		t.Error("Port 61616 should not have priority for TLS plugin")
	}
}

// TestPluginPriority verifies both plugins have priority 100
func TestPluginPriority(t *testing.T) {
	tcpPlugin := &Plugin{}
	tlsPlugin := &TLSPlugin{}

	if tcpPlugin.Priority() != 100 {
		t.Errorf("Expected priority 100, got %d", tcpPlugin.Priority())
	}
	if tlsPlugin.Priority() != 100 {
		t.Errorf("Expected priority 100, got %d", tlsPlugin.Priority())
	}
}

// TestPluginName verifies plugin names
func TestPluginName(t *testing.T) {
	tcpPlugin := &Plugin{}
	tlsPlugin := &TLSPlugin{}

	if tcpPlugin.Name() != ActiveMQOpenWire {
		t.Errorf("Expected name '%s', got '%s'", ActiveMQOpenWire, tcpPlugin.Name())
	}
	if tlsPlugin.Name() != ActiveMQOpenWireTLS {
		t.Errorf("Expected name '%s', got '%s'", ActiveMQOpenWireTLS, tlsPlugin.Name())
	}
}

// TestDetectActiveMQWithMockServer tests DetectActiveMQ() against a mock TCP server
func TestDetectActiveMQWithMockServer(t *testing.T) {
	tests := []struct {
		name             string
		serverBehavior   func(net.Conn)
		expectDetected   bool
		expectVersion    int
		expectError      bool
	}{
		{
			name: "valid_activemq_response",
			serverBehavior: func(conn net.Conn) {
				defer conn.Close()

				// Read the incoming probe (21 bytes)
				buf := make([]byte, 256)
				n, err := conn.Read(buf)
				if err != nil {
					return
				}

				// Validate probe format (21 bytes, type 0x01, magic "ActiveMQ")
				if n < 21 {
					t.Errorf("Expected probe >= 21 bytes, got %d", n)
					return
				}
				if buf[4] != 0x01 {
					t.Errorf("Expected probe type 0x01, got 0x%02x", buf[4])
					return
				}
				if string(buf[5:13]) != "ActiveMQ" {
					t.Errorf("Expected probe magic 'ActiveMQ', got '%s'", string(buf[5:13]))
					return
				}

				// Respond with valid WIREFORMAT_INFO (version 12)
				response := buildMockWireFormatInfoResponse(12)
				conn.Write(response)
			},
			expectDetected: true,
			expectVersion:  12,
			expectError:    false,
		},
		{
			name: "invalid_response_garbage",
			serverBehavior: func(conn net.Conn) {
				defer conn.Close()

				// Read probe
				buf := make([]byte, 256)
				conn.Read(buf)

				// Respond with random garbage bytes
				garbage := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
				conn.Write(garbage)
			},
			expectDetected: false,
			expectVersion:  0,
			expectError:    true, // DetectActiveMQ returns InvalidResponseError
		},
		{
			name: "server_closes_immediately",
			serverBehavior: func(conn net.Conn) {
				// Accept connection then immediately close
				conn.Close()
			},
			expectDetected: false,
			expectVersion:  0,
			expectError:    true, // Connection closed before response
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Start mock TCP server on random port
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to start mock server: %v", err)
			}
			defer listener.Close()

			port := listener.Addr().(*net.TCPAddr).Port

			// Server goroutine
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				tt.serverBehavior(conn)
			}()

			// Give server time to start
			time.Sleep(50 * time.Millisecond)

			// Connect to mock server
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
			if err != nil {
				t.Fatalf("Failed to connect to mock server: %v", err)
			}
			defer conn.Close()

			// Call DetectActiveMQ
			version, detected, err := DetectActiveMQ(conn, 5*time.Second)

			// Verify results
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error, got nil")
				}
			} else {
				if err != nil {
					t.Errorf("Expected no error, got %v", err)
				}
			}

			if detected != tt.expectDetected {
				t.Errorf("Expected detected=%v, got %v", tt.expectDetected, detected)
			}

			if version != tt.expectVersion {
				t.Errorf("Expected version=%d, got %d", tt.expectVersion, version)
			}
		})
	}
}

// TestActiveMQ performs Docker integration test using dockertest pattern
func TestActiveMQ(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	testcases := []test.Testcase{
		{
			Description: "activemq-openwire",
			Port:        61616,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil && res.Protocol == "activemq-openwire"
			},
			RunConfig: dockertest.RunOptions{
				Repository: "apache/activemq-classic",
				Tag:        "5.18.3",
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.Description, func(t *testing.T) {
			plugin := &Plugin{}
			err := test.RunTest(t, tc, plugin)
			if err != nil {
				t.Fatalf("Test failed: %v", err)
			}
		})
	}
}
