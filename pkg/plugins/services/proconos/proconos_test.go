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

package proconos

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// Mock connection for testing
type mockConn struct {
	*bytes.Buffer
	writeBuf *bytes.Buffer
}

func newMockConn(response []byte) net.Conn {
	return &mockConn{
		Buffer:   bytes.NewBuffer(response),
		writeBuf: bytes.NewBuffer(nil),
	}
}

func (mc *mockConn) Write(b []byte) (n int, err error) {
	return mc.writeBuf.Write(b)
}

func (mc *mockConn) Close() error                       { return nil }
func (mc *mockConn) LocalAddr() net.Addr                { return nil }
func (mc *mockConn) RemoteAddr() net.Addr               { return nil }
func (mc *mockConn) SetDeadline(t time.Time) error      { return nil }
func (mc *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (mc *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// buildMockProConOSResponse creates a mock ProConOS protocol response
func buildMockProConOSResponse() []byte {
	// Response must be at least long enough for all fields
	// Offset 8: Ladder Logic Runtime
	// Offset 44: PLC Type
	// Offset 76: Project Name
	response := make([]byte, 150)
	response[0] = 0xcc // Valid ProConOS signature

	// Add Ladder Logic Runtime at offset 8
	ladderRuntime := "3.5.0.10"
	copy(response[8:], ladderRuntime)
	response[8+len(ladderRuntime)] = 0x00 // Null terminator

	// Add PLC Type at offset 44
	plcType := "ProConOS"
	copy(response[44:], plcType)
	response[44+len(plcType)] = 0x00

	// Add Project Name at offset 76
	projectName := "TestProject"
	copy(response[76:], projectName)
	response[76+len(projectName)] = 0x00

	// Add Boot Project after Project Name (offset 76 + len + null + variable)
	bootProjectOffset := 76 + len(projectName) + 1
	bootProject := "BootProj"
	copy(response[bootProjectOffset:], bootProject)
	response[bootProjectOffset+len(bootProject)] = 0x00

	// Add Project Source Code after Boot Project
	sourceCodeOffset := bootProjectOffset + len(bootProject) + 1
	sourceCode := "main.st"
	copy(response[sourceCodeOffset:], sourceCode)
	response[sourceCodeOffset+len(sourceCode)] = 0x00

	return response
}

// buildInvalidResponse creates a response with invalid signature
func buildInvalidResponse() []byte {
	return []byte{0x00, 0x01, 0x02, 0x03}
}

func TestProConOSDetection(t *testing.T) {
	tests := []struct {
		name                   string
		response               []byte
		expectDetected         bool
		expectLadderRuntime    string
		expectPLCType          string
		expectProjectName      string
	}{
		{
			name:                "Valid ProConOS response",
			response:            buildMockProConOSResponse(),
			expectDetected:      true,
			expectLadderRuntime: "3.5.0.10",
			expectPLCType:       "ProConOS",
			expectProjectName:   "TestProject",
		},
		{
			name:           "Invalid signature",
			response:       buildInvalidResponse(),
			expectDetected: false,
		},
		{
			name:           "Empty response",
			response:       []byte{},
			expectDetected: false,
		},
		{
			name:           "Response too short",
			response:       []byte{0xcc, 0x01},
			expectDetected: true, // Still valid signature, just minimal metadata
		},
		{
			name:           "Minimum valid response (9 bytes)",
			response:       []byte{0xcc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expectDetected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newMockConn(tt.response)
			plugin := &ProConOSPlugin{}
			target := plugins.Target{Host: "127.0.0.1"}

			result, err := plugin.Run(conn, 5*time.Second, target)

			if tt.expectDetected {
				if result == nil {
					t.Errorf("Expected detection, got nil (err: %v)", err)
				} else if tt.expectLadderRuntime != "" {
					if svc, ok := result.Metadata().(plugins.ServiceProConOS); ok {
						if svc.LadderLogicRuntime != tt.expectLadderRuntime {
							t.Errorf("Expected LadderLogicRuntime %q, got %q", tt.expectLadderRuntime, svc.LadderLogicRuntime)
						}
						if svc.PLCType != tt.expectPLCType {
							t.Errorf("Expected PLCType %q, got %q", tt.expectPLCType, svc.PLCType)
						}
						if svc.ProjectName != tt.expectProjectName {
							t.Errorf("Expected ProjectName %q, got %q", tt.expectProjectName, svc.ProjectName)
						}
					} else {
						t.Errorf("Expected ServiceProConOS metadata, got %T", result.Metadata())
					}
				}
			} else {
				if result != nil {
					t.Errorf("Expected no detection, got result")
				}
			}
		})
	}
}

func TestProConOSPortPriority(t *testing.T) {
	plugin := &ProConOSPlugin{}

	tests := []struct {
		port     uint16
		expected bool
	}{
		{20547, true},  // ProConOS default port
		{8080, false},  // Random port
		{80, false},    // HTTP port
		{443, false},   // HTTPS port
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			result := plugin.PortPriority(tt.port)
			if result != tt.expected {
				t.Errorf("PortPriority(%d) = %v, expected %v", tt.port, result, tt.expected)
			}
		})
	}
}

func TestProConOSMetadata(t *testing.T) {
	plugin := &ProConOSPlugin{}

	if plugin.Name() != "proconos" {
		t.Errorf("Name() = %q, expected %q", plugin.Name(), "proconos")
	}

	if plugin.Type() != plugins.TCP {
		t.Errorf("Type() = %v, expected %v", plugin.Type(), plugins.TCP)
	}

	if plugin.Priority() != 400 {
		t.Errorf("Priority() = %d, expected %d", plugin.Priority(), 400)
	}
}

func TestExtractNullTerminatedString(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		offset   int
		expected string
	}{
		{
			name:     "Normal string",
			data:     []byte("hello\x00world"),
			offset:   0,
			expected: "hello",
		},
		{
			name:     "String at offset",
			data:     []byte{0x00, 0x00, 0x00, 't', 'e', 's', 't', 0x00},
			offset:   3,
			expected: "test",
		},
		{
			name:     "No null terminator",
			data:     []byte("hello"),
			offset:   0,
			expected: "hello",
		},
		{
			name:     "Offset beyond data",
			data:     []byte("test"),
			offset:   10,
			expected: "",
		},
		{
			name:     "Empty string at offset",
			data:     []byte{0x00, 0x00, 0x00},
			offset:   0,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractNullTerminatedString(tt.data, tt.offset)
			if result != tt.expected {
				t.Errorf("extractNullTerminatedString() = %q, expected %q", result, tt.expected)
			}
		})
	}
}

func TestGenerateProConOSCPE(t *testing.T) {
	tests := []struct {
		name     string
		runtime  string
		expected []string
	}{
		{
			name:     "Standard ProConOS version",
			runtime:  "V4.2ProConOS V4.2.0214 Oct 28 2011",
			expected: []string{"cpe:2.3:a:phoenix_contact:proconos:4.2.0214:*:*:*:*:*:*:*"},
		},
		{
			name:     "Empty string",
			runtime:  "",
			expected: nil,
		},
		{
			name:     "No ProConOS in string",
			runtime:  "Some other runtime V1.0",
			expected: nil,
		},
		{
			name:     "Lowercase proconos",
			runtime:  "proconos v3.1.5 Jan 01 2020",
			expected: []string{"cpe:2.3:a:phoenix_contact:proconos:3.1.5:*:*:*:*:*:*:*"},
		},
		{
			name:     "Version at end of string",
			runtime:  "ProConOS V5.0",
			expected: []string{"cpe:2.3:a:phoenix_contact:proconos:5.0:*:*:*:*:*:*:*"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateProConOSCPE(tt.runtime)
			if tt.expected == nil {
				if result != nil {
					t.Errorf("expected nil, got %v", result)
				}
				return
			}
			if len(result) != len(tt.expected) {
				t.Errorf("expected %d CPEs, got %d", len(tt.expected), len(result))
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("CPE[%d]: expected %q, got %q", i, tt.expected[i], result[i])
				}
			}
		})
	}
}
