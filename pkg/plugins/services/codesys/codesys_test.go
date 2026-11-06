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

package codesys

import (
	"bytes"
	"io"
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

// buildMockV2Response creates a mock V2 protocol response
func buildMockV2Response() []byte {
	response := make([]byte, 150)
	response[0] = 0xbb // Same two-byte signature the request sends
	response[1] = 0xbb

	// Add mock metadata at expected offsets
	osName := "Windows"
	copy(response[65:], osName)
	response[65+len(osName)] = 0x00 // Null terminator

	osType := "NT"
	copy(response[97:], osType)
	response[97+len(osType)] = 0x00

	productType := "CODESYS V2.3.9.60"
	copy(response[129:], productType)
	response[129+len(productType)] = 0x00

	return response
}

// buildInvalidResponse creates a response with invalid signature
func buildInvalidResponse() []byte {
	return []byte{0x00, 0x01, 0x02, 0x03}
}

func TestCODESYSV2Detection(t *testing.T) {
	tests := []struct {
		name           string
		response       []byte
		expectDetected bool
		expectVersion  string
	}{
		{
			name:           "Valid V2 response",
			response:       buildMockV2Response(),
			expectDetected: true,
			expectVersion:  "2.3.9.60",
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
			response:       []byte{0xbb, 0x01},
			expectDetected: false, // Too short - minimum 10 bytes required (CWE-125 fix)
		},
		{
			name: "only first signature byte",
			response: func() []byte {
				buf := make([]byte, 150)
				buf[0] = 0xbb
				return buf
			}(),
			expectDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newMockConn(tt.response)
			plugin := &CODESYSPlugin{}
			target := plugins.Target{Host: "127.0.0.1"}

			result, err := plugin.Run(conn, 5*time.Second, target)

			if tt.expectDetected {
				if result == nil {
					t.Errorf("Expected detection, got nil (err: %v)", err)
				} else if tt.expectVersion != "" {
					if svc, ok := result.Metadata().(plugins.ServiceCODESYS); ok {
						if svc.Version != tt.expectVersion {
							t.Errorf("Expected version %q, got %q", tt.expectVersion, svc.Version)
						}
					} else {
						t.Errorf("Expected ServiceCODESYS metadata, got %T", result.Metadata())
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

func TestCODESYSPortPriority(t *testing.T) {
	plugin := &CODESYSPlugin{}

	tests := []struct {
		port     uint16
		expected bool
	}{
		{2455, true},   // Primary port
		{1217, true},   // Older gateway port
		{1200, true},   // Legacy port
		{11740, false}, // V3 port (not in PortPriority for now)
		{8080, false},  // Random port
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

func TestCODESYSMetadata(t *testing.T) {
	plugin := &CODESYSPlugin{}

	if plugin.Name() != "codesys" {
		t.Errorf("Name() = %q, expected %q", plugin.Name(), "codesys")
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

func TestExtractVersionFromProduct(t *testing.T) {
	tests := []struct {
		productType     string
		expectedVersion string
	}{
		{"CODESYS V2.3.9.60", "2.3.9.60"},
		{"CODESYS V3.5.16.0", "3.5.16.0"},
		{"CODESYS", ""},
		{"", ""},
		{"V2.3", "2.3"},
	}

	for _, tt := range tests {
		t.Run(tt.productType, func(t *testing.T) {
			result := extractVersionFromProduct(tt.productType)
			if result != tt.expectedVersion {
				t.Errorf("extractVersionFromProduct(%q) = %q, expected %q",
					tt.productType, result, tt.expectedVersion)
			}
		})
	}
}

type scriptedRead struct {
	data []byte
	err  error
}

type scriptedConn struct {
	reads []scriptedRead
	i     int
}

func (c *scriptedConn) Read(b []byte) (int, error) {
	if c.i >= len(c.reads) {
		return 0, io.EOF
	}
	r := c.reads[c.i]
	c.i++
	n := copy(b, r.data)
	return n, r.err
}

func (c *scriptedConn) Write(b []byte) (int, error)        { return len(b), nil }
func (c *scriptedConn) Close() error                       { return nil }
func (c *scriptedConn) LocalAddr() net.Addr                { return nil }
func (c *scriptedConn) RemoteAddr() net.Addr               { return nil }
func (c *scriptedConn) SetDeadline(t time.Time) error      { return nil }
func (c *scriptedConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *scriptedConn) SetWriteDeadline(t time.Time) error { return nil }

type timeoutErr struct{}

func (timeoutErr) Error() string   { return "i/o timeout" }
func (timeoutErr) Timeout() bool   { return true }
func (timeoutErr) Temporary() bool { return true }

func TestCODESYSHardErrorIsMiss(t *testing.T) {
	conn := &scriptedConn{reads: []scriptedRead{
		{err: io.ErrClosedPipe},
		{data: buildMockV2Response()},
	}}
	plugin := &CODESYSPlugin{}
	result, err := plugin.Run(conn, time.Second, plugins.Target{Host: "127.0.0.1"})
	if err != nil {
		t.Fatalf("reset should be a miss, not a scan error: %v", err)
	}
	if result != nil {
		t.Fatal("reset must not continue on a dead connection")
	}
}

func TestCODESYSTimeoutEmptyTriesBigEndian(t *testing.T) {
	conn := &scriptedConn{reads: []scriptedRead{
		{err: timeoutErr{}},
		{data: buildMockV2Response()},
	}}
	plugin := &CODESYSPlugin{}
	result, err := plugin.Run(conn, time.Second, plugins.Target{Host: "127.0.0.1"})
	if err != nil {
		t.Fatalf("timeout-as-empty should try big-endian, got error: %v", err)
	}
	if result == nil {
		t.Fatal("timeout-as-empty should still detect a big-endian response")
	}
}
