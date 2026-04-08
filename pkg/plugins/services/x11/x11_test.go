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

package x11

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// buildX11SuccessResponse constructs a mock X11 success response (status=1).
//
// The success response header (8 bytes) plus additional data fields:
//
//	Offset 0:   status = 1 (Success)
//	Offset 1:   unused = 0
//	Offset 2-3: major version (little-endian)
//	Offset 4-5: minor version (little-endian)
//	Offset 6-7: additional data length in 4-byte units
//	Offset 8+:  additional data (release-number, resource IDs, etc.)
//	Offset 24-25: vendor-length (little-endian uint16)
//	Offset 40+: vendor string
func buildX11SuccessResponse(major, minor uint16, vendor string) []byte {
	vendorLen := uint16(len(vendor))
	// Pad vendor to 4-byte alignment
	vendorPadded := vendorLen
	if vendorPadded%4 != 0 {
		vendorPadded = vendorPadded + (4 - vendorPadded%4)
	}

	totalLen := 40 + int(vendorPadded)
	response := make([]byte, totalLen)

	response[0] = x11StatusSuccess // status
	response[1] = 0                // unused

	binary.LittleEndian.PutUint16(response[2:4], major)
	binary.LittleEndian.PutUint16(response[4:6], minor)

	// Additional data length in 4-byte units (from byte 8 onward)
	additionalBytes := uint16((totalLen - 8) / 4)
	binary.LittleEndian.PutUint16(response[6:8], additionalBytes)

	// Offset 8-11: release-number (dummy)
	binary.LittleEndian.PutUint32(response[8:12], 12000000)
	// Offset 12-15: resource-id-base (dummy)
	binary.LittleEndian.PutUint32(response[12:16], 0x00400000)
	// Offset 16-19: resource-id-mask (dummy)
	binary.LittleEndian.PutUint32(response[16:20], 0x001fffff)
	// Offset 20-23: motion-buffer-size (dummy)
	binary.LittleEndian.PutUint32(response[20:24], 256)
	// Offset 24-25: vendor-length
	binary.LittleEndian.PutUint16(response[24:26], vendorLen)
	// Offset 26-27: maximum-request-length (dummy)
	binary.LittleEndian.PutUint16(response[26:28], 65535)
	// Offset 28-39: screens, formats, roots count, etc. (zeroed)

	// Offset 40: vendor string
	if vendorLen > 0 {
		copy(response[40:40+vendorLen], vendor)
	}

	return response
}

// buildX11FailedResponse constructs a mock X11 failure response (status=0).
func buildX11FailedResponse(major, minor uint16, reason string) []byte {
	reasonLen := uint8(len(reason))
	response := make([]byte, 8+len(reason))
	response[0] = x11StatusFailed
	response[1] = reasonLen
	binary.LittleEndian.PutUint16(response[2:4], major)
	binary.LittleEndian.PutUint16(response[4:6], minor)
	binary.LittleEndian.PutUint16(response[6:8], uint16(len(reason)/4))
	copy(response[8:], reason)
	return response
}

// buildX11AuthResponse constructs a mock X11 authenticate response (status=2).
func buildX11AuthResponse(major, minor uint16) []byte {
	response := make([]byte, 8)
	response[0] = x11StatusAuthenticate
	response[1] = 0
	binary.LittleEndian.PutUint16(response[2:4], major)
	binary.LittleEndian.PutUint16(response[4:6], minor)
	binary.LittleEndian.PutUint16(response[6:8], 0)
	return response
}

// TestParseX11Response tests parsing of various X11 response messages.
func TestParseX11Response(t *testing.T) {
	tests := []struct {
		name         string
		response     []byte
		expectDetect bool
		expectMajor  uint16
		expectMinor  uint16
		expectVendor string
		expectAccess bool
	}{
		{
			name:         "valid success response with vendor",
			response:     buildX11SuccessResponse(11, 0, "The X.Org Foundation"),
			expectDetect: true,
			expectMajor:  11,
			expectMinor:  0,
			expectVendor: "The X.Org Foundation",
			expectAccess: true,
		},
		{
			name:         "valid success response without vendor",
			response:     buildX11SuccessResponse(11, 0, ""),
			expectDetect: true,
			expectMajor:  11,
			expectMinor:  0,
			expectVendor: "",
			expectAccess: true,
		},
		{
			name:         "valid failed response",
			response:     buildX11FailedResponse(11, 0, "No such display"),
			expectDetect: true,
			expectMajor:  11,
			expectMinor:  0,
			expectVendor: "",
			expectAccess: false,
		},
		{
			name:         "valid authenticate response",
			response:     buildX11AuthResponse(11, 0),
			expectDetect: true,
			expectMajor:  11,
			expectMinor:  0,
			expectVendor: "",
			expectAccess: false,
		},
		{
			name:         "invalid response - garbage data",
			response:     []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8},
			expectDetect: false,
		},
		{
			name:         "empty response",
			response:     []byte{},
			expectDetect: false,
		},
		{
			name:         "short response - less than 8 bytes",
			response:     []byte{0x01, 0x00, 0x0b, 0x00},
			expectDetect: false,
		},
		{
			name:         "invalid version - major not 11",
			response:     buildX11SuccessResponse(10, 0, ""),
			expectDetect: false,
		},
		{
			name:         "invalid version - minor > 99",
			response:     buildX11SuccessResponse(11, 100, ""),
			expectDetect: false,
		},
		{
			name:         "invalid status code",
			response:     []byte{0x03, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x00, 0x00},
			expectDetect: false,
		},
		{
			name:         "exactly 8 bytes minimum valid header",
			response:     buildX11FailedResponse(11, 0, ""),
			expectDetect: true,
			expectMajor:  11,
			expectMinor:  0,
			expectAccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, detected := parseX11Response(tt.response)
			if detected != tt.expectDetect {
				t.Errorf("parseX11Response() detected=%v, want %v", detected, tt.expectDetect)
			}
			if !detected {
				return
			}
			if info.MajorVersion != tt.expectMajor {
				t.Errorf("MajorVersion=%d, want %d", info.MajorVersion, tt.expectMajor)
			}
			if info.MinorVersion != tt.expectMinor {
				t.Errorf("MinorVersion=%d, want %d", info.MinorVersion, tt.expectMinor)
			}
			if info.Vendor != tt.expectVendor {
				t.Errorf("Vendor=%q, want %q", info.Vendor, tt.expectVendor)
			}
			if info.AccessGranted != tt.expectAccess {
				t.Errorf("AccessGranted=%v, want %v", info.AccessGranted, tt.expectAccess)
			}
		})
	}
}

// TestPortPriority verifies that PortPriority returns true for ports 6000-6063.
func TestPortPriority(t *testing.T) {
	plugin := &Plugin{}

	// All ports in X11 range should be true
	for port := uint16(6000); port <= 6063; port++ {
		if !plugin.PortPriority(port) {
			t.Errorf("PortPriority(%d) = false, want true", port)
		}
	}

	// Ports outside X11 range should be false
	outOfRange := []uint16{5999, 6064, 80, 443, 22}
	for _, port := range outOfRange {
		if plugin.PortPriority(port) {
			t.Errorf("PortPriority(%d) = true, want false", port)
		}
	}
}

// TestPluginName verifies the plugin returns the correct name.
func TestPluginName(t *testing.T) {
	plugin := &Plugin{}
	if plugin.Name() != X11 {
		t.Errorf("Name() = %q, want %q", plugin.Name(), X11)
	}
}

// TestPluginType verifies the plugin returns TCP as the protocol type.
func TestPluginType(t *testing.T) {
	plugin := &Plugin{}
	if plugin.Type() != plugins.TCP {
		t.Errorf("Type() = %v, want TCP", plugin.Type())
	}
}

// TestPluginPriority verifies the plugin priority.
func TestPluginPriority(t *testing.T) {
	plugin := &Plugin{}
	if plugin.Priority() != 10 {
		t.Errorf("Priority() = %d, want 10", plugin.Priority())
	}
}

// TestRunWithMockServer tests the Run method against mock TCP servers.
func TestRunWithMockServer(t *testing.T) {
	tests := []struct {
		name           string
		serverBehavior func(net.Conn)
		targetPort     uint16
		expectNil      bool
		expectError    bool
		expectProtocol string
		expectVersion  string
		expectDisplay  int
	}{
		{
			name: "valid X11 success response",
			serverBehavior: func(conn net.Conn) {
				defer conn.Close()
				// Read the setup request (12 bytes)
				buf := make([]byte, 64)
				n, err := conn.Read(buf)
				if err != nil || n < 12 {
					return
				}
				// Respond with success including vendor
				resp := buildX11SuccessResponse(11, 0, "The X.Org Foundation")
				_, _ = conn.Write(resp)
			},
			targetPort:     6000,
			expectNil:      false,
			expectProtocol: "x11",
			expectVersion:  "11.0",
			expectDisplay:  0,
		},
		{
			name: "valid X11 failed response - still detected as X11",
			serverBehavior: func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
				resp := buildX11FailedResponse(11, 0, "No such display")
				_, _ = conn.Write(resp)
			},
			targetPort:     6001,
			expectNil:      false,
			expectProtocol: "x11",
			expectVersion:  "11.0",
			expectDisplay:  1,
		},
		{
			name: "valid X11 authenticate response",
			serverBehavior: func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
				resp := buildX11AuthResponse(11, 0)
				_, _ = conn.Write(resp)
			},
			targetPort:     6002,
			expectNil:      false,
			expectProtocol: "x11",
			expectVersion:  "11.0",
			expectDisplay:  2,
		},
		{
			name: "invalid response - garbage data",
			serverBehavior: func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
				_, _ = conn.Write([]byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8})
			},
			targetPort:  6000,
			expectNil:   true,
			expectError: false,
		},
		{
			name: "empty response - server closes connection",
			serverBehavior: func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 64)
				_, _ = conn.Read(buf)
				// Send nothing, close immediately - causes EOF
			},
			targetPort:  6000,
			expectNil:   true,
			expectError: true, // EOF from closed connection
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

			tcpAddr, ok := listener.Addr().(*net.TCPAddr)
			if !ok {
				t.Fatal("listener address is not TCP")
			}
			serverPort := tcpAddr.Port

			// Start server goroutine
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				tt.serverBehavior(conn)
			}()

			// Brief pause for server to be ready
			time.Sleep(10 * time.Millisecond)

			// Connect to mock server
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
			if err != nil {
				t.Fatalf("Failed to connect to mock server: %v", err)
			}
			defer conn.Close()

			// Build target with the configured port
			addrStr := fmt.Sprintf("127.0.0.1:%d", tt.targetPort)
			addrPort := netip.MustParseAddrPort(addrStr)
			target := plugins.Target{
				Host:       "127.0.0.1",
				Address:    addrPort,
				Misconfigs: true,
			}

			plugin := &Plugin{}
			result, err := plugin.Run(conn, 5*time.Second, target)

			if tt.expectError {
				if err == nil {
					t.Errorf("Run() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Errorf("Run() returned unexpected error: %v", err)
			}

			if tt.expectNil {
				if result != nil {
					t.Errorf("Run() = %v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Run() returned nil, want non-nil service")
			}

			if result.Protocol != tt.expectProtocol {
				t.Errorf("Protocol = %q, want %q", result.Protocol, tt.expectProtocol)
			}

			if result.Version != tt.expectVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.expectVersion)
			}

			// Verify display number through metadata
			meta, ok := result.Metadata().(plugins.ServiceX11)
			if !ok {
				t.Fatalf("Metadata() type assertion failed, got %T", result.Metadata())
			}
			if meta.DisplayNumber != tt.expectDisplay {
				t.Errorf("DisplayNumber = %d, want %d", meta.DisplayNumber, tt.expectDisplay)
			}

			// For success response: verify AnonymousAccess and SecurityFindings
			if tt.name == "valid X11 success response" {
				if !result.AnonymousAccess {
					t.Error("expected AnonymousAccess to be true for successful X11 connection")
				}
				if len(result.SecurityFindings) != 1 {
					t.Fatalf("expected 1 finding, got %d", len(result.SecurityFindings))
				}
				if result.SecurityFindings[0].ID != "x11-unauth-access" {
					t.Errorf("expected finding ID 'x11-unauth-access', got %q", result.SecurityFindings[0].ID)
				}
				if result.SecurityFindings[0].Severity != plugins.SeverityCritical {
					t.Errorf("expected severity critical, got %s", result.SecurityFindings[0].Severity)
				}
			}

			// For failed and authenticate responses: verify no AnonymousAccess or SecurityFindings
			if tt.name == "valid X11 failed response - still detected as X11" ||
				tt.name == "valid X11 authenticate response" {
				if result.AnonymousAccess {
					t.Error("expected AnonymousAccess to be false")
				}
				if len(result.SecurityFindings) != 0 {
					t.Errorf("expected 0 security findings, got %d", len(result.SecurityFindings))
				}
			}
		})
	}
}
