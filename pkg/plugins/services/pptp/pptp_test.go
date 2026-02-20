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

package pptp

import (
	"encoding/binary"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// mockConn implements net.Conn for testing. SetDeadline methods return nil so
// that utils.SendRecv (which calls SetWriteDeadline / SetReadDeadline) works
// without a real network connection.
type mockConn struct {
	readData  []byte
	writeData []byte
	readErr   error
	writeErr  error
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
	n = copy(b, m.readData)
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	if m.writeErr != nil {
		return 0, m.writeErr
	}
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// buildMockSCCRP constructs a 156-byte SCCRP packet with the given fields.
// This mirrors the wire format defined in RFC 2637.
func buildMockSCCRP(hostname, vendor string, firmware, protocolVersion uint16, framingCaps, bearerCaps uint32, maxChannels uint16, resultCode uint8) []byte {
	pkt := make([]byte, 156)
	binary.BigEndian.PutUint16(pkt[0:2], 156)         // Length
	binary.BigEndian.PutUint16(pkt[2:4], 1)            // PPTP Message Type
	binary.BigEndian.PutUint32(pkt[4:8], 0x1A2B3C4D)  // Magic Cookie
	binary.BigEndian.PutUint16(pkt[8:10], 2)           // Control Message Type = 2 (SCCRP)
	binary.BigEndian.PutUint16(pkt[10:12], 0)          // Reserved0
	binary.BigEndian.PutUint16(pkt[12:14], protocolVersion)
	pkt[14] = resultCode
	pkt[15] = 0 // Error Code
	binary.BigEndian.PutUint32(pkt[16:20], framingCaps)
	binary.BigEndian.PutUint32(pkt[20:24], bearerCaps)
	binary.BigEndian.PutUint16(pkt[24:26], maxChannels)
	binary.BigEndian.PutUint16(pkt[26:28], firmware)
	copy(pkt[28:92], hostname)
	copy(pkt[92:156], vendor)
	return pkt
}

// defaultTarget is a convenience target for tests.
var defaultTarget = plugins.Target{
	Address: netip.MustParseAddrPort("127.0.0.1:1723"),
}

// TestExtractNullTerminated verifies the null-terminator extraction helper.
func TestExtractNullTerminated(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "normal string with null terminator",
			input:    append([]byte("linux"), make([]byte, 59)...),
			expected: "linux",
		},
		{
			name:     "all null bytes returns empty string",
			input:    make([]byte, 64),
			expected: "",
		},
		{
			name:     "string fills entire field with no null byte",
			input:    []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), // 64 bytes
			expected: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
		},
		{
			name:     "string with embedded null returns prefix only",
			input:    []byte{'h', 'i', 0, 'z', 'z'},
			expected: "hi",
		},
		{
			name:     "single non-null byte",
			input:    []byte{'X'},
			expected: "X",
		},
		{
			name:     "null at first byte returns empty string",
			input:    []byte{0, 'a', 'b', 'c'},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNullTerminated(tt.input)
			if got != tt.expected {
				t.Errorf("extractNullTerminated(%q) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestFormatVersion verifies major.minor formatting, including the zero-case.
func TestFormatVersion(t *testing.T) {
	tests := []struct {
		name     string
		major    uint16
		minor    uint16
		expected string
	}{
		{
			name:     "version 1.0",
			major:    1,
			minor:    0,
			expected: "1.0",
		},
		{
			name:     "both zero returns empty string",
			major:    0,
			minor:    0,
			expected: "",
		},
		{
			name:     "minor only non-zero",
			major:    0,
			minor:    1,
			expected: "0.1",
		},
		{
			name:     "double-digit components",
			major:    10,
			minor:    20,
			expected: "10.20",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatVersion(tt.major, tt.minor)
			if got != tt.expected {
				t.Errorf("formatVersion(%d, %d) = %q, want %q", tt.major, tt.minor, got, tt.expected)
			}
		})
	}
}

// TestVersionString verifies the uint16-to-decimal string helper.
func TestVersionString(t *testing.T) {
	tests := []struct {
		name     string
		input    uint16
		expected string
	}{
		{name: "zero", input: 0, expected: "0"},
		{name: "one", input: 1, expected: "1"},
		{name: "nine", input: 9, expected: "9"},
		{name: "ten", input: 10, expected: "10"},
		{name: "large number", input: 1023, expected: "1023"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := versionString(tt.input)
			if got != tt.expected {
				t.Errorf("versionString(%d) = %q, want %q", tt.input, got, tt.expected)
			}
		})
	}
}

// TestBuildSCCRQ verifies the constructed request packet.
func TestBuildSCCRQ(t *testing.T) {
	pkt := buildSCCRQ()

	if len(pkt) != 156 {
		t.Fatalf("buildSCCRQ() len = %d, want 156", len(pkt))
	}

	// Length field at bytes 0-1
	length := binary.BigEndian.Uint16(pkt[0:2])
	if length != 156 {
		t.Errorf("length field = %d, want 156", length)
	}

	// Magic cookie at offset 4
	cookie := binary.BigEndian.Uint32(pkt[4:8])
	if cookie != 0x1A2B3C4D {
		t.Errorf("magic cookie = %#x, want 0x1A2B3C4D", cookie)
	}

	// Control message type = 1 (SCCRQ) at offset 8
	msgType := binary.BigEndian.Uint16(pkt[8:10])
	if msgType != 1 {
		t.Errorf("control message type = %d, want 1", msgType)
	}

	// Hostname "nerva" at offset 28
	hostname := extractNullTerminated(pkt[28:92])
	if hostname != "nerva" {
		t.Errorf("hostname = %q, want %q", hostname, "nerva")
	}

	// Vendor "nerva" at offset 92
	vendor := extractNullTerminated(pkt[92:156])
	if vendor != "nerva" {
		t.Errorf("vendor = %q, want %q", vendor, "nerva")
	}
}

// TestRunKnownVendors tests that Run correctly parses SCCRP responses for
// real-world PPTP implementations and returns a populated service.
func TestRunKnownVendors(t *testing.T) {
	plugin := &Plugin{}

	tests := []struct {
		name             string
		hostname         string
		vendor           string
		firmware         uint16
		framingCaps      uint32
		bearerCaps       uint32
		maxChannels      uint16
		resultCode       uint8
		protocolVersion  uint16
		wantHostname     string
		wantVendor       string
		wantFirmware     uint16
		wantProtocolVer  string
	}{
		{
			name:            "pptpd Linux",
			hostname:        "local",
			vendor:          "linux",
			firmware:        1,
			framingCaps:     0,
			bearerCaps:      0,
			maxChannels:     10,
			resultCode:      1,
			protocolVersion: 0x0100,
			wantHostname:    "local",
			wantVendor:      "linux",
			wantFirmware:    1,
			wantProtocolVer: "1.0",
		},
		{
			name:            "Microsoft RRAS",
			hostname:        "",
			vendor:          "Microsoft",
			firmware:        0,
			framingCaps:     1,
			bearerCaps:      1,
			maxChannels:     0,
			resultCode:      1,
			protocolVersion: 0x0100,
			wantHostname:    "",
			wantVendor:      "Microsoft",
			wantFirmware:    0,
			wantProtocolVer: "1.0",
		},
		{
			name:            "MikroTik",
			hostname:        "MikroTik",
			vendor:          "MikroTik",
			firmware:        1,
			framingCaps:     3,
			bearerCaps:      3,
			maxChannels:     200,
			resultCode:      1,
			protocolVersion: 0x0100,
			wantHostname:    "MikroTik",
			wantVendor:      "MikroTik",
			wantFirmware:    1,
			wantProtocolVer: "1.0",
		},
		{
			name:            "Cisco",
			hostname:        "main",
			vendor:          "Cisco Systems",
			firmware:        4608,
			framingCaps:     1,
			bearerCaps:      1,
			maxChannels:     255,
			resultCode:      1,
			protocolVersion: 0x0100,
			wantHostname:    "main",
			wantVendor:      "Cisco Systems",
			wantFirmware:    4608,
			wantProtocolVer: "1.0",
		},
		{
			name:            "YAMAHA",
			hostname:        "RT57i",
			vendor:          "YAMAHA Corporation",
			firmware:        32838,
			framingCaps:     1,
			bearerCaps:      1,
			maxChannels:     1,
			resultCode:      1,
			protocolVersion: 0x0100,
			wantHostname:    "RT57i",
			wantVendor:      "YAMAHA Corporation",
			wantFirmware:    32838,
			wantProtocolVer: "1.0",
		},
		{
			name:            "DrayTek",
			hostname:        "Vigor",
			vendor:          "DrayTek",
			firmware:        1,
			framingCaps:     1,
			bearerCaps:      1,
			maxChannels:     8,
			resultCode:      1,
			protocolVersion: 0x0100,
			wantHostname:    "Vigor",
			wantVendor:      "DrayTek",
			wantFirmware:    1,
			wantProtocolVer: "1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pkt := buildMockSCCRP(
				tt.hostname, tt.vendor,
				tt.firmware, tt.protocolVersion,
				tt.framingCaps, tt.bearerCaps,
				tt.maxChannels, tt.resultCode,
			)
			conn := &mockConn{readData: pkt}

			svc, err := plugin.Run(conn, 5*time.Second, defaultTarget)
			if err != nil {
				t.Fatalf("Run() error = %v, want nil", err)
			}
			if svc == nil {
				t.Fatal("Run() returned nil service, want non-nil")
			}

			if svc.Protocol != "pptp" {
				t.Errorf("service.Protocol = %q, want %q", svc.Protocol, "pptp")
			}

			var payload plugins.ServicePPTP
			if err := json.Unmarshal(svc.Raw, &payload); err != nil {
				t.Fatalf("json.Unmarshal(service.Raw) error = %v", err)
			}

			if payload.Hostname != tt.wantHostname {
				t.Errorf("Hostname = %q, want %q", payload.Hostname, tt.wantHostname)
			}
			if payload.VendorString != tt.wantVendor {
				t.Errorf("VendorString = %q, want %q", payload.VendorString, tt.wantVendor)
			}
			if payload.FirmwareRevision != tt.wantFirmware {
				t.Errorf("FirmwareRevision = %d, want %d", payload.FirmwareRevision, tt.wantFirmware)
			}
			if payload.ProtocolVersion != tt.wantProtocolVer {
				t.Errorf("ProtocolVersion = %q, want %q", payload.ProtocolVersion, tt.wantProtocolVer)
			}
			if payload.ResultCode != tt.resultCode {
				t.Errorf("ResultCode = %d, want %d", payload.ResultCode, tt.resultCode)
			}
		})
	}
}

// TestRunEdgeCases tests negative / malformed response handling.
func TestRunEdgeCases(t *testing.T) {
	plugin := &Plugin{}

	tests := []struct {
		name     string
		response []byte
		wantSvc  bool // true if we expect a non-nil service
		wantErr  bool // true if we expect a non-nil error
	}{
		{
			name:     "empty response returns nil nil",
			response: []byte{},
			wantSvc:  false,
			wantErr:  false,
		},
		{
			name:     "response too short (< 156 bytes)",
			response: make([]byte, 100),
			wantSvc:  false,
			wantErr:  false,
		},
		{
			name:     "response exactly 155 bytes (off-by-one boundary)",
			response: make([]byte, 155),
			wantSvc:  false,
			wantErr:  false,
		},
		{
			name: "wrong magic cookie",
			response: func() []byte {
				pkt := buildMockSCCRP("host", "vendor", 1, 0x0100, 0, 0, 1, 1)
				binary.BigEndian.PutUint32(pkt[4:8], 0xDEADBEEF)
				return pkt
			}(),
			wantSvc: false,
			wantErr: false,
		},
		{
			name: "wrong control message type (1 instead of 2)",
			response: func() []byte {
				pkt := buildMockSCCRP("host", "vendor", 1, 0x0100, 0, 0, 1, 1)
				binary.BigEndian.PutUint16(pkt[8:10], 1) // SCCRQ, not SCCRP
				return pkt
			}(),
			wantSvc: false,
			wantErr: false,
		},
		{
			name: "control message type 3 (unknown) rejected",
			response: func() []byte {
				pkt := buildMockSCCRP("host", "vendor", 1, 0x0100, 0, 0, 1, 1)
				binary.BigEndian.PutUint16(pkt[8:10], 3)
				return pkt
			}(),
			wantSvc: false,
			wantErr: false,
		},
		{
			name: "valid header with result code != 1 is still detected",
			response: buildMockSCCRP("host", "vendor", 1, 0x0100, 0, 0, 1, 3),
			wantSvc: true,
			wantErr: false,
		},
		{
			name: "oversized response (> 156 bytes) still detects",
			response: func() []byte {
				pkt := buildMockSCCRP("router", "vendor", 1, 0x0100, 0, 0, 1, 1)
				// Append extra trailing bytes (some implementations may send more data).
				return append(pkt, make([]byte, 100)...)
			}(),
			wantSvc: true,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{readData: tt.response}

			svc, err := plugin.Run(conn, 5*time.Second, defaultTarget)

			if tt.wantErr && err == nil {
				t.Error("Run() error = nil, want non-nil error")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("Run() error = %v, want nil", err)
			}
			if tt.wantSvc && svc == nil {
				t.Error("Run() returned nil service, want non-nil")
			}
			if !tt.wantSvc && svc != nil {
				t.Errorf("Run() returned non-nil service %v, want nil", svc)
			}
		})
	}
}

// TestRunResultCodeCaptured verifies that a non-1 result code is preserved in
// the service payload (detection succeeds even when the server rejects the
// connection attempt).
func TestRunResultCodeCaptured(t *testing.T) {
	plugin := &Plugin{}

	const wantResultCode = uint8(7)
	pkt := buildMockSCCRP("router", "vendor", 0, 0x0100, 0, 0, 1, wantResultCode)
	conn := &mockConn{readData: pkt}

	svc, err := plugin.Run(conn, 5*time.Second, defaultTarget)
	if err != nil {
		t.Fatalf("Run() error = %v, want nil", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service for non-1 result code; service should still be detected")
	}

	var payload plugins.ServicePPTP
	if err := json.Unmarshal(svc.Raw, &payload); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	if payload.ResultCode != wantResultCode {
		t.Errorf("ResultCode = %d, want %d", payload.ResultCode, wantResultCode)
	}
}

// TestRunCapabilitiesAndChannels verifies that framing/bearer capabilities and
// max-channel values are faithfully copied into the service payload.
func TestRunCapabilitiesAndChannels(t *testing.T) {
	plugin := &Plugin{}

	pkt := buildMockSCCRP(
		"gw", "vendor",
		5,      // firmware
		0x0100, // protocol version
		3,      // framingCaps: sync + async
		3,      // bearerCaps:  digital + analog
		64,     // maxChannels
		1,
	)
	conn := &mockConn{readData: pkt}

	svc, err := plugin.Run(conn, 5*time.Second, defaultTarget)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service")
	}

	var payload plugins.ServicePPTP
	if err := json.Unmarshal(svc.Raw, &payload); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}

	if payload.FramingCapabilities != 3 {
		t.Errorf("FramingCapabilities = %d, want 3", payload.FramingCapabilities)
	}
	if payload.BearerCapabilities != 3 {
		t.Errorf("BearerCapabilities = %d, want 3", payload.BearerCapabilities)
	}
	if payload.MaxChannels != 64 {
		t.Errorf("MaxChannels = %d, want 64", payload.MaxChannels)
	}
}

// TestRunReadError verifies that I/O errors from SendRecv propagate correctly.
func TestRunReadError(t *testing.T) {
	plugin := &Plugin{}
	readErr := net.UnknownNetworkError("mock read failure")
	conn := &mockConn{readErr: readErr}

	svc, err := plugin.Run(conn, 5*time.Second, defaultTarget)
	if svc != nil {
		t.Errorf("Run() returned non-nil service on read error: %v", svc)
	}
	if err == nil {
		t.Fatal("Run() returned nil error, want propagated read error")
	}
}

// TestRunZeroProtocolVersion verifies that a zero protocol version (0x0000)
// results in an empty ProtocolVersion string in the service payload.
func TestRunZeroProtocolVersion(t *testing.T) {
	plugin := &Plugin{}
	pkt := buildMockSCCRP("host", "vendor", 1, 0x0000, 0, 0, 1, 1)
	conn := &mockConn{readData: pkt}

	svc, err := plugin.Run(conn, 5*time.Second, defaultTarget)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service")
	}

	var payload plugins.ServicePPTP
	if err := json.Unmarshal(svc.Raw, &payload); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}
	if payload.ProtocolVersion != "" {
		t.Errorf("ProtocolVersion = %q, want empty string for 0x0000", payload.ProtocolVersion)
	}
}

// TestRunBoundaryValues verifies correct handling of uint16/uint32 boundary values
// for firmware revision, max channels, and capability bitmasks.
func TestRunBoundaryValues(t *testing.T) {
	plugin := &Plugin{}
	pkt := buildMockSCCRP(
		"edge", "boundary",
		65535,      // firmware: uint16 max
		0x0100,     // protocol version 1.0
		0xFFFFFFFF, // framingCaps: all bits set
		0xFFFFFFFF, // bearerCaps: all bits set
		65535,      // maxChannels: uint16 max
		255,        // resultCode: uint8 max
	)
	conn := &mockConn{readData: pkt}

	svc, err := plugin.Run(conn, 5*time.Second, defaultTarget)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if svc == nil {
		t.Fatal("Run() returned nil service")
	}

	var payload plugins.ServicePPTP
	if err := json.Unmarshal(svc.Raw, &payload); err != nil {
		t.Fatalf("json.Unmarshal error = %v", err)
	}

	if payload.FirmwareRevision != 65535 {
		t.Errorf("FirmwareRevision = %d, want 65535", payload.FirmwareRevision)
	}
	if payload.MaxChannels != 65535 {
		t.Errorf("MaxChannels = %d, want 65535", payload.MaxChannels)
	}
	if payload.FramingCapabilities != 0xFFFFFFFF {
		t.Errorf("FramingCapabilities = %d, want 4294967295", payload.FramingCapabilities)
	}
	if payload.BearerCapabilities != 0xFFFFFFFF {
		t.Errorf("BearerCapabilities = %d, want 4294967295", payload.BearerCapabilities)
	}
	if payload.ResultCode != 255 {
		t.Errorf("ResultCode = %d, want 255", payload.ResultCode)
	}
}

// TestExtractNullTerminatedEmpty verifies the helper handles an empty slice.
func TestExtractNullTerminatedEmpty(t *testing.T) {
	got := extractNullTerminated([]byte{})
	if got != "" {
		t.Errorf("extractNullTerminated(empty) = %q, want empty string", got)
	}
}

// TestRunWriteError verifies that a write error during SCCRQ send propagates.
func TestRunWriteError(t *testing.T) {
	plugin := &Plugin{}
	writeErr := net.UnknownNetworkError("mock write failure")
	conn := &mockConn{writeErr: writeErr}

	svc, err := plugin.Run(conn, 5*time.Second, defaultTarget)
	if svc != nil {
		t.Errorf("Run() returned non-nil service on write error: %v", svc)
	}
	if err == nil {
		t.Fatal("Run() returned nil error, want propagated write error")
	}
}

// TestPortPriority verifies that only the PPTP default port 1723 returns true.
func TestPortPriority(t *testing.T) {
	plugin := &Plugin{}

	tests := []struct {
		port     uint16
		expected bool
	}{
		{1723, true},
		{1722, false},
		{1724, false},
		{0, false},
		{65535, false},
	}

	for _, tt := range tests {
		got := plugin.PortPriority(tt.port)
		if got != tt.expected {
			t.Errorf("PortPriority(%d) = %v, want %v", tt.port, got, tt.expected)
		}
	}
}

// TestPluginMetadata verifies the Name, Type, and Priority methods.
func TestPluginMetadata(t *testing.T) {
	plugin := &Plugin{}

	if plugin.Name() != "pptp" {
		t.Errorf("Name() = %q, want %q", plugin.Name(), "pptp")
	}
	if plugin.Type() != plugins.TCP {
		t.Errorf("Type() = %v, want plugins.TCP", plugin.Type())
	}
	if plugin.Priority() <= 0 {
		t.Errorf("Priority() = %d, want > 0", plugin.Priority())
	}
}
