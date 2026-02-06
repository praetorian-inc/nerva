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

package bacnet

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	readData  []byte
	writeData []byte
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	n = copy(b, m.readData)
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.writeData = append(m.writeData, b...)
	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestPluginType(t *testing.T) {
	p := &Plugin{}
	if p.Type() != plugins.UDP {
		t.Errorf("expected UDP, got %v", p.Type())
	}
}

func TestPluginPriority(t *testing.T) {
	p := &Plugin{}
	if p.Priority() != 400 {
		t.Errorf("expected priority 400, got %d", p.Priority())
	}
}

func TestPluginPortPriority(t *testing.T) {
	p := &Plugin{}
	if !p.PortPriority(47808) {
		t.Error("expected PortPriority(47808) to return true")
	}
	if p.PortPriority(80) {
		t.Error("expected PortPriority(80) to return false")
	}
}

func TestPluginName(t *testing.T) {
	p := &Plugin{}
	if p.Name() != "bacnet" {
		t.Errorf("expected bacnet, got %s", p.Name())
	}
}

func TestParseValidIAm(t *testing.T) {
	// Valid 25-byte I-Am response
	// BVLC [0-3]: Type=0x81, Function=0x0A, Length=0x0019 (25 bytes total)
	// NPDU [4-5]: Version=0x01, Control=0x00 (NO network addressing - critical!)
	// APDU [6-7]: Type=0x10 (Unconfirmed-Request), Service=0x00 (I-Am)
	// I-Am fields [8-18]:
	//   Object ID [8-12]: Tag=0xC4, Value=0x02000001 (Device 1)
	//   Max APDU [13-14]: Tag=0x21, Value=0x50 (80 bytes)
	//   Segmentation [15-16]: Tag=0x91, Value=0x03 (none)
	//   Vendor ID [17-18]: Tag=0x21, Value=0x05 (Johnson Controls)
	// Trailing [19-24]: Padding to reach 25-byte minimum
	validIAm := []byte{
		0x81, 0x0A, 0x00, 0x19, // BVLC
		0x01, 0x00,             // NPDU (control=0x00, no addressing!)
		0x10, 0x00,             // APDU
		0xC4,                   // Object ID tag
		0x02, 0x00, 0x00, 0x01, // Device instance 1
		0x21, 0x50,             // Max APDU 80
		0x91, 0x03,             // Segmentation none
		0x21, 0x05,             // Vendor ID 5
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Padding
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.100:47808"),
		Host:    "test.local",
	}

	service, deviceInstance, err := parseIAmWithInstance(validIAm, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if deviceInstance != 1 {
		t.Errorf("expected deviceInstance 1, got %d", deviceInstance)
	}

	if service == nil {
		t.Fatal("expected non-nil service")
	}

	if service.Protocol != plugins.ProtoBACnet {
		t.Errorf("expected protocol %s, got %s", plugins.ProtoBACnet, service.Protocol)
	}

	if service.IP != "192.168.1.100" {
		t.Errorf("expected IP 192.168.1.100, got %s", service.IP)
	}
	if service.Port != 47808 {
		t.Errorf("expected port 47808, got %d", service.Port)
	}
}

func TestParseInvalidIAm(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		errorMsg string
	}{
		{
			name:     "too short",
			data:     []byte{0x81, 0x0A, 0x00, 0x10},
			errorMsg: "response too short",
		},
		{
			name:     "invalid BVLC type",
			data:     make([]byte, 30),
			errorMsg: "invalid BVLC type",
		},
		{
			name: "invalid BVLC function",
			data: func() []byte {
				d := make([]byte, 30)
				d[0] = 0x81
				d[1] = 0xFF // Invalid function
				return d
			}(),
			errorMsg: "invalid BVLC function",
		},
	}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.100:47808"),
		Host:    "test.local",
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, err := parseIAmWithInstance(tt.data, target)
			if err == nil {
				t.Error("expected error, got nil")
			}
		})
	}
}

func TestVendorMapping(t *testing.T) {
	tests := []struct {
		vendorID     uint16
		expectedName string
	}{
		{5, "Johnson Controls Inc."},
		{12, "Honeywell Inc."},
		{7, "Siemens Building Technologies"},
		{9999, "unknown (ID: 9999)"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedName, func(t *testing.T) {
			name := getVendorName(tt.vendorID)
			if name != tt.expectedName {
				t.Errorf("expected %s, got %s", tt.expectedName, name)
			}
		})
	}
}

func TestVendorSlug(t *testing.T) {
	tests := []struct {
		vendorID     uint16
		expectedSlug string
	}{
		{5, "johnson_controls"},
		{12, "honeywell"},
		{7, "siemens"},
		{9999, "*"},
	}

	for _, tt := range tests {
		t.Run(tt.expectedSlug, func(t *testing.T) {
			slug := getVendorSlug(tt.vendorID)
			if slug != tt.expectedSlug {
				t.Errorf("expected %s, got %s", tt.expectedSlug, slug)
			}
		})
	}
}

func TestCPEGeneration(t *testing.T) {
	tests := []struct {
		name        string
		vendorID    uint16
		model       string
		firmware    string
		expectedCPE string
	}{
		{
			name:        "known vendor with model and firmware",
			vendorID:    5,
			model:       "BCU-4000",
			firmware:    "v1.2.3",
			expectedCPE: "cpe:2.3:h:johnson_controls:bcu_4000:v1_2_3:*:*:*:*:*:*:*",
		},
		{
			name:        "known vendor without model",
			vendorID:    12,
			model:       "",
			firmware:    "",
			expectedCPE: "cpe:2.3:h:honeywell:*:*:*:*:*:*:*:*:*",
		},
		{
			name:        "unknown vendor",
			vendorID:    9999,
			model:       "test",
			firmware:    "1.0",
			expectedCPE: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpes := generateCPE(tt.vendorID, tt.model, tt.firmware)
			if tt.expectedCPE == "" {
				if len(cpes) != 0 {
					t.Errorf("expected no CPE, got %v", cpes)
				}
			} else {
				if len(cpes) != 1 {
					t.Fatalf("expected 1 CPE, got %d", len(cpes))
				}
				if cpes[0] != tt.expectedCPE {
					t.Errorf("expected %s, got %s", tt.expectedCPE, cpes[0])
				}
			}
		})
	}
}

func TestNormalizeCPE(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"BCU-4000", "bcu_4000"},
		{"v1.2.3", "v1_2_3"},
		{"Test Device", "test_device"},
		{"ABC-123.XYZ", "abc_123_xyz"},
		{"", "*"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeCPE(tt.input)
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}
