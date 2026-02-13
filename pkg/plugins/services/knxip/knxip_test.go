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

package knxip

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	readData  []byte
	writeData []byte
	readErr   error
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readErr != nil {
		return 0, m.readErr
	}
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

// Plugin Interface Tests

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

func TestPluginName(t *testing.T) {
	p := &Plugin{}
	if p.Name() != "knxip" {
		t.Errorf("expected knxip, got %s", p.Name())
	}
}

func TestPluginPortPriority(t *testing.T) {
	p := &Plugin{}
	if !p.PortPriority(3671) {
		t.Error("expected PortPriority(3671) to return true")
	}
	if p.PortPriority(80) {
		t.Error("expected PortPriority(80) to return false")
	}
	if p.PortPriority(47808) {
		t.Error("expected PortPriority(47808) to return false")
	}
}

// knxMediumString Tests

func TestKnxMediumString(t *testing.T) {
	tests := []struct {
		code     byte
		expected string
	}{
		{0x01, "TP1"},
		{0x02, "PL110"},
		{0x04, "RF"},
		{0x20, "IP"},
		{0x00, "0x00"},
		{0xFF, "0xFF"},
		{0x10, "0x10"},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("code_0x%02X", tt.code), func(t *testing.T) {
			result := knxMediumString(tt.code)
			if result != tt.expected {
				t.Errorf("knxMediumString(0x%02X) = %s, want %s", tt.code, result, tt.expected)
			}
		})
	}
}

// serviceFamilyName Tests

func TestServiceFamilyName(t *testing.T) {
	tests := []struct {
		id       byte
		expected string
	}{
		{0x02, "Core"},
		{0x03, "DeviceManagement"},
		{0x04, "Tunnelling"},
		{0x05, "Routing"},
		{0x06, "RemoteLogging"},
		{0x08, "ObjectServer"},
		{0x00, ""},
		{0x01, ""},
		{0x07, ""},
		{0xFF, ""},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("family_0x%02X", tt.id), func(t *testing.T) {
			result := serviceFamilyName(tt.id)
			if result != tt.expected {
				t.Errorf("serviceFamilyName(0x%02X) = %s, want %s", tt.id, result, tt.expected)
			}
		})
	}
}

// parseDeviceInfo Tests

func TestParseDeviceInfo_ValidDIB(t *testing.T) {
	// Build a valid DIB_DEV_INFO (54+ bytes)
	dib := make([]byte, 54)
	dib[0] = 54    // Length
	dib[1] = 0x01  // Type: DIB_DEV_INFO
	dib[2] = 0x02  // Medium: PL110
	dib[3] = 0x00  // Status

	// KNX Address: 1.2.3 = (1<<12) | (2<<8) | 3 = 0x1203
	dib[4] = 0x12
	dib[5] = 0x03

	// Project ID (2 bytes)
	dib[6] = 0x00
	dib[7] = 0x01

	// Serial Number: 001122334455
	dib[8] = 0x00
	dib[9] = 0x11
	dib[10] = 0x22
	dib[11] = 0x33
	dib[12] = 0x44
	dib[13] = 0x55

	// Multicast address (4 bytes)
	dib[14] = 0xE0
	dib[15] = 0x00
	dib[16] = 0x17
	dib[17] = 0x0C

	// MAC Address: AA:BB:CC:DD:EE:FF
	dib[18] = 0xAA
	dib[19] = 0xBB
	dib[20] = 0xCC
	dib[21] = 0xDD
	dib[22] = 0xEE
	dib[23] = 0xFF

	// Device Name: "TestKNXDevice" + null padding
	name := "TestKNXDevice"
	copy(dib[24:54], []byte(name))

	var result plugins.ServiceKNXIP
	parseDeviceInfo(dib, &result)

	if result.KNXMedium != "PL110" {
		t.Errorf("KNXMedium = %s, want PL110", result.KNXMedium)
	}
	if result.KNXAddress != "1.2.3" {
		t.Errorf("KNXAddress = %s, want 1.2.3", result.KNXAddress)
	}
	if result.SerialNumber != "001122334455" {
		t.Errorf("SerialNumber = %s, want 001122334455", result.SerialNumber)
	}
	if result.MACAddress != "AA:BB:CC:DD:EE:FF" {
		t.Errorf("MACAddress = %s, want AA:BB:CC:DD:EE:FF", result.MACAddress)
	}
	if result.DeviceName != "TestKNXDevice" {
		t.Errorf("DeviceName = %s, want TestKNXDevice", result.DeviceName)
	}
}

func TestParseDeviceInfo_ShortDIB(t *testing.T) {
	shortDIB := make([]byte, 20) // Less than 54 bytes required
	var result plugins.ServiceKNXIP

	// Should not panic, should leave result empty
	parseDeviceInfo(shortDIB, &result)

	if result.DeviceName != "" || result.KNXAddress != "" {
		t.Error("expected empty result for short DIB")
	}
}

func TestParseDeviceInfo_NullTerminatedName(t *testing.T) {
	dib := make([]byte, 54)
	dib[0] = 54
	dib[1] = 0x01
	dib[2] = 0x20 // IP medium

	// Device name with trailing nulls and spaces
	name := "Device\x00\x00   \x00"
	copy(dib[24:54], []byte(name))

	var result plugins.ServiceKNXIP
	parseDeviceInfo(dib, &result)

	if result.DeviceName != "Device" {
		t.Errorf("DeviceName = %q, want %q", result.DeviceName, "Device")
	}
}

func TestParseDeviceInfo_AllKNXMediums(t *testing.T) {
	tests := []struct {
		code     byte
		expected string
	}{
		{0x01, "TP1"},
		{0x02, "PL110"},
		{0x04, "RF"},
		{0x20, "IP"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			dib := make([]byte, 54)
			dib[0] = 54
			dib[1] = 0x01
			dib[2] = tt.code

			var result plugins.ServiceKNXIP
			parseDeviceInfo(dib, &result)

			if result.KNXMedium != tt.expected {
				t.Errorf("KNXMedium = %s, want %s", result.KNXMedium, tt.expected)
			}
		})
	}
}

// parseServiceFamilies Tests

func TestParseServiceFamilies_ValidDIB(t *testing.T) {
	// DIB_SUPP_SVC_FAMILIES: len(1) + type(1) + (family_id(1) + version(1))...
	dib := []byte{
		0x0A,       // Length: 10 bytes
		0x02,       // Type: DIB_SUPP_SVC_FAMILIES
		0x02, 0x01, // Core v1
		0x04, 0x01, // Tunnelling v1
		0x05, 0x01, // Routing v1
		0x08, 0x01, // ObjectServer v1
	}

	var result plugins.ServiceKNXIP
	parseServiceFamilies(dib, &result)

	expected := []string{"Core", "Tunnelling", "Routing", "ObjectServer"}
	if len(result.ServiceFamilies) != len(expected) {
		t.Fatalf("got %d families, want %d", len(result.ServiceFamilies), len(expected))
	}
	for i, fam := range expected {
		if result.ServiceFamilies[i] != fam {
			t.Errorf("ServiceFamilies[%d] = %s, want %s", i, result.ServiceFamilies[i], fam)
		}
	}
}

func TestParseServiceFamilies_ShortDIB(t *testing.T) {
	shortDIB := []byte{0x02, 0x02} // Only header, no families
	var result plugins.ServiceKNXIP

	parseServiceFamilies(shortDIB, &result)

	if len(result.ServiceFamilies) != 0 {
		t.Errorf("expected empty families for short DIB, got %v", result.ServiceFamilies)
	}
}

func TestParseServiceFamilies_UnknownFamilies(t *testing.T) {
	dib := []byte{
		0x08,       // Length
		0x02,       // Type
		0x02, 0x01, // Core (known)
		0x07, 0x01, // Unknown family
		0x04, 0x01, // Tunnelling (known)
	}

	var result plugins.ServiceKNXIP
	parseServiceFamilies(dib, &result)

	// Should only have Core and Tunnelling, not unknown
	if len(result.ServiceFamilies) != 2 {
		t.Fatalf("expected 2 families, got %d: %v", len(result.ServiceFamilies), result.ServiceFamilies)
	}
	if result.ServiceFamilies[0] != "Core" || result.ServiceFamilies[1] != "Tunnelling" {
		t.Errorf("unexpected families: %v", result.ServiceFamilies)
	}
}

// parseSearchResponse Tests

func TestParseSearchResponse_ValidResponse(t *testing.T) {
	// Build complete Search Response:
	// Header (6) + HPAI (8) + DIB_DEV_INFO (54) + DIB_SUPP_SVC (8)
	response := make([]byte, 76)

	// KNXnet/IP Header
	response[0] = 0x06 // Header length
	response[1] = 0x10 // Protocol version
	response[2] = 0x02 // Service type high byte
	response[3] = 0x02 // Service type low byte (0x0202 = Search Response)
	response[4] = 0x00 // Total length high
	response[5] = 76   // Total length low

	// Control Endpoint HPAI (8 bytes)
	response[6] = 0x08 // Structure length
	response[7] = 0x01 // Host protocol (UDP)
	// IP and port follow (6 bytes)

	// DIB_DEV_INFO at offset 14 (54 bytes)
	response[14] = 54   // DIB length
	response[15] = 0x01 // DIB type: Device Info
	response[16] = 0x01 // Medium: TP1
	response[18] = 0x10 // KNX Address high: 1.0.x
	response[19] = 0x05 // KNX Address low: x.x.5
	// Serial at offset 22-27
	response[22] = 0xDE
	response[23] = 0xAD
	response[24] = 0xBE
	response[25] = 0xEF
	response[26] = 0x12
	response[27] = 0x34
	// MAC at offset 32-37
	response[32] = 0x00
	response[33] = 0x11
	response[34] = 0x22
	response[35] = 0x33
	response[36] = 0x44
	response[37] = 0x55
	// Name at offset 38-67
	copy(response[38:68], []byte("KNX/IP Router"))

	// DIB_SUPP_SVC at offset 68 (8 bytes)
	response[68] = 0x08 // DIB length
	response[69] = 0x02 // DIB type: Supported Services
	response[70] = 0x02 // Core
	response[71] = 0x01
	response[72] = 0x04 // Tunnelling
	response[73] = 0x01
	response[74] = 0x05 // Routing
	response[75] = 0x01

	result, err := parseSearchResponse(response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.KNXMedium != "TP1" {
		t.Errorf("KNXMedium = %s, want TP1", result.KNXMedium)
	}
	if result.DeviceName != "KNX/IP Router" {
		t.Errorf("DeviceName = %s, want KNX/IP Router", result.DeviceName)
	}
	if len(result.ServiceFamilies) != 3 {
		t.Errorf("expected 3 service families, got %d", len(result.ServiceFamilies))
	}
}

func TestParseSearchResponse_TooShort(t *testing.T) {
	shortResponse := make([]byte, 10) // Less than 14 bytes
	_, err := parseSearchResponse(shortResponse)
	if err == nil {
		t.Error("expected error for too-short response")
	}
	if err.Error() != "response too short" {
		t.Errorf("unexpected error message: %v", err)
	}
}

func TestParseSearchResponse_ZeroDIBLength(t *testing.T) {
	// Valid header but DIB with zero length
	response := make([]byte, 20)
	response[0] = 0x06
	response[1] = 0x10
	response[2] = 0x02
	response[3] = 0x02
	response[14] = 0x00 // Zero-length DIB

	// Should not infinite loop, should return without error
	result, err := parseSearchResponse(response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Result will have empty fields due to malformed DIB
	_ = result
}

func TestParseSearchResponse_DIBExceedsBounds(t *testing.T) {
	response := make([]byte, 20)
	response[0] = 0x06
	response[1] = 0x10
	response[2] = 0x02
	response[3] = 0x02
	response[14] = 0xFF // DIB claims 255 bytes, but response is only 20 bytes
	response[15] = 0x01

	result, err := parseSearchResponse(response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Should break out of loop, not crash
	_ = result
}

func TestParseSearchResponse_OnlyDeviceInfo(t *testing.T) {
	response := make([]byte, 68) // Header (6) + HPAI (8) + DIB_DEV_INFO (54)
	response[0] = 0x06
	response[1] = 0x10
	response[2] = 0x02
	response[3] = 0x02
	response[4] = 0x00
	response[5] = 68
	response[6] = 0x08
	response[7] = 0x01

	response[14] = 54
	response[15] = 0x01
	response[16] = 0x20 // IP medium
	copy(response[38:68], []byte("Solo Device"))

	result, err := parseSearchResponse(response)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.DeviceName != "Solo Device" {
		t.Errorf("DeviceName = %s, want 'Solo Device'", result.DeviceName)
	}
	if len(result.ServiceFamilies) != 0 {
		t.Errorf("expected no service families, got %v", result.ServiceFamilies)
	}
}

// Run() Integration Tests

func TestRun_ValidSearchResponse(t *testing.T) {
	// Build valid response
	response := make([]byte, 76)
	response[0] = 0x06
	response[1] = 0x10
	response[2] = 0x02
	response[3] = 0x02
	response[4] = 0x00
	response[5] = 76
	response[6] = 0x08
	response[7] = 0x01
	response[14] = 54
	response[15] = 0x01
	response[16] = 0x01 // TP1
	response[18] = 0x10
	response[19] = 0x01
	copy(response[38:68], []byte("Test Router"))
	response[68] = 0x06
	response[69] = 0x02
	response[70] = 0x02
	response[71] = 0x01
	response[72] = 0x04
	response[73] = 0x01

	conn := &mockConn{readData: response}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.100:3671"),
		Host:    "test.local",
	}

	p := &Plugin{}
	service, err := p.Run(conn, 5*time.Second, target)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("expected non-nil service")
	}
	if service.IP != "192.168.1.100" {
		t.Errorf("IP = %s, want 192.168.1.100", service.IP)
	}
	if service.Port != 3671 {
		t.Errorf("Port = %d, want 3671", service.Port)
	}
}

func TestRun_InvalidHeader(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
	}{
		{"too short", []byte{0x06, 0x10, 0x02}},
		{"wrong header length", []byte{0x05, 0x10, 0x02, 0x02, 0x00, 0x10, 0x00, 0x00}},
		{"wrong protocol version", []byte{0x06, 0x11, 0x02, 0x02, 0x00, 0x10, 0x00, 0x00}},
		{"wrong service type", []byte{0x06, 0x10, 0x02, 0x01, 0x00, 0x10, 0x00, 0x00}}, // Search Request, not Response
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{readData: tt.response}
			target := plugins.Target{
				Address: netip.MustParseAddrPort("192.168.1.100:3671"),
			}

			p := &Plugin{}
			service, err := p.Run(conn, 5*time.Second, target)

			if err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if service != nil {
				t.Error("expected nil service for invalid header")
			}
		})
	}
}

// Shodan Validation Tests

// Helper function to build Search Response for Shodan tests
func buildSearchResponse(medium byte, addr uint16, serial, mac, name string, families []byte) []byte {
	// Header (6) + HPAI (8) + DIB_DEV_INFO (54) + DIB_SUPP_SVC (variable)
	svcLen := 2 + len(families)*2
	totalLen := 6 + 8 + 54 + svcLen
	response := make([]byte, totalLen)

	// Header
	response[0] = 0x06
	response[1] = 0x10
	response[2] = 0x02
	response[3] = 0x02
	binary.BigEndian.PutUint16(response[4:6], uint16(totalLen))

	// HPAI
	response[6] = 0x08
	response[7] = 0x01

	// DIB_DEV_INFO
	response[14] = 54
	response[15] = 0x01
	response[16] = medium
	binary.BigEndian.PutUint16(response[18:20], addr)

	// Serial (decode hex string)
	serialBytes, _ := hex.DecodeString(serial)
	copy(response[22:28], serialBytes)

	// MAC (parse and copy)
	macParts := strings.Split(mac, ":")
	for i, p := range macParts {
		b, _ := hex.DecodeString(p)
		response[32+i] = b[0]
	}

	// Name
	copy(response[38:68], []byte(name))

	// DIB_SUPP_SVC
	response[68] = byte(svcLen)
	response[69] = 0x02
	for i, fam := range families {
		response[70+i*2] = fam
		response[70+i*2+1] = 0x01
	}

	return response
}

func TestShodanSample_SiemensIPRouter(t *testing.T) {
	// Siemens N146/21 style response
	// Services: Core, DeviceManagement, Tunnelling
	response := buildSearchResponse(
		0x01,                    // TP1 medium
		0x1001,                  // Address 1.0.1
		"001122AABBCC",          // Serial
		"00:11:22:AA:BB:CC",     // MAC
		"IP-Router N 146/21",    // Name
		[]byte{0x02, 0x03, 0x04}, // Core, DevMgmt, Tunnelling
	)

	result, err := parseSearchResponse(response)
	if err != nil {
		t.Fatalf("failed to parse Siemens response: %v", err)
	}

	if result.DeviceName != "IP-Router N 146/21" {
		t.Errorf("DeviceName = %q", result.DeviceName)
	}
	if result.KNXMedium != "TP1" {
		t.Errorf("KNXMedium = %q", result.KNXMedium)
	}
	if len(result.ServiceFamilies) != 3 {
		t.Errorf("expected 3 services, got %d", len(result.ServiceFamilies))
	}
}

func TestShodanSample_ABBIPInterface(t *testing.T) {
	// ABB IP Interface style
	// Services: Core, Tunnelling only
	response := buildSearchResponse(
		0x01,                  // TP1
		0x1105,                // Address 1.1.5
		"AABBCCDDEEFF",        // Serial
		"AA:BB:CC:DD:EE:FF",   // MAC
		"ABB IP Interface",    // Name
		[]byte{0x02, 0x04},    // Core, Tunnelling
	)

	result, err := parseSearchResponse(response)
	if err != nil {
		t.Fatalf("failed to parse ABB response: %v", err)
	}

	if result.KNXAddress != "1.1.5" {
		t.Errorf("KNXAddress = %q, want 1.1.5", result.KNXAddress)
	}
	if len(result.ServiceFamilies) != 2 {
		t.Errorf("expected 2 services (Core, Tunnelling), got %v", result.ServiceFamilies)
	}
}

func TestShodanSample_WeinzierilIPRouter(t *testing.T) {
	// Weinzierl KNX IP Router 751
	// Services: Core, DevMgmt, Tunnelling, Routing, ObjectServer
	response := buildSearchResponse(
		0x20,                           // IP medium
		0x0F01,                         // Address 0.15.1
		"FFEEDDCCBBAA",                 // Serial
		"FF:EE:DD:CC:BB:AA",            // MAC
		"KNX IP Router 751",            // Name
		[]byte{0x02, 0x03, 0x04, 0x05, 0x08}, // All services
	)

	result, err := parseSearchResponse(response)
	if err != nil {
		t.Fatalf("failed to parse Weinzierl response: %v", err)
	}

	if result.KNXMedium != "IP" {
		t.Errorf("KNXMedium = %q, want IP", result.KNXMedium)
	}
	if len(result.ServiceFamilies) != 5 {
		t.Errorf("expected 5 services, got %d: %v", len(result.ServiceFamilies), result.ServiceFamilies)
	}

	// Verify all expected services present
	expectedServices := map[string]bool{
		"Core": true, "DeviceManagement": true, "Tunnelling": true,
		"Routing": true, "ObjectServer": true,
	}
	for _, svc := range result.ServiceFamilies {
		if !expectedServices[svc] {
			t.Errorf("unexpected service: %s", svc)
		}
	}
}
