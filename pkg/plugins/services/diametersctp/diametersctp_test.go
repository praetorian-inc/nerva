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

package diametersctp

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// mockConn implements net.Conn for testing without actual SCTP
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

// encodeTestUnsigned32 encodes a uint32 in big-endian format for testing
func encodeTestUnsigned32(value uint32) []byte {
	data := make([]byte, 4)
	binary.BigEndian.PutUint32(data, value)
	return data
}

// TestDecodeFirmwareRevision verifies FreeDiameter version decoding from Firmware-Revision AVP value
func TestDecodeFirmwareRevision(t *testing.T) {
	tests := []struct {
		name             string
		firmwareRevision uint32
		expectedVersion  string
	}{
		{"Standard FreeDiameter version", 10500, "1.5.0"},
		{"FreeDiameter 1.4.0", 10400, "1.4.0"},
		{"With patch version", 10201, "1.2.1"},
		{"Low minor nonzero patch", 10003, "1.0.3"},
		{"Major version 2", 20000, "2.0.0"},
		{"Zero unset version", 0, "0.0.0"},
		{"Edge case maximum", 99999, "9.99.99"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version := decodeFirmwareRevision(tt.firmwareRevision)
			if version != tt.expectedVersion {
				t.Errorf("decodeFirmwareRevision(%d) = %s, want %s", tt.firmwareRevision, version, tt.expectedVersion)
			}
		})
	}
}

// TestIdentifyVendor verifies Product-Name to vendor/product mapping for CPE generation
func TestIdentifyVendor(t *testing.T) {
	tests := []struct {
		name            string
		productName     string
		expectedVendor  string
		expectedProduct string
	}{
		{"Standard FreeDiameter", "freeDiameter", "freediameter", "freediameter"},
		{"Case insensitive", "FREEDIAMETER", "freediameter", "freediameter"},
		{"Open5GS core", "Open5GS", "open5gs", "open5gs"},
		{"Open5GS variant", "open5gs-hss", "open5gs", "open5gs"},
		{"Oracle product", "Oracle Communications", "oracle", "diameter"},
		{"Ericsson", "Ericsson Diameter", "ericsson", "diameter"},
		{"Unknown vendor", "CustomDiameter", "*", "diameter"},
		{"Empty input", "", "*", "diameter"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vendor, product := identifyVendor(tt.productName)
			if vendor != tt.expectedVendor {
				t.Errorf("identifyVendor(%s) vendor = %s, want %s", tt.productName, vendor, tt.expectedVendor)
			}
			if product != tt.expectedProduct {
				t.Errorf("identifyVendor(%s) product = %s, want %s", tt.productName, product, tt.expectedProduct)
			}
		})
	}
}

// TestBuildCPE verifies CPE 2.3 format string generation
func TestBuildCPE(t *testing.T) {
	tests := []struct {
		name        string
		vendor      string
		product     string
		version     string
		expectedCPE string
	}{
		{"FreeDiameter with version", "freediameter", "freediameter", "1.5.0", "cpe:2.3:a:freediameter:freediameter:1.5.0:*:*:*:*:*:*:*"},
		{"Open5GS with version", "open5gs", "open5gs", "2.7.0", "cpe:2.3:a:open5gs:open5gs:2.7.0:*:*:*:*:*:*:*"},
		{"Unknown with empty version", "*", "diameter", "", "cpe:2.3:a:*:diameter:*:*:*:*:*:*:*:*"},
		{"Oracle with version", "oracle", "diameter", "3.0", "cpe:2.3:a:oracle:diameter:3.0:*:*:*:*:*:*:*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildCPE(tt.vendor, tt.product, tt.version)
			if cpe != tt.expectedCPE {
				t.Errorf("buildCPE(%s, %s, %s) = %s, want %s", tt.vendor, tt.product, tt.version, cpe, tt.expectedCPE)
			}
		})
	}
}

// TestEncodeUnsigned32 verifies big-endian uint32 encoding
func TestEncodeUnsigned32(t *testing.T) {
	tests := []struct {
		name          string
		input         uint32
		expectedBytes []byte
	}{
		{"Zero", 0, []byte{0x00, 0x00, 0x00, 0x00}},
		{"DIAMETER_SUCCESS", 2001, []byte{0x00, 0x00, 0x07, 0xD1}},
		{"Max uint32", 0xFFFFFFFF, []byte{0xFF, 0xFF, 0xFF, 0xFF}},
		{"Firmware revision", 10500, []byte{0x00, 0x00, 0x29, 0x04}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := encodeUnsigned32(tt.input)
			if len(result) != 4 {
				t.Errorf("encodeUnsigned32(%d) length = %d, want 4", tt.input, len(result))
			}
			for i := 0; i < 4; i++ {
				if result[i] != tt.expectedBytes[i] {
					t.Errorf("encodeUnsigned32(%d)[%d] = 0x%02X, want 0x%02X", tt.input, i, result[i], tt.expectedBytes[i])
				}
			}
		})
	}
}

// TestBuildAVP verifies AVP (Attribute-Value Pair) message construction
func TestBuildAVP(t *testing.T) {
	tests := []struct {
		name      string
		code      uint32
		mandatory bool
		data      []byte
	}{
		{"Origin-Host with mandatory", AVP_ORIGIN_HOST, true, []byte("test.local\x00")},
		{"Product-Name mandatory", AVP_PRODUCT_NAME, true, []byte("nerva\x00")},
		{"Vendor-Id no padding", AVP_VENDOR_ID, true, []byte{0, 0, 0, 0}},
		{"Firmware-Rev optional", AVP_FIRMWARE_REV, false, []byte{0, 0, 0x29, 0x04}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			avp := buildAVP(tt.code, tt.mandatory, tt.data)

			// Verify AVP code (first 4 bytes)
			avpCode := binary.BigEndian.Uint32(avp[0:4])
			if avpCode != tt.code {
				t.Errorf("AVP code = %d, want %d", avpCode, tt.code)
			}

			// Verify M-bit flag (byte 4)
			flags := avp[4]
			expectedFlag := byte(0)
			if tt.mandatory {
				expectedFlag = M_BIT
			}
			if flags != expectedFlag {
				t.Errorf("AVP flags = 0x%02X, want 0x%02X", flags, expectedFlag)
			}

			// Verify AVP length (bytes 5-7)
			avpLength := (uint32(avp[5]) << 16) | (uint32(avp[6]) << 8) | uint32(avp[7])
			expectedLength := 8 + len(tt.data)
			if avpLength != uint32(expectedLength) {
				t.Errorf("AVP length = %d, want %d", avpLength, expectedLength)
			}

			// Verify padding to 32-bit boundary
			if len(avp)%4 != 0 {
				t.Errorf("AVP length %d not padded to 32-bit boundary", len(avp))
			}

			// Verify data content (bytes 8 onwards, before padding)
			for i := 0; i < len(tt.data); i++ {
				if avp[8+i] != tt.data[i] {
					t.Errorf("AVP data[%d] = 0x%02X, want 0x%02X", i, avp[8+i], tt.data[i])
				}
			}
		})
	}
}

// buildMockCEA creates a valid CEA for testing
func buildMockCEA(productName string, firmwareRevision uint32, includeVersion bool) []byte {
	// Diameter Header (20 bytes)
	header := make([]byte, 20)
	// Version = 1
	header[0] = DIAMETER_VERSION
	// Command Flags: R-bit cleared (0x00) for answer
	header[4] = 0x00
	// Command Code = 257 (CER/CEA)
	binary.BigEndian.PutUint32(header[4:8], CER_COMMAND_CODE)
	header[4] = 0x00 // Overwrite flags byte
	// Application-ID = 0
	binary.BigEndian.PutUint32(header[8:12], 0)
	// Hop-by-Hop ID
	binary.BigEndian.PutUint32(header[12:16], 12345)
	// End-to-End ID
	binary.BigEndian.PutUint32(header[16:20], 67890)

	// Build AVPs
	avps := []byte{}

	// Result-Code AVP (Code 268, Mandatory) - Value: 2001 (DIAMETER_SUCCESS)
	avps = append(avps, buildAVP(AVP_RESULT_CODE, true, encodeTestUnsigned32(DIAMETER_SUCCESS))...)

	// Origin-Host AVP (Code 264, Mandatory)
	avps = append(avps, buildAVP(AVP_ORIGIN_HOST, true, []byte("test.diameter.local\x00"))...)

	// Origin-Realm AVP (Code 296, Mandatory)
	avps = append(avps, buildAVP(AVP_ORIGIN_REALM, true, []byte("local\x00"))...)

	// Host-IP-Address AVP (Code 257, Mandatory)
	// Address format: AddressType (2 bytes) + Address
	// AddressType 1 = IPv4
	ipAddr := []byte{0x00, 0x01, 127, 0, 0, 1} // IPv4: 127.0.0.1
	avps = append(avps, buildAVP(AVP_HOST_IP_ADDR, true, ipAddr)...)

	// Vendor-Id AVP (Code 266, Mandatory)
	avps = append(avps, buildAVP(AVP_VENDOR_ID, true, encodeTestUnsigned32(0))...)

	// Product-Name AVP (Code 269, Mandatory)
	if productName != "" {
		productBytes := append([]byte(productName), 0x00) // Null-terminated
		avps = append(avps, buildAVP(AVP_PRODUCT_NAME, true, productBytes)...)
	}

	// Firmware-Revision AVP (Code 267, Optional)
	if includeVersion {
		avps = append(avps, buildAVP(AVP_FIRMWARE_REV, false, encodeTestUnsigned32(firmwareRevision))...)
	}

	// Update message length in header
	totalLength := len(header) + len(avps)
	// Bytes 1-3 contain the message length (24-bit big-endian)
	header[1] = byte((totalLength >> 16) & 0xFF)
	header[2] = byte((totalLength >> 8) & 0xFF)
	header[3] = byte(totalLength & 0xFF)

	return append(header, avps...)
}

// TestValidateCEA verifies CEA (Capabilities-Exchange-Answer) structure validation
func TestValidateCEA(t *testing.T) {
	tests := []struct {
		name          string
		buildResponse func() []byte
		expectedError string
	}{
		{
			name: "Valid CEA",
			buildResponse: func() []byte {
				return buildMockCEA("freeDiameter", 10500, true)
			},
			expectedError: "",
		},
		{
			name: "Empty response",
			buildResponse: func() []byte {
				return []byte{}
			},
			expectedError: "response too short",
		},
		{
			name: "Too short",
			buildResponse: func() []byte {
				return []byte{0x01, 0x00, 0x00}
			},
			expectedError: "response too short",
		},
		{
			name: "Invalid version",
			buildResponse: func() []byte {
				cea := buildMockCEA("test", 0, false)
				cea[0] = 0x02 // Change version to 2
				return cea
			},
			expectedError: "invalid version: 2",
		},
		{
			name: "Wrong command code",
			buildResponse: func() []byte {
				cea := buildMockCEA("test", 0, false)
				// Change command code to 258 (bytes 5-7)
				cea[5] = 0x00
				cea[6] = 0x01
				cea[7] = 0x02
				return cea
			},
			expectedError: "invalid command code: 258",
		},
		{
			name: "R-bit set request",
			buildResponse: func() []byte {
				cea := buildMockCEA("test", 0, false)
				cea[4] = R_BIT // Set R-bit (request flag)
				return cea
			},
			expectedError: "R-bit set in CEA",
		},
		{
			name: "Incomplete short length",
			buildResponse: func() []byte {
				cea := buildMockCEA("test", 0, false)
				// Change length to claim 200 bytes
				cea[1] = 0x00
				cea[2] = 0x00
				cea[3] = 0xC8 // 200 in hex
				return cea
			},
			expectedError: "invalid message length",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := tt.buildResponse()
			err := validateCEA(response)

			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("validateCEA() error = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("validateCEA() error = nil, want error containing %q", tt.expectedError)
				} else if !contains(err.Error(), tt.expectedError) {
					t.Errorf("validateCEA() error = %q, want error containing %q", err.Error(), tt.expectedError)
				}
			}
		})
	}
}

// contains checks if a string contains a substring
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && (s[:len(substr)] == substr || s[len(s)-len(substr):] == substr || containsMiddle(s, substr)))
}

func containsMiddle(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestPortPriority verifies plugin recognizes Diameter port 3868
func TestPortPriority(t *testing.T) {
	plugin := &DIAMETERSCTPPlugin{}

	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{"Diameter port", 3868, true},
		{"Non-Diameter port", 8080, false},
		{"Zero port", 0, false},
		{"HTTPS port", 443, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := plugin.PortPriority(tt.port)
			if result != tt.expected {
				t.Errorf("PortPriority(%d) = %v, want %v", tt.port, result, tt.expected)
			}
		})
	}
}

// TestName verifies plugin returns "diameter-sctp" as name
func TestName(t *testing.T) {
	plugin := &DIAMETERSCTPPlugin{}
	name := plugin.Name()
	if name != DIAMETER_SCTP {
		t.Errorf("Name() = %s, want %s", name, DIAMETER_SCTP)
	}
}

// TestType verifies plugin returns plugins.SCTP as protocol type
func TestType(t *testing.T) {
	plugin := &DIAMETERSCTPPlugin{}
	protocolType := plugin.Type()
	if protocolType != plugins.SCTP {
		t.Errorf("Type() = %v, want plugins.SCTP", protocolType)
	}
}

// TestPriority verifies plugin priority is 60
func TestPriority(t *testing.T) {
	plugin := &DIAMETERSCTPPlugin{}
	priority := plugin.Priority()
	if priority != 60 {
		t.Errorf("Priority() = %d, want 60", priority)
	}
}

// TestEnrichDiameter verifies CEA data extraction
func TestEnrichDiameter(t *testing.T) {
	tests := []struct {
		name               string
		buildCEA           func() []byte
		expectedProduct    string
		expectedFirmwareRev uint32
		expectedOriginHost  string
		expectedOriginRealm string
		expectError        bool
	}{
		{
			name: "Full response with product and firmware",
			buildCEA: func() []byte {
				return buildMockCEA("freeDiameter", 10500, true)
			},
			expectedProduct:    "freeDiameter",
			expectedFirmwareRev: 10500,
			expectError:        false,
		},
		{
			name: "No firmware revision",
			buildCEA: func() []byte {
				return buildMockCEA("test", 0, false)
			},
			expectedProduct:    "test",
			expectedFirmwareRev: 0,
			expectError:        false,
		},
		{
			name: "No product name, use Origin-Host fallback",
			buildCEA: func() []byte {
				// Build CEA without Product-Name AVP, but Origin-Host is present
				return buildMockCEA("", 10500, true)
			},
			expectedOriginHost:  "test.diameter.local",
			expectedOriginRealm: "local",
			expectedFirmwareRev: 10500,
			expectError:        false,
		},
		{
			name: "Null-terminated string",
			buildCEA: func() []byte {
				return buildMockCEA("freeDiameter\x00extra", 10500, true)
			},
			expectedProduct:    "freeDiameter",
			expectedFirmwareRev: 10500,
			expectError:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cea := tt.buildCEA()
			productName, firmwareRev, originHost, originRealm, errorMessage, err := enrichDiameter(cea)

			if tt.expectError {
				if err == nil {
					t.Error("enrichDiameter() error = nil, want error")
				}
			} else {
				if err != nil {
					t.Errorf("enrichDiameter() error = %v, want nil", err)
				}
				if productName != tt.expectedProduct {
					t.Errorf("enrichDiameter() product = %s, want %s", productName, tt.expectedProduct)
				}
				if firmwareRev != tt.expectedFirmwareRev {
					t.Errorf("enrichDiameter() firmwareRev = %d, want %d", firmwareRev, tt.expectedFirmwareRev)
				}
				if tt.expectedOriginHost != "" && originHost != tt.expectedOriginHost {
					t.Errorf("enrichDiameter() originHost = %s, want %s", originHost, tt.expectedOriginHost)
				}
				if tt.expectedOriginRealm != "" && originRealm != tt.expectedOriginRealm {
					t.Errorf("enrichDiameter() originRealm = %s, want %s", originRealm, tt.expectedOriginRealm)
				}
				// errorMessage should be empty on success
				if errorMessage != "" {
					t.Errorf("enrichDiameter() errorMessage = %s, want empty on success", errorMessage)
				}
			}
		})
	}
}

// TestBuildCER verifies CER message construction
func TestBuildCER(t *testing.T) {
	cer := buildCER()

	// Verify minimum length
	if len(cer) < 20 {
		t.Fatalf("buildCER() length = %d, want >= 20", len(cer))
	}

	// Test header version (byte 0)
	if cer[0] != DIAMETER_VERSION {
		t.Errorf("CER version = %d, want %d", cer[0], DIAMETER_VERSION)
	}

	// Test message length (bytes 1-3)
	msgLength := (uint32(cer[1]) << 16) | (uint32(cer[2]) << 8) | uint32(cer[3])
	if msgLength != uint32(len(cer)) {
		t.Errorf("CER message length = %d, want %d", msgLength, len(cer))
	}

	// Test R-bit set (byte 4)
	if cer[4]&R_BIT == 0 {
		t.Error("CER R-bit not set, want R-bit set")
	}

	// Test command code (bytes 5-7)
	commandCode := (uint32(cer[5]) << 16) | (uint32(cer[6]) << 8) | uint32(cer[7])
	if commandCode != CER_COMMAND_CODE {
		t.Errorf("CER command code = %d, want %d", commandCode, CER_COMMAND_CODE)
	}

	// Test Application-ID (bytes 8-11)
	appID := binary.BigEndian.Uint32(cer[8:12])
	if appID != 0 {
		t.Errorf("CER Application-ID = %d, want 0", appID)
	}

	// Verify presence of mandatory AVPs by checking for their codes in the message
	mandatoryAVPs := map[uint32]string{
		AVP_ORIGIN_HOST:  "Origin-Host",
		AVP_ORIGIN_REALM: "Origin-Realm",
		AVP_HOST_IP_ADDR: "Host-IP-Address",
		AVP_VENDOR_ID:    "Vendor-Id",
		AVP_PRODUCT_NAME: "Product-Name",
	}

	offset := 20
	foundAVPs := make(map[uint32]bool)
	for offset < len(cer)-8 {
		avpCode := binary.BigEndian.Uint32(cer[offset : offset+4])
		foundAVPs[avpCode] = true

		// Get AVP length and move to next AVP
		avpLength := (uint32(cer[offset+5]) << 16) | (uint32(cer[offset+6]) << 8) | uint32(cer[offset+7])
		paddedLength := avpLength
		if avpLength%4 != 0 {
			paddedLength += 4 - (avpLength % 4)
		}
		offset += int(paddedLength)
	}

	for code, name := range mandatoryAVPs {
		if !foundAVPs[code] {
			t.Errorf("CER missing mandatory AVP: %s (code %d)", name, code)
		}
	}
}

// TestValidateCEAOverflowProtection verifies message length overflow validation
func TestValidateCEAOverflowProtection(t *testing.T) {
	tests := []struct {
		name          string
		buildResponse func() []byte
		expectedError string
	}{
		{
			name: "Message length exceeds maximum (16MB)",
			buildResponse: func() []byte {
				cea := buildMockCEA("test", 0, false)
				// Set message length to 17MB (exceeds 16MB limit)
				// 17MB = 17 * 1024 * 1024 = 17825792 = 0x01100000
				cea[1] = 0x01
				cea[2] = 0x10
				cea[3] = 0x00
				return cea
			},
			expectedError: "invalid message length",
		},
		{
			name: "Message length larger than response buffer",
			buildResponse: func() []byte {
				cea := buildMockCEA("test", 0, false)
				// Set message length to claim 1000 bytes but response is ~200 bytes
				cea[1] = 0x00
				cea[2] = 0x03
				cea[3] = 0xE8 // 1000 bytes
				return cea
			},
			expectedError: "invalid message length",
		},
		{
			name: "Valid message at boundary (exactly buffer size)",
			buildResponse: func() []byte {
				cea := buildMockCEA("test", 0, false)
				// Message length should match actual size (valid)
				actualLength := len(cea)
				cea[1] = byte((actualLength >> 16) & 0xFF)
				cea[2] = byte((actualLength >> 8) & 0xFF)
				cea[3] = byte(actualLength & 0xFF)
				return cea
			},
			expectedError: "", // No error expected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := tt.buildResponse()
			err := validateCEA(response)

			if tt.expectedError == "" {
				if err != nil {
					t.Errorf("validateCEA() error = %v, want nil", err)
				}
			} else {
				if err == nil {
					t.Errorf("validateCEA() error = nil, want error containing %q", tt.expectedError)
				} else if !contains(err.Error(), tt.expectedError) {
					t.Errorf("validateCEA() error = %q, want error containing %q", err.Error(), tt.expectedError)
				}
			}
		})
	}
}

// TestEnrichDiameterAVPOverflowProtection verifies AVP length overflow validation
func TestEnrichDiameterAVPOverflowProtection(t *testing.T) {
	tests := []struct {
		name          string
		buildCEA      func() []byte
		expectedError bool
		description   string
	}{
		{
			name: "AVP length exceeds message bounds",
			buildCEA: func() []byte {
				// Build a valid CEA first
				cea := buildMockCEA("test", 10500, true)
				// Corrupt the first AVP length (Result-Code AVP at offset 20)
				// Set AVP length to claim 1000 bytes (will exceed message)
				cea[25] = 0x00 // High byte of 24-bit length
				cea[26] = 0x03 // Mid byte
				cea[27] = 0xE8 // Low byte (1000 decimal)
				return cea
			},
			expectedError: true, // Parser stops early, won't find required AVPs
			description:   "Parser should stop at invalid AVP without crashing",
		},
		{
			name: "Valid CEA with multiple AVPs",
			buildCEA: func() []byte {
				return buildMockCEA("freeDiameter", 10500, true)
			},
			expectedError: false,
			description:   "Valid message should parse successfully",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cea := tt.buildCEA()
			_, _, _, _, _, err := enrichDiameter(cea)

			if tt.expectedError {
				if err == nil {
					t.Errorf("enrichDiameter() error = nil, want error (%s)", tt.description)
				}
			} else {
				if err != nil {
					t.Errorf("enrichDiameter() error = %v, want nil (%s)", err, tt.description)
				}
			}
		})
	}
}
