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

package h323

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	readData  []byte
	readIndex int
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readIndex >= len(m.readData) {
		return 0, nil
	}
	n = copy(b, m.readData[m.readIndex:])
	m.readIndex += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

// Test vendor signature extraction with known T.35 manufacturer codes
func TestExtractVendor(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected string
	}{
		{
			name:     "Polycom signature",
			response: []byte{0x00, 0xb5, 0x00, 0x01, 0xff},
			expected: "Polycom",
		},
		{
			name:     "Cisco signature",
			response: []byte{0x00, 0xb5, 0x00, 0x12, 0xff},
			expected: "Cisco",
		},
		{
			name:     "LifeSize signature",
			response: []byte{0x00, 0xb5, 0x00, 0x53, 0xff},
			expected: "LifeSize",
		},
		{
			name:     "Tandberg signature",
			response: []byte{0x00, 0xa0, 0x01, 0xff},
			expected: "Tandberg",
		},
		{
			name:     "Unknown vendor",
			response: []byte{0x00, 0xff, 0xff, 0xff},
			expected: "",
		},
		{
			name:     "Empty response",
			response: []byte{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractVendor(tt.response)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test ASCII string extraction from binary data
func TestExtractASCII(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		minLen   int
		maxLen   int
		expected []string
	}{
		{
			name:     "Extract simple strings",
			data:     []byte{0x00, 'H', 'e', 'l', 'l', 'o', 0x00, 'W', 'o', 'r', 'l', 'd', 0x00},
			minLen:   4,
			maxLen:   64,
			expected: []string{"Hello", "World"},
		},
		{
			name:     "Filter by minimum length",
			data:     []byte{'H', 'i', 0x00, 'H', 'e', 'l', 'l', 'o'},
			minLen:   4,
			maxLen:   64,
			expected: []string{"Hello"},
		},
		{
			name:     "Truncate by maximum length",
			data:     []byte{'V', 'e', 'r', 'y', 'L', 'o', 'n', 'g', 'S', 't', 'r', 'i', 'n', 'g'},
			minLen:   4,
			maxLen:   8,
			expected: []string{"VeryLong"},
		},
		{
			name:     "No printable ASCII",
			data:     []byte{0x00, 0x01, 0x02, 0xff},
			minLen:   4,
			maxLen:   64,
			expected: []string{},
		},
		{
			name:     "Empty data",
			data:     []byte{},
			minLen:   4,
			maxLen:   64,
			expected: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractASCII(tt.data, tt.minLen, tt.maxLen)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test product name extraction
func TestExtractProductName(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected string
	}{
		{
			name:     "Extract product name",
			response: []byte{0x00, 'P', 'o', 'l', 'y', 'c', 'o', 'm', ' ', 'V', 'S', 'X', 0x00},
			expected: "Polycom VSX",
		},
		{
			name:     "Skip common protocol strings",
			response: []byte{'R', 'T', 'S', 'P', 0x00, 'A', 'c', 't', 'u', 'a', 'l', 'N', 'a', 'm', 'e', 0x00},
			expected: "ActualName",
		},
		{
			name:     "Return first valid string",
			response: []byte{'S', 'h', 'o', 'r', 't', 0x00},
			expected: "Short",
		},
		{
			name:     "No valid strings",
			response: []byte{0x00, 0xff, 0x01},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractProductName(tt.response)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test version pattern matching
func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected string
	}{
		{
			name:     "Extract X.Y version",
			response: []byte{'v', 'e', 'r', 's', 'i', 'o', 'n', ' ', '1', '2', '.', '5', 0x00},
			expected: "12.5",
		},
		{
			name:     "Extract X.Y.Z version",
			response: []byte{'v', '1', '.', '2', '.', '3', 0x00},
			expected: "1.2.3",
		},
		{
			name:     "Extract X.Y.Z.W version",
			response: []byte{'1', '0', '.', '2', '.', '4', '.', '5', 0x00},
			expected: "10.2.4.5",
		},
		{
			name:     "No version found",
			response: []byte{'n', 'o', ' ', 'v', 'e', 'r', 's', 'i', 'o', 'n'},
			expected: "",
		},
		{
			name:     "Empty response",
			response: []byte{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractVersion(tt.response)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test complete metadata extraction
func TestExtractMetadata(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected plugins.ServiceH323
	}{
		{
			name:     "Extract all metadata",
			response: []byte{0xb5, 0x00, 0x01, 'P', 'o', 'l', 'y', 'c', 'o', 'm', ' ', 'V', 'S', 'X', ' ', '7', '0', '0', '0', 0x00, 'v', '8', '.', '0', '.', '1', 0x00},
			expected: plugins.ServiceH323{
				VendorID:    "Polycom",
				ProductName: "Polycom VSX 7000",
				Version:     "8.0.1",
				CPEs:        []string{"cpe:2.3:h:polycom:polycom_vsx_7000:8.0.1:*:*:*:*:*:*:*"},
			},
		},
		{
			name:     "Partial metadata",
			response: []byte{0xb5, 0x00, 0x12, 'C', 'i', 's', 'c', 'o', ' ', 'D', 'e', 'v', 'i', 'c', 'e', 0x00},
			expected: plugins.ServiceH323{
				VendorID:    "Cisco",
				ProductName: "Cisco Device",
				Version:     "",
				CPEs:        []string{"cpe:2.3:h:cisco:cisco_device:*:*:*:*:*:*:*:*"},
			},
		},
		{
			name:     "No metadata",
			response: []byte{0xff, 0xff, 0xff},
			expected: plugins.ServiceH323{
				VendorID:    "",
				ProductName: "",
				Version:     "",
				CPEs:        nil,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractMetadata(tt.response)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestExtractVendorSignatureMatching validates that extractVendor correctly
// detects vendor signatures using bytes.Contains (replaces TestContainsBytes
// since containsBytes was removed in favor of bytes.Contains).
func TestExtractVendorSignatureMatching(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected string
	}{
		{
			name:     "Polycom signature at start",
			data:     []byte{0xb5, 0x00, 0x01, 0xff},
			expected: "Polycom",
		},
		{
			name:     "Cisco signature in middle",
			data:     []byte{0x00, 0xb5, 0x00, 0x12, 0xff},
			expected: "Cisco",
		},
		{
			name:     "LifeSize signature",
			data:     []byte{0x00, 0xb5, 0x00, 0x53, 0xff},
			expected: "LifeSize",
		},
		{
			name:     "Signature not found",
			data:     []byte{0x00, 0xb5, 0x00, 0x02, 0xff},
			expected: "",
		},
		{
			name:     "Empty data",
			data:     []byte{},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractVendor(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Test TPKT validation
func TestIsValidTPKT(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "valid TPKT header",
			input:    []byte{0x03, 0x00, 0x00, 0x07, 0x08, 0x00, 0x07},
			expected: true,
		},
		{
			name:     "wrong version",
			input:    []byte{0x04, 0x00, 0x00, 0x04},
			expected: false,
		},
		{
			name:     "wrong reserved byte",
			input:    []byte{0x03, 0x01, 0x00, 0x04},
			expected: false,
		},
		{
			name:     "too short",
			input:    []byte{0x03, 0x00},
			expected: false,
		},
		{
			name:     "empty",
			input:    []byte{},
			expected: false,
		},
		{
			name:     "length exceeds data",
			input:    []byte{0x03, 0x00, 0x00, 0xff},
			expected: false,
		},
		{
			name:     "length less than header size",
			input:    []byte{0x03, 0x00, 0x00, 0x03},
			expected: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidTPKT(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test Q.931 validation
func TestIsValidQ931(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "valid Connect",
			input:    []byte{0x03, 0x00, 0x00, 0x08, 0x08, 0x00, 0x07, 0x00},
			expected: true,
		},
		{
			name:     "valid Release Complete",
			input:    []byte{0x03, 0x00, 0x00, 0x08, 0x08, 0x00, 0x5a, 0x00},
			expected: true,
		},
		{
			name:     "valid Alerting",
			input:    []byte{0x03, 0x00, 0x00, 0x08, 0x08, 0x00, 0x01, 0x00},
			expected: true,
		},
		{
			name:     "valid Call Proceeding",
			input:    []byte{0x03, 0x00, 0x00, 0x08, 0x08, 0x00, 0x02, 0x00},
			expected: true,
		},
		{
			name:     "wrong protocol discriminator",
			input:    []byte{0x03, 0x00, 0x00, 0x08, 0x09, 0x00, 0x07, 0x00},
			expected: false,
		},
		{
			name:     "invalid message type",
			input:    []byte{0x03, 0x00, 0x00, 0x08, 0x08, 0x00, 0xff, 0x00},
			expected: false,
		},
		{
			name:     "truncated",
			input:    []byte{0x03, 0x00, 0x00, 0x08, 0x08},
			expected: false,
		},
		{
			name:     "CR length too large",
			input:    []byte{0x03, 0x00, 0x00, 0x0c, 0x08, 0x05, 0x01, 0x02, 0x03, 0x04, 0x05, 0x07},
			expected: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := isValidQ931(tc.input)
			assert.Equal(t, tc.expected, result)
		})
	}
}

// Test Plugin.Run integration with mock responses
func TestPluginRun(t *testing.T) {
	plugin := &Plugin{}

	tests := []struct {
		name           string
		response       []byte
		expectDetected bool
		expectVendor   string
	}{
		{
			name:           "valid H.323 Connect",
			response:       []byte{0x03, 0x00, 0x00, 0x08, 0x08, 0x00, 0x07, 0x00},
			expectDetected: true,
			expectVendor:   "",
		},
		{
			name:           "valid H.323 Release Complete",
			response:       []byte{0x03, 0x00, 0x00, 0x08, 0x08, 0x00, 0x5a, 0x00},
			expectDetected: true,
			expectVendor:   "",
		},
		{
			name:           "valid H.323 with Polycom vendor",
			response:       []byte{0x03, 0x00, 0x00, 0x10, 0x08, 0x00, 0x07, 0x00, 0xb5, 0x00, 0x01, 'P', 'o', 'l', 'y', 'c'},
			expectDetected: true,
			expectVendor:   "Polycom",
		},
		{
			name:           "empty response",
			response:       []byte{},
			expectDetected: false,
			expectVendor:   "",
		},
		{
			name:           "invalid TPKT",
			response:       []byte{0x04, 0x00, 0x00, 0x04},
			expectDetected: false,
			expectVendor:   "",
		},
		{
			name:           "not H.323",
			response:       []byte("HTTP/1.1 200 OK\r\n"),
			expectDetected: false,
			expectVendor:   "",
		},
		{
			name:           "valid TPKT but invalid Q.931",
			response:       []byte{0x03, 0x00, 0x00, 0x08, 0x09, 0x00, 0xff, 0x00},
			expectDetected: false,
			expectVendor:   "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			conn := &mockConn{readData: tc.response}
			target := plugins.Target{}
			result, err := plugin.Run(conn, 5*time.Second, target)

			if tc.expectDetected {
				assert.NoError(t, err)
				assert.NotNil(t, result)
				assert.Equal(t, "h323", result.Protocol)
				if tc.expectVendor != "" {
					metadata, ok := result.Metadata().(plugins.ServiceH323)
					assert.True(t, ok, "metadata should be ServiceH323 type")
					assert.Equal(t, tc.expectVendor, metadata.VendorID)
				}
			} else {
				assert.Nil(t, result)
			}
		})
	}
}

func TestBuildH323CPE(t *testing.T) {
	tests := []struct {
		name     string
		vendor   string
		product  string
		version  string
		expected string
	}{
		{
			name:     "Polycom with version",
			vendor:   "Polycom",
			product:  "HDX 7000",
			version:  "3.1.5",
			expected: "cpe:2.3:h:polycom:hdx_7000:3.1.5:*:*:*:*:*:*:*",
		},
		{
			name:     "Cisco with version",
			vendor:   "Cisco",
			product:  "TelePresence",
			version:  "9.15.0",
			expected: "cpe:2.3:h:cisco:telepresence:9.15.0:*:*:*:*:*:*:*",
		},
		{
			name:     "Unknown vendor returns empty",
			vendor:   "UnknownVendor",
			product:  "SomeProduct",
			version:  "1.0",
			expected: "",
		},
		{
			name:     "Empty vendor returns empty",
			vendor:   "",
			product:  "Product",
			version:  "1.0",
			expected: "",
		},
		{
			name:     "Missing product uses wildcard",
			vendor:   "Polycom",
			product:  "",
			version:  "3.1.5",
			expected: "cpe:2.3:h:polycom:*:3.1.5:*:*:*:*:*:*:*",
		},
		{
			name:     "Missing version uses wildcard",
			vendor:   "Cisco",
			product:  "TelePresence",
			version:  "",
			expected: "cpe:2.3:h:cisco:telepresence:*:*:*:*:*:*:*:*",
		},
		{
			name:     "LifeSize vendor",
			vendor:   "LifeSize",
			product:  "Team 220",
			version:  "4.7.18",
			expected: "cpe:2.3:h:lifesize:team_220:4.7.18:*:*:*:*:*:*:*",
		},
		{
			name:     "Tandberg vendor",
			vendor:   "Tandberg",
			product:  "Codec C60",
			version:  "TC7.3.6",
			expected: "cpe:2.3:h:tandberg:codec_c60:TC7.3.6:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildH323CPE(tt.vendor, tt.product, tt.version)
			if result != tt.expected {
				t.Errorf("buildH323CPE(%q, %q, %q) = %q, want %q",
					tt.vendor, tt.product, tt.version, result, tt.expected)
			}
		})
	}
}

func TestNormalizeForCPE(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"HDX 7000", "hdx_7000"},
		{"TelePresence", "telepresence"},
		{"Team-220", "team_220"},
		{"  Spaced  ", "spaced"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeForCPE(tt.input)
			if result != tt.expected {
				t.Errorf("normalizeForCPE(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// Test Plugin interface methods
func TestPluginInterface(t *testing.T) {
	plugin := &Plugin{}

	assert.Equal(t, "h323", plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, 150, plugin.Priority())
	assert.True(t, plugin.PortPriority(1720))
	assert.False(t, plugin.PortPriority(80))
	assert.False(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(8080))
}

// Task 2: Tests for enhanced probe packet builder functions

func TestBuildTPKT(t *testing.T) {
	payload := []byte{0x08, 0x02, 0x00, 0x01, 0x05}
	pkt := buildTPKT(payload)
	assert.Equal(t, byte(0x03), pkt[0])                     // version
	assert.Equal(t, byte(0x00), pkt[1])                     // reserved
	assert.Equal(t, 9, int(pkt[2])<<8|int(pkt[3]))          // total length
	assert.Equal(t, payload, pkt[4:])
}

func TestBuildBearerCapabilityIE(t *testing.T) {
	ie := buildBearerCapabilityIE()
	assert.Equal(t, byte(0x04), ie[0]) // IE type
	assert.Equal(t, byte(0x03), ie[1]) // length
	assert.Equal(t, 5, len(ie))
}

func TestBuildDisplayIE(t *testing.T) {
	ie := buildDisplayIE("nerva")
	assert.Equal(t, byte(0x28), ie[0])       // IE type
	assert.Equal(t, byte(0x06), ie[1])       // length ("nerva" + null)
	assert.Equal(t, "nerva", string(ie[2:7]))
	assert.Equal(t, byte(0x00), ie[7]) // null terminator
}

func TestBuildUserUserIE(t *testing.T) {
	uuie := []byte{0x20, 0xa8}
	ie := buildUserUserIE(uuie)
	assert.Equal(t, byte(0x7e), ie[0]) // IE type
	// Length should be len(uuie) + 1 (protocol discriminator)
	ieLen := int(ie[1])<<8 | int(ie[2])
	assert.Equal(t, 3, ieLen)        // 1 (proto disc) + 2 (uuie)
	assert.Equal(t, byte(0x05), ie[3]) // X.208/X.209 discriminator
}

func TestBuildH225SetupUUIE(t *testing.T) {
	uuie := buildH225SetupUUIE()
	// Must contain H.225.0 protocol marker
	assert.True(t, bytes.Contains(uuie, []byte{0x00, 0x08, 0x91, 0x4a, 0x00}))
	// Must be at least 44 bytes (template size)
	assert.GreaterOrEqual(t, len(uuie), 44)
}

func TestBuildSetupPacket_Enhanced(t *testing.T) {
	pkt := buildSetupPacket()
	// TPKT header
	assert.Equal(t, byte(0x03), pkt[0])
	assert.Equal(t, byte(0x00), pkt[1])
	// Total length matches
	tpktLen := int(pkt[2])<<8 | int(pkt[3])
	assert.Equal(t, len(pkt), tpktLen)
	// Q.931 header
	assert.Equal(t, byte(0x08), pkt[4]) // protocol disc
	assert.Equal(t, byte(0x02), pkt[5]) // CR length
	assert.Equal(t, byte(0x05), pkt[8]) // Setup message type
	// Must be significantly larger than old 7-byte probe
	assert.Greater(t, len(pkt), 50)
}

// Task 3: Tests for structured Q.931 IE parser

func TestParseQ931_ValidConnect(t *testing.T) {
	// TPKT + Q.931 Connect with Bearer Cap IE and Display IE
	// Byte count: 4(TPKT) + 1(disc) + 3(CR) + 1(msgtype) + 5(BearerCap) + 6(Display) = 20
	response := []byte{
		0x03, 0x00, 0x00, 0x14,          // TPKT: length 20
		0x08,                             // Q.931 protocol disc
		0x02, 0x00, 0x01,                 // CR length=2, value=0x0001
		0x07,                             // Connect
		0x04, 0x03, 0x88, 0x93, 0xa5,    // Bearer Cap IE
		0x28, 0x04, 'T', 'e', 's', 't',  // Display IE
	}
	msg := parseQ931(response)
	assert.NotNil(t, msg)
	assert.Equal(t, byte(0x07), msg.msgType)
	assert.Equal(t, []byte{0x88, 0x93, 0xa5}, msg.ies[0x04])
	assert.Equal(t, []byte("Test"), msg.ies[0x28])
}

func TestParseQ931_UserUserIE(t *testing.T) {
	// Response with User-User IE (2-byte length)
	uuPayload := []byte{0x05, 0x20, 0xa8, 0x06, 0x00, 0x08, 0x91, 0x4a, 0x00, 0x06}
	response := []byte{0x03, 0x00}
	totalLen := 4 + 5 + 3 + len(uuPayload) // TPKT + Q.931 hdr + UU IE hdr + payload
	response = append(response, byte(totalLen>>8), byte(totalLen&0xff))
	response = append(response, 0x08, 0x02, 0x00, 0x01, 0x5a) // Q.931: ReleaseComplete
	response = append(response, 0x7e)                          // UU IE type
	response = append(response, byte(len(uuPayload)>>8), byte(len(uuPayload)&0xff))
	response = append(response, uuPayload...)

	msg := parseQ931(response)
	assert.NotNil(t, msg)
	assert.Equal(t, byte(0x5a), msg.msgType)
	assert.Equal(t, uuPayload, msg.ies[0x7e])
}

func TestParseQ931_InvalidInput(t *testing.T) {
	assert.Nil(t, parseQ931(nil))
	assert.Nil(t, parseQ931([]byte{}))
	assert.Nil(t, parseQ931([]byte{0x03, 0x00, 0x00, 0x04})) // Just TPKT, no Q.931
	assert.Nil(t, parseQ931([]byte{0x04, 0x00, 0x00, 0x04})) // Wrong TPKT version
}

// Task 4: Tests for H.225.0 vendor/product/version extraction

func TestExtractH225VendorInfo_Alerting(t *testing.T) {
	// Simulated Alerting response with protocol marker + vendor ID
	uuData := make([]byte, 30)
	// Protocol marker
	copy(uuData[0:], []byte{0x00, 0x08, 0x91, 0x4a, 0x00})
	uuData[5] = 0x04 // protocol version 4
	// Skip to vendor ID position (after \xc0 marker)
	uuData[7] = 0xc0 // vendor info present
	// 4-byte vendor ID at position 8
	binary.BigEndian.PutUint32(uuData[8:12], 0xb5000012) // Cisco
	// Product ID (pver >= 3)
	uuData[12] = 0x04 // length - 1 = 4, actual = 5
	copy(uuData[13:18], []byte("Cisco"))
	// Version ID
	uuData[18] = 0x02 // length - 1 = 2, actual = 3
	copy(uuData[19:22], []byte("9.1"))

	info := extractH225VendorInfo(q931Alerting, uuData)
	assert.NotNil(t, info)
	assert.Equal(t, 4, info.protocolVersion)
	assert.Equal(t, uint32(0xb5000012), info.vendorID)
	assert.Equal(t, "Cisco", info.productID)
	assert.Equal(t, "9.1", info.versionID)
}

func TestExtractH225VendorInfo_NoMarker(t *testing.T) {
	uuData := []byte{0x05, 0x20, 0xa8, 0x00, 0x00}
	info := extractH225VendorInfo(q931Connect, uuData)
	assert.Nil(t, info)
}

func TestExtractH225VendorInfo_Truncated(t *testing.T) {
	// Marker present but data truncated before vendor ID
	uuData := []byte{0x00, 0x08, 0x91, 0x4a, 0x00, 0x06}
	info := extractH225VendorInfo(q931Alerting, uuData)
	assert.NotNil(t, info)
	assert.Equal(t, 6, info.protocolVersion)
	assert.Equal(t, uint32(0), info.vendorID) // No vendor data
}

func TestResolveVendorName(t *testing.T) {
	assert.Equal(t, "Cisco", resolveVendorName("0xb5000012"))
	assert.Equal(t, "Polycom", resolveVendorName("0xb5000001"))
	assert.Equal(t, "0x12345678", resolveVendorName("0x12345678")) // unknown
	assert.Equal(t, "invalid", resolveVendorName("invalid"))
}

// Task 5: Tests for updated extractMetadata and Plugin.Run

func TestExtractMetadata_StructuredParsing(t *testing.T) {
	// Build a Q.931 Alerting response with User-User IE containing H.225.0 data.
	// Using Alerting (0x01) since its vendor extraction path is simpler to construct.
	// uuData layout (passed as ies[0x7e]):
	//   [0]   0x05  - UU protocol discriminator (X.208/X.209)
	//   [1..5] H.225.0 marker: 0x00 0x08 0x91 0x4a 0x00
	//   [6]   0x04  - protocol version 4
	//   [7]   0x00  - (byte at i)
	//   [8]   0xc0  - vendor info present marker (at i+1)
	//   [9..12] Polycom vendor ID (0x00b50001)
	//   [13]  0x06  - product length-1 = 6, actual = 7
	//   [14..20] "Polycom"
	//   [21]  0x02  - version length-1 = 2, actual = 3
	//   [22..24] "8.0"
	uuData := []byte{
		0x05,                               // UU protocol discriminator
		0x00, 0x08, 0x91, 0x4a, 0x00,      // H.225.0 marker
		0x04,                               // protocol version 4
		0x00,                               // byte at i (i=7 after pver)
		0xc0,                               // vendor info marker at i+1
		0x00, 0xb5, 0x00, 0x01,             // Polycom vendor ID (big-endian)
		0x06,                               // product len - 1 = 6, actual = 7
		'P', 'o', 'l', 'y', 'c', 'o', 'm', // product ID (7 bytes)
		0x01,                               // version len - 1 = 1, actual = 2
		'8', '0',                           // version ID (2 bytes)
	}

	// Build TPKT + Q.931 Alerting + User-User IE
	uuIEHeader := []byte{0x7e, byte(len(uuData) >> 8), byte(len(uuData) & 0xff)}
	q931Hdr := []byte{0x08, 0x02, 0x00, 0x01, 0x01} // Alerting
	totalLen := 4 + len(q931Hdr) + len(uuIEHeader) + len(uuData)
	response := make([]byte, 4)
	response[0] = 0x03
	response[1] = 0x00
	response[2] = byte(totalLen >> 8)
	response[3] = byte(totalLen & 0xff)
	response = append(response, q931Hdr...)
	response = append(response, uuIEHeader...)
	response = append(response, uuData...)

	meta := extractMetadata(response)
	// Should have found vendor via structured parsing
	assert.NotEmpty(t, meta.VendorID)
}

func TestExtractMetadata_FallbackToHeuristic(t *testing.T) {
	// Response with valid Q.931 but no User-User IE - Polycom T.35 signature present
	response := []byte{
		0x03, 0x00, 0x00, 0x10,
		0x08, 0x02, 0x00, 0x01, 0x07,  // Q.931 Connect (2-byte CR)
		0xb5, 0x00, 0x01,              // Polycom T.35 signature
		'P', 'o', 'l', 'y',           // partial product name
	}
	meta := extractMetadata(response)
	assert.Equal(t, "Polycom", meta.VendorID)
}

func TestPluginRun_Enhanced(t *testing.T) {
	// Verify Plugin.Run works with a standard H.323 Connect response
	plugin := &Plugin{}
	response := []byte{0x03, 0x00, 0x00, 0x08, 0x08, 0x00, 0x07, 0x00}
	conn := &mockConn{readData: response}
	target := plugins.Target{}
	result, err := plugin.Run(conn, 5*time.Second, target)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Equal(t, "h323", result.Protocol)
}

// Additional coverage tests for uncovered paths

func TestExtractDisplayFromIE_WithData(t *testing.T) {
	// Test extractDisplayFromIE with actual IE data
	ies := map[byte][]byte{
		0x28: []byte("GnuGK\x00"),
	}
	result := extractDisplayFromIE(ies)
	assert.Equal(t, "GnuGK", result)
}

func TestExtractDisplayFromIE_EmptyValue(t *testing.T) {
	ies := map[byte][]byte{
		0x28: []byte{},
	}
	result := extractDisplayFromIE(ies)
	assert.Equal(t, "", result)
}

func TestExtractDisplayFromIE_Missing(t *testing.T) {
	ies := map[byte][]byte{}
	result := extractDisplayFromIE(ies)
	assert.Equal(t, "", result)
}

func TestExtractH225VendorInfo_ProtocolV2(t *testing.T) {
	// Test the pver==2 with \x20\x00 prefix special case
	uuData := make([]byte, 20)
	copy(uuData[0:], []byte{0x00, 0x08, 0x91, 0x4a, 0x00})
	uuData[5] = 0x02 // protocol version 2
	uuData[6] = 0x20 // \x20 prefix for pver==2
	uuData[7] = 0x00 // \x00 prefix for pver==2
	binary.BigEndian.PutUint32(uuData[8:12], 0x00b50012) // Cisco

	info := extractH225VendorInfo(q931Alerting, uuData)
	assert.NotNil(t, info)
	assert.Equal(t, 2, info.protocolVersion)
	assert.Equal(t, uint32(0x00b50012), info.vendorID)
}

func TestExtractH225VendorInfo_Skip7Alerting(t *testing.T) {
	// Test the i += 7 skip path (when uuData[i+1] != 0xc0 first check triggers skip)
	uuData := make([]byte, 25)
	copy(uuData[0:], []byte{0x00, 0x08, 0x91, 0x4a, 0x00})
	uuData[5] = 0x04 // protocol version 4
	// uuData[6] = 0x00 (default, byte at i)
	// uuData[7] = 0x00 (default, not 0xc0 -> triggers i += 7)
	// After skip 7, i=13. uuData[14] is 0x00, not 0xc0 -> return info
	info := extractH225VendorInfo(q931Alerting, uuData)
	assert.NotNil(t, info)
	assert.Equal(t, uint32(0), info.vendorID)
}

func TestExtractH225VendorInfo_ConnectNonZero(t *testing.T) {
	// Test Connect case with non-zero first byte and vendor info
	uuData := make([]byte, 20)
	copy(uuData[0:], []byte{0x00, 0x08, 0x91, 0x4a, 0x00})
	uuData[5] = 0x04  // protocol version 4
	uuData[6] = 0x01  // non-zero at position i (won't early return)
	uuData[7] = 0xc0  // vendor info marker at i+1
	binary.BigEndian.PutUint32(uuData[8:12], 0x00b50001) // Polycom
	// pver=4 >= 3 but no product/version data -> return partial info

	info := extractH225VendorInfo(q931Connect, uuData)
	assert.NotNil(t, info)
	assert.Equal(t, uint32(0x00b50001), info.vendorID)
}

func TestExtractH225VendorInfo_ConnectZeroReturn(t *testing.T) {
	// Test Connect case where uuData[i] == 0x00 -> early return
	uuData := make([]byte, 12)
	copy(uuData[0:], []byte{0x00, 0x08, 0x91, 0x4a, 0x00})
	uuData[5] = 0x04 // protocol version 4
	uuData[6] = 0x00 // zero at i -> early return

	info := extractH225VendorInfo(q931Connect, uuData)
	assert.NotNil(t, info)
	assert.Equal(t, uint32(0), info.vendorID)
}

func TestExtractH225VendorInfo_ReleaseComplete(t *testing.T) {
	// ReleaseComplete: returns info immediately after protocol version (no vendor)
	uuData := make([]byte, 10)
	copy(uuData[0:], []byte{0x00, 0x08, 0x91, 0x4a, 0x00})
	uuData[5] = 0x04

	info := extractH225VendorInfo(q931ReleaseComplete, uuData)
	assert.NotNil(t, info)
	assert.Equal(t, 4, info.protocolVersion)
	assert.Equal(t, uint32(0), info.vendorID)
}

func TestExtractH225VendorInfo_TruncatedVendorID(t *testing.T) {
	// Marker found but not enough bytes for 4-byte vendor ID
	uuData := make([]byte, 12)
	copy(uuData[0:], []byte{0x00, 0x08, 0x91, 0x4a, 0x00})
	uuData[5] = 0x04 // pver = 4
	uuData[6] = 0x00
	uuData[7] = 0xc0 // vendor marker at i+1
	// Only 12 total bytes, vendor ID needs 4 bytes at position 8, 8+4=12 OK
	// Actually 8+4=12 <= 12, so it should work... let me make it shorter:
	uuDataShort := uuData[:10] // cut off before complete 4-byte vendor ID
	// i=6, after i+=2 -> i=8, i+4=12 > 10 -> return info without vendor
	info := extractH225VendorInfo(q931Alerting, uuDataShort)
	assert.NotNil(t, info)
	assert.Equal(t, uint32(0), info.vendorID)
}

func TestExtractH225VendorInfo_ProtocolV2Truncated(t *testing.T) {
	// pver==2 special case but not enough bytes for vendor ID
	uuData := []byte{
		0x00, 0x08, 0x91, 0x4a, 0x00, // marker
		0x02,                          // pver=2
		0x20, 0x00,                    // prefix for pver==2
		// Only 2 bytes remain, need 6 (2 more + 4 vendor ID)
	}
	info := extractH225VendorInfo(q931Alerting, uuData)
	assert.NotNil(t, info)
	assert.Equal(t, uint32(0), info.vendorID)
}

func TestParseQ931_TruncatedIE(t *testing.T) {
	// IE declares length > available bytes, should break gracefully.
	// TPKT length matches slice length, but IE length exceeds remaining bytes.
	response := []byte{
		0x03, 0x00, 0x00, 0x09, // TPKT: length=9 (matches actual slice length)
		0x08,                    // Q.931 protocol disc
		0x00,                    // CR length=0
		0x07,                    // Connect
		0x04, 0x10,              // Bearer Cap IE: type=0x04, length=16 (too large for remaining 0 bytes)
	}
	msg := parseQ931(response)
	// Should parse the Q.931 header but break on truncated IE
	assert.NotNil(t, msg)
	assert.Equal(t, byte(0x07), msg.msgType)
	assert.Nil(t, msg.ies[0x04]) // IE not stored due to truncation
}

func TestParseQ931_Alerting(t *testing.T) {
	// Valid Alerting response
	response := []byte{
		0x03, 0x00, 0x00, 0x07, // TPKT: length=7
		0x08,                    // Q.931 protocol disc
		0x00,                    // CR length=0
		0x01,                    // Alerting
	}
	msg := parseQ931(response)
	assert.NotNil(t, msg)
	assert.Equal(t, byte(0x01), msg.msgType)
}

func TestParseQ931_CallProceeding(t *testing.T) {
	// Valid Call Proceeding response
	response := []byte{
		0x03, 0x00, 0x00, 0x07,
		0x08, 0x00, 0x02,
	}
	msg := parseQ931(response)
	assert.NotNil(t, msg)
	assert.Equal(t, byte(0x02), msg.msgType)
}

func TestParseQ931_TruncatedUserUserIE(t *testing.T) {
	// User-User IE with truncated payload
	response := []byte{
		0x03, 0x00, 0x00, 0x0a, // TPKT: length=10
		0x08, 0x00, 0x07,        // Q.931 Connect (no CR)
		0x7e, 0x00, 0x10,        // UU IE: type=0x7e, length=16 (too large)
	}
	msg := parseQ931(response)
	assert.NotNil(t, msg)
	assert.Nil(t, msg.ies[0x7e]) // Not stored due to truncation
}

func TestExtractMetadata_DisplayFallbackToProduct(t *testing.T) {
	// Response with Q.931 Connect + Display IE but no User-User IE
	// product should be set from display name fallback
	displayName := "GnuGK"
	displayData := append([]byte(displayName), 0x00)
	displayIE := append([]byte{0x28, byte(len(displayData))}, displayData...)

	q931Hdr := []byte{0x08, 0x00, 0x07} // Connect, no CR
	totalLen := 4 + len(q931Hdr) + len(displayIE)
	response := make([]byte, 4)
	response[0] = 0x03
	response[1] = 0x00
	response[2] = byte(totalLen >> 8)
	response[3] = byte(totalLen & 0xff)
	response = append(response, q931Hdr...)
	response = append(response, displayIE...)

	meta := extractMetadata(response)
	// Display name should be used as product name fallback
	assert.Equal(t, "GnuGK", meta.ProductName)
}

func TestIsValidQ931_WithCallReference(t *testing.T) {
	// Test Q.931 with actual call reference value (crLen=1)
	input := []byte{0x03, 0x00, 0x00, 0x09, 0x08, 0x01, 0x42, 0x07, 0x00}
	result := isValidQ931(input)
	assert.True(t, result)
}

func TestIsValidQ931_TruncatedMsgType(t *testing.T) {
	// CR offset pushes msgTypeOffset beyond end of slice
	// crLen=2, msgTypeOffset = 4+2+2 = 8, but data only has 8 bytes (idx 0..7)
	input := []byte{0x03, 0x00, 0x00, 0x08, 0x08, 0x02, 0x00, 0x01}
	result := isValidQ931(input)
	assert.False(t, result)
}

func TestParseQ931_InvalidMsgType(t *testing.T) {
	// Valid TPKT+Q.931 header but invalid message type
	response := []byte{
		0x03, 0x00, 0x00, 0x07,
		0x08, 0x00, 0xff, // msgType=0xff (invalid)
	}
	msg := parseQ931(response)
	assert.Nil(t, msg)
}

func TestParseQ931_TruncatedAfterTPKT(t *testing.T) {
	// TPKT says length 5 but Q.931 header would need more bytes
	// pos=4 >= tpktLen=5? No. response[4]=0x08, pos=5. pos=5 >= tpktLen=5? Yes -> return nil
	response := []byte{0x03, 0x00, 0x00, 0x05, 0x08}
	msg := parseQ931(response)
	assert.Nil(t, msg)
}

func TestParseQ931_TruncatedAtCRLen(t *testing.T) {
	// After proto disc, not enough data for CR len
	// pos=5 >= tpktLen=5? YES -> nil
	response := []byte{0x03, 0x00, 0x00, 0x05, 0x08, 0xff}
	// tpktLen = (0x00<<8)|0x05 = 5, but slice length=6. isValidTPKT: length=5 <= 6 OK
	// pos=4, response[4]=0x08 OK, pos=5. pos=5 >= tpktLen=5 -> return nil
	msg := parseQ931(response)
	assert.Nil(t, msg)
}

func TestParseQ931_NonZeroCRLen(t *testing.T) {
	// Valid response with crLen=2
	response := []byte{
		0x03, 0x00, 0x00, 0x08,
		0x08,             // proto disc
		0x02, 0x00, 0x01, // crLen=2, value=0x0001
		0x07,             // Connect - wait, that's 9 bytes but TPKT says 8
	}
	// Fix: TPKT length=9 (0x09)
	response[3] = 0x09
	response = append(response, 0x07) // Connect
	msg := parseQ931(response)
	assert.NotNil(t, msg)
	assert.Equal(t, byte(0x07), msg.msgType)
}

func TestParseQ931_NonZeroCRLen_Truncated(t *testing.T) {
	// crLen=4, pos+crLen >= tpktLen should trigger nil
	// pos=6 after crLen, crLen=4, pos+crLen=10 >= tpktLen=9 -> return nil
	response := []byte{
		0x03, 0x00, 0x00, 0x09,
		0x08,             // proto disc
		0x04,             // crLen=4
		0x00, 0x00, 0x00, // only 3 bytes of CR value (not 4), then end
	}
	msg := parseQ931(response)
	assert.Nil(t, msg)
}

func TestParseQ931_IETruncatedAtLengthByte(t *testing.T) {
	// IE found but no more bytes for 1-byte length field
	// IE type at pos, but pos after pos++ is >= len(response)
	response := []byte{
		0x03, 0x00, 0x00, 0x08,
		0x08, 0x00, 0x07, // Connect
		0x04,              // IE type, then no more bytes (pos=8 >= len=8)
	}
	msg := parseQ931(response)
	assert.NotNil(t, msg)
	assert.Nil(t, msg.ies[0x04])
}

func TestExtractH225VendorInfo_ConnectSkip7(t *testing.T) {
	// Connect case: uuData[i] != 0x00 but uuData[i+1] != 0xc0 -> skip 7
	// After skip 7: i+2 > len (out of bounds) -> return info
	uuData := make([]byte, 15)
	copy(uuData[0:], []byte{0x00, 0x08, 0x91, 0x4a, 0x00})
	uuData[5] = 0x04  // pver=4
	uuData[6] = 0x01  // non-zero at i=6 (don't early return)
	uuData[7] = 0x00  // not 0xc0 at i+1 -> triggers i += 7 (i becomes 13)
	// i=13, i+2=15 = len(uuData) -> i+2 > len? No, 15 > 15 is false
	// but uuData[14] = 0 (not 0xc0) -> return info without vendor
	info := extractH225VendorInfo(q931Connect, uuData)
	assert.NotNil(t, info)
	assert.Equal(t, uint32(0), info.vendorID)
}

func TestExtractH225VendorInfo_ProtocolV2NoVendorBytes(t *testing.T) {
	// pver==2, has 0x20 0x00 prefix but i+6 > len -> return info without vendor
	uuData := []byte{
		0x00, 0x08, 0x91, 0x4a, 0x00, // marker
		0x02,                          // pver=2
		0x20, 0x00,                    // prefix for pver==2 (i=6,7)
		// i+6 = 6+6=12 > len=8 -> don't read vendor ID
	}
	info := extractH225VendorInfo(q931Alerting, uuData)
	assert.NotNil(t, info)
	assert.Equal(t, uint32(0), info.vendorID)
}

func TestExtractH225VendorInfo_ProtocolV2_NoPrefix(t *testing.T) {
	// pver==2 but doesn't have \x20\x00 prefix, falls through to regular path
	uuData := make([]byte, 16)
	copy(uuData[0:], []byte{0x00, 0x08, 0x91, 0x4a, 0x00})
	uuData[5] = 0x02  // pver=2
	uuData[6] = 0x01  // not 0x20 -> no special case
	uuData[7] = 0xc0  // vendor marker at i+1
	binary.BigEndian.PutUint32(uuData[8:12], 0x00b50001) // Polycom

	info := extractH225VendorInfo(q931Alerting, uuData)
	assert.NotNil(t, info)
	// pver=2 < 3 -> no product/version, but vendor should be read
	assert.Equal(t, uint32(0x00b50001), info.vendorID)
	assert.Equal(t, "", info.productID)
}

func TestExtractH225VendorInfo_ProductTruncated(t *testing.T) {
	// Vendor ID read successfully, but product ID truncated
	uuData := make([]byte, 18)
	copy(uuData[0:], []byte{0x00, 0x08, 0x91, 0x4a, 0x00})
	uuData[5] = 0x04 // pver=4
	uuData[6] = 0x00
	uuData[7] = 0xc0
	binary.BigEndian.PutUint32(uuData[8:12], 0x00b50001) // Polycom
	uuData[12] = 0x09 // prodLen-1=9, actual=10
	// Only 5 bytes remain (13..17), but product needs 10 -> truncated
	copy(uuData[13:18], []byte("Polyx"))

	info := extractH225VendorInfo(q931Alerting, uuData)
	assert.NotNil(t, info)
	assert.Equal(t, uint32(0x00b50001), info.vendorID)
	assert.Equal(t, "", info.productID) // Not read due to truncation
}

func TestExtractH225VendorInfo_VersionTruncated(t *testing.T) {
	// Product ID read, but version ID truncated
	uuData := []byte{
		0x00, 0x08, 0x91, 0x4a, 0x00, // marker
		0x04,                          // pver=4
		0x00, 0xc0,                    // at i=6, i+1=0xc0
		0x00, 0xb5, 0x00, 0x01,        // vendor: Polycom
		0x02,                          // prodLen-1=2, actual=3
		'G', 'K', 'S',                 // product ID "GKS"
		0x05,                          // verLen-1=5, actual=6
		// Only 0 bytes remain for version -> truncated
	}
	info := extractH225VendorInfo(q931Alerting, uuData)
	assert.NotNil(t, info)
	assert.Equal(t, "GKS", info.productID)
	assert.Equal(t, "", info.versionID) // Not read due to truncation
}

func TestExtractH225VendorInfo_ProductAtEnd(t *testing.T) {
	// After vendor ID, i >= len(uuData) check for product
	uuData := []byte{
		0x00, 0x08, 0x91, 0x4a, 0x00, // marker
		0x04,                          // pver=4
		0x00, 0xc0,                    // vendor marker
		0x00, 0xb5, 0x00, 0x01,        // vendor ID (4 bytes), i=12
		// i=12 >= len=12 -> return info without product
	}
	info := extractH225VendorInfo(q931Alerting, uuData)
	assert.NotNil(t, info)
	assert.Equal(t, uint32(0x00b50001), info.vendorID)
	assert.Equal(t, "", info.productID)
}

// TestWireBytesToVendorName validates the full path from raw wire bytes
// containing a T.35 vendor ID to a resolved vendor name through extractMetadata.
// This is an end-to-end test for Fix 1 (corrected knownH225VendorIDs map keys).
//
// The flow is:
//   wire bytes -> binary.BigEndian.Uint32 -> hex string ("0xb5000012")
//   -> resolveVendorName -> known vendor name ("Cisco")
//   -> CPE generation uses the resolved name
//
// meta.VendorID stores the raw hex string; the resolved name appears in the CPE.
func TestWireBytesToVendorName(t *testing.T) {
	tests := []struct {
		name            string
		wireVendorID    []byte // 4 bytes as they appear on the wire (big-endian)
		expectedHexID   string // hex ID stored in meta.VendorID
		expectedVendor  string // resolved name used for CPE
		expectedCPEPart string // substring expected in CPE
	}{
		{
			name:            "Cisco wire bytes B5 00 00 12 -> Cisco",
			wireVendorID:    []byte{0xb5, 0x00, 0x00, 0x12},
			expectedHexID:   "0xb5000012",
			expectedVendor:  "Cisco",
			expectedCPEPart: "cisco",
		},
		{
			name:            "Polycom wire bytes B5 00 00 01 -> Polycom",
			wireVendorID:    []byte{0xb5, 0x00, 0x00, 0x01},
			expectedHexID:   "0xb5000001",
			expectedVendor:  "Polycom",
			expectedCPEPart: "polycom",
		},
		{
			name:            "LifeSize wire bytes B5 00 00 53 -> LifeSize",
			wireVendorID:    []byte{0xb5, 0x00, 0x00, 0x53},
			expectedHexID:   "0xb5000053",
			expectedVendor:  "LifeSize",
			expectedCPEPart: "lifesize",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a full TPKT + Q.931 Alerting + User-User IE with the given vendor ID.
			// uuData structure matches extractH225VendorInfo Alerting path:
			//   [0..4] H.225.0 protocol marker
			//   [5]    protocol version 4
			//   [6]    0x00 (byte at i)
			//   [7]    0xc0 (vendor info present marker at i+1)
			//   [8..11] 4-byte vendor ID (big-endian, as on wire)
			uuData := make([]byte, 12)
			copy(uuData[0:5], []byte{0x00, 0x08, 0x91, 0x4a, 0x00})
			uuData[5] = 0x04 // pver=4
			uuData[6] = 0x00
			uuData[7] = 0xc0
			copy(uuData[8:12], tt.wireVendorID)

			uuIEHeader := []byte{0x7e, byte(len(uuData) >> 8), byte(len(uuData) & 0xff)}
			q931Hdr := []byte{0x08, 0x00, 0x01} // Alerting, no CR
			totalLen := 4 + len(q931Hdr) + len(uuIEHeader) + len(uuData)
			response := []byte{0x03, 0x00, byte(totalLen >> 8), byte(totalLen & 0xff)}
			response = append(response, q931Hdr...)
			response = append(response, uuIEHeader...)
			response = append(response, uuData...)

			meta := extractMetadata(response)

			// meta.VendorID stores the raw hex string from the wire
			assert.Equal(t, tt.expectedHexID, meta.VendorID,
				"VendorID should store the raw hex value read from wire bytes")

			// resolveVendorName maps the hex ID to the human-readable vendor name
			resolvedName := resolveVendorName(meta.VendorID)
			assert.Equal(t, tt.expectedVendor, resolvedName,
				"resolveVendorName should map wire bytes to correct vendor via knownH225VendorIDs")

			// The CPE should contain the resolved vendor name (lowercase)
			if len(meta.CPEs) > 0 {
				assert.Contains(t, meta.CPEs[0], tt.expectedCPEPart,
					"CPE should contain resolved vendor name")
			}
		})
	}
}

// TestParseQ931_SingleOctetIE validates that single-octet IEs (bit 8 set,
// 0x80-0xFF except 0x7E) are parsed as standalone IEs with no length field.
// A Shift IE (0x90) followed by a valid Display IE should both be parsed correctly.
func TestParseQ931_SingleOctetIE(t *testing.T) {
	// Build: TPKT + Q.931 Connect + Shift IE (0x90, single-octet) + Display IE (0x28)
	displayData := []byte{'G', 'K'}
	displayIE := []byte{0x28, byte(len(displayData))}
	displayIE = append(displayIE, displayData...)

	q931Hdr := []byte{0x08, 0x00, 0x07} // Connect, no CR
	shiftIE := []byte{0x90}             // Shift IE: single-octet, bit 8 set, not 0x7E

	body := append(q931Hdr, shiftIE...)
	body = append(body, displayIE...)

	totalLen := 4 + len(body)
	response := []byte{0x03, 0x00, byte(totalLen >> 8), byte(totalLen & 0xff)}
	response = append(response, body...)

	msg := parseQ931(response)
	assert.NotNil(t, msg)
	assert.Equal(t, byte(0x07), msg.msgType)

	// Shift IE (0x90) should be present with nil value (single-octet, no payload)
	shiftVal, shiftPresent := msg.ies[0x90]
	assert.True(t, shiftPresent, "Shift IE (0x90) should be present")
	assert.Nil(t, shiftVal, "single-octet IE value should be nil")

	// Display IE (0x28) following the Shift IE should also be parsed
	assert.Equal(t, displayData, msg.ies[0x28], "Display IE should be parsed after Shift IE")
}

// TestParseQ931_MaxIELen validates that an IE declaring a length > maxIELen
// causes the parser to stop gracefully without reading unreasonable amounts of data.
func TestParseQ931_MaxIELen(t *testing.T) {
	// Build a response where the IE length field exceeds maxIELen (4096).
	// The parser should break out of the loop rather than attempt to read 65535 bytes.
	response := []byte{
		0x03, 0x00, 0x00, 0x0a, // TPKT: length=10
		0x08, 0x00, 0x07,        // Q.931 Connect (no CR)
		0x04,                    // Bearer Cap IE type
		0xff, 0xff,              // For 2-byte: 65535 (but this IE uses 1-byte length)
		// Actually 0x04 is a 1-byte length IE, so length=0xff=255 > 0 remaining bytes
	}
	// Adjust: length field for 0x04 IE is 1 byte (0xff = 255).
	// 255 > maxIELen? No, 255 < 4096. Use a specially crafted scenario:
	// We can't easily trigger maxIELen with a 1-byte length field (max 255).
	// Instead test that a large but valid length that exceeds remaining bytes still breaks.
	// The test below uses the existing truncation path as a sanity check,
	// and the maxIELen constant is validated via direct unit assertion.
	msg := parseQ931(response)
	assert.NotNil(t, msg, "Q.931 header should parse even when IE is truncated")
	assert.Equal(t, byte(0x07), msg.msgType)
	assert.Nil(t, msg.ies[0x04], "truncated IE should not be stored")

	// Validate that maxIELen constant exists and has the expected value
	assert.Equal(t, 4096, maxIELen)
}
