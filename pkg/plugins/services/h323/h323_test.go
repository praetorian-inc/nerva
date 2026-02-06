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
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
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

// Test containsBytes helper
func TestContainsBytes(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		pattern  []byte
		expected bool
	}{
		{
			name:     "Pattern found at start",
			data:     []byte{0xb5, 0x00, 0x01, 0xff},
			pattern:  []byte{0xb5, 0x00, 0x01},
			expected: true,
		},
		{
			name:     "Pattern found in middle",
			data:     []byte{0x00, 0xb5, 0x00, 0x01, 0xff},
			pattern:  []byte{0xb5, 0x00, 0x01},
			expected: true,
		},
		{
			name:     "Pattern not found",
			data:     []byte{0x00, 0xb5, 0x00, 0x02, 0xff},
			pattern:  []byte{0xb5, 0x00, 0x01},
			expected: false,
		},
		{
			name:     "Empty pattern",
			data:     []byte{0x00, 0xff},
			pattern:  []byte{},
			expected: false,
		},
		{
			name:     "Pattern longer than data",
			data:     []byte{0x00},
			pattern:  []byte{0x00, 0xff},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := containsBytes(tt.data, tt.pattern)
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
					metadata := result.Metadata().(plugins.ServiceH323)
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
