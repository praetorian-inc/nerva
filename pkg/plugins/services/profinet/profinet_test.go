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

package profinet

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPROFINETName tests plugin name
func TestPROFINETName(t *testing.T) {
	t.Parallel()

	p := &PROFINETPlugin{}
	assert.Equal(t, "profinet", p.Name())
}

// TestPROFINETType tests plugin type
func TestPROFINETType(t *testing.T) {
	t.Parallel()

	p := &PROFINETPlugin{}
	assert.Equal(t, plugins.TCP, p.Type())
}

// TestPROFINETPriority tests plugin priority
func TestPROFINETPriority(t *testing.T) {
	t.Parallel()

	p := &PROFINETPlugin{}
	assert.Equal(t, 400, p.Priority(), "ICS protocol priority should be 400")
}

// TestPROFINETPortPriority tests port priority logic
func TestPROFINETPortPriority(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{
			name:     "port 34962 (RT_UNICAST) returns true",
			port:     34962,
			expected: true,
		},
		{
			name:     "port 34963 (RT_MULTICAST) returns true",
			port:     34963,
			expected: true,
		},
		{
			name:     "port 34964 (CONTEXT_MGR) returns true",
			port:     34964,
			expected: true,
		},
		{
			name:     "port 80 returns false",
			port:     80,
			expected: false,
		},
		{
			name:     "port 443 returns false",
			port:     443,
			expected: false,
		},
		{
			name:     "port 34961 returns false",
			port:     34961,
			expected: false,
		},
		{
			name:     "port 34965 returns false",
			port:     34965,
			expected: false,
		},
	}

	p := &PROFINETPlugin{}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := p.PortPriority(tc.port)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// TestExtractAnnotation tests annotation extraction
func TestExtractAnnotation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		response []byte
		expected string
	}{
		{
			name: "valid annotation with Siemens device",
			response: func() []byte {
				// Create a valid PROFINET response (>200 bytes) with annotation
				response := make([]byte, 300)
				// Fill first 169 bytes with dummy data
				for i := 0; i < 169; i++ {
					response[i] = 0x00
				}
				// Set annotation length at offset 169 (4 bytes, little-endian)
				annotationText := "Siemens SCALANCE X308-2"
				annotationLen := uint32(len(annotationText))
				binary.LittleEndian.PutUint32(response[169:173], annotationLen)
				// Copy annotation text starting at byte 173
				copy(response[173:], []byte(annotationText))
				return response
			}(),
			expected: "Siemens SCALANCE X308-2",
		},
		{
			name:     "response too short (< 173 bytes)",
			response: make([]byte, 150),
			expected: "",
		},
		{
			name: "annotation length is zero",
			response: func() []byte {
				response := make([]byte, 200)
				// Set annotation length to 0 at offset 169
				binary.LittleEndian.PutUint32(response[169:173], 0)
				return response
			}(),
			expected: "",
		},
		{
			name: "annotation length exceeds limit (> 1024)",
			response: func() []byte {
				response := make([]byte, 200)
				// Set annotation length to 2000 (exceeds 1024 limit)
				binary.LittleEndian.PutUint32(response[169:173], 2000)
				return response
			}(),
			expected: "",
		},
		{
			name: "annotation length exceeds buffer bounds (uint32 overflow protection)",
			response: func() []byte {
				response := make([]byte, 200)
				// Remaining buffer after offset 173 is only 27 bytes (200-173)
				// Set annotation length to 1000 which exceeds remaining buffer
				// This tests protection against uint32→int overflow on 32-bit systems
				binary.LittleEndian.PutUint32(response[169:173], 1000)
				copy(response[173:], []byte("Short"))
				return response
			}(),
			expected: "",
		},
		{
			name: "annotation length exceeds response size",
			response: func() []byte {
				response := make([]byte, 200)
				// Set annotation length to 100 but response only has 27 bytes after offset 173
				// With bounds validation fix, this is now rejected to prevent overflow
				binary.LittleEndian.PutUint32(response[169:173], 100)
				copy(response[173:], []byte("Short text"))
				return response
			}(),
			expected: "", // Changed from "Short text" - now properly rejects invalid lengths
		},
		{
			name: "annotation with null terminator",
			response: func() []byte {
				response := make([]byte, 250)
				// Set annotation with null terminator in the middle
				annotationText := "Siemens\x00Extra"
				annotationLen := uint32(len(annotationText))
				binary.LittleEndian.PutUint32(response[169:173], annotationLen)
				copy(response[173:], []byte(annotationText))
				return response
			}(),
			expected: "Siemens",
		},
		{
			name: "annotation with non-printable characters",
			response: func() []byte {
				response := make([]byte, 250)
				// Include non-printable characters (ASCII < 32 or >= 127)
				annotationText := "Siemens\x01\x02\x03Device\x7F\x80"
				annotationLen := uint32(len(annotationText))
				binary.LittleEndian.PutUint32(response[169:173], annotationLen)
				copy(response[173:], []byte(annotationText))
				return response
			}(),
			expected: "SiemensDevice",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := extractAnnotation(tc.response)
			assert.Equal(t, tc.expected, got)
		})
	}
}

// TestParseAnnotation tests vendor and device extraction
func TestParseAnnotation(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		annotation     string
		expectName     string
		expectType     string
		expectVendor   string
	}{
		{
			name:           "Siemens SCALANCE detection",
			annotation:     "Siemens SCALANCE X308-2",
			expectName:     "Siemens",
			expectType:     "SCALANCE X308", // Regex \w+ stops at hyphen
			expectVendor:   "siemens",
		},
		{
			name:           "Siemens ET200 detection",
			annotation:     "ET 200SP IM155-6PN",
			expectName:     "ET",
			expectType:     "ET 200SP",
			expectVendor:   "", // No "siemens" in annotation text
		},
		{
			name:           "Siemens S7 detection",
			annotation:     "Siemens S7-1500",
			expectName:     "Siemens",
			expectType:     "S7-1500",
			expectVendor:   "siemens",
		},
		{
			name:           "Siemens SIMATIC detection",
			annotation:     "SIMATIC HMI Panel",
			expectName:     "SIMATIC",
			expectType:     "SIMATIC HMI",
			expectVendor:   "", // No "siemens" in annotation text
		},
		{
			name:           "Bosch detection",
			annotation:     "Bosch Rexroth IndraControl L40",
			expectName:     "Bosch",
			expectType:     "IndraControl L40",
			expectVendor:   "bosch",
		},
		{
			name:           "Bosch Rexroth detection",
			annotation:     "Rexroth IndraMotion MLC",
			expectName:     "Rexroth",
			expectType:     "IndraMotion MLC",
			expectVendor:   "bosch",
		},
		{
			name:           "Phoenix Contact detection",
			annotation:     "Phoenix Contact AXC F 2152",
			expectName:     "Phoenix",
			expectType:     "AXC F 2152",
			expectVendor:   "phoenix_contact",
		},
		{
			name:           "Beckhoff detection",
			annotation:     "Beckhoff CX5020",
			expectName:     "Beckhoff",
			expectType:     "",
			expectVendor:   "beckhoff",
		},
		{
			name:           "Hilscher detection",
			annotation:     "Hilscher netX Gateway",
			expectName:     "Hilscher",
			expectType:     "",
			expectVendor:   "hilscher",
		},
		{
			name:           "unknown vendor",
			annotation:     "Generic PROFINET Device",
			expectName:     "Generic",
			expectType:     "",
			expectVendor:   "",
		},
		{
			name:           "empty annotation",
			annotation:     "",
			expectName:     "",
			expectType:     "",
			expectVendor:   "",
		},
		{
			name:           "case insensitive vendor detection",
			annotation:     "siemens scalance X308",
			expectName:     "siemens",
			expectType:     "scalance X308",
			expectVendor:   "siemens",
		},
		{
			name:           "long annotation truncates device name",
			annotation:     "Very Long Device Name That Exceeds The Typical Length For Device Names And Should Be Handled Properly Without The First Word Being Used As The Device Name",
			expectName:     "Very", // Takes first word (up to first space within 50 chars)
			expectType:     "",
			expectVendor:   "",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			deviceName, deviceType, vendor := parseAnnotation(tc.annotation)
			assert.Equal(t, tc.expectName, deviceName, "device name mismatch")
			assert.Equal(t, tc.expectType, deviceType, "device type mismatch")
			assert.Equal(t, tc.expectVendor, vendor, "vendor mismatch")
		})
	}
}

// TestPROFINETValidResponse tests detection with valid DCE/RPC EPM response
func TestPROFINETValidResponse(t *testing.T) {
	t.Parallel()

	p := &PROFINETPlugin{}

	// Create pipe for mock connection
	server, client := net.Pipe()

	// Prepare valid PROFINET response (>200 bytes) with annotation
	response := make([]byte, 300)
	// Fill with valid DCE/RPC response structure
	for i := 0; i < 169; i++ {
		response[i] = 0x00
	}
	// Add annotation at offset 169
	annotationText := "Siemens SCALANCE X308-2"
	annotationLen := uint32(len(annotationText))
	binary.LittleEndian.PutUint32(response[169:173], annotationLen)
	copy(response[173:], []byte(annotationText))

	// Write response in background
	go func() {
		// Read probe first (discard it)
		buf := make([]byte, 256)
		_, err := server.Read(buf)
		if err != nil {
			return
		}
		// Send response
		_, _ = server.Write(response)
		server.Close()
	}()

	addr := netip.MustParseAddrPort("127.0.0.1:34962")
	target := plugins.Target{Host: "127.0.0.1", Address: addr}
	result, err := p.Run(client, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, result)

	// Check metadata
	meta := result.Metadata()
	profinetMeta, ok := meta.(plugins.ServicePROFINET)
	require.True(t, ok, "metadata should be ServicePROFINET type")
	assert.Equal(t, "Siemens", profinetMeta.DeviceName)
	assert.Equal(t, "SCALANCE X308", profinetMeta.DeviceType) // Regex \w+ stops at hyphen
	assert.Equal(t, "siemens", profinetMeta.Vendor)
	assert.NotEmpty(t, profinetMeta.CPEs)
}

// TestPROFINETShortResponse tests rejection of too-short responses
func TestPROFINETShortResponse(t *testing.T) {
	t.Parallel()

	p := &PROFINETPlugin{}

	// Create pipe for mock connection
	server, client := net.Pipe()

	// Prepare short response (< 200 bytes)
	response := make([]byte, 150)

	// Write response in background
	go func() {
		// Read probe first (discard it)
		buf := make([]byte, 256)
		_, err := server.Read(buf)
		if err != nil {
			return
		}
		// Send short response
		_, _ = server.Write(response)
		server.Close()
	}()

	addr := netip.MustParseAddrPort("127.0.0.1:34962")
	target := plugins.Target{Host: "127.0.0.1", Address: addr}
	result, err := p.Run(client, 5*time.Second, target)

	// Should return nil service (response too short)
	if err != nil {
		return // error is acceptable
	}
	require.Nil(t, result, "short response should not detect PROFINET")
}

// TestPROFINETNoAnnotation tests response without annotation
func TestPROFINETNoAnnotation(t *testing.T) {
	t.Parallel()

	p := &PROFINETPlugin{}

	// Create pipe for mock connection
	server, client := net.Pipe()

	// Prepare valid length response (>200 bytes) but no valid annotation
	response := make([]byte, 250)
	// Set annotation length to 0 at offset 169
	binary.LittleEndian.PutUint32(response[169:173], 0)

	// Write response in background
	go func() {
		// Read probe first (discard it)
		buf := make([]byte, 256)
		_, err := server.Read(buf)
		if err != nil {
			return
		}
		// Send response
		_, _ = server.Write(response)
		server.Close()
	}()

	addr := netip.MustParseAddrPort("127.0.0.1:34962")
	target := plugins.Target{Host: "127.0.0.1", Address: addr}
	result, err := p.Run(client, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, result, "valid DCE/RPC response should detect PROFINET even without annotation")

	// Check metadata (should be empty ServicePROFINET)
	meta := result.Metadata()
	profinetMeta, ok := meta.(plugins.ServicePROFINET)
	require.True(t, ok, "metadata should be ServicePROFINET type")
	assert.Empty(t, profinetMeta.DeviceName)
	assert.Empty(t, profinetMeta.DeviceType)
	assert.Empty(t, profinetMeta.Vendor)
	assert.Empty(t, profinetMeta.CPEs)
}

// TestPROFINETInvalidResponse tests invalid responses
func TestPROFINETInvalidResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		response []byte
	}{
		{
			name:     "empty response",
			response: []byte{},
		},
		{
			name:     "very short response",
			response: []byte{0x01, 0x02, 0x03},
		},
		{
			name:     "response at boundary (199 bytes)",
			response: make([]byte, 199),
		},
	}

	p := &PROFINETPlugin{}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			// Create pipe for mock connection
			server, client := net.Pipe()

			// Write response in background
			go func() {
				// Read probe first (discard it)
				buf := make([]byte, 256)
				_, err := server.Read(buf)
				if err != nil {
					return
				}
				// Send response
				if len(tc.response) > 0 {
					_, _ = server.Write(tc.response)
				}
				server.Close()
			}()

			addr := netip.MustParseAddrPort("127.0.0.1:34962")
			target := plugins.Target{Host: "127.0.0.1", Address: addr}
			result, err := p.Run(client, 5*time.Second, target)

			// Should either error or return nil
			if err != nil {
				return // error is acceptable
			}
			require.Nil(t, result, "invalid response should not detect PROFINET")
		})
	}
}

// TestGenerateCPEs tests CPE generation
func TestGenerateCPEs(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		vendor     string
		deviceType string
		expected   string
	}{
		{
			name:       "Siemens SCALANCE",
			vendor:     "siemens",
			deviceType: "SCALANCE X308-2",
			expected:   "cpe:2.3:h:siemens:scalance_x308_2:*:*:*:*:*:*:*:*",
		},
		{
			name:       "Bosch with device type",
			vendor:     "bosch",
			deviceType: "IndraControl L40",
			expected:   "cpe:2.3:h:bosch:indracontrol_l40:*:*:*:*:*:*:*:*",
		},
		{
			name:       "vendor only (no device type)",
			vendor:     "siemens",
			deviceType: "",
			expected:   "cpe:2.3:h:siemens:profinet:*:*:*:*:*:*:*:*",
		},
		{
			name:       "Phoenix Contact with spaces and underscores",
			vendor:     "phoenix_contact",
			deviceType: "AXC F 2152",
			expected:   "cpe:2.3:h:phoenix_contact:axc_f_2152:*:*:*:*:*:*:*:*",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			cpes := generateCPEs(tc.vendor, tc.deviceType)
			require.Len(t, cpes, 1, "should generate exactly one CPE")
			assert.Equal(t, tc.expected, cpes[0])
		})
	}
}

// TestCleanString tests string cleaning
func TestCleanString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "normal string",
			input:    "Siemens SCALANCE",
			expected: "Siemens SCALANCE",
		},
		{
			name:     "string with null terminator",
			input:    "Siemens\x00Extra",
			expected: "Siemens",
		},
		{
			name:     "string with non-printable chars",
			input:    "Device\x01\x02\x03Name",
			expected: "DeviceName",
		},
		{
			name:     "string with leading/trailing spaces",
			input:    "  Siemens  ",
			expected: "Siemens",
		},
		{
			name:     "empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "string with high ASCII",
			input:    "Device\x7F\x80\x90",
			expected: "Device",
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := cleanString(tc.input)
			assert.Equal(t, tc.expected, got)
		})
	}
}
