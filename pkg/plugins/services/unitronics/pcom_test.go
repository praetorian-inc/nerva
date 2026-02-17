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

package unitronics

import (
	"encoding/binary"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

// TestBuildPCOMIDRequest verifies the PCOM/TCP ASCII ID command request is correctly constructed
func TestBuildPCOMIDRequest(t *testing.T) {
	request, err := buildPCOMIDRequest()

	assert.NoError(t, err, "Should build request without error")

	// Verify total packet length is 14 bytes (6 header + 8 payload)
	assert.Equal(t, 14, len(request), "Total packet length should be 14 bytes")

	// Verify header mode byte is 0x65 (ASCII)
	assert.Equal(t, byte(ASCII_MODE), request[2], "Header mode byte should be 0x65 (ASCII)")

	// Verify header reserved byte is 0x00
	assert.Equal(t, byte(0x00), request[3], "Header reserved byte should be 0x00")

	// Verify payload length field is 8 (little-endian)
	payloadLength := binary.LittleEndian.Uint16(request[4:6])
	assert.Equal(t, uint16(8), payloadLength, "Payload length field should be 8 (little-endian)")

	// Verify ASCII payload starts with '/' (0x2F)
	assert.Equal(t, byte(STX_ASCII), request[6], "ASCII payload should start with '/' (0x2F)")

	// Verify unit ID is "00"
	unitID := string(request[7:9])
	assert.Equal(t, "00", unitID, "Unit ID should be '00'")

	// Verify command is "ID"
	command := string(request[9:11])
	assert.Equal(t, "ID", command, "Command should be 'ID'")

	// Verify checksum is "ED"
	checksum := string(request[11:13])
	assert.Equal(t, "ED", checksum, "Checksum should be 'ED'")

	// Verify ETX is '\r' (0x0D)
	assert.Equal(t, byte(ETX_ASCII), request[13], "ETX should be '\\r' (0x0D)")
}

// TestParsePCOMIDResponse_ValidResponse verifies parsing of a valid PCOM/TCP response
func TestParsePCOMIDResponse_ValidResponse(t *testing.T) {
	// Build a valid response for V130-33-T38 (model code "180701")
	// TCP header: [random_id, random_id, 0x65, 0x00, length_lo, length_hi]
	// ASCII payload (24 bytes): /A00ID + model(6) + hw(1) + major(3) + minor(3) + build(2) + checksum(2) + \r
	// Example: /A00ID1807012003028005F\r
	response := []byte{
		// 6-byte TCP header
		0x00, 0x01, // Transaction ID (random)
		0x65,       // Mode: ASCII (0x65)
		0x00,       // Reserved
		0x18, 0x00, // Payload length: 24 bytes (little-endian)

		// 24-byte ASCII payload
		0x2F,                   // STX: '/'
		0x41,                   // Response indicator: 'A'
		0x30, 0x30,             // Unit ID echo: "00"
		0x49, 0x44,             // Command echo: "ID"
		0x31, 0x38, 0x30, 0x37, 0x30, 0x31, // Model code: "180701"
		0x32, // HW version: "2"
		0x30, 0x30, 0x33, // OS major: "003"
		0x30, 0x32, 0x38, // OS minor: "028"
		0x30, 0x30, // OS build: "00"
		0x35, 0x46, // Checksum: "5F"
		0x0D, // ETX: '\r'
	}

	data, err := parsePCOMIDResponse(response)

	assert.NoError(t, err, "Should parse valid response without error")
	assert.Equal(t, "180701", data.Model, "Model should be '180701'")
	assert.Equal(t, "2", data.HWVersion, "HWVersion should be '2'")
	assert.Equal(t, "003.028.00", data.OSVersion, "OSVersion should be '003.028.00'")
	assert.Equal(t, "00", data.UnitID, "UnitID should be '00'")
}

// TestParsePCOMIDResponse_TooShort verifies error when response is shorter than minimum length
func TestParsePCOMIDResponse_TooShort(t *testing.T) {
	// Response shorter than MIN_RESPONSE_LENGTH (13 bytes)
	response := []byte{0x00, 0x01, 0x65, 0x00, 0x08, 0x00, 0x2F, 0x41, 0x30, 0x30, 0x49, 0x44}

	_, err := parsePCOMIDResponse(response)

	assert.Error(t, err, "Should error on response too short")
}

// TestParsePCOMIDResponse_WrongMode verifies error when mode byte is not 0x65
func TestParsePCOMIDResponse_WrongMode(t *testing.T) {
	// Build response with wrong mode byte (0x66 BINARY_MODE instead of 0x65 ASCII_MODE)
	response := []byte{
		0x00, 0x01, // Transaction ID
		0x66,       // Mode: BINARY (wrong)
		0x00,       // Reserved
		0x18, 0x00, // Payload length
		// ASCII payload
		0x2F, 0x41, 0x30, 0x30, 0x49, 0x44,
		0x31, 0x38, 0x30, 0x37, 0x30, 0x31,
		0x32, 0x30, 0x30, 0x33, 0x30, 0x32, 0x38,
		0x30, 0x30, 0x35, 0x46, 0x0D,
	}

	_, err := parsePCOMIDResponse(response)

	assert.Error(t, err, "Should error on wrong mode byte")
}

// TestParsePCOMIDResponse_MissingSTX verifies error when first payload byte is not 0x2F
func TestParsePCOMIDResponse_MissingSTX(t *testing.T) {
	// Build response with missing STX (0x41 instead of 0x2F)
	response := []byte{
		0x00, 0x01, 0x65, 0x00, 0x18, 0x00,
		0x41, // Wrong: should be 0x2F
		0x41, 0x30, 0x30, 0x49, 0x44,
		0x31, 0x38, 0x30, 0x37, 0x30, 0x31,
		0x32, 0x30, 0x30, 0x33, 0x30, 0x32, 0x38,
		0x30, 0x30, 0x35, 0x46, 0x0D,
	}

	_, err := parsePCOMIDResponse(response)

	assert.Error(t, err, "Should error on missing STX")
}

// TestParsePCOMIDResponse_MissingResponseIndicator verifies error when second payload byte is not 'A'
func TestParsePCOMIDResponse_MissingResponseIndicator(t *testing.T) {
	// Build response with missing response indicator (0x42 'B' instead of 0x41 'A')
	response := []byte{
		0x00, 0x01, 0x65, 0x00, 0x18, 0x00,
		0x2F,
		0x42, // Wrong: should be 0x41 'A'
		0x30, 0x30, 0x49, 0x44,
		0x31, 0x38, 0x30, 0x37, 0x30, 0x31,
		0x32, 0x30, 0x30, 0x33, 0x30, 0x32, 0x38,
		0x30, 0x30, 0x35, 0x46, 0x0D,
	}

	_, err := parsePCOMIDResponse(response)

	assert.Error(t, err, "Should error on missing response indicator")
}

// TestParsePCOMIDResponse_MissingIDEcho verifies error when bytes [4-5] are not "ID"
func TestParsePCOMIDResponse_MissingIDEcho(t *testing.T) {
	// Build response with missing ID echo (0x58, 0x59 "XY" instead of 0x49, 0x44 "ID")
	response := []byte{
		0x00, 0x01, 0x65, 0x00, 0x18, 0x00,
		0x2F, 0x41, 0x30, 0x30,
		0x58, 0x59, // Wrong: should be 0x49, 0x44 "ID"
		0x31, 0x38, 0x30, 0x37, 0x30, 0x31,
		0x32, 0x30, 0x30, 0x33, 0x30, 0x32, 0x38,
		0x30, 0x30, 0x35, 0x46, 0x0D,
	}

	_, err := parsePCOMIDResponse(response)

	assert.Error(t, err, "Should error on missing ID echo")
}

// TestParsePCOMIDResponse_PayloadTooShort verifies error when payload is shorter than 24 bytes
func TestParsePCOMIDResponse_PayloadTooShort(t *testing.T) {
	// Build response with valid prefix but payload shorter than 24 bytes
	response := []byte{
		0x00, 0x01, 0x65, 0x00, 0x10, 0x00, // Length: 16 bytes (too short)
		0x2F, 0x41, 0x30, 0x30, 0x49, 0x44,
		0x31, 0x38, 0x30, 0x37, 0x30, 0x31, // Only 16 bytes total
	}

	_, err := parsePCOMIDResponse(response)

	assert.Error(t, err, "Should error on payload too short")
}

// TestGenerateCPE verifies CPE generation with different model names and versions
func TestGenerateCPE(t *testing.T) {
	tests := []struct {
		name        string
		model       string
		osVersion   string
		expectedCPE string
	}{
		{
			name:        "Known model with version",
			model:       "V130-33-T38",
			osVersion:   "003.028.00",
			expectedCPE: "cpe:2.3:h:unitronics:v130-33-t38:003.028.00:*:*:*:*:*:*:*",
		},
		{
			name:        "Model with empty version",
			model:       "V350-35-T38",
			osVersion:   "",
			expectedCPE: "cpe:2.3:h:unitronics:v350-35-t38:*:*:*:*:*:*:*:*",
		},
		{
			name:        "Different model name",
			model:       "SM70 J T20",
			osVersion:   "005.010.02",
			expectedCPE: "cpe:2.3:h:unitronics:sm70_j_t20:005.010.02:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateCPE(tt.model, tt.osVersion)
			assert.Equal(t, tt.expectedCPE, result)
		})
	}
}

// TestNormalizeForCPE verifies string normalization for CPE format
func TestNormalizeForCPE(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "V130-33-T38",
			input:    "V130-33-T38",
			expected: "v130-33-t38",
		},
		{
			name:     "SM70 J T20 (spaces to underscores)",
			input:    "SM70 J T20",
			expected: "sm70_j_t20",
		},
		{
			name:     "Empty string",
			input:    "",
			expected: "",
		},
		{
			name:     "Already lowercase",
			input:    "v570-57-t40",
			expected: "v570-57-t40",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := normalizeForCPE(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestPluginMetadata verifies plugin metadata methods
func TestPluginMetadata(t *testing.T) {
	plugin := &PCOMPlugin{}

	// Test Name() returns "pcom"
	assert.Equal(t, PCOM, plugin.Name(), "Name should be 'pcom'")

	// Test Type() returns plugins.TCP
	assert.Equal(t, plugins.TCP, plugin.Type(), "Type should be plugins.TCP")

	// Test Priority() returns 400
	assert.Equal(t, 400, plugin.Priority(), "Priority should be 400")

	// Test PortPriority(20256) returns true
	assert.True(t, plugin.PortPriority(20256), "PortPriority(20256) should return true")

	// Test PortPriority(502) returns false
	assert.False(t, plugin.PortPriority(502), "PortPriority(502) should return false")
}

// TestModelCodes verifies the model code mapping
func TestModelCodes(t *testing.T) {
	tests := []struct {
		name      string
		modelCode string
		expected  string
		exists    bool
	}{
		{
			name:      "Known model code 180701",
			modelCode: "180701",
			expected:  "V130-33-T38",
			exists:    true,
		},
		{
			name:      "Unknown model code FFFFFF",
			modelCode: "FFFFFF",
			expected:  "",
			exists:    false,
		},
		{
			name:      "Known model code 420701",
			modelCode: "420701",
			expected:  "V350-35-T38",
			exists:    true,
		},
		{
			name:      "Known model code 2A0801",
			modelCode: "2A0801",
			expected:  "SM70-J-T20",
			exists:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, exists := modelCodes[tt.modelCode]
			assert.Equal(t, tt.exists, exists, "Model code existence check failed")
			if tt.exists {
				assert.Equal(t, tt.expected, result, "Model name mismatch")
			}
		})
	}
}
