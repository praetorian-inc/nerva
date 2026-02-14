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

package ethernetip

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildListIdentityRequest(t *testing.T) {
	request := buildListIdentityRequest()

	// Verify packet is 24 bytes
	assert.Equal(t, 24, len(request), "List Identity request should be 24 bytes")

	// Verify command is 0x0063
	assert.Equal(t, byte(0x63), request[0], "Command should be 0x63 (List Identity)")
	assert.Equal(t, byte(0x00), request[1], "Command high byte should be 0x00")

	// Verify length is 0
	assert.Equal(t, byte(0x00), request[2], "Length should be 0")
	assert.Equal(t, byte(0x00), request[3], "Length high byte should be 0")

	// Verify session handle is 0
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, request[4:8], "Session handle should be 0")

	// Verify status is 0
	assert.Equal(t, []byte{0x00, 0x00, 0x00, 0x00}, request[8:12], "Status should be 0")

	// Verify sender context (magic)
	assert.Equal(t, []byte{0xc1, 0xde, 0xbe, 0xd1}, request[12:16], "Sender context should be magic bytes")
}

func TestParseListIdentityResponse_ValidResponse(t *testing.T) {
	// Valid EtherNet/IP List Identity response
	// Based on Rockwell Automation device
	response := []byte{
		// Encapsulation header (24 bytes)
		0x63, 0x00, // Command: List Identity (0x0063)
		0x28, 0x00, // Length: 40 bytes
		0x00, 0x00, 0x00, 0x00, // Session Handle: 0
		0x00, 0x00, 0x00, 0x00, // Status: 0 (success)
		0xc1, 0xde, 0xbe, 0xd1, // Sender Context (echo magic)
		0x00, 0x00, 0x00, 0x00, // Sender Context cont.
		0x00, 0x00, 0x00, 0x00, // Options: 0

		// CPF Item Count (2 bytes)
		0x01, 0x00, // Item count: 1

		// CPF Item (varies, contains device identity)
		0x0c, 0x00, // Type Code: CIP Identity (0x000C)
		0x20, 0x00, // Item Length: 32 bytes

		// Identity Object (32 bytes minimum)
		0x01, 0x00, // Protocol Version: 1
		0x00, 0x00, // Socket Address (sin_family)
		0x00, 0x00, // Socket Address (sin_port)
		0x00, 0x00, 0x00, 0x00, // Socket Address (sin_addr)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Socket Address (sin_zero)

		0x01, 0x00, // Vendor ID: 1 (Rockwell Automation)
		0x0e, 0x00, // Device Type: 14 (Communications Adapter)
		0x6f, 0x00, // Product Code: 111
		0x03,       // Revision Major: 3
		0x01,       // Revision Minor: 1
		0x00, 0x00, // Status: 0
		0x01, 0x02, 0x03, 0x04, // Serial Number: 0x04030201
		0x0d,       // Product Name Length: 13
		// Product Name: "1756-ENBT/A"
		0x31, 0x37, 0x35, 0x36, 0x2d, 0x45, 0x4e, 0x42, 0x54, 0x2f, 0x41, 0x00, 0x00,
	}

	data, err := parseListIdentityResponse(response)

	assert.NoError(t, err, "Should parse valid response without error")
	assert.Equal(t, uint16(1), data.VendorID, "Vendor ID should be 1")
	assert.Equal(t, uint16(14), data.DeviceType, "Device Type should be 14")
	assert.Equal(t, uint16(111), data.ProductCode, "Product Code should be 111")
	assert.Equal(t, uint8(3), data.RevisionMajor, "Revision Major should be 3")
	assert.Equal(t, uint8(1), data.RevisionMinor, "Revision Minor should be 1")
	assert.Equal(t, uint32(0x04030201), data.SerialNumber, "Serial Number should be 0x04030201")
	assert.Contains(t, data.ProductName, "1756-ENBT", "Product name should contain 1756-ENBT")
}

func TestParseListIdentityResponse_TooShort(t *testing.T) {
	response := []byte{0x63, 0x00}

	_, err := parseListIdentityResponse(response)

	assert.Error(t, err, "Should error on response too short")
}

func TestParseListIdentityResponse_WrongCommand(t *testing.T) {
	response := make([]byte, 80)
	response[0] = 0x65 // Wrong command
	response[1] = 0x00

	_, err := parseListIdentityResponse(response)

	assert.Error(t, err, "Should error on wrong command")
}

func TestMapVendorID(t *testing.T) {
	tests := []struct {
		vendorID     uint16
		expectedName string
	}{
		{1, "Rockwell Automation/Allen-Bradley"},
		{2, "Namco Controls Corp."},
		{47, "Omron Corporation"},
		{145, "Siemens Energy & Automation"},
		{9999, "Unknown"}, // Unknown vendor
	}

	for _, tt := range tests {
		t.Run(tt.expectedName, func(t *testing.T) {
			result := mapVendorID(tt.vendorID)
			assert.Equal(t, tt.expectedName, result)
		})
	}
}

func TestBuildCPE(t *testing.T) {
	tests := []struct {
		name         string
		vendorName   string
		productName  string
		revision     string
		expectedCPE  string
	}{
		{
			name:         "Rockwell device with version",
			vendorName:   "Rockwell Automation/Allen-Bradley",
			productName:  "1756-ENBT/A",
			revision:     "3.1",
			expectedCPE:  "cpe:2.3:h:rockwell_automation:1756-enbt\\/a:3.1:*:*:*:*:*:*:*",
		},
		{
			name:         "Unknown vendor",
			vendorName:   "Unknown",
			productName:  "Device",
			revision:     "1.0",
			expectedCPE:  "cpe:2.3:h:unknown:device:1.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildCPE(tt.vendorName, tt.productName, tt.revision)
			assert.Equal(t, tt.expectedCPE, result)
		})
	}
}

func TestNormalizeForCPE(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"Rockwell Automation/Allen-Bradley", "rockwell_automation"},
		{"WAGO", "wago"},
		{"SEW-EURODRIVE", "sew-eurodrive"},
		{"Phoenix Contact", "phoenix_contact"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizeForCPE(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}
