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

package hartip

import (
	"testing"
)

// TestBuildSessionInitiateProbe validates the structure of the Session Initiate probe
func TestBuildSessionInitiateProbe(t *testing.T) {
	probe := buildSessionInitiateProbe()

	// Validate probe length (8 byte header + 5 byte body = 13 bytes total)
	expectedLength := 13
	if len(probe) != expectedLength {
		t.Errorf("Expected probe length %d, got %d", expectedLength, len(probe))
	}

	// Validate header fields
	if probe[0] != 0x01 {
		t.Errorf("Expected Version 0x01, got 0x%02x", probe[0])
	}

	if probe[1] != 0x00 {
		t.Errorf("Expected Message Type 0x00 (Request), got 0x%02x", probe[1])
	}

	if probe[2] != 0x00 {
		t.Errorf("Expected Message ID 0x00 (Session Initiate), got 0x%02x", probe[2])
	}

	if probe[3] != 0x00 {
		t.Errorf("Expected Status 0x00, got 0x%02x", probe[3])
	}

	// Transaction ID is bytes 4-5 (can be any value)
	// Length should be 13 (0x00 0x0D in big-endian)
	length := uint16(probe[6])<<8 | uint16(probe[7])
	if length != 13 {
		t.Errorf("Expected Length 13, got %d", length)
	}

	// Validate body fields
	if probe[8] != 0x01 {
		t.Errorf("Expected Master Type 0x01, got 0x%02x", probe[8])
	}

	// Inactivity Close Time should be 60000ms (0x0000EA60 in big-endian)
	inactivityTime := uint32(probe[9])<<24 | uint32(probe[10])<<16 | uint32(probe[11])<<8 | uint32(probe[12])
	expectedTime := uint32(60000)
	if inactivityTime != expectedTime {
		t.Errorf("Expected Inactivity Close Time %d ms, got %d ms", expectedTime, inactivityTime)
	}
}

// TestIsValidHARTIPResponse tests the response validation logic
func TestIsValidHARTIPResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		probe    []byte
		expected bool
	}{
		{
			name: "Valid Response",
			response: []byte{
				0x01,       // Version
				0x01,       // Message Type (Response)
				0x00,       // Message ID (Session Initiate)
				0x00,       // Status (Success)
				0x12, 0x34, // Transaction ID (matches probe)
				0x00, 0x0D, // Length
				0x01,                   // Master Type
				0x00, 0x00, 0xEA, 0x60, // Inactivity Time
			},
			probe: []byte{
				0x01,       // Version
				0x00,       // Message Type (Request)
				0x00,       // Message ID
				0x00,       // Status
				0x12, 0x34, // Transaction ID
				0x00, 0x0D, // Length
				0x01,                   // Master Type
				0x00, 0x00, 0xEA, 0x60, // Inactivity Time
			},
			expected: true,
		},
		{
			name: "Too Short Response",
			response: []byte{
				0x01, 0x01, 0x00,
			},
			probe: []byte{
				0x01, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x0D,
				0x01, 0x00, 0x00, 0xEA, 0x60,
			},
			expected: false,
		},
		{
			name: "Invalid Version",
			response: []byte{
				0x02,       // Wrong version
				0x01,       // Message Type (Response)
				0x00,       // Message ID
				0x00,       // Status
				0x12, 0x34, // Transaction ID
				0x00, 0x0D, // Length
				0x01,                   // Master Type
				0x00, 0x00, 0xEA, 0x60, // Inactivity Time
			},
			probe: []byte{
				0x01, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x0D,
				0x01, 0x00, 0x00, 0xEA, 0x60,
			},
			expected: false,
		},
		{
			name: "Wrong Transaction ID",
			response: []byte{
				0x01,       // Version
				0x01,       // Message Type (Response)
				0x00,       // Message ID
				0x00,       // Status
				0x56, 0x78, // Wrong Transaction ID
				0x00, 0x0D, // Length
				0x01,                   // Master Type
				0x00, 0x00, 0xEA, 0x60, // Inactivity Time
			},
			probe: []byte{
				0x01, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x0D,
				0x01, 0x00, 0x00, 0xEA, 0x60,
			},
			expected: false,
		},
		{
			name: "NAK Response (should still be valid HART-IP)",
			response: []byte{
				0x01,       // Version
				0x0F,       // Message Type (NAK)
				0x00,       // Message ID
				0x00,       // Status
				0x12, 0x34, // Transaction ID
				0x00, 0x0D, // Length
				0x01,                   // Master Type
				0x00, 0x00, 0xEA, 0x60, // Inactivity Time
			},
			probe: []byte{
				0x01, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x0D,
				0x01, 0x00, 0x00, 0xEA, 0x60,
			},
			expected: true,
		},
		{
			name: "Error Response (should still be valid HART-IP)",
			response: []byte{
				0x01,       // Version
				0x03,       // Message Type (Error)
				0x00,       // Message ID
				0x05,       // Status (some error)
				0x12, 0x34, // Transaction ID
				0x00, 0x0D, // Length
				0x01,                   // Master Type
				0x00, 0x00, 0xEA, 0x60, // Inactivity Time
			},
			probe: []byte{
				0x01, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x0D,
				0x01, 0x00, 0x00, 0xEA, 0x60,
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidHARTIPResponse(tt.response, tt.probe)
			if result != tt.expected {
				t.Errorf("Expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestParseHARTIPResponse tests metadata extraction from responses
func TestParseHARTIPResponse(t *testing.T) {
	tests := []struct {
		name           string
		response       []byte
		expectedStatus string
	}{
		{
			name: "Success Response",
			response: []byte{
				0x01,       // Version
				0x01,       // Message Type (Response)
				0x00,       // Message ID
				0x00,       // Status (Success)
				0x12, 0x34, // Transaction ID
				0x00, 0x0D, // Length
				0x01,                   // Master Type
				0x00, 0x00, 0xEA, 0x60, // Inactivity Time
			},
			expectedStatus: "Success",
		},
		{
			name: "Error Response",
			response: []byte{
				0x01,       // Version
				0x03,       // Message Type (Error)
				0x00,       // Message ID
				0x05,       // Status (some error code)
				0x12, 0x34, // Transaction ID
				0x00, 0x0D, // Length
				0x01,                   // Master Type
				0x00, 0x00, 0xEA, 0x60, // Inactivity Time
			},
			expectedStatus: "Error",
		},
		{
			name: "NAK Response",
			response: []byte{
				0x01,       // Version
				0x0F,       // Message Type (NAK)
				0x00,       // Message ID
				0x00,       // Status
				0x12, 0x34, // Transaction ID
				0x00, 0x0D, // Length
				0x01,                   // Master Type
				0x00, 0x00, 0xEA, 0x60, // Inactivity Time
			},
			expectedStatus: "NAK",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, messageType, status, statusDesc, txID := parseHARTIPResponse(tt.response)

			// Validate version
			if version != 1 {
				t.Errorf("Expected version 1, got %d", version)
			}

			// Validate message type matches response
			expectedMsgType := uint8(tt.response[1])
			if messageType != expectedMsgType {
				t.Errorf("Expected message type 0x%02x, got 0x%02x", expectedMsgType, messageType)
			}

			// Validate status
			expectedStatus := uint8(tt.response[3])
			if status != expectedStatus {
				t.Errorf("Expected status 0x%02x, got 0x%02x", expectedStatus, status)
			}

			// Validate status description
			if statusDesc != tt.expectedStatus {
				t.Errorf("Expected status description '%s', got '%s'", tt.expectedStatus, statusDesc)
			}

			// Validate transaction ID
			expectedTxID := uint16(tt.response[4])<<8 | uint16(tt.response[5])
			if txID != expectedTxID {
				t.Errorf("Expected transaction ID 0x%04x, got 0x%04x", expectedTxID, txID)
			}
		})
	}
}
