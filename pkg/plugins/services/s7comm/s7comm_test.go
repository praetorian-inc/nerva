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

package s7comm

import (
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestS7comm_PluginInterface(t *testing.T) {
	p := &S7COMMPlugin{}

	assert.Equal(t, "s7comm", p.Name())
	assert.Equal(t, plugins.TCP, p.Type())
	assert.Equal(t, 400, p.Priority())
	assert.True(t, p.PortPriority(102))
	assert.False(t, p.PortPriority(80))
}

func TestS7comm_ValidCOTPResponse(t *testing.T) {
	// Valid COTP CC response
	response := []byte{
		0x03, 0x00, 0x00, 0x16, // TPKT: version=3, reserved=0, length=22
		0x11, 0xD0, // COTP: header len, CC type (0xD0)
		0x00, 0x01, // Destination reference
		0x00, 0x01, // Source reference
		0x00,             // Class/Option
		0xC0, 0x01, 0x0A, // TPDU size param
		0xC1, 0x02, 0x01, 0x00, // Src TSAP param
		0xC2, 0x02, 0x01, 0x02, // Dst TSAP param
	}

	assert.True(t, validateCOTPConfirm(response))
}

func TestS7comm_InvalidResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x03, 0x00}},
		{"wrong TPKT version", []byte{0x02, 0x00, 0x00, 0x10, 0x11, 0xD0}},
		{"disconnect request", []byte{0x03, 0x00, 0x00, 0x10, 0x11, 0x80}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.False(t, validateCOTPConfirm(tt.response))
		})
	}
}

func TestS7comm_PLCTypeDetection(t *testing.T) {
	tests := []struct {
		orderCode string
		expected  string
	}{
		{"6ES7 315-2AH14-0AB0", "S7-300"},
		{"6ES7 416-3ES06-0AB0", "S7-400"},
		{"6ES7 214-1AG40-0XB0", "S7-1200"},
		{"6ES7 151-8AB01-0AB0", "S7-1500"},
		{"UNKNOWN", "S7"},
	}

	for _, tt := range tests {
		t.Run(tt.orderCode, func(t *testing.T) {
			result := detectPLCType(tt.orderCode)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestS7comm_CPEGeneration(t *testing.T) {
	serviceData := plugins.ServiceS7comm{
		PLCType:         "S7-1200",
		FirmwareVersion: "V4.4.0",
	}

	cpes := generateCPEs(serviceData)

	require.Len(t, cpes, 1)
	assert.Equal(t, "cpe:2.3:h:siemens:simatic_s7_1200:4.4.0:*:*:*:*:*:*:*", cpes[0])
}

func TestS7comm_CPEGenerationWildcard(t *testing.T) {
	serviceData := plugins.ServiceS7comm{
		PLCType:         "S7-300",
		FirmwareVersion: "",
	}

	cpes := generateCPEs(serviceData)

	require.Len(t, cpes, 1)
	assert.Equal(t, "cpe:2.3:h:siemens:simatic_s7_300:*:*:*:*:*:*:*:*", cpes[0])
}

func TestS7comm_CPEGenerationEmpty(t *testing.T) {
	serviceData := plugins.ServiceS7comm{
		PLCType: "",
	}

	cpes := generateCPEs(serviceData)

	assert.Len(t, cpes, 0)
}

func TestS7comm_BuildCOTPConnectionRequest(t *testing.T) {
	packet := buildCOTPConnectionRequest(TSAPDestRack0Slot2)

	// Verify TPKT header
	assert.Equal(t, byte(0x03), packet[0]) // Version
	assert.Equal(t, byte(0x00), packet[1]) // Reserved

	// Verify COTP type
	assert.Equal(t, byte(0xE0), packet[5]) // Connection Request
}

func TestS7comm_ValidateS7SetupResponse(t *testing.T) {
	// Valid S7 Setup Ack-Data response
	response := []byte{
		0x03, 0x00, 0x00, 0x1B, // TPKT
		0x02, 0xF0, 0x80, // COTP DT
		0x32, 0x03, // S7 Protocol ID, Ack-Data
		0x00, 0x00, 0x00, 0x00, // Reserved, PDU ref
		0x00, 0x08, 0x00, 0x00, // Param len, Data len
		0xF0, 0x00, // Setup comm function
		0x00, 0x01, 0x00, 0x01, // AmQ
		0x01, 0xE0, // PDU size
	}

	assert.True(t, validateS7SetupResponse(response))
}

func TestS7comm_ValidateS7SetupResponseInvalid(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x03, 0x00, 0x00, 0x10}},
		{"wrong protocol id", []byte{
			0x03, 0x00, 0x00, 0x15,
			0x02, 0xF0, 0x80,
			0x33, 0x03, // Wrong protocol ID
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x08, 0x00, 0x00,
		}},
		{"wrong message type", []byte{
			0x03, 0x00, 0x00, 0x15,
			0x02, 0xF0, 0x80,
			0x32, 0x01, // Job instead of Ack-Data
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x08, 0x00, 0x00,
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.False(t, validateS7SetupResponse(tt.response))
		})
	}
}

func TestS7comm_CleanString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"normal", "CPU 1214C", "CPU 1214C"},
		{"with null", "CPU 1214C\x00extra", "CPU 1214C"},
		{"with control chars", "CPU\x01\x02 1214C", "CPU 1214C"},
		{"leading spaces", "  CPU 1214C  ", "CPU 1214C"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := cleanString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// Mock connection test using net.Pipe()
func TestS7comm_MockHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := &S7COMMPlugin{}

	// Goroutine to simulate S7 server
	go func() {
		buf := make([]byte, 256)

		// Read COTP CR
		n, _ := server.Read(buf)
		if n > 0 {
			// Send COTP CC response
			cotpCC := []byte{
				0x03, 0x00, 0x00, 0x16,
				0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00,
				0xC0, 0x01, 0x0A,
				0xC1, 0x02, 0x01, 0x00,
				0xC2, 0x02, 0x01, 0x02,
			}
			_, _ = server.Write(cotpCC)
		}

		// Read S7 Setup request
		n, _ = server.Read(buf)
		if n > 0 {
			// Send S7 Setup Ack
			s7Ack := []byte{
				0x03, 0x00, 0x00, 0x1B, // TPKT
				0x02, 0xF0, 0x80, // COTP DT
				0x32, 0x03, // S7 Protocol ID, Ack-Data
				0x00, 0x00, 0x00, 0x00, // Reserved, PDU ref
				0x00, 0x08, 0x00, 0x00, // Param len, Data len
				0xF0, 0x00, // Setup comm function
				0x00, 0x01, 0x00, 0x01, // AmQ
				0x01, 0xE0, // PDU size
			}
			_, _ = server.Write(s7Ack)
		}

		// Read SZL request (may or may not happen)
		_, _ = server.Read(buf)
		// Close after timeout to allow test to complete
	}()

	target := plugins.Target{}
	service, err := p.Run(client, 5*time.Second, target)

	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "s7comm", service.Protocol)
}

func TestS7comm_EmptyResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := &S7COMMPlugin{}

	// Server reads request but returns empty (simulating no S7comm)
	go func() {
		buf := make([]byte, 256)
		// Read the COTP CR request
		_, _ = server.Read(buf)
		// Don't write anything back - close connection
		server.Close()
	}()

	target := plugins.Target{}
	service, _ := p.Run(client, 1*time.Second, target)

	// Closed connection returns error, which is acceptable
	// In production, empty response (no data before timeout) returns nil, nil
	// This test verifies we handle connection closure gracefully
	assert.Nil(t, service)
}

func TestS7comm_BuildSZLRequest(t *testing.T) {
	packet := buildSZLRequest(0x001C, 0x0000)

	// Verify TPKT header
	assert.Equal(t, byte(0x03), packet[0]) // Version
	assert.Equal(t, byte(0x00), packet[1]) // Reserved

	// Verify S7 Protocol ID is present (after TPKT + COTP DT)
	// TPKT(4) + COTP DT(3) = offset 7
	assert.Equal(t, byte(0x32), packet[7]) // S7 Protocol ID

	// Verify message type is UserData (0x07)
	assert.Equal(t, byte(0x07), packet[8])

	// Verify SZL ID is in the packet (0x001C)
	// SZL data starts after S7 header + params
	found := false
	for i := 0; i < len(packet)-1; i++ {
		if packet[i] == 0x00 && packet[i+1] == 0x1C {
			found = true
			break
		}
	}
	assert.True(t, found, "SZL ID 0x001C should be present in packet")
}

func TestS7comm_ParseSZL001CResponse(t *testing.T) {
	tests := []struct {
		name            string
		response        []byte
		expectedOrder   string
		expectedFW      string
		expectedModule  string
	}{
		{
			name: "full response with firmware",
			response: []byte(
				"\x03\x00\x00\x50" + // TPKT header
					"\x02\xF0\x80" + // COTP DT
					"\x32\x07" + // S7 UserData
					"\x00\x00\x00\x00\x00\x00\x00\x00" + // padding
					"6ES7 214-1AG40-0XB0\x00" + // Order code
					"V4.4.0\x00" + // Firmware version
					"CPU 1214C DC/DC/DC\x00", // Module name
			),
			expectedOrder:  "6ES7 214-1AG40-0XB0",
			expectedFW:     "V4.4.0",
			expectedModule: "CPU 1214C DC/DC/DC",
		},
		{
			name:           "response without V prefix",
			response:       []byte("6ES7 315-2AH14-0AB0 2.8.0 CPU 315-2DP"),
			expectedOrder:  "6ES7 315-2AH14-0AB0",
			expectedFW:     "2.8.0",
			expectedModule: "CPU 315-2DP",
		},
		{
			name:           "order code only",
			response:       []byte("Some data 6ES7 416-3ES06-0AB0 more data"),
			expectedOrder:  "6ES7 416-3ES06-0AB0",
			expectedFW:     "",
			expectedModule: "",
		},
		{
			name:           "real siemens firmware format",
			response:       []byte("Module: 6ES7 315-2AG10-0AB0  v.2.6.6\nBasic Firmware: v.2.6.6\nModule name: CPU 315-2 DP"),
			expectedOrder:  "6ES7 315-2AG10-0AB0",
			expectedFW:     "v.2.6.6",
			expectedModule: "CPU 315-2 DP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceData := plugins.ServiceS7comm{}
			result := parseSZL001CResponse(tt.response, serviceData)

			assert.Equal(t, tt.expectedOrder, result.OrderCode)
			assert.Equal(t, tt.expectedFW, result.FirmwareVersion)
			if tt.expectedModule != "" {
				assert.Contains(t, result.ModuleName, "CPU")
			}
		})
	}
}

func TestS7comm_ParseSZL001CResponseEmpty(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
	}{
		{"empty response", []byte{}},
		{"no matching data", []byte("random binary data without patterns")},
		{"partial data", []byte("\x00\x01\x02\x03\x04")},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceData := plugins.ServiceS7comm{}
			result := parseSZL001CResponse(tt.response, serviceData)

			// Should return empty but not panic
			assert.Equal(t, "", result.OrderCode)
			assert.Equal(t, "", result.FirmwareVersion)
			assert.Equal(t, "", result.ModuleName)
		})
	}
}
