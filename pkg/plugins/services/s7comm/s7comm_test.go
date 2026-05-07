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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
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
		{"exactly 5 bytes", []byte{0x03, 0x00, 0x00, 0x05, 0x11}},
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
		{"wrong TPKT version with 17+ bytes", []byte{
			0x02, 0x00, 0x00, 0x15, // TPKT version=0x02 (invalid, not 0x03)
			0x02, 0xF0, 0x80,
			0x32, 0x03, // Otherwise valid S7 Ack-Data
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x08, 0x00, 0x00,
			0x00,
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
		name           string
		response       []byte
		expectedOrder  string
		expectedFW     string
		expectedModule string
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

// TestS7comm_ValidateS7SetupResponseBoundsCheck verifies CWE-125 fix
// An 8-byte malicious response should be rejected before out-of-bounds read at response[8]
func TestS7comm_ValidateS7SetupResponseBoundsCheck(t *testing.T) {
	// Malicious 8-byte response that would cause out-of-bounds read
	// if bounds check incorrectly allows len(response)=8
	// s7Offset=7, so accessing response[7] and response[8] requires len>=9
	maliciousResponse := []byte{
		0x03, 0x00, 0x00, 0x08, // TPKT: valid header, length=8
		0x02, 0xF0, 0x80, // COTP DT header (3 bytes)
		0x32, // S7 Protocol ID at offset 7
		// Missing byte at offset 8 - would trigger out-of-bounds read
	}

	// Should safely reject without panic or out-of-bounds access
	assert.False(t, validateS7SetupResponse(maliciousResponse),
		"8-byte response must be rejected to prevent out-of-bounds read at response[8]")
}

// makeProtectionResponse builds a synthetic SZL 0x0232 response with the given
// protection level placed at the correct sch_rel field offset.
//
// Layout: TPKT(4) + COTP DT(3) + S7 header(10) + S7 params(12) + SZL resp header(4) +
// SZL header(8) + item: index(2) + sch_schal(2) + sch_par(2) + sch_rel(2) = 49 bytes.
func makeProtectionResponse(level byte) []byte {
	resp := make([]byte, 49)
	// TPKT header
	resp[0] = 0x03
	resp[3] = 49
	// COTP DT
	resp[4] = 0x02
	resp[5] = 0xF0
	resp[6] = 0x80
	// S7 header
	resp[7] = 0x32         // Protocol ID
	resp[8] = 0x07         // UserData
	resp[14] = 0x0c        // Param length = 12 (low byte; high byte stays 0)
	// SZL response header (at offset 29)
	resp[29] = 0xFF        // Return code OK
	resp[30] = 0x09        // Transport size
	// SZL header (at offset 33)
	resp[33] = 0x02        // SZL ID high
	resp[34] = 0x32        // SZL ID low (0x0232)
	resp[36] = 0x04        // SZL index low (0x0004)
	resp[40] = 0x01        // Item count low = 1
	// Item: index at 41-42, sch_schal at 43-44, sch_par at 45-46, sch_rel at 47-48
	resp[42] = 0x04        // Item index low (0x0004)
	resp[48] = level       // Protection level (low byte of sch_rel)
	return resp
}

func TestParseSZL0232Response(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected uint8
	}{
		{
			name:     "level 1 no protection",
			response: makeProtectionResponse(1),
			expected: 1,
		},
		{
			name:     "level 2 read-only",
			response: makeProtectionResponse(2),
			expected: 2,
		},
		{
			name:     "level 3 full protection",
			response: makeProtectionResponse(3),
			expected: 3,
		},
		{
			name:     "level 0 not extracted",
			response: makeProtectionResponse(0),
			expected: 0,
		},
		{
			name:     "level 4 out of range",
			response: makeProtectionResponse(4),
			expected: 0,
		},
		{
			name:     "response too short",
			response: []byte{0x03, 0x00, 0x00, 0x08},
			expected: 0,
		},
		{
			name: "valid header but truncated before protection byte",
			response: func() []byte {
				r := make([]byte, 30) // 17 + 12 + 1 = 30, need 49
				r[0] = 0x03
				r[7] = 0x32
				r[14] = 0x0c // paramLen=12, protOffset=48, but len=30
				return r
			}(),
			expected: 0,
		},
		{
			name:     "empty response",
			response: []byte{},
			expected: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseSZL0232Response(tt.response)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// TestS7commSecurityFindingsMockHandshake exercises the full Run() path with
// Misconfigs=true. The mock server completes the COTP + S7 Setup handshake,
// responds to the SZL 0x001C query with a minimal module-ID payload, then
// responds to the SZL 0x0232 query with protection level 1. The test asserts
// that Run() returns exactly one finding with ID "s7comm-no-protection" and
// that the evidence contains "protection_level=1".
func TestS7commSecurityFindingsMockHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := &S7COMMPlugin{}

	go func() {
		defer server.Close()
		buf := make([]byte, 512)

		// Read COTP CR → send COTP CC
		n, _ := server.Read(buf)
		if n == 0 {
			return
		}
		cotpCC := []byte{
			0x03, 0x00, 0x00, 0x16,
			0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00,
			0xC0, 0x01, 0x0A,
			0xC1, 0x02, 0x01, 0x00,
			0xC2, 0x02, 0x01, 0x02,
		}
		_, _ = server.Write(cotpCC)

		// Read S7 Setup → send S7 Setup Ack
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		s7Ack := []byte{
			0x03, 0x00, 0x00, 0x1B,
			0x02, 0xF0, 0x80,
			0x32, 0x03,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x08, 0x00, 0x00,
			0xF0, 0x00,
			0x00, 0x01, 0x00, 0x01,
			0x01, 0xE0,
		}
		_, _ = server.Write(s7Ack)

		// Read SZL 0x001C request → send minimal module-ID response.
		// parseSZL001CResponse scans the raw byte slice for an order-code
		// pattern and optionally a "CPU" substring; wrap the payload in a
		// TPKT header so the response is non-empty and contains recognisable
		// strings.
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		szl001CPayload := []byte("6ES7 214-1AG40-0XB0 V4.4.0 CPU 1214C DC/DC/DC")
		szl001CLen := 4 + len(szl001CPayload)
		szl001CResp := []byte{
			0x03, 0x00,
			byte(szl001CLen >> 8), byte(szl001CLen & 0xFF),
		}
		szl001CResp = append(szl001CResp, szl001CPayload...)
		_, _ = server.Write(szl001CResp)

		// Read SZL 0x0232 request → send protection-level=1 response.
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		_, _ = server.Write(makeProtectionResponse(1))
	}()

	target := plugins.Target{Misconfigs: true}
	service, err := p.Run(client, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)
	require.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "s7comm-no-protection", service.SecurityFindings[0].ID)
	assert.Contains(t, service.SecurityFindings[0].Evidence, "protection_level=1")
}

// TestBuildProtectionEvidence covers the evidence-string builder across the
// combinations of populated and absent PLC identification fields.
func TestBuildProtectionEvidence(t *testing.T) {
	tests := []struct {
		name            string
		protectionLevel uint8
		moduleName      string
		orderCode       string
		wantContains    []string
		wantAbsent      []string
	}{
		{
			name:            "all fields populated",
			protectionLevel: 1,
			moduleName:      "CPU 1214C",
			orderCode:       "6ES7 214-1AG40-0XB0",
			wantContains:    []string{"protection_level=1", "module=CPU 1214C", "order_code=6ES7 214-1AG40-0XB0"},
		},
		{
			name:            "protection level only",
			protectionLevel: 2,
			wantContains:    []string{"protection_level=2"},
			wantAbsent:      []string{"module=", "order_code="},
		},
		{
			name:            "protection level and module name only",
			protectionLevel: 1,
			moduleName:      "CPU 315-2 DP",
			wantContains:    []string{"protection_level=1", "module=CPU 315-2 DP"},
			wantAbsent:      []string{"order_code="},
		},
		{
			name:            "protection level and order code only",
			protectionLevel: 1,
			orderCode:       "6ES7 315-2AH14-0AB0",
			wantContains:    []string{"protection_level=1", "order_code=6ES7 315-2AH14-0AB0"},
			wantAbsent:      []string{"module="},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceData := plugins.ServiceS7comm{
				ProtectionLevel: tt.protectionLevel,
				ModuleName:      tt.moduleName,
				OrderCode:       tt.orderCode,
			}
			evidence := buildProtectionEvidence(serviceData)

			for _, want := range tt.wantContains {
				assert.Contains(t, evidence, want)
			}
			for _, absent := range tt.wantAbsent {
				assert.NotContains(t, evidence, absent)
			}
		})
	}
}

// TestS7commNoFindingProtectedPLC verifies that Run() with Misconfigs=true
// produces no security findings when the PLC reports protection level 3
// (full protection).
func TestS7commNoFindingProtectedPLC(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := &S7COMMPlugin{}

	go func() {
		defer server.Close()
		buf := make([]byte, 512)

		// COTP CR → CC
		n, _ := server.Read(buf)
		if n == 0 {
			return
		}
		cotpCC := []byte{
			0x03, 0x00, 0x00, 0x16,
			0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00,
			0xC0, 0x01, 0x0A,
			0xC1, 0x02, 0x01, 0x00,
			0xC2, 0x02, 0x01, 0x02,
		}
		_, _ = server.Write(cotpCC)

		// S7 Setup → Ack
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		s7Ack := []byte{
			0x03, 0x00, 0x00, 0x1B,
			0x02, 0xF0, 0x80,
			0x32, 0x03,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x08, 0x00, 0x00,
			0xF0, 0x00,
			0x00, 0x01, 0x00, 0x01,
			0x01, 0xE0,
		}
		_, _ = server.Write(s7Ack)

		// SZL 0x001C → minimal response (no meaningful module data needed)
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		szl001CPayload := []byte{0x03, 0x00, 0x00, 0x04} // minimal 4-byte TPKT, no order code
		_, _ = server.Write(szl001CPayload)

		// SZL 0x0232 → protection level 3 (full protection)
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		_, _ = server.Write(makeProtectionResponse(3))
	}()

	target := plugins.Target{Misconfigs: true}
	service, err := p.Run(client, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Empty(t, service.SecurityFindings)
}

// TestS7commEmptyFirstResponse exercises the Run() path where SendRecv for the
// first COTP CR returns zero bytes without an error (line 96-97). The mock
// server reads the CR and then closes its end without writing anything, which
// causes the client read to time out and return an empty slice.
func TestS7commEmptyFirstResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := &S7COMMPlugin{}

	go func() {
		defer server.Close()
		buf := make([]byte, 256)
		// Absorb the COTP CR but write nothing back — the client read will
		// time out and Recv returns []byte{}, nil which triggers len==0 path.
		_, _ = server.Read(buf)
		// Block until the client side times out; no write.
		buf2 := make([]byte, 1)
		_, _ = server.Read(buf2)
	}()

	target := plugins.Target{}
	service, err := p.Run(client, 500*time.Millisecond, target)

	assert.NoError(t, err)
	assert.Nil(t, service)
}

// TestS7commAlternateTSAPFallback exercises lines 101-110: the first COTP CR
// gets an invalid CC response (wrong PDU type), so Run() retries with the
// alternate TSAP (TSAPDestOPConnection) and the second CC is valid.
func TestS7commAlternateTSAPFallback(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := &S7COMMPlugin{}

	go func() {
		defer server.Close()
		buf := make([]byte, 512)

		// First COTP CR → send an invalid CC (disconnect request PDU type 0x80)
		n, _ := server.Read(buf)
		if n == 0 {
			return
		}
		invalidCC := []byte{
			0x03, 0x00, 0x00, 0x07,
			0x02, 0x80, 0x00, // PDU type 0x80 — not a CC
		}
		_, _ = server.Write(invalidCC)

		// Second COTP CR (alternate TSAP) → send a valid CC
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		cotpCC := []byte{
			0x03, 0x00, 0x00, 0x16,
			0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00,
			0xC0, 0x01, 0x0A,
			0xC1, 0x02, 0x01, 0x00,
			0xC2, 0x02, 0x01, 0x02,
		}
		_, _ = server.Write(cotpCC)

		// S7 Setup → send S7 Ack so Run() continues normally
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		s7Ack := []byte{
			0x03, 0x00, 0x00, 0x1B,
			0x02, 0xF0, 0x80,
			0x32, 0x03,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x08, 0x00, 0x00,
			0xF0, 0x00,
			0x00, 0x01, 0x00, 0x01,
			0x01, 0xE0,
		}
		_, _ = server.Write(s7Ack)

		// Absorb SZL requests (may or may not arrive before server.Close())
		_, _ = server.Read(buf)
		_, _ = server.Read(buf)
	}()

	target := plugins.Target{}
	service, err := p.Run(client, 5*time.Second, target)

	// Alternate TSAP succeeded → basic S7comm service detected
	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "s7comm", service.Protocol)
}

// TestS7commAlternateTSAPSendRecvError exercises the error return in the
// alternate TSAP branch (line ~105): after the first COTP CC is invalid,
// the second SendRecv returns an error because the server closes the
// connection before writing a response.
func TestS7commAlternateTSAPSendRecvError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := &S7COMMPlugin{}

	go func() {
		defer server.Close()
		buf := make([]byte, 512)

		// First COTP CR → send invalid CC (wrong PDU type)
		n, _ := server.Read(buf)
		if n == 0 {
			return
		}
		invalidCC := []byte{
			0x03, 0x00, 0x00, 0x07,
			0x02, 0x80, 0x00, // PDU type 0x80 — not a CC
		}
		_, _ = server.Write(invalidCC)

		// Second COTP CR (alternate TSAP) → read then close without replying
		_, _ = server.Read(buf)
		// server.Close() via defer fires → client SendRecv returns ReadError
	}()

	target := plugins.Target{}
	service, err := p.Run(client, 5*time.Second, target)

	// Error propagated from alternate TSAP SendRecv
	assert.Error(t, err)
	assert.Nil(t, service)
}

// TestS7commAlternateTSAPEmptyResponse exercises the zero-length / invalid
// response branch (line ~108) after the alternate TSAP attempt: the first CC
// is invalid, the second attempt times out and returns an empty response, so
// Run() returns nil, nil.
func TestS7commAlternateTSAPEmptyResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := &S7COMMPlugin{}

	go func() {
		defer server.Close()
		buf := make([]byte, 512)

		// First COTP CR → invalid CC
		n, _ := server.Read(buf)
		if n == 0 {
			return
		}
		invalidCC := []byte{
			0x03, 0x00, 0x00, 0x07,
			0x02, 0x80, 0x00,
		}
		_, _ = server.Write(invalidCC)

		// Second COTP CR (alternate TSAP) → read but write nothing; client times out
		_, _ = server.Read(buf)
		// Block until client timeout by absorbing one more read
		buf2 := make([]byte, 1)
		_, _ = server.Read(buf2)
	}()

	target := plugins.Target{}
	service, err := p.Run(client, 500*time.Millisecond, target)

	assert.NoError(t, err)
	assert.Nil(t, service)
}

// TestS7commS7SetupSendRecvError exercises lines 119-121: COTP handshake
// succeeds but the server closes the connection before sending the S7 Setup
// response. SendRecv returns an error, and Run() returns a basic detection.
func TestS7commS7SetupSendRecvError(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := &S7COMMPlugin{}

	go func() {
		defer server.Close()
		buf := make([]byte, 512)

		// COTP CR → valid CC
		n, _ := server.Read(buf)
		if n == 0 {
			return
		}
		cotpCC := []byte{
			0x03, 0x00, 0x00, 0x16,
			0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00,
			0xC0, 0x01, 0x0A,
			0xC1, 0x02, 0x01, 0x00,
			0xC2, 0x02, 0x01, 0x02,
		}
		_, _ = server.Write(cotpCC)

		// S7 Setup → read request then close without replying
		_, _ = server.Read(buf)
		// server.Close() via defer triggers a read error on the client side
	}()

	target := plugins.Target{}
	service, err := p.Run(client, 5*time.Second, target)

	// Basic detection returned (no error propagated from S7 Setup failure)
	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "s7comm", service.Protocol)
}

// TestS7commS7SetupInvalidResponse exercises lines 125-127: COTP handshake
// succeeds but the S7 Setup response fails validateS7SetupResponse (wrong
// protocol ID). Run() returns a basic detection without metadata.
func TestS7commS7SetupInvalidResponse(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := &S7COMMPlugin{}

	go func() {
		defer server.Close()
		buf := make([]byte, 512)

		// COTP CR → valid CC
		n, _ := server.Read(buf)
		if n == 0 {
			return
		}
		cotpCC := []byte{
			0x03, 0x00, 0x00, 0x16,
			0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00,
			0xC0, 0x01, 0x0A,
			0xC1, 0x02, 0x01, 0x00,
			0xC2, 0x02, 0x01, 0x02,
		}
		_, _ = server.Write(cotpCC)

		// S7 Setup → send response with wrong S7 protocol ID (0x33 instead of 0x32)
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		badS7Ack := []byte{
			0x03, 0x00, 0x00, 0x1B,
			0x02, 0xF0, 0x80,
			0x33, 0x03, // Wrong protocol ID — fails validateS7SetupResponse
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x08, 0x00, 0x00,
			0xF0, 0x00,
			0x00, 0x01, 0x00, 0x01,
			0x01, 0xE0,
		}
		_, _ = server.Write(badS7Ack)
	}()

	target := plugins.Target{}
	service, err := p.Run(client, 5*time.Second, target)

	// Basic detection returned (no error propagated from S7 Setup validation failure)
	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "s7comm", service.Protocol)
}

// TestS7commReadOnlyFindingMockHandshake exercises the full Run() path with
// Misconfigs=true and protection level 2. The mock server completes the full
// COTP + S7 Setup handshake then responds to SZL queries with level 2. The
// test asserts Run() returns exactly one finding with ID "s7comm-read-only"
// and severity Medium.
func TestS7commReadOnlyFindingMockHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := &S7COMMPlugin{}

	go func() {
		defer server.Close()
		buf := make([]byte, 512)

		// COTP CR → CC
		n, _ := server.Read(buf)
		if n == 0 {
			return
		}
		cotpCC := []byte{
			0x03, 0x00, 0x00, 0x16,
			0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00,
			0xC0, 0x01, 0x0A,
			0xC1, 0x02, 0x01, 0x00,
			0xC2, 0x02, 0x01, 0x02,
		}
		_, _ = server.Write(cotpCC)

		// S7 Setup → Ack
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		s7Ack := []byte{
			0x03, 0x00, 0x00, 0x1B,
			0x02, 0xF0, 0x80,
			0x32, 0x03,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x08, 0x00, 0x00,
			0xF0, 0x00,
			0x00, 0x01, 0x00, 0x01,
			0x01, 0xE0,
		}
		_, _ = server.Write(s7Ack)

		// SZL 0x001C → minimal module-ID response
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		szl001CPayload := []byte("6ES7 315-2AH14-0AB0 V2.8.0 CPU 315-2 DP")
		szl001CLen := 4 + len(szl001CPayload)
		szl001CResp := []byte{
			0x03, 0x00,
			byte(szl001CLen >> 8), byte(szl001CLen & 0xFF),
		}
		szl001CResp = append(szl001CResp, szl001CPayload...)
		_, _ = server.Write(szl001CResp)

		// SZL 0x0232 → protection level 2
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		_, _ = server.Write(makeProtectionResponse(2))
	}()

	target := plugins.Target{Misconfigs: true}
	service, err := p.Run(client, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)
	require.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "s7comm-read-only", service.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityMedium, service.SecurityFindings[0].Severity)
	assert.Contains(t, service.SecurityFindings[0].Evidence, "protection_level=2")
}

// TestS7commMisconfigsDisabledMockHandshake exercises the full Run() path with
// Misconfigs=false. Even though the PLC reports protection level 1 (no
// protection), Run() must return a service with no security findings because
// misconfig scanning is disabled.
func TestS7commMisconfigsDisabledMockHandshake(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()

	p := &S7COMMPlugin{}

	go func() {
		defer server.Close()
		buf := make([]byte, 512)

		// COTP CR → CC
		n, _ := server.Read(buf)
		if n == 0 {
			return
		}
		cotpCC := []byte{
			0x03, 0x00, 0x00, 0x16,
			0x11, 0xD0, 0x00, 0x01, 0x00, 0x01, 0x00,
			0xC0, 0x01, 0x0A,
			0xC1, 0x02, 0x01, 0x00,
			0xC2, 0x02, 0x01, 0x02,
		}
		_, _ = server.Write(cotpCC)

		// S7 Setup → Ack
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		s7Ack := []byte{
			0x03, 0x00, 0x00, 0x1B,
			0x02, 0xF0, 0x80,
			0x32, 0x03,
			0x00, 0x00, 0x00, 0x00,
			0x00, 0x08, 0x00, 0x00,
			0xF0, 0x00,
			0x00, 0x01, 0x00, 0x01,
			0x01, 0xE0,
		}
		_, _ = server.Write(s7Ack)

		// SZL 0x001C → module-ID response with order code
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		szl001CPayload := []byte("6ES7 214-1AG40-0XB0 V4.4.0 CPU 1214C DC/DC/DC")
		szl001CLen := 4 + len(szl001CPayload)
		szl001CResp := []byte{
			0x03, 0x00,
			byte(szl001CLen >> 8), byte(szl001CLen & 0xFF),
		}
		szl001CResp = append(szl001CResp, szl001CPayload...)
		_, _ = server.Write(szl001CResp)

		// SZL 0x0232 → protection level 1 (no protection)
		n, _ = server.Read(buf)
		if n == 0 {
			return
		}
		_, _ = server.Write(makeProtectionResponse(1))
	}()

	// Misconfigs=false: security findings must not be populated
	target := plugins.Target{Misconfigs: false}
	service, err := p.Run(client, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Equal(t, "s7comm", service.Protocol)
	assert.Empty(t, service.SecurityFindings,
		"security findings must be nil/empty when Misconfigs=false even if PLC has no protection")
}

func TestS7commSecurityFindings(t *testing.T) {
	tests := []struct {
		name             string
		protectionLevel  uint8
		moduleName       string
		orderCode        string
		misconfigs       bool
		wantFindingCount int
		wantFindingID    string
		wantSeverity     plugins.Severity
		wantEvidenceKeys []string
	}{
		{
			name:             "level 1 misconfigs enabled yields critical finding",
			protectionLevel:  1,
			moduleName:       "CPU 1214C DC/DC/DC",
			orderCode:        "6ES7 214-1AG40-0XB0",
			misconfigs:       true,
			wantFindingCount: 1,
			wantFindingID:    "s7comm-no-protection",
			wantSeverity:     plugins.SeverityCritical,
			wantEvidenceKeys: []string{"protection_level=1", "module=CPU 1214C DC/DC/DC", "order_code=6ES7 214-1AG40-0XB0"},
		},
		{
			name:             "level 2 misconfigs enabled yields medium finding",
			protectionLevel:  2,
			moduleName:       "CPU 315-2 DP",
			orderCode:        "6ES7 315-2AH14-0AB0",
			misconfigs:       true,
			wantFindingCount: 1,
			wantFindingID:    "s7comm-read-only",
			wantSeverity:     plugins.SeverityMedium,
			wantEvidenceKeys: []string{"protection_level=2", "module=CPU 315-2 DP"},
		},
		{
			name:             "level 3 misconfigs enabled yields no finding",
			protectionLevel:  3,
			misconfigs:       true,
			wantFindingCount: 0,
		},
		{
			name:             "level 0 not extracted yields no finding",
			protectionLevel:  0,
			misconfigs:       true,
			wantFindingCount: 0,
		},
		{
			name:             "level 1 misconfigs disabled yields no finding",
			protectionLevel:  1,
			misconfigs:       false,
			wantFindingCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serviceData := plugins.ServiceS7comm{
				ProtectionLevel: tt.protectionLevel,
				ModuleName:      tt.moduleName,
				OrderCode:       tt.orderCode,
			}

			var findings []plugins.SecurityFinding
			if tt.misconfigs {
				findings = checkProtectionLevel(serviceData)
			}

			require.Len(t, findings, tt.wantFindingCount)
			if tt.wantFindingCount == 0 {
				return
			}

			assert.Equal(t, tt.wantFindingID, findings[0].ID)
			assert.Equal(t, tt.wantSeverity, findings[0].Severity)
			for _, key := range tt.wantEvidenceKeys {
				assert.Contains(t, findings[0].Evidence, key)
			}
		})
	}
}
