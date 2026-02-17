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

package gesrtp

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

// mockConn simulates a network connection with predefined responses
type mockConn struct {
	responses [][]byte
	readIndex int
	written   []byte
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readIndex >= len(m.responses) {
		return 0, io.EOF
	}
	response := m.responses[m.readIndex]
	m.readIndex++
	copy(b, response)
	return len(response), nil
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	m.written = append(m.written, b...)
	return len(b), nil
}

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestPluginName(t *testing.T) {
	plugin := &GESRTPPlugin{}
	assert.Equal(t, "gesrtp", plugin.Name())
}

func TestPluginType(t *testing.T) {
	plugin := &GESRTPPlugin{}
	assert.Equal(t, plugins.TCP, plugin.Type())
}

func TestPluginPriority(t *testing.T) {
	plugin := &GESRTPPlugin{}
	assert.Equal(t, 400, plugin.Priority())
}

func TestPortPriority(t *testing.T) {
	plugin := &GESRTPPlugin{}
	assert.True(t, plugin.PortPriority(18245))
	assert.False(t, plugin.PortPriority(80))
	assert.False(t, plugin.PortPriority(443))
}

func TestRunEmptyResponse(t *testing.T) {
	plugin := &GESRTPPlugin{}
	conn := &mockConn{responses: [][]byte{{}}}
	target := plugins.Target{Host: "192.168.1.1"}

	service, err := plugin.Run(conn, time.Second, target)

	assert.Nil(t, err)
	assert.Nil(t, service)
}

func TestRunInitResponseTooShort(t *testing.T) {
	plugin := &GESRTPPlugin{}
	// Response less than 56 bytes
	shortResponse := make([]byte, 30)
	conn := &mockConn{responses: [][]byte{shortResponse}}
	target := plugins.Target{Host: "192.168.1.1"}

	service, err := plugin.Run(conn, time.Second, target)

	assert.Nil(t, err)
	assert.Nil(t, service)
}

func TestRunInitResponseWrongFirstByte(t *testing.T) {
	plugin := &GESRTPPlugin{}
	// Valid length but wrong first byte (not 0x01)
	response := make([]byte, 56)
	response[0] = 0x02 // Wrong byte (should be 0x01)
	response[8] = 0x0f // Correct protocol ID
	conn := &mockConn{responses: [][]byte{response}}
	target := plugins.Target{Host: "192.168.1.1"}

	service, err := plugin.Run(conn, time.Second, target)

	assert.Nil(t, err)
	assert.Nil(t, service)
}

func TestRunInitResponseWrongProtocolID(t *testing.T) {
	plugin := &GESRTPPlugin{}
	// Valid length and first byte but wrong protocol ID
	response := make([]byte, 56)
	response[0] = 0x01 // Correct init response byte
	response[8] = 0x10 // Wrong protocol ID (should be 0x0f)
	conn := &mockConn{responses: [][]byte{response}}
	target := plugins.Target{Host: "192.168.1.1"}

	service, err := plugin.Run(conn, time.Second, target)

	assert.Nil(t, err)
	assert.Nil(t, service)
}

func TestRunValidInitButFailedSCADAEnable(t *testing.T) {
	plugin := &GESRTPPlugin{}
	// Valid init response
	initResponse := make([]byte, 56)
	initResponse[0] = 0x01 // Init response
	initResponse[8] = 0x0f // Protocol ID

	// Invalid SCADA enable response (wrong first byte)
	scadaResponse := make([]byte, 56)
	scadaResponse[0] = 0x02 // Wrong (should be 0x03)

	conn := &mockConn{responses: [][]byte{initResponse, scadaResponse}}
	target := plugins.Target{Host: "192.168.1.1"}

	service, err := plugin.Run(conn, time.Second, target)

	assert.Nil(t, err)
	assert.Nil(t, service)
}

func TestRunValidInitAndSCADAButNoControllerType(t *testing.T) {
	plugin := &GESRTPPlugin{}
	// Valid init response
	initResponse := make([]byte, 56)
	initResponse[0] = 0x01 // Init response
	initResponse[8] = 0x0f // Protocol ID

	// Valid SCADA enable response
	scadaResponse := make([]byte, 56)
	scadaResponse[0] = 0x03 // Return response

	// Empty controller type response
	conn := &mockConn{responses: [][]byte{initResponse, scadaResponse, {}}}
	target := plugins.Target{Host: "192.168.1.1"}

	service, err := plugin.Run(conn, time.Second, target)

	// Should still return service (basic detection succeeded)
	assert.Nil(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "gesrtp", service.Protocol)
}

func TestRunValidInitAndSCADAButInvalidControllerType(t *testing.T) {
	plugin := &GESRTPPlugin{}
	// Valid init response
	initResponse := make([]byte, 56)
	initResponse[0] = 0x01 // Init response
	initResponse[8] = 0x0f // Protocol ID

	// Valid SCADA enable response
	scadaResponse := make([]byte, 56)
	scadaResponse[0] = 0x03 // Return response

	// Invalid controller type response (too short)
	shortResponse := make([]byte, 30)
	conn := &mockConn{responses: [][]byte{initResponse, scadaResponse, shortResponse}}
	target := plugins.Target{Host: "192.168.1.1"}

	service, err := plugin.Run(conn, time.Second, target)

	// Should still return service (basic detection succeeded)
	assert.Nil(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "gesrtp", service.Protocol)
}

func TestRunFullValidExchange96ByteResponse(t *testing.T) {
	plugin := &GESRTPPlugin{}
	// Valid init response
	initResponse := make([]byte, 56)
	initResponse[0] = 0x01 // Init response
	initResponse[8] = 0x0f // Protocol ID

	// Valid SCADA enable response
	scadaResponse := make([]byte, 56)
	scadaResponse[0] = 0x03 // Return response

	// Valid controller type response (96 bytes = header + payload)
	ctrlResponse := make([]byte, 96)
	// Header (56 bytes)
	ctrlResponse[0] = 0x03 // Return response
	// Set text_length to 40 (LE uint16 at bytes 4-5)
	ctrlResponse[4] = 0x28 // 40 in little-endian (low byte)
	ctrlResponse[5] = 0x00 // high byte

	// Payload (40 bytes starting at offset 56)
	// Service echo at payload offset 8
	ctrlResponse[56+8] = 0x43
	// Device indicator at payload offset 9
	ctrlResponse[56+9] = 0x0a // Series 90/RX3i
	// PLC name at payload offset 12 (8 bytes max)
	plcName := "LSPS"
	copy(ctrlResponse[56+12:], []byte(plcName))

	conn := &mockConn{responses: [][]byte{initResponse, scadaResponse, ctrlResponse}}
	target := plugins.Target{Host: "192.168.1.1"}

	service, err := plugin.Run(conn, time.Second, target)

	assert.Nil(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "gesrtp", service.Protocol)

	// Verify metadata
	metadata := service.Metadata().(plugins.ServiceGESRTP)
	assert.Equal(t, "LSPS", metadata.PLCName)
	assert.Equal(t, uint8(0x0a), metadata.DeviceIndicator)
	assert.NotEmpty(t, metadata.CPEs)
}

func TestRunFullValidExchangeSplitResponse(t *testing.T) {
	plugin := &GESRTPPlugin{}
	// Valid init response
	initResponse := make([]byte, 56)
	initResponse[0] = 0x01 // Init response
	initResponse[8] = 0x0f // Protocol ID

	// Valid SCADA enable response
	scadaResponse := make([]byte, 56)
	scadaResponse[0] = 0x03 // Return response

	// Controller type response split into header (56 bytes) and payload (40 bytes)
	ctrlHeader := make([]byte, 56)
	ctrlHeader[0] = 0x03 // Return response
	// Set text_length to 40 (LE uint16 at bytes 4-5)
	ctrlHeader[4] = 0x28 // 40 in little-endian
	ctrlHeader[5] = 0x00

	ctrlPayload := make([]byte, 40)
	// Service echo at payload offset 8
	ctrlPayload[8] = 0x43
	// Device indicator at payload offset 9
	ctrlPayload[9] = 0x12 // PACSystems
	// PLC name at payload offset 12
	plcName := "PSRE_PL"
	copy(ctrlPayload[12:], []byte(plcName))

	conn := &mockConn{responses: [][]byte{initResponse, scadaResponse, ctrlHeader, ctrlPayload}}
	target := plugins.Target{Host: "192.168.1.1"}

	service, err := plugin.Run(conn, time.Second, target)

	assert.Nil(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "gesrtp", service.Protocol)

	// Verify metadata
	metadata := service.Metadata().(plugins.ServiceGESRTP)
	assert.Equal(t, "PSRE_PL", metadata.PLCName)
	assert.Equal(t, uint8(0x12), metadata.DeviceIndicator)
	assert.NotEmpty(t, metadata.CPEs)
}

func TestExtractNullTerminatedString(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected string
	}{
		{
			name:     "Simple string",
			input:    []byte("HELLO\x00\x00\x00"),
			expected: "HELLO",
		},
		{
			name:     "Full length no null",
			input:    []byte("ABCDEFGH"),
			expected: "ABCDEFGH",
		},
		{
			name:     "Empty",
			input:    []byte("\x00\x00\x00\x00"),
			expected: "",
		},
		{
			name:     "With trailing garbage",
			input:    []byte("TEST\x00\xFF\xFF\xFF"),
			expected: "TEST",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractNullTerminatedString(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateCPE(t *testing.T) {
	tests := []struct {
		name            string
		plcName         string
		expectedContain string
	}{
		{
			name:            "Generic PLC name",
			plcName:         "LSPS",
			expectedContain: "cpe:2.3:h:ge:pacsystems:",
		},
		{
			name:            "RX3I in name",
			plcName:         "RX3I_CP",
			expectedContain: "pacsystems_rx3i",
		},
		{
			name:            "Empty name",
			plcName:         "",
			expectedContain: "cpe:2.3:h:ge:pacsystems:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpes := generateCPE(tt.plcName)
			assert.NotEmpty(t, cpes)
			assert.Contains(t, cpes[0], tt.expectedContain)
		})
	}
}

func TestEOFHandling(t *testing.T) {
	plugin := &GESRTPPlugin{}
	// Mock connection that returns EOF on first read
	conn := &mockConn{responses: [][]byte{}}
	target := plugins.Target{Host: "192.168.1.1"}

	service, err := plugin.Run(conn, time.Second, target)

	// EOF gets wrapped in ReadError by utils.SendRecv, so we expect an error
	assert.NotNil(t, err)
	assert.Nil(t, service)
}

func TestTextLengthUpperBoundCheck(t *testing.T) {
	plugin := &GESRTPPlugin{}
	// Valid init response
	initResponse := make([]byte, 56)
	initResponse[0] = 0x01 // Init response
	initResponse[8] = 0x0f // Protocol ID

	// Valid SCADA enable response
	scadaResponse := make([]byte, 56)
	scadaResponse[0] = 0x03 // Return response

	// Controller type response with textLength set to 65535 (max uint16)
	ctrlHeader := make([]byte, 56)
	ctrlHeader[0] = 0x03 // Return response
	// Set text_length to 65535 (LE uint16 at bytes 4-5)
	ctrlHeader[4] = 0xFF // low byte
	ctrlHeader[5] = 0xFF // high byte

	conn := &mockConn{responses: [][]byte{initResponse, scadaResponse, ctrlHeader}}
	target := plugins.Target{Host: "192.168.1.1"}

	service, err := plugin.Run(conn, time.Second, target)

	// Should still return service (basic detection succeeded)
	assert.Nil(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "gesrtp", service.Protocol)

	// Verify metadata is empty (textLength capped, no payload parsed)
	metadata := service.Metadata().(plugins.ServiceGESRTP)
	assert.Equal(t, "", metadata.PLCName)
	assert.Equal(t, uint8(0), metadata.DeviceIndicator)
}
