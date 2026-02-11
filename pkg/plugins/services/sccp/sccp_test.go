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

package sccp

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockConn implements net.Conn for testing
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

// buildSCCPHeader creates a valid SCCP header
func buildSCCPHeader(length uint32, messageID uint32) []byte {
	header := make([]byte, 12)
	binary.LittleEndian.PutUint32(header[0:4], length)
	binary.LittleEndian.PutUint32(header[4:8], 0)       // Reserved
	binary.LittleEndian.PutUint32(header[8:12], messageID)
	return header
}

// buildStationRegisterAckMessage creates a mock RegisterAckMessage (0x0081)
func buildStationRegisterAckMessage(keepAlive, dateTemplate uint32, secondaryKeepAlive uint32, protocolVersion uint32) []byte {
	// SCCP Header (12 bytes) + Payload
	payload := make([]byte, 28)
	binary.LittleEndian.PutUint32(payload[0:4], keepAlive)
	binary.LittleEndian.PutUint32(payload[4:8], dateTemplate)
	binary.LittleEndian.PutUint32(payload[8:12], secondaryKeepAlive)
	binary.LittleEndian.PutUint32(payload[12:16], protocolVersion)

	header := buildSCCPHeader(uint32(len(payload)), 0x0081) // RegisterAckMessage ID
	return append(header, payload...)
}

// buildStationRegisterRejectMessage creates a mock RegisterRejectMessage (0x009D)
func buildStationRegisterRejectMessage(errorMessage string) []byte {
	// SCCP Header + Error text (32 bytes max)
	payload := make([]byte, 32)
	copy(payload, errorMessage)

	header := buildSCCPHeader(uint32(len(payload)), 0x009D) // RegisterRejectMessage ID
	return append(header, payload...)
}

func TestPlugin_Name(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, SCCP, p.Name())
}

func TestPlugin_Type(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, plugins.TCP, p.Type())
}

func TestPlugin_Priority(t *testing.T) {
	p := &Plugin{}
	assert.Equal(t, 150, p.Priority())
}

func TestPlugin_PortPriority(t *testing.T) {
	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{"default port 2000", 2000, true},
		{"secure port 2443", 2443, true},
		{"other port", 8080, false},
	}

	p := &Plugin{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := p.PortPriority(tt.port)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestPlugin_Run(t *testing.T) {
	tests := []struct {
		name           string
		response       []byte
		expectedError  bool
		expectedNil    bool
		expectedDevice string
		expectedProto  string
	}{
		{
			name:           "valid RegisterAckMessage",
			response:       buildStationRegisterAckMessage(30, 0, 0, 20), // Protocol version 20
			expectedError:  false,
			expectedNil:    false,
			expectedDevice: "Station",
			expectedProto:  "20",
		},
		{
			name:          "empty response",
			response:      []byte{},
			expectedError: false,
			expectedNil:   true,
		},
		{
			name:          "too short response",
			response:      []byte{0x01, 0x02, 0x03},
			expectedError: false,
			expectedNil:   true,
		},
		{
			name:          "invalid SCCP header - wrong reserved field",
			response:      append([]byte{0x14, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0x81, 0x00, 0x00, 0x00}, make([]byte, 20)...),
			expectedError: false,
			expectedNil:   true,
		},
		{
			name:          "valid header but unknown message ID",
			response:      append(buildSCCPHeader(20, 0x9999), make([]byte, 20)...),
			expectedError: false,
			expectedNil:   true,
		},
		{
			name:          "RegisterRejectMessage",
			response:      buildStationRegisterRejectMessage("Device not authorized"),
			expectedError: false,
			expectedNil:   true,
		},
		{
			name:           "RegisterAckMessage with different protocol version",
			response:       buildStationRegisterAckMessage(30, 0, 0, 11), // Protocol version 11
			expectedError:  false,
			expectedNil:    false,
			expectedDevice: "Station",
			expectedProto:  "11",
		},
		{
			name:          "header length mismatch",
			response:      append(buildSCCPHeader(100, 0x0081), make([]byte, 10)...),
			expectedError: false,
			expectedNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{readData: tt.response}
			p := &Plugin{}
			target := plugins.Target{Host: "test.local"}

			service, err := p.Run(conn, 2*time.Second, target)

			if tt.expectedError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}

			if tt.expectedNil {
				assert.Nil(t, service)
			} else {
				require.NotNil(t, service)
				assert.Equal(t, "sccp", service.Protocol)
				assert.Equal(t, "tcp", service.Transport)

				// Verify metadata
				metadata := service.Metadata()
				require.NotNil(t, metadata)
				sccpMetadata, ok := metadata.(plugins.ServiceSCCP)
				require.True(t, ok, "metadata should be ServiceSCCP type")

				if tt.expectedDevice != "" {
					assert.Equal(t, tt.expectedDevice, sccpMetadata.DeviceType)
				}
				if tt.expectedProto != "" {
					assert.Equal(t, tt.expectedProto, sccpMetadata.ProtocolVersion)
				}
			}
		})
	}
}

func TestIsValidSCCPHeader(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "valid header with complete payload",
			data:     append(buildSCCPHeader(20, 0x0081), make([]byte, 20)...),
			expected: true,
		},
		{
			name:     "too short",
			data:     []byte{0x01, 0x02, 0x03},
			expected: false,
		},
		{
			name:     "non-zero reserved field",
			data:     []byte{0x14, 0x00, 0x00, 0x00, 0xFF, 0x00, 0x00, 0x00, 0x81, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "zero length",
			data:     buildSCCPHeader(0, 0x0081),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isValidSCCPHeader(tt.data)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildStationRegisterMessage(t *testing.T) {
	packet := buildStationRegisterMessage()

	// Should have 12-byte header + payload
	require.GreaterOrEqual(t, len(packet), 12)

	// Verify header structure
	length := binary.LittleEndian.Uint32(packet[0:4])
	assert.Greater(t, length, uint32(0))

	reserved := binary.LittleEndian.Uint32(packet[4:8])
	assert.Equal(t, uint32(0), reserved)

	messageID := binary.LittleEndian.Uint32(packet[8:12])
	assert.Equal(t, uint32(0x0001), messageID) // StationRegisterMessage ID
}

func TestExtractDeviceInfo(t *testing.T) {
	tests := []struct {
		name             string
		response         []byte
		expectedDevice   string
		expectedVersion  string
		expectedMaxStreams int
	}{
		{
			name:             "standard response with version 20",
			response:         buildStationRegisterAckMessage(30, 0, 0, 20),
			expectedDevice:   "Station",
			expectedVersion:  "20",
			expectedMaxStreams: 0,
		},
		{
			name:             "response with version 11",
			response:         buildStationRegisterAckMessage(30, 0, 0, 11),
			expectedDevice:   "Station",
			expectedVersion:  "11",
			expectedMaxStreams: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := extractDeviceInfo(tt.response)
			assert.Equal(t, tt.expectedDevice, info.DeviceType)
			assert.Equal(t, tt.expectedVersion, info.ProtocolVersion)
		})
	}
}
