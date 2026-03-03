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

package m2ua

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TestM2UAPlugin_Run_ValidASPUpAck tests detection with valid ASP Up Ack
func TestM2UAPlugin_Run_ValidASPUpAck(t *testing.T) {
	// Build valid ASP Up Ack (Class 3, Type 4)
	response := buildValidASPUpAck()

	// Create mock connection
	conn := &mockConn{
		readData: response,
	}

	plugin := &M2UAPlugin{}
	target := plugins.Target{
		Host: "test.m2ua.local",
	}

	service, err := plugin.Run(conn, time.Second, target)

	require.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, M2UA_SCTP, service.Protocol)
	assert.Equal(t, "test.m2ua.local", service.Host)

	// Verify metadata
	assert.NotEmpty(t, service.Raw)
}

// TestM2UAPlugin_Run_ErrorResponse tests handling of error responses
func TestM2UAPlugin_Run_ErrorResponse(t *testing.T) {
	// Build valid Error message (Class 0, Type 0)
	response := buildValidErrorResponse()

	conn := &mockConn{
		readData: response,
	}

	plugin := &M2UAPlugin{}
	target := plugins.Target{
		Host: "test.m2ua.local",
	}

	service, err := plugin.Run(conn, time.Second, target)

	// Error response should still return a service (detected but with error)
	require.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, M2UA_SCTP, service.Protocol)
}

// TestM2UAPlugin_Run_InvalidResponse tests rejection of invalid responses
func TestM2UAPlugin_Run_InvalidResponse(t *testing.T) {
	// Build response with wrong version
	response := make([]byte, 20)
	response[0] = 0x02 // Wrong version (should be 0x01)

	conn := &mockConn{
		readData: response,
	}

	plugin := &M2UAPlugin{}
	target := plugins.Target{
		Host: "test.m2ua.local",
	}

	service, err := plugin.Run(conn, time.Second, target)

	assert.Error(t, err)
	assert.Nil(t, service)
}

// TestM2UAPlugin_PortPriority tests default port recognition
func TestM2UAPlugin_PortPriority(t *testing.T) {
	plugin := &M2UAPlugin{}

	assert.True(t, plugin.PortPriority(2904))
	assert.False(t, plugin.PortPriority(2905))
	assert.False(t, plugin.PortPriority(80))
}

// TestM2UAPlugin_Name tests plugin name
func TestM2UAPlugin_Name(t *testing.T) {
	plugin := &M2UAPlugin{}
	assert.Equal(t, M2UA_SCTP, plugin.Name())
}

// TestM2UAPlugin_Type tests protocol type
func TestM2UAPlugin_Type(t *testing.T) {
	plugin := &M2UAPlugin{}
	assert.Equal(t, plugins.SCTP, plugin.Type())
}

// TestM2UAPlugin_Priority tests plugin priority
func TestM2UAPlugin_Priority(t *testing.T) {
	plugin := &M2UAPlugin{}
	assert.Equal(t, 60, plugin.Priority())
}

// TestBuildASPUp tests ASP Up message construction
func TestBuildASPUp(t *testing.T) {
	aspUp := buildASPUp()

	assert.NotNil(t, aspUp)
	assert.GreaterOrEqual(t, len(aspUp), 8) // Minimum SIGTRAN header size

	// Check SIGTRAN header
	assert.Equal(t, byte(0x01), aspUp[0], "version should be 1")
	assert.Equal(t, byte(0x00), aspUp[1], "reserved should be 0")
	assert.Equal(t, byte(0x03), aspUp[2], "message class should be 3 (ASPSM)")
	assert.Equal(t, byte(0x01), aspUp[3], "message type should be 1 (ASP Up)")

	// Check message length
	msgLength := binary.BigEndian.Uint32(aspUp[4:8])
	assert.Equal(t, uint32(len(aspUp)), msgLength)
	assert.GreaterOrEqual(t, msgLength, uint32(8))
	assert.Equal(t, uint32(0), msgLength%4, "length must be multiple of 4")
}

// TestValidateASPUpAck tests ASP Up Ack validation
func TestValidateASPUpAck(t *testing.T) {
	tests := []struct {
		name      string
		response  []byte
		wantError bool
	}{
		{
			name:      "valid ASP Up Ack",
			response:  buildValidASPUpAck(),
			wantError: false,
		},
		{
			name:      "valid Error response",
			response:  buildValidErrorResponse(),
			wantError: false,
		},
		{
			name:      "too short",
			response:  []byte{0x01, 0x00},
			wantError: true,
		},
		{
			name: "wrong version",
			response: func() []byte {
				msg := buildValidASPUpAck()
				msg[0] = 0x02 // Wrong version
				return msg
			}(),
			wantError: true,
		},
		{
			name: "invalid message class",
			response: func() []byte {
				msg := buildValidASPUpAck()
				msg[2] = 0xFF // Invalid class
				return msg
			}(),
			wantError: true,
		},
		{
			name: "non-zero reserved byte",
			response: func() []byte {
				msg := buildValidASPUpAck()
				msg[1] = 0x01
				return msg
			}(),
			wantError: true,
		},
		{
			name: "message length below minimum",
			response: func() []byte {
				msg := buildValidASPUpAck()
				binary.BigEndian.PutUint32(msg[4:8], 4)
				return msg
			}(),
			wantError: true,
		},
		{
			name: "message length not multiple of 4",
			response: func() []byte {
				msg := make([]byte, 12)
				msg[0] = 0x01
				msg[2] = 0x03
				msg[3] = 0x04
				binary.BigEndian.PutUint32(msg[4:8], 9)
				return msg
			}(),
			wantError: true,
		},
		{
			name: "message length exceeds received bytes",
			response: func() []byte {
				msg := buildValidASPUpAck()
				binary.BigEndian.PutUint32(msg[4:8], 100)
				return msg
			}(),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateASPUpAck(tt.response)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper functions

// buildValidASPUpAck creates a valid ASP Up Ack response
func buildValidASPUpAck() []byte {
	// SIGTRAN Common Header (8 bytes)
	header := make([]byte, 8)
	header[0] = 0x01 // Version
	header[1] = 0x00 // Reserved
	header[2] = 0x03 // Message Class: ASPSM
	header[3] = 0x04 // Message Type: ASP Up Ack

	// Message Length (including header)
	binary.BigEndian.PutUint32(header[4:8], 8)

	return header
}

// buildValidErrorResponse creates a valid Error response
func buildValidErrorResponse() []byte {
	// SIGTRAN Common Header (8 bytes)
	header := make([]byte, 8)
	header[0] = 0x01 // Version
	header[1] = 0x00 // Reserved
	header[2] = 0x00 // Message Class: MGMT (Management)
	header[3] = 0x00 // Message Type: Error

	// Message Length
	binary.BigEndian.PutUint32(header[4:8], 8)

	return header
}

// mockConn implements net.Conn for testing
type mockConn struct {
	readData  []byte
	writeData []byte
	readErr   error
	writeErr  error
	closed    bool
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

func (m *mockConn) Close() error {
	m.closed = true
	return nil
}

func (m *mockConn) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}
}

func (m *mockConn) RemoteAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2904}
}

func (m *mockConn) SetDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (m *mockConn) SetWriteDeadline(t time.Time) error {
	return nil
}
