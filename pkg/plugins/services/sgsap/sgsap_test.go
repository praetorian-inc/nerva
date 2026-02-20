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

package sgsap

import (
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSGsAPPlugin_Run_ValidResponse tests detection with valid SGsAP response
func TestSGsAPPlugin_Run_ValidResponse(t *testing.T) {
	// Build valid SGsAP response (any message type 0x00-0x1f)
	response := buildValidSGsAPResponse(0x16) // SGsAP-RESET-ACK

	// Create mock connection
	conn := &mockConn{
		readData: response,
	}

	plugin := &SGsAPPlugin{}
	target := plugins.Target{
		Host: "test.sgsap.local",
	}

	service, err := plugin.Run(conn, time.Second, target)

	require.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, SGSAP_SCTP, service.Protocol)
	assert.Equal(t, "test.sgsap.local", service.Host)

	// Verify metadata
	assert.NotEmpty(t, service.Raw)
}

// TestSGsAPPlugin_Run_StatusResponse tests handling of STATUS responses
func TestSGsAPPlugin_Run_StatusResponse(t *testing.T) {
	// Build valid STATUS message (0x1d)
	response := buildValidSGsAPStatusResponse()

	conn := &mockConn{
		readData: response,
	}

	plugin := &SGsAPPlugin{}
	target := plugins.Target{
		Host: "test.sgsap.local",
	}

	service, err := plugin.Run(conn, time.Second, target)

	// STATUS response should return a service
	require.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, SGSAP_SCTP, service.Protocol)
}

// TestSGsAPPlugin_Run_InvalidResponse tests rejection of invalid responses
func TestSGsAPPlugin_Run_InvalidResponse(t *testing.T) {
	// Build response with invalid message type (> 0x1f)
	response := []byte{0x20} // Invalid message type

	conn := &mockConn{
		readData: response,
	}

	plugin := &SGsAPPlugin{}
	target := plugins.Target{
		Host: "test.sgsap.local",
	}

	service, err := plugin.Run(conn, time.Second, target)

	assert.Error(t, err)
	assert.Nil(t, service)
}

// TestSGsAPPlugin_PortPriority tests default port recognition
func TestSGsAPPlugin_PortPriority(t *testing.T) {
	plugin := &SGsAPPlugin{}

	assert.True(t, plugin.PortPriority(29118))
	assert.False(t, plugin.PortPriority(9900))
	assert.False(t, plugin.PortPriority(80))
}

// TestSGsAPPlugin_Name tests plugin name
func TestSGsAPPlugin_Name(t *testing.T) {
	plugin := &SGsAPPlugin{}
	assert.Equal(t, SGSAP_SCTP, plugin.Name())
}

// TestSGsAPPlugin_Type tests protocol type
func TestSGsAPPlugin_Type(t *testing.T) {
	plugin := &SGsAPPlugin{}
	assert.Equal(t, plugins.SCTP, plugin.Type())
}

// TestSGsAPPlugin_Priority tests plugin priority
func TestSGsAPPlugin_Priority(t *testing.T) {
	plugin := &SGsAPPlugin{}
	assert.Equal(t, 60, plugin.Priority())
}

// TestBuildSGsAPStatus tests SGsAP-STATUS message construction
func TestBuildSGsAPStatus(t *testing.T) {
	statusMsg := buildSGsAPStatus()

	assert.NotNil(t, statusMsg)
	assert.Equal(t, 4, len(statusMsg)) // STATUS message is 4 bytes

	// Check message structure
	assert.Equal(t, byte(0x1d), statusMsg[0], "message type should be 0x1d (STATUS)")
	assert.Equal(t, byte(0x08), statusMsg[1], "IEI should be 0x08 (SGs cause)")
	assert.Equal(t, byte(0x01), statusMsg[2], "length should be 0x01")
	assert.Equal(t, byte(0x01), statusMsg[3], "value should be 0x01 (IMSI detached)")
}

// TestValidateSGsAPResponse tests SGsAP response validation
func TestValidateSGsAPResponse(t *testing.T) {
	tests := []struct {
		name      string
		response  []byte
		wantError bool
	}{
		{
			name:      "valid STATUS response",
			response:  buildValidSGsAPStatusResponse(),
			wantError: false,
		},
		{
			name:      "valid PAGING-REQUEST",
			response:  buildValidSGsAPResponse(0x01),
			wantError: false,
		},
		{
			name:      "valid RESET-ACK",
			response:  buildValidSGsAPResponse(0x16),
			wantError: false,
		},
		{
			name:      "too short (empty)",
			response:  []byte{},
			wantError: true,
		},
		{
			name:      "invalid message type (too high)",
			response:  []byte{0x20},
			wantError: true,
		},
		{
			name:      "invalid message type (way too high)",
			response:  []byte{0xFF},
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateSGsAPResponse(tt.response)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestEnrichSGsAP tests metadata extraction
func TestEnrichSGsAP(t *testing.T) {
	tests := []struct {
		name           string
		response       []byte
		wantMsgType    uint8
		wantSGsCause   uint8
		wantError      bool
	}{
		{
			name:         "STATUS with SGs cause",
			response:     buildValidSGsAPStatusResponse(),
			wantMsgType:  0x1d,
			wantSGsCause: 0x01,
			wantError:    false,
		},
		{
			name:         "RESET-ACK without IEs",
			response:     buildValidSGsAPResponse(0x16),
			wantMsgType:  0x16,
			wantSGsCause: 0,
			wantError:    false,
		},
		{
			name:         "empty response",
			response:     []byte{},
			wantMsgType:  0,
			wantSGsCause: 0,
			wantError:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msgType, sgsCause, err := enrichSGsAP(tt.response)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantMsgType, msgType)
				assert.Equal(t, tt.wantSGsCause, sgsCause)
			}
		})
	}
}

// Helper functions

// buildValidSGsAPResponse creates a valid SGsAP response with given message type
func buildValidSGsAPResponse(messageType uint8) []byte {
	// Simple SGsAP message: just message type (no IEs)
	return []byte{messageType}
}

// buildValidSGsAPStatusResponse creates a valid SGsAP-STATUS response
func buildValidSGsAPStatusResponse() []byte {
	// SGsAP-STATUS message (4 bytes)
	msg := make([]byte, 4)
	msg[0] = 0x1d // Message Type: SGsAP-STATUS
	msg[1] = 0x08 // IEI: SGs cause
	msg[2] = 0x01 // Length
	msg[3] = 0x01 // Value: IMSI detached for EPS services
	return msg
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
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 29118}
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
