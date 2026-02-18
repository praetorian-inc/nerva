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

package x2ap

import (
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestX2APPlugin_Run_ValidSetupResponse tests detection with valid X2 Setup Response
func TestX2APPlugin_Run_ValidSetupResponse(t *testing.T) {
	// Build valid X2 Setup Response (Successful Outcome)
	response := buildValidX2SetupResponse()

	// Create mock connection
	conn := &mockConn{
		readData: response,
	}

	plugin := &X2APPlugin{}
	target := plugins.Target{
		Host: "test.x2ap.local",
	}

	service, err := plugin.Run(conn, time.Second, target)

	require.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, X2AP_SCTP, service.Protocol)
	assert.Equal(t, "test.x2ap.local", service.Host)

	// Verify metadata
	assert.NotEmpty(t, service.Raw)
}

// TestX2APPlugin_Run_ErrorResponse tests handling of error responses
func TestX2APPlugin_Run_ErrorResponse(t *testing.T) {
	// Build valid Unsuccessful Outcome
	response := buildValidErrorResponse()

	conn := &mockConn{
		readData: response,
	}

	plugin := &X2APPlugin{}
	target := plugins.Target{
		Host: "test.x2ap.local",
	}

	service, err := plugin.Run(conn, time.Second, target)

	// Error response should still return a service (detected but with error)
	require.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, X2AP_SCTP, service.Protocol)
}

// TestX2APPlugin_Run_InvalidResponse tests rejection of invalid responses
func TestX2APPlugin_Run_InvalidResponse(t *testing.T) {
	// Build response with invalid choice tag
	response := make([]byte, 20)
	response[0] = 0xFF // Invalid choice tag

	conn := &mockConn{
		readData: response,
	}

	plugin := &X2APPlugin{}
	target := plugins.Target{
		Host: "test.x2ap.local",
	}

	service, err := plugin.Run(conn, time.Second, target)

	assert.Error(t, err)
	assert.Nil(t, service)
}

// TestX2APPlugin_PortPriority tests default port recognition
func TestX2APPlugin_PortPriority(t *testing.T) {
	plugin := &X2APPlugin{}

	assert.True(t, plugin.PortPriority(36422))
	assert.False(t, plugin.PortPriority(2905))
	assert.False(t, plugin.PortPriority(80))
}

// TestX2APPlugin_Name tests plugin name
func TestX2APPlugin_Name(t *testing.T) {
	plugin := &X2APPlugin{}
	assert.Equal(t, X2AP_SCTP, plugin.Name())
}

// TestX2APPlugin_Type tests protocol type
func TestX2APPlugin_Type(t *testing.T) {
	plugin := &X2APPlugin{}
	assert.Equal(t, plugins.SCTP, plugin.Type())
}

// TestX2APPlugin_Priority tests plugin priority
func TestX2APPlugin_Priority(t *testing.T) {
	plugin := &X2APPlugin{}
	assert.Equal(t, 60, plugin.Priority())
}

// TestBuildX2SetupRequest tests X2 Setup Request message construction
func TestBuildX2SetupRequest(t *testing.T) {
	x2Setup := buildX2SetupRequest()

	assert.NotNil(t, x2Setup)
	assert.GreaterOrEqual(t, len(x2Setup), 4) // Minimum APER encoding size

	// Check X2AP message structure
	assert.Equal(t, byte(0x00), x2Setup[0], "should be InitiatingMessage choice")
	assert.Equal(t, byte(0x06), x2Setup[1], "procedure code should be 6 (X2Setup)")
	assert.Equal(t, byte(0x00), x2Setup[2], "criticality should be reject (0x00)")
}

// TestValidateX2SetupResponse tests X2 Setup Response validation
func TestValidateX2SetupResponse(t *testing.T) {
	tests := []struct {
		name      string
		response  []byte
		wantError bool
	}{
		{
			name:      "valid X2 Setup Response",
			response:  buildValidX2SetupResponse(),
			wantError: false,
		},
		{
			name:      "valid Unsuccessful Outcome",
			response:  buildValidErrorResponse(),
			wantError: false,
		},
		{
			name:      "too short",
			response:  []byte{0x00},
			wantError: true,
		},
		{
			name: "invalid choice tag",
			response: func() []byte {
				msg := buildValidX2SetupResponse()
				msg[0] = 0xFF // Invalid choice tag
				return msg
			}(),
			wantError: true,
		},
		{
			name: "wrong procedure code",
			response: func() []byte {
				msg := buildValidX2SetupResponse()
				msg[1] = 0xFF // Wrong procedure code
				return msg
			}(),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateX2SetupResponse(tt.response)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper functions

// buildValidX2SetupResponse creates a valid X2 Setup Response
func buildValidX2SetupResponse() []byte {
	// Minimal X2AP Successful Outcome for X2Setup
	msg := make([]byte, 4)
	msg[0] = 0x20 // Successful Outcome choice
	msg[1] = 0x06 // Procedure code: id-x2Setup (6)
	msg[2] = 0x00 // Criticality: reject
	msg[3] = 0x00 // Value length (minimal)

	return msg
}

// buildValidErrorResponse creates a valid Unsuccessful Outcome response
func buildValidErrorResponse() []byte {
	// Minimal X2AP Unsuccessful Outcome for X2Setup
	msg := make([]byte, 4)
	msg[0] = 0x40 // Unsuccessful Outcome choice
	msg[1] = 0x06 // Procedure code: id-x2Setup (6)
	msg[2] = 0x00 // Criticality: reject
	msg[3] = 0x00 // Value length (minimal)

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
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 36422}
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
