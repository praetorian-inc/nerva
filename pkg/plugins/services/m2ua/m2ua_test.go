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
	response := buildValidASPUpAck()

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
	assert.NotEmpty(t, service.Raw)
}

// TestM2UAPlugin_Run_ErrorResponse tests handling of error responses
func TestM2UAPlugin_Run_ErrorResponse(t *testing.T) {
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

// TestM2UAPlugin_Run_MAUPResponse tests detection with MAUP class response (M2UA-unique)
func TestM2UAPlugin_Run_MAUPResponse(t *testing.T) {
	response := buildValidMAUPResponse()

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
	assert.False(t, plugin.PortPriority(2905)) // M3UA port, not M2UA
	assert.False(t, plugin.PortPriority(3868))
	assert.False(t, plugin.PortPriority(80))
}

// TestM2UAPlugin_Name tests plugin name
func TestM2UAPlugin_Name(t *testing.T) {
	plugin := &M2UAPlugin{}
	assert.Equal(t, M2UA_SCTP, plugin.Name())
	assert.Equal(t, "m2ua", plugin.Name())
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

// TestValidateResponse tests response validation including MAUP class
func TestValidateResponse(t *testing.T) {
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
			name:      "valid MAUP response (M2UA-unique)",
			response:  buildValidMAUPResponse(),
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
			name: "invalid reserved byte",
			response: func() []byte {
				msg := buildValidASPUpAck()
				msg[1] = 0x01 // Non-zero reserved
				return msg
			}(),
			wantError: true,
		},
		{
			name: "invalid message class",
			response: func() []byte {
				msg := buildValidASPUpAck()
				msg[2] = 0xFF // Invalid class (not ASPSM=3, MGMT=0, or MAUP=6)
				return msg
			}(),
			wantError: true,
		},
		{
			name: "invalid ASPSM message type",
			response: func() []byte {
				msg := buildValidASPUpAck()
				msg[3] = 0x02 // Wrong type for ASPSM (should be 0x04 ASP Up Ack)
				return msg
			}(),
			wantError: true,
		},
		{
			name: "invalid MGMT message type",
			response: func() []byte {
				msg := buildValidErrorResponse()
				msg[3] = 0x01 // Wrong type for MGMT (should be 0x00 Error)
				return msg
			}(),
			wantError: true,
		},
		{
			name: "length too small",
			response: func() []byte {
				msg := buildValidASPUpAck()
				binary.BigEndian.PutUint32(msg[4:8], 4) // Length < 8 (minimum header)
				return msg
			}(),
			wantError: true,
		},
		{
			name: "length not multiple of 4",
			response: func() []byte {
				// Build a longer message with non-multiple-of-4 length
				msg := make([]byte, 12)
				msg[0] = 0x01 // Version
				msg[1] = 0x00 // Reserved
				msg[2] = 0x03 // ASPSM class
				msg[3] = 0x04 // ASP Up Ack
				binary.BigEndian.PutUint32(msg[4:8], 9) // Not a multiple of 4
				return msg
			}(),
			wantError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateResponse(tt.response)
			if tt.wantError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// TestEnrichM2UA_ErrorCode tests extraction of error code TLV parameter
func TestEnrichM2UA_ErrorCode(t *testing.T) {
	// Build a MGMT Error message with an Error Code parameter (Tag 0x000c)
	errCode := uint32(0x00000001) // Error code value
	response := buildResponseWithErrorCode(errCode)

	messageClass, messageType, extractedErrCode, infoString, err := enrichM2UA(response)

	require.NoError(t, err)
	assert.Equal(t, uint8(MGMT_CLASS), messageClass)
	assert.Equal(t, uint8(ERROR_TYPE), messageType)
	assert.Equal(t, errCode, extractedErrCode)
	assert.Empty(t, infoString)
}

// TestEnrichM2UA_InfoString tests extraction of info string TLV parameter
func TestEnrichM2UA_InfoString(t *testing.T) {
	// Build an ASP Up Ack with an Info String parameter (Tag 0x0004)
	infoStr := "M2UA test"
	response := buildResponseWithInfoString(infoStr)

	messageClass, messageType, errorCode, extractedInfo, err := enrichM2UA(response)

	require.NoError(t, err)
	assert.Equal(t, uint8(ASPSM_CLASS), messageClass)
	assert.Equal(t, uint8(ASP_UP_ACK), messageType)
	assert.Equal(t, uint32(0), errorCode)
	assert.Equal(t, infoStr, extractedInfo)
}

// TestEnrichM2UA_HeaderOnly tests enrichment of a header-only response
func TestEnrichM2UA_HeaderOnly(t *testing.T) {
	response := buildValidASPUpAck()

	messageClass, messageType, errorCode, infoString, err := enrichM2UA(response)

	require.NoError(t, err)
	assert.Equal(t, uint8(ASPSM_CLASS), messageClass)
	assert.Equal(t, uint8(ASP_UP_ACK), messageType)
	assert.Equal(t, uint32(0), errorCode)
	assert.Empty(t, infoString)
}

// Helper functions

// buildValidASPUpAck creates a valid ASP Up Ack response (Class 3, Type 4)
func buildValidASPUpAck() []byte {
	header := make([]byte, 8)
	header[0] = 0x01 // Version
	header[1] = 0x00 // Reserved
	header[2] = 0x03 // Message Class: ASPSM
	header[3] = 0x04 // Message Type: ASP Up Ack
	binary.BigEndian.PutUint32(header[4:8], 8)
	return header
}

// buildValidErrorResponse creates a valid Error response (Class 0, Type 0)
func buildValidErrorResponse() []byte {
	header := make([]byte, 8)
	header[0] = 0x01 // Version
	header[1] = 0x00 // Reserved
	header[2] = 0x00 // Message Class: MGMT
	header[3] = 0x00 // Message Type: Error
	binary.BigEndian.PutUint32(header[4:8], 8)
	return header
}

// buildValidMAUPResponse creates a valid MAUP response (Class 6, any type)
// MAUP (MTP2 User Adaptation Protocol) is unique to M2UA and definitively identifies it
func buildValidMAUPResponse() []byte {
	header := make([]byte, 8)
	header[0] = 0x01 // Version
	header[1] = 0x00 // Reserved
	header[2] = 0x06 // Message Class: MAUP (M2UA-unique)
	header[3] = 0x01 // Message Type: any MAUP type
	binary.BigEndian.PutUint32(header[4:8], 8)
	return header
}

// buildResponseWithErrorCode builds an Error response containing an Error Code TLV
func buildResponseWithErrorCode(errCode uint32) []byte {
	// TLV: Tag(2) + Length(2) + Value(4) = 8 bytes
	// Total: 8 (header) + 8 (TLV) = 16 bytes
	msg := make([]byte, 16)
	msg[0] = 0x01 // Version
	msg[1] = 0x00 // Reserved
	msg[2] = 0x00 // MGMT class
	msg[3] = 0x00 // Error type
	binary.BigEndian.PutUint32(msg[4:8], 16) // Total length

	// Error Code TLV: Tag=0x000c, Length=8 (4 tag+len + 4 value)
	binary.BigEndian.PutUint16(msg[8:10], 0x000c)
	binary.BigEndian.PutUint16(msg[10:12], 8)
	binary.BigEndian.PutUint32(msg[12:16], errCode)

	return msg
}

// buildResponseWithInfoString builds an ASP Up Ack containing an Info String TLV
func buildResponseWithInfoString(info string) []byte {
	infoBytes := []byte(info)
	infoLen := len(infoBytes)

	// Pad to 4-byte boundary
	paddedLen := infoLen
	if infoLen%4 != 0 {
		paddedLen += 4 - (infoLen % 4)
	}

	// TLV: Tag(2) + Length(2) + Value(infoLen) + padding
	// paramLength = 4 + infoLen (includes tag+len fields)
	paramTotalBytes := 4 + paddedLen
	totalLen := 8 + paramTotalBytes // header + TLV

	msg := make([]byte, totalLen)
	msg[0] = 0x01              // Version
	msg[1] = 0x00              // Reserved
	msg[2] = byte(ASPSM_CLASS) // ASPSM class
	msg[3] = byte(ASP_UP_ACK)  // ASP Up Ack
	binary.BigEndian.PutUint32(msg[4:8], uint32(totalLen))

	// Info String TLV: Tag=0x0004, Length=4+infoLen
	binary.BigEndian.PutUint16(msg[8:10], 0x0004)
	binary.BigEndian.PutUint16(msg[10:12], uint16(4+infoLen))
	copy(msg[12:12+infoLen], infoBytes)

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
