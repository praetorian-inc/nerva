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

package m2pa

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TestM2PAPlugin_Run_ValidLinkStatus tests detection with valid Link Status response
func TestM2PAPlugin_Run_ValidLinkStatus(t *testing.T) {
	response := buildValidLinkStatusResponse(LinkStateReady)

	conn := &mockConn{
		readData: response,
	}

	plugin := &M2PAPlugin{}
	target := plugins.Target{
		Host: "test.m2pa.local",
	}

	service, err := plugin.Run(conn, time.Second, target)

	require.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, M2PA_SCTP, service.Protocol)
	assert.Equal(t, "test.m2pa.local", service.Host)
	assert.NotEmpty(t, service.Raw)
}

// TestM2PAPlugin_Run_ErrorResponse tests handling of error responses
func TestM2PAPlugin_Run_ErrorResponse(t *testing.T) {
	response := buildValidErrorResponse()

	conn := &mockConn{
		readData: response,
	}

	plugin := &M2PAPlugin{}
	target := plugins.Target{
		Host: "test.m2pa.local",
	}

	service, err := plugin.Run(conn, time.Second, target)

	require.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, M2PA_SCTP, service.Protocol)
}

// TestM2PAPlugin_Run_InvalidResponse tests rejection of invalid responses
func TestM2PAPlugin_Run_InvalidResponse(t *testing.T) {
	response := make([]byte, 20)
	response[0] = 0x02 // Wrong version

	conn := &mockConn{
		readData: response,
	}

	plugin := &M2PAPlugin{}
	target := plugins.Target{
		Host: "test.m2pa.local",
	}

	service, err := plugin.Run(conn, time.Second, target)

	assert.Error(t, err)
	assert.Nil(t, service)
}

// TestM2PAPlugin_PortPriority tests default port recognition
func TestM2PAPlugin_PortPriority(t *testing.T) {
	plugin := &M2PAPlugin{}

	assert.True(t, plugin.PortPriority(3565))
	assert.False(t, plugin.PortPriority(2905))
	assert.False(t, plugin.PortPriority(2904))
	assert.False(t, plugin.PortPriority(80))
}

// TestM2PAPlugin_Name tests plugin name
func TestM2PAPlugin_Name(t *testing.T) {
	plugin := &M2PAPlugin{}
	assert.Equal(t, M2PA_SCTP, plugin.Name())
}

// TestM2PAPlugin_Type tests protocol type
func TestM2PAPlugin_Type(t *testing.T) {
	plugin := &M2PAPlugin{}
	assert.Equal(t, plugins.SCTP, plugin.Type())
}

// TestM2PAPlugin_Priority tests plugin priority
func TestM2PAPlugin_Priority(t *testing.T) {
	plugin := &M2PAPlugin{}
	assert.Equal(t, 60, plugin.Priority())
}

// TestBuildLinkStatus tests Link Status probe message construction
func TestBuildLinkStatus(t *testing.T) {
	msg := buildLinkStatus()

	assert.NotNil(t, msg)
	assert.Equal(t, LINK_STATUS_LENGTH, len(msg))

	// Check SIGTRAN header
	assert.Equal(t, byte(0x01), msg[0], "version should be 1")
	assert.Equal(t, byte(0x00), msg[1], "reserved should be 0")
	assert.Equal(t, byte(0x0B), msg[2], "message class should be 11 (M2PA)")
	assert.Equal(t, byte(0x02), msg[3], "message type should be 2 (Link Status)")

	// Check message length
	msgLength := binary.BigEndian.Uint32(msg[4:8])
	assert.Equal(t, uint32(LINK_STATUS_LENGTH), msgLength)
	assert.Equal(t, uint32(0), msgLength%4, "length must be multiple of 4")

	// Check link status value (Alignment = 1)
	linkState := binary.BigEndian.Uint32(msg[16:20])
	assert.Equal(t, uint32(LinkStateAlignment), linkState)
}

// TestValidateResponse tests response validation
func TestValidateResponse(t *testing.T) {
	tests := []struct {
		name      string
		response  []byte
		wantError bool
	}{
		{
			name:      "valid Link Status response",
			response:  buildValidLinkStatusResponse(LinkStateReady),
			wantError: false,
		},
		{
			name:      "valid Error response",
			response:  buildValidErrorResponse(),
			wantError: false,
		},
		{
			name:      "valid Link Status with Alignment",
			response:  buildValidLinkStatusResponse(LinkStateAlignment),
			wantError: false,
		},
		{
			name:      "valid Link Status with Processor Outage",
			response:  buildValidLinkStatusResponse(LinkStateProcessorOutage),
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
				msg := buildValidLinkStatusResponse(LinkStateReady)
				msg[0] = 0x02
				return msg
			}(),
			wantError: true,
		},
		{
			name: "invalid reserved byte",
			response: func() []byte {
				msg := buildValidLinkStatusResponse(LinkStateReady)
				msg[1] = 0xFF
				return msg
			}(),
			wantError: true,
		},
		{
			name: "invalid message class",
			response: func() []byte {
				msg := buildValidLinkStatusResponse(LinkStateReady)
				msg[2] = 0x03 // ASPSM class - not expected for M2PA-specific response
				return msg
			}(),
			wantError: true,
		},
		{
			name: "invalid M2PA message type",
			response: func() []byte {
				msg := buildValidLinkStatusResponse(LinkStateReady)
				msg[3] = 0x05 // Invalid type for M2PA class
				return msg
			}(),
			wantError: true,
		},
		{
			name: "invalid MGMT message type",
			response: func() []byte {
				msg := buildValidErrorResponse()
				msg[3] = 0x03 // Invalid MGMT type
				return msg
			}(),
			wantError: true,
		},
		{
			name: "message length exceeds response",
			response: func() []byte {
				msg := buildValidLinkStatusResponse(LinkStateReady)
				binary.BigEndian.PutUint32(msg[4:8], 100) // Length > actual
				return msg
			}(),
			wantError: true,
		},
		{
			name: "message length too small",
			response: func() []byte {
				msg := buildValidLinkStatusResponse(LinkStateReady)
				binary.BigEndian.PutUint32(msg[4:8], 4) // Less than header
				return msg
			}(),
			wantError: true,
		},
		{
			name: "message length not multiple of 4",
			response: func() []byte {
				msg := make([]byte, 21)
				msg[0] = 0x01
				msg[1] = 0x00
				msg[2] = M2PA_MSG_CLASS
				msg[3] = M2PA_LINK_STATUS
				binary.BigEndian.PutUint32(msg[4:8], 21) // Not multiple of 4
				return msg
			}(),
			wantError: true,
		},
		{
			name: "valid User Data response",
			response: func() []byte {
				msg := buildValidLinkStatusResponse(0)
				msg[3] = M2PA_USER_DATA // Type 1
				return msg
			}(),
			wantError: false,
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

// TestEnrichM2PA_LinkStatus tests enrichment of Link Status responses
func TestEnrichM2PA_LinkStatus(t *testing.T) {
	tests := []struct {
		name          string
		linkState     uint32
		wantStateName string
	}{
		{"alignment", LinkStateAlignment, "Alignment"},
		{"proving normal", LinkStateProvingNormal, "Proving Normal"},
		{"proving emergency", LinkStateProvingEmergency, "Proving Emergency"},
		{"ready", LinkStateReady, "Ready"},
		{"processor outage", LinkStateProcessorOutage, "Processor Outage"},
		{"processor recovered", LinkStateProcessorRecov, "Processor Recovered"},
		{"busy", LinkStateBusy, "Busy"},
		{"busy ended", LinkStateBusyEnded, "Busy Ended"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := buildValidLinkStatusResponse(tt.linkState)

			msgClass, msgType, linkState, errorCode, infoStr, err := enrichM2PA(response)

			require.NoError(t, err)
			assert.Equal(t, uint8(M2PA_MSG_CLASS), msgClass)
			assert.Equal(t, uint8(M2PA_LINK_STATUS), msgType)
			assert.Equal(t, tt.linkState, linkState)
			assert.Equal(t, uint32(0), errorCode)
			assert.Empty(t, infoStr)
			assert.Equal(t, tt.wantStateName, linkStateName(linkState))
		})
	}
}

// TestEnrichM2PA_Error tests enrichment of Error responses with TLV parameters
func TestEnrichM2PA_Error(t *testing.T) {
	response := buildErrorWithParams(7, "M2PA test error")

	msgClass, msgType, linkState, errorCode, infoStr, err := enrichM2PA(response)

	require.NoError(t, err)
	assert.Equal(t, uint8(MGMT_CLASS), msgClass)
	assert.Equal(t, uint8(ERROR_TYPE), msgType)
	assert.Equal(t, uint32(0), linkState)
	assert.Equal(t, uint32(7), errorCode)
	assert.Equal(t, "M2PA test error", infoStr)
}

// TestEnrichM2PA_HeaderOnly tests enrichment with no payload
func TestEnrichM2PA_HeaderOnly(t *testing.T) {
	response := buildValidErrorResponse()

	msgClass, msgType, linkState, errorCode, infoStr, err := enrichM2PA(response)

	require.NoError(t, err)
	assert.Equal(t, uint8(MGMT_CLASS), msgClass)
	assert.Equal(t, uint8(ERROR_TYPE), msgType)
	assert.Equal(t, uint32(0), linkState)
	assert.Equal(t, uint32(0), errorCode)
	assert.Empty(t, infoStr)
}

// TestEnrichM2PA_TooShort tests enrichment with too-short response
func TestEnrichM2PA_TooShort(t *testing.T) {
	_, _, _, _, _, err := enrichM2PA([]byte{0x01})

	assert.Error(t, err)
}

// TestLinkStateName tests link state name mapping
func TestLinkStateName(t *testing.T) {
	assert.Equal(t, "Alignment", linkStateName(1))
	assert.Equal(t, "Proving Normal", linkStateName(2))
	assert.Equal(t, "Proving Emergency", linkStateName(3))
	assert.Equal(t, "Ready", linkStateName(4))
	assert.Equal(t, "Processor Outage", linkStateName(5))
	assert.Equal(t, "Processor Recovered", linkStateName(6))
	assert.Equal(t, "Busy", linkStateName(7))
	assert.Equal(t, "Busy Ended", linkStateName(8))
	assert.Equal(t, "", linkStateName(0))
	assert.Equal(t, "", linkStateName(99))
}

// TestServiceM2PA_Type tests metadata interface implementation
func TestServiceM2PA_Type(t *testing.T) {
	s := ServiceM2PA{}
	assert.Equal(t, M2PA_SCTP, s.Type())
}

// Helper functions

// buildValidLinkStatusResponse creates a valid M2PA Link Status response
func buildValidLinkStatusResponse(linkState uint32) []byte {
	msg := make([]byte, LINK_STATUS_LENGTH)
	msg[0] = 0x01             // Version
	msg[1] = 0x00             // Reserved
	msg[2] = M2PA_MSG_CLASS   // Message Class: M2PA (11)
	msg[3] = M2PA_LINK_STATUS // Message Type: Link Status (2)

	binary.BigEndian.PutUint32(msg[4:8], LINK_STATUS_LENGTH)

	// BSN = 0, FSN = 0 (already zeroed)

	// Link Status
	binary.BigEndian.PutUint32(msg[16:20], linkState)

	return msg
}

// buildValidErrorResponse creates a valid Error response (header only)
func buildValidErrorResponse() []byte {
	header := make([]byte, 8)
	header[0] = 0x01 // Version
	header[1] = 0x00 // Reserved
	header[2] = 0x00 // Message Class: MGMT
	header[3] = 0x00 // Message Type: Error

	binary.BigEndian.PutUint32(header[4:8], 8)

	return header
}

// buildErrorWithParams creates an Error response with Error Code and Info String TLV params
func buildErrorWithParams(errorCode uint32, infoString string) []byte {
	// Error Code TLV: Tag(2) + Length(2) + Value(4) = 8 bytes
	// Info String TLV: Tag(2) + Length(2) + Value(variable) padded to 4
	infoLen := len(infoString)
	infoPadded := infoLen
	if infoPadded%4 != 0 {
		infoPadded += 4 - (infoPadded % 4)
	}

	totalLength := HEADER_LENGTH + 8 + 4 + infoPadded // header + error TLV + info header + info padded
	msg := make([]byte, totalLength)

	// Header
	msg[0] = 0x01
	msg[1] = 0x00
	msg[2] = MGMT_CLASS
	msg[3] = ERROR_TYPE
	binary.BigEndian.PutUint32(msg[4:8], uint32(totalLength))

	// Error Code TLV (Tag 0x000c)
	offset := HEADER_LENGTH
	binary.BigEndian.PutUint16(msg[offset:offset+2], 0x000c)
	binary.BigEndian.PutUint16(msg[offset+2:offset+4], 8) // Length = tag(2) + len(2) + value(4)
	binary.BigEndian.PutUint32(msg[offset+4:offset+8], errorCode)

	// Info String TLV (Tag 0x0004)
	offset += 8
	binary.BigEndian.PutUint16(msg[offset:offset+2], 0x0004)
	binary.BigEndian.PutUint16(msg[offset+2:offset+4], uint16(4+infoLen))
	copy(msg[offset+4:offset+4+infoLen], infoString)

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
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 3565}
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
