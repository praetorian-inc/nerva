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

package pcworx

import (
	"bytes"
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockConn implements net.Conn interface for testing
type mockConn struct {
	readBuf  *bytes.Buffer
	writeBuf *bytes.Buffer
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	return m.readBuf.Read(b)
}

func (m *mockConn) Write(b []byte) (n int, err error) {
	return m.writeBuf.Write(b)
}

func (m *mockConn) Close() error { return nil }

func (m *mockConn) LocalAddr() net.Addr { return nil }

func (m *mockConn) RemoteAddr() net.Addr { return nil }

func (m *mockConn) SetDeadline(t time.Time) error { return nil }

func (m *mockConn) SetReadDeadline(t time.Time) error { return nil }

func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func newMockConn(response []byte) *mockConn {
	return &mockConn{
		readBuf:  bytes.NewBuffer(response),
		writeBuf: &bytes.Buffer{},
	}
}

func TestPCWorxPlugin_Name(t *testing.T) {
	plugin := &PCWorxPlugin{}
	assert.Equal(t, "pcworx", plugin.Name())
}

func TestPCWorxPlugin_Type(t *testing.T) {
	plugin := &PCWorxPlugin{}
	assert.Equal(t, plugins.TCP, plugin.Type())
}

func TestPCWorxPlugin_Priority(t *testing.T) {
	plugin := &PCWorxPlugin{}
	assert.Equal(t, 400, plugin.Priority())
}

func TestPCWorxPlugin_PortPriority(t *testing.T) {
	plugin := &PCWorxPlugin{}

	tests := []struct {
		port     uint16
		expected bool
	}{
		{1962, true},
		{80, false},
		{443, false},
		{1963, false},
	}

	for _, tt := range tests {
		t.Run("", func(t *testing.T) {
			assert.Equal(t, tt.expected, plugin.PortPriority(tt.port))
		})
	}
}

func TestPCWorxPlugin_Run_EmptyResponse(t *testing.T) {
	plugin := &PCWorxPlugin{}
	conn := newMockConn([]byte{})
	target := plugins.Target{Host: "test.example.com"}

	result, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestPCWorxPlugin_Run_InitResponseTooShort(t *testing.T) {
	plugin := &PCWorxPlugin{}
	// Response less than 18 bytes
	conn := newMockConn([]byte{0x81, 0x01, 0x00, 0x10})
	target := plugins.Target{Host: "test.example.com"}

	result, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestPCWorxPlugin_Run_WrongFirstByte(t *testing.T) {
	plugin := &PCWorxPlugin{}
	// First byte is not 0x81
	response := make([]byte, 20)
	response[0] = 0x80 // Wrong byte
	conn := newMockConn(response)
	target := plugins.Target{Host: "test.example.com"}

	result, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestPCWorxPlugin_Run_ValidInitButEmptySession(t *testing.T) {
	plugin := &PCWorxPlugin{}

	// Concatenate: init response + empty session response
	initResp := make([]byte, 20)
	initResp[0] = 0x81
	initResp[17] = 0x42 // Session ID

	// Empty session response
	sessionResp := []byte{}

	fullResp := append(initResp, sessionResp...)
	conn := newMockConn(fullResp)
	target := plugins.Target{Host: "test.example.com"}

	result, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestPCWorxPlugin_Run_InvalidInfoResponse(t *testing.T) {
	plugin := &PCWorxPlugin{}

	// Init response
	initResp := make([]byte, 20)
	initResp[0] = 0x81
	initResp[17] = 0x42 // Session ID

	// Session response (non-empty)
	sessionResp := []byte{0x01, 0x02, 0x03}

	// Info response with wrong first byte
	infoResp := make([]byte, 200)
	infoResp[0] = 0x80 // Wrong byte

	fullResp := append(initResp, sessionResp...)
	fullResp = append(fullResp, infoResp...)
	conn := newMockConn(fullResp)
	target := plugins.Target{Host: "test.example.com"}

	result, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestExtractNullTerminatedString(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		offset   int
		expected string
	}{
		{
			name:     "normal string",
			data:     []byte("Hello\x00World"),
			offset:   0,
			expected: "Hello",
		},
		{
			name:     "string at offset",
			data:     []byte("xxxHello\x00"),
			offset:   3,
			expected: "Hello",
		},
		{
			name:     "offset beyond data",
			data:     []byte("Hello"),
			offset:   10,
			expected: "",
		},
		{
			name:     "no null terminator",
			data:     []byte("Hello"),
			offset:   0,
			expected: "Hello",
		},
		{
			name:     "empty at offset",
			data:     []byte("xxx\x00"),
			offset:   3,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractNullTerminatedString(tt.data, tt.offset)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestNormalizePLCType(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"ILC 151 ETH", "ilc_151_eth"},
		{"ILC151ETH", "ilc151eth"},
		{"ILC  151  ETH", "ilc__151__eth"},
		{"", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := normalizePLCType(tt.input)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGenerateCPE(t *testing.T) {
	tests := []struct {
		name        string
		plcType     string
		fwVersion   string
		expectedCPE string
	}{
		{
			name:        "with version",
			plcType:     "ILC 151 ETH",
			fwVersion:   "1.0.20",
			expectedCPE: "cpe:2.3:h:phoenixcontact:ilc_151_eth:1.0.20:*:*:*:*:*:*:*",
		},
		{
			name:        "without version",
			plcType:     "ILC 151 ETH",
			fwVersion:   "",
			expectedCPE: "cpe:2.3:h:phoenixcontact:ilc_151_eth:*:*:*:*:*:*:*:*",
		},
		{
			name:        "no spaces in plc type",
			plcType:     "ILC151ETH",
			fwVersion:   "2.3.4",
			expectedCPE: "cpe:2.3:h:phoenixcontact:ilc151eth:2.3.4:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := generateCPE(tt.plcType, tt.fwVersion)
			assert.Equal(t, tt.expectedCPE, result)
		})
	}
}

func TestPCWorxPlugin_Run_FullValidExchange(t *testing.T) {
	plugin := &PCWorxPlugin{}

	// Build complete mock response with all three packets
	initResp := make([]byte, 20)
	initResp[0] = 0x81
	initResp[17] = 0x42 // Session ID

	// Session response
	sessionResp := []byte{0x01, 0x02, 0x03, 0x04}

	// Info response with embedded strings
	infoResp := make([]byte, 200)
	infoResp[0] = 0x81

	// PLC Type at offset 30
	copy(infoResp[30:], []byte("ILC 151 ETH\x00"))

	// Firmware Version at offset 66
	copy(infoResp[66:], []byte("1.0.20\x00"))

	// Firmware Date at offset 79
	copy(infoResp[79:], []byte("2023-01-15\x00"))

	// Firmware Time at offset 91
	copy(infoResp[91:], []byte("12:34:56\x00"))

	// Model Number at offset 152
	copy(infoResp[152:], []byte("2702072\x00"))

	fullResp := append(initResp, sessionResp...)
	fullResp = append(fullResp, infoResp...)
	conn := newMockConn(fullResp)

	target := plugins.Target{Host: "test.example.com"}

	result, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, result)

	// Verify service metadata
	metadata := result.Metadata()
	pcworxData, ok := metadata.(plugins.ServicePCWorx)
	require.True(t, ok, "Expected ServicePCWorx metadata")

	assert.Equal(t, "ILC 151 ETH", pcworxData.PLCType)
	assert.Equal(t, "1.0.20", pcworxData.FirmwareVersion)
	assert.Equal(t, "2023-01-15", pcworxData.FirmwareDate)
	assert.Equal(t, "12:34:56", pcworxData.FirmwareTime)
	assert.Equal(t, "2702072", pcworxData.ModelNumber)
	assert.Equal(t, 1, len(pcworxData.CPEs))
	assert.Equal(t, "cpe:2.3:h:phoenixcontact:ilc_151_eth:1.0.20:*:*:*:*:*:*:*", pcworxData.CPEs[0])
}
