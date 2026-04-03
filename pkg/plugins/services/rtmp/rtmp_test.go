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

package rtmp

import (
	"io"
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockConn struct {
	data []byte
	pos  int
}

func newMockConn(data []byte) *mockConn {
	return &mockConn{data: data}
}

func (c *mockConn) Read(b []byte) (n int, err error) {
	if c.pos >= len(c.data) {
		return 0, io.EOF
	}
	n = copy(b, c.data[c.pos:])
	c.pos += n
	return n, nil
}

func (c *mockConn) Write(b []byte) (n int, err error)  { return len(b), nil }
func (c *mockConn) Close() error                       { return nil }
func (c *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *mockConn) SetDeadline(t time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestRTMPPlugin_Name(t *testing.T) {
	p := &RTMPPlugin{}
	assert.Equal(t, "rtmp", p.Name())
}

func TestRTMPPlugin_PortPriority(t *testing.T) {
	p := &RTMPPlugin{}
	assert.True(t, p.PortPriority(1935))
	assert.False(t, p.PortPriority(80))
	assert.False(t, p.PortPriority(443))
}

func TestRTMPPlugin_Detect_FullS0S1(t *testing.T) {
	// S0 (version 3) + S1 (1536 bytes)
	response := make([]byte, 1+1536)
	response[0] = 0x03

	conn := newMockConn(response)
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, "rtmp", svc.Protocol)
}

func TestRTMPPlugin_Detect_PartialS1(t *testing.T) {
	// S0 + partial S1 (only 100 bytes received)
	response := make([]byte, 101)
	response[0] = 0x03

	conn := newMockConn(response)
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, "rtmp", svc.Protocol)
}

func TestRTMPPlugin_Reject_WrongVersion(t *testing.T) {
	response := make([]byte, 1537)
	response[0] = 0x06 // Not version 3

	conn := newMockConn(response)
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestRTMPPlugin_Reject_TooShort(t *testing.T) {
	// Only 5 bytes (need at least 9)
	response := []byte{0x03, 0x00, 0x00, 0x00, 0x00}

	conn := newMockConn(response)
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestRTMPPlugin_Reject_HTTP(t *testing.T) {
	response := []byte("HTTP/1.1 200 OK\r\n")

	conn := newMockConn(response)
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestRTMPPlugin_Reject_SSH(t *testing.T) {
	response := []byte("SSH-2.0-OpenSSH_8.9\r\n")

	conn := newMockConn(response)
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestRTMPPlugin_Reject_Empty(t *testing.T) {
	conn := newMockConn([]byte{})
	p := &RTMPPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestIsValidRTMPResponse(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Full S0+S1",
			data:     append([]byte{0x03}, make([]byte, 1536)...),
			expected: true,
		},
		{
			name:     "Minimal valid (S0 + 4-byte timestamp + 4 zero bytes)",
			data:     []byte{0x03, 0x00, 0x01, 0x02, 0x03, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "Wrong version",
			data:     []byte{0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "Non-zero S1 bytes 4-7 (not RTMP)",
			data:     []byte{0x03, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04},
			expected: false,
		},
		{
			name:     "Too short (5 bytes, need 9)",
			data:     []byte{0x03, 0x00, 0x00, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "Too short (2 bytes)",
			data:     []byte{0x03, 0x00},
			expected: false,
		},
		{
			name:     "Single byte (S0 only)",
			data:     []byte{0x03},
			expected: false,
		},
		{
			name:     "Empty",
			data:     []byte{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isValidRTMPResponse(tt.data))
		})
	}
}
