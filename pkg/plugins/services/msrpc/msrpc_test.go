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

package msrpc

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

// buildBindAck constructs a minimal valid DCE/RPC bind_ack response
func buildBindAck(fragLen int) []byte {
	resp := make([]byte, fragLen)
	resp[0] = rpcVersionMajor  // version 5
	resp[1] = rpcVersionMinor  // minor 0
	resp[2] = pduTypeBindAck   // bind_ack
	resp[3] = 0x03             // flags: first+last
	resp[4] = 0x10             // data rep: LE
	resp[8] = byte(fragLen)    // frag_length low byte
	resp[9] = byte(fragLen >> 8) // frag_length high byte
	resp[12] = 0x01            // call_id
	return resp
}

func TestMSRPCPlugin_Name(t *testing.T) {
	p := &MSRPCPlugin{}
	assert.Equal(t, "msrpc", p.Name())
}

func TestMSRPCPlugin_PortPriority(t *testing.T) {
	p := &MSRPCPlugin{}
	assert.True(t, p.PortPriority(135))
	assert.False(t, p.PortPriority(80))
	assert.False(t, p.PortPriority(445))
}

func TestMSRPCPlugin_Detect_BindAck(t *testing.T) {
	// Real bind_ack captured from Samba AD DC (60 bytes)
	response := []byte{
		0x05, 0x00, 0x0c, 0x03, 0x10, 0x00, 0x00, 0x00,
		0x3c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
		0xd0, 0x16, 0xd0, 0x16, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x00, 0x31, 0x33, 0x35, 0x00, 0x00, 0x00,
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
		0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
		0x02, 0x00, 0x00, 0x00,
	}

	conn := newMockConn(response)
	p := &MSRPCPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, "msrpc", svc.Protocol)
}

func TestMSRPCPlugin_Detect_MinimalBindAck(t *testing.T) {
	response := buildBindAck(24)

	conn := newMockConn(response)
	p := &MSRPCPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, "msrpc", svc.Protocol)
}

func TestMSRPCPlugin_Reject_WrongVersion(t *testing.T) {
	response := buildBindAck(24)
	response[0] = 0x04 // Wrong major version

	conn := newMockConn(response)
	p := &MSRPCPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestMSRPCPlugin_Reject_WrongPDUType(t *testing.T) {
	response := buildBindAck(24)
	response[2] = 0x0b // bind instead of bind_ack

	conn := newMockConn(response)
	p := &MSRPCPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestMSRPCPlugin_Reject_FragLengthMismatch(t *testing.T) {
	response := buildBindAck(24)
	response[8] = 0x60 // Claim frag_length=96, but only 24 bytes

	conn := newMockConn(response)
	p := &MSRPCPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestMSRPCPlugin_Reject_TooShort(t *testing.T) {
	response := []byte{0x05, 0x00, 0x0c}

	conn := newMockConn(response)
	p := &MSRPCPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestMSRPCPlugin_Reject_HTTP(t *testing.T) {
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	conn := newMockConn(response)
	p := &MSRPCPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestMSRPCPlugin_Reject_Empty(t *testing.T) {
	conn := newMockConn([]byte{})
	p := &MSRPCPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestIsValidBindAck(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Valid bind_ack",
			data:     buildBindAck(24),
			expected: true,
		},
		{
			name:     "Too short",
			data:     []byte{0x05, 0x00, 0x0c},
			expected: false,
		},
		{
			name:     "Wrong version",
			data:     func() []byte { d := buildBindAck(24); d[0] = 4; return d }(),
			expected: false,
		},
		{
			name:     "Wrong PDU type",
			data:     func() []byte { d := buildBindAck(24); d[2] = 0x0b; return d }(),
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
			assert.Equal(t, tt.expected, isValidBindAck(tt.data))
		})
	}
}
