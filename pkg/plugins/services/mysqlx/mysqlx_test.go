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

package mysqlx

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

func TestMySQLXPlugin_Name(t *testing.T) {
	p := &MySQLXPlugin{}
	assert.Equal(t, "mysqlx", p.Name())
}

func TestMySQLXPlugin_PortPriority(t *testing.T) {
	p := &MySQLXPlugin{}
	assert.True(t, p.PortPriority(33060))
	assert.False(t, p.PortPriority(3306))
	assert.False(t, p.PortPriority(80))
}

func TestMySQLXPlugin_Detect_Notice(t *testing.T) {
	// Real MySQL X Protocol NOTICE frame captured from MySQL 8.0
	// Frame: length=5 (LE), type=11 (NOTICE), payload=08051a00
	response := []byte{0x05, 0x00, 0x00, 0x00, 0x0b, 0x08, 0x05, 0x1a, 0x00}

	conn := newMockConn(response)
	p := &MySQLXPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, "mysqlx", svc.Protocol)
}

func TestMySQLXPlugin_Detect_Error(t *testing.T) {
	// MySQL X Protocol ERROR frame (type=1)
	// length=3 (LE), type=1, payload=0800
	response := []byte{0x03, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00}

	conn := newMockConn(response)
	p := &MySQLXPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, "mysqlx", svc.Protocol)
}

func TestMySQLXPlugin_Reject_HTTP(t *testing.T) {
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	conn := newMockConn(response)
	p := &MySQLXPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestMySQLXPlugin_Reject_SSH(t *testing.T) {
	response := []byte("SSH-2.0-OpenSSH_8.9\r\n")

	conn := newMockConn(response)
	p := &MySQLXPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestMySQLXPlugin_Reject_TooShort(t *testing.T) {
	response := []byte{0x05, 0x00, 0x00}

	conn := newMockConn(response)
	p := &MySQLXPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestMySQLXPlugin_Reject_BadLength(t *testing.T) {
	// Length says 99 but only 5 bytes total
	response := []byte{0x63, 0x00, 0x00, 0x00, 0x0b}

	conn := newMockConn(response)
	p := &MySQLXPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestMySQLXPlugin_Reject_UnknownType(t *testing.T) {
	// Valid length but unknown message type (0xFF)
	response := []byte{0x01, 0x00, 0x00, 0x00, 0xFF}

	conn := newMockConn(response)
	p := &MySQLXPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestMySQLXPlugin_Reject_Empty(t *testing.T) {
	conn := newMockConn([]byte{})
	p := &MySQLXPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestMySQLXPlugin_Reject_CrimsonV3Probe(t *testing.T) {
	// CrimsonV3 probe response should not match MySQL X
	response := []byte{0x00, 0x0a, 0x01, 0x2b, 0x1b, 0x00, 0x52, 0x65, 0x64, 0x20, 0x4c, 0x69, 0x6f, 0x6e, 0x00}

	conn := newMockConn(response)
	p := &MySQLXPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestIsValidMySQLXFrame(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name:     "Valid NOTICE frame",
			data:     []byte{0x05, 0x00, 0x00, 0x00, 0x0b, 0x08, 0x05, 0x1a, 0x00},
			expected: true,
		},
		{
			name:     "Valid OK frame",
			data:     []byte{0x01, 0x00, 0x00, 0x00, 0x00},
			expected: true,
		},
		{
			name:     "Valid ERROR frame",
			data:     []byte{0x03, 0x00, 0x00, 0x00, 0x01, 0x08, 0x00},
			expected: true,
		},
		{
			name:     "Too short",
			data:     []byte{0x01, 0x00, 0x00},
			expected: false,
		},
		{
			name:     "Length mismatch",
			data:     []byte{0x63, 0x00, 0x00, 0x00, 0x0b},
			expected: false,
		},
		{
			name:     "Unknown message type",
			data:     []byte{0x01, 0x00, 0x00, 0x00, 0xFF},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isValidMySQLXFrame(tt.data))
		})
	}
}
