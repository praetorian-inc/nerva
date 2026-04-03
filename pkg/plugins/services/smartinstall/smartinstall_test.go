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

package smartinstall

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

func TestSmartInstallPlugin_Name(t *testing.T) {
	p := &SmartInstallPlugin{}
	assert.Equal(t, "smart-install", p.Name())
}

func TestSmartInstallPlugin_PortPriority(t *testing.T) {
	p := &SmartInstallPlugin{}
	assert.True(t, p.PortPriority(4786))
	assert.False(t, p.PortPriority(80))
	assert.False(t, p.PortPriority(3050)) // Firebird port
}

func TestSmartInstallPlugin_Detect_ValidResponse(t *testing.T) {
	// Standard Smart Install response per Cisco-Talos smi_check
	response := []byte{
		0x00, 0x00, 0x00, 0x04,
		0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x03,
		0x00, 0x00, 0x00, 0x08,
		0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x00,
	}

	conn := newMockConn(response)
	p := &SmartInstallPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	require.NotNil(t, svc)
	assert.Equal(t, "smart-install", svc.Protocol)
}

func TestSmartInstallPlugin_Reject_TooShort(t *testing.T) {
	response := []byte{0x00, 0x00, 0x00, 0x04}

	conn := newMockConn(response)
	p := &SmartInstallPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestSmartInstallPlugin_Reject_WrongPrefix(t *testing.T) {
	// Wrong first 4 bytes
	response := make([]byte, 24)
	response[0] = 0x00
	response[1] = 0x00
	response[2] = 0x00
	response[3] = 0x01 // Not 0x04

	conn := newMockConn(response)
	p := &SmartInstallPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestSmartInstallPlugin_Reject_HTTP(t *testing.T) {
	response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")

	conn := newMockConn(response)
	p := &SmartInstallPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestSmartInstallPlugin_Reject_Empty(t *testing.T) {
	conn := newMockConn([]byte{})
	p := &SmartInstallPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestSmartInstallPlugin_Reject_TooLong(t *testing.T) {
	// 25 bytes (should be exactly 24)
	response := make([]byte, 25)
	copy(response, smiResponsePrefix)

	conn := newMockConn(response)
	p := &SmartInstallPlugin{}
	svc, err := p.Run(conn, time.Second, plugins.Target{})
	require.NoError(t, err)
	assert.Nil(t, svc)
}

func TestIsValidSmartInstallResponse(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		expected bool
	}{
		{
			name: "Valid Smart Install response",
			data: []byte{
				0x00, 0x00, 0x00, 0x04,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x03,
				0x00, 0x00, 0x00, 0x08,
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
			},
			expected: true,
		},
		{
			name:     "Too short",
			data:     []byte{0x00, 0x00, 0x00, 0x04},
			expected: false,
		},
		{
			name:     "Wrong prefix",
			data:     make([]byte, 24), // all zeros
			expected: false,
		},
		{
			name: "Correct prefix but wrong inner fields",
			data: []byte{
				0x00, 0x00, 0x00, 0x04,
				0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x07, // should be 0x03
				0x00, 0x00, 0x00, 0x08,
				0x00, 0x00, 0x00, 0x01,
				0x00, 0x00, 0x00, 0x00,
			},
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
			assert.Equal(t, tt.expected, isValidSmartInstallResponse(tt.data))
		})
	}
}
