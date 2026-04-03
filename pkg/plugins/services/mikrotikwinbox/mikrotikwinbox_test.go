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

package mikrotikwinbox

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/plugins/fingerprinters"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockConn is a net.Conn that reads from a pre-defined byte slice.
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

func (c *mockConn) Write(b []byte) (n int, err error) {
	return len(b), nil
}

func (c *mockConn) Close() error                       { return nil }
func (c *mockConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (c *mockConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }
func (c *mockConn) SetDeadline(t time.Time) error      { return nil }
func (c *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestDetectWinbox(t *testing.T) {
	tests := []struct {
		name      string
		response  []byte
		wantMatch bool
	}{
		{
			name:      "M2 magic detected",
			response:  []byte{0x4D, 0x32, 0x00, 0x00, 0x00, 0x00},
			wantMatch: true,
		},
		{
			name:      "non-M2 first byte rejected",
			response:  []byte{0x00, 0x32, 0x00, 0x00},
			wantMatch: false,
		},
		{
			name:      "non-M2 second byte rejected",
			response:  []byte{0x4D, 0x00, 0x00, 0x00},
			wantMatch: false,
		},
		{
			name:      "HTTP response rejected",
			response:  []byte("HTTP/1.1 200 OK\r\n"),
			wantMatch: false,
		},
		{
			name:      "short response (1 byte) rejected",
			response:  []byte{0x4D},
			wantMatch: false,
		},
		{
			name:      "empty response rejected",
			response:  []byte{},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newMockConn(tt.response)
			svc, err := detectWinbox(conn, time.Second, plugins.Target{})
			require.NoError(t, err)
			if tt.wantMatch {
				require.NotNil(t, svc)
			} else {
				assert.Nil(t, svc)
			}
		})
	}
}

func TestDetectAPI(t *testing.T) {
	tests := []struct {
		name      string
		response  []byte
		wantMatch bool
	}{
		{
			name: "valid API !trap response",
			// API sentence: length 0x05, "!trap", then attributes and null terminator
			response:  []byte{0x05, '!', 't', 'r', 'a', 'p', 0x00},
			wantMatch: true,
		},
		{
			name: "valid API !done response",
			// API sentence: length 0x05, "!done", null terminator
			response:  []byte{0x05, '!', 'd', 'o', 'n', 'e', 0x00},
			wantMatch: true,
		},
		{
			name:      "!trap embedded in longer response",
			response:  []byte{0x05, '!', 't', 'r', 'a', 'p', 0x10, '=', 'm', 'e', 's', 's', 'a', 'g', 'e', '=', 'e', 'r', 'r', 'o', 'r', 0x00},
			wantMatch: true,
		},
		{
			name:      "binary response with zero bytes but no API words rejected",
			response:  []byte{0x04, 'a', 'b', 'c', 0x00, 'd'},
			wantMatch: false,
		},
		{
			name:      "response without API reply words rejected",
			response:  []byte{0x04, 'a', 'b', 'c', 'd'},
			wantMatch: false,
		},
		{
			name:      "plain text SSH banner rejected",
			response:  []byte("SSH-2.0-OpenSSH_8.9"),
			wantMatch: false,
		},
		{
			name:      "MySQL greeting with null bytes rejected",
			response:  []byte{0x4a, 0x00, 0x00, 0x00, 0x0a, '8', '.', '0', '.', '3', '2', 0x00},
			wantMatch: false,
		},
		{
			name:      "empty response rejected",
			response:  []byte{},
			wantMatch: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := newMockConn(tt.response)
			svc, err := detectAPI(conn, time.Second, plugins.Target{})
			require.NoError(t, err)
			if tt.wantMatch {
				require.NotNil(t, svc)
			} else {
				assert.Nil(t, svc)
			}
		})
	}
}

func TestPortPriority(t *testing.T) {
	p := &MikroTikWinboxPlugin{}

	assert.True(t, p.PortPriority(DefaultWinboxPort), "should return true for Winbox port 8291")
	assert.True(t, p.PortPriority(DefaultAPIPort), "should return true for API port 8728")
	assert.False(t, p.PortPriority(80), "should return false for HTTP port")
	assert.False(t, p.PortPriority(443), "should return false for HTTPS port")
	assert.False(t, p.PortPriority(22), "should return false for SSH port")
	assert.False(t, p.PortPriority(0), "should return false for port 0")
}

func TestName(t *testing.T) {
	p := &MikroTikWinboxPlugin{}
	assert.Equal(t, "mikrotik-winbox", p.Name())
}

func TestBuildMikroTikRouterOSCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "empty version uses wildcard",
			version:  "",
			expected: "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
		},
		{
			name:     "specific version",
			version:  "7.14.3",
			expected: "cpe:2.3:o:mikrotik:routeros:7.14.3:*:*:*:*:*:*:*",
		},
		{
			name:     "legacy version",
			version:  "6.49.7",
			expected: "cpe:2.3:o:mikrotik:routeros:6.49.7:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := fingerprinters.BuildMikroTikRouterOSCPE(tt.version)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestRun_APIPortRoutesToAPIDetection(t *testing.T) {
	// Run() with port 8728 must route to API detection.
	// A valid !trap response confirms the API code path was exercised.
	p := &MikroTikWinboxPlugin{}
	conn := newMockConn([]byte{0x05, '!', 't', 'r', 'a', 'p', 0x00})
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:8728"),
	}
	svc, err := p.Run(conn, time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc, "port 8728 with valid API response should be detected")
	assert.Equal(t, DefaultAPIPort, svc.Port)
}

func TestRun_WinboxPortRoutesToWinboxDetection(t *testing.T) {
	// Run() with port 8291 must route to Winbox detection.
	// A valid M2 magic response confirms the Winbox code path was exercised.
	p := &MikroTikWinboxPlugin{}
	conn := newMockConn([]byte{0x4D, 0x32, 0x00, 0x00, 0x00, 0x00})
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:8291"),
	}
	svc, err := p.Run(conn, time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, svc, "port 8291 with M2 magic should be detected as Winbox")
	assert.Equal(t, DefaultWinboxPort, svc.Port)
}

func TestRun_NonPriorityPortReturnsNil(t *testing.T) {
	// Non-priority ports must return nil to avoid false positives from the
	// 2-byte M2 magic being too weak for arbitrary port detection.
	p := &MikroTikWinboxPlugin{}
	// Port 80 is not a priority port; provide M2 magic bytes to ensure
	// the nil return is from port gating, not from the M2 check failing.
	conn := newMockConn([]byte{0x4D, 0x32, 0x00, 0x00})
	target := plugins.Target{}

	// Manually set the port via address — use a helper that creates a target
	// with a non-priority port. Since plugins.Target wraps an address, we
	// call Run directly and rely on Port() returning 0 for a zero-value target.
	svc, err := p.Run(conn, time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, svc, "non-priority port should return nil")
}
