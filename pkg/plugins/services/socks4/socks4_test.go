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

package socks4

import (
	"net"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockConn implements net.Conn for testing.
type mockConn struct {
	readData  []byte
	writeData []byte
	readErr   error
	writeErr  error
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

func (m *mockConn) Close() error                       { return nil }
func (m *mockConn) LocalAddr() net.Addr                { return nil }
func (m *mockConn) RemoteAddr() net.Addr               { return nil }
func (m *mockConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error { return nil }

func TestValidateSOCKS4Response(t *testing.T) {
	tests := []struct {
		name           string
		response       []byte
		expectedStatus byte
		expectError    bool
	}{
		// Valid status codes
		{"valid granted", []byte{0x00, 0x5A}, 0x5A, false},
		{"valid rejected", []byte{0x00, 0x5B}, 0x5B, false},
		{"valid identd-required", []byte{0x00, 0x5C}, 0x5C, false},
		{"valid identd-mismatch", []byte{0x00, 0x5D}, 0x5D, false},
		// Error cases
		{"empty response", []byte{}, 0, true},
		{"single byte", []byte{0x00}, 0, true},
		{"wrong version 0x04", []byte{0x04, 0x5A}, 0, true},
		{"wrong version 0x05", []byte{0x05, 0x00}, 0, true},
		{"unknown status 0x59", []byte{0x00, 0x59}, 0, true},
		{"unknown status 0x5E", []byte{0x00, 0x5E}, 0, true},
		// Real-world full 8-byte response
		{"full 8-byte valid", []byte{0x00, 0x5A, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01}, 0x5A, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, err := validateSOCKS4Response(tt.response)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedStatus, status)
			}
		})
	}
}

func TestStatusName(t *testing.T) {
	tests := []struct {
		status   byte
		expected string
	}{
		{0x5A, "granted"},
		{0x5B, "rejected"},
		{0x5C, "identd-required"},
		{0x5D, "identd-mismatch"},
		{0x00, "unknown"},
		{0xFF, "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, statusName(tt.status))
		})
	}
}

func TestSOCKS4Plugin_Name(t *testing.T) {
	p := &SOCKS4Plugin{}
	assert.Equal(t, SOCKS4, p.Name())
}

func TestSOCKS4Plugin_Type(t *testing.T) {
	p := &SOCKS4Plugin{}
	assert.Equal(t, plugins.TCP, p.Type())
}

func TestSOCKS4Plugin_Priority(t *testing.T) {
	p := &SOCKS4Plugin{}
	assert.Equal(t, 410, p.Priority())
}

func TestSOCKS4Plugin_PortPriority(t *testing.T) {
	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{"socks default 1080", 1080, true},
		{"alternate 1081", 1081, true},
		// SOCKS4 does NOT include Tor port 9050 (Tor only uses SOCKS5)
		{"tor 9050", 9050, false},
		{"http 8080", 8080, false},
	}

	p := &SOCKS4Plugin{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, p.PortPriority(tt.port))
		})
	}
}

func TestBuildSOCKS4CPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:*:socks4_proxy:*:*:*:*:*:*:*:*", buildSOCKS4CPE())
}

func TestSOCKS4Plugin_Run(t *testing.T) {
	tests := []struct {
		name            string
		response        []byte
		expectNil       bool
		expectError     bool
		status          string
		anonymousAccess bool
	}{
		// Valid responses
		{"granted", []byte{0x00, 0x5A}, false, false, "granted", true},
		{"rejected", []byte{0x00, 0x5B}, false, false, "rejected", false},
		{"identd-required", []byte{0x00, 0x5C}, false, false, "identd-required", false},
		{"identd-mismatch", []byte{0x00, 0x5D}, false, false, "identd-mismatch", false},
		// Invalid/non-SOCKS4 responses — expect nil service, no error
		{"empty response", []byte{}, true, false, "", false},
		{"too short", []byte{0x00}, true, false, "", false},
		{"wrong version", []byte{0x05, 0x00}, true, false, "", false},
		{"unknown status", []byte{0x00, 0x59}, true, false, "", false},
		// Shodan vectors - real-world SOCKS4 responses (full 8-byte)
		{"shodan: open socks4 proxy", []byte{0x00, 0x5A, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01}, false, false, "granted", true},
		{"shodan: rejected socks4", []byte{0x00, 0x5B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, false, false, "rejected", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{readData: tt.response}
			p := &SOCKS4Plugin{}
			target := plugins.Target{Host: "test.local"}

			service, err := p.Run(conn, 2*time.Second, target)

			if tt.expectError {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, service)
				return
			}

			require.NotNil(t, service)
			assert.Equal(t, "socks4", service.Protocol)
			assert.Equal(t, "tcp", service.Transport)

			metadata := service.Metadata()
			require.NotNil(t, metadata)
			socks4Meta, ok := metadata.(plugins.ServiceSOCKS4)
			require.True(t, ok, "metadata should be ServiceSOCKS4")

			assert.Equal(t, tt.status, socks4Meta.Status)
			assert.Equal(t, tt.anonymousAccess, socks4Meta.AnonymousAccess)
			assert.False(t, socks4Meta.SOCKS4a)
			assert.NotEmpty(t, socks4Meta.CPEs)
		})
	}
}

func TestSOCKS4Plugin_SendsCorrectRequest(t *testing.T) {
	// Verify that the correct SOCKS4 CONNECT packet is sent to the server.
	// Expected: VER=0x04, CMD=CONNECT(0x01), DSTPORT=80(0x0050),
	// DSTIP=127.0.0.1, USERID=empty (null-terminated).
	conn := &mockConn{readData: []byte{0x00, 0x5A}}
	p := &SOCKS4Plugin{}
	target := plugins.Target{Host: "test.local"}

	_, _ = p.Run(conn, 2*time.Second, target)

	assert.Equal(t, []byte{0x04, 0x01, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01, 0x00}, conn.writeData)
}

// TestSOCKS4Docker_Negative verifies that the SOCKS4 plugin does NOT false-positive
// on a SOCKS5-only server. The serjs/go-socks5-proxy image speaks SOCKS5 only;
// sending a SOCKS4 probe should yield no detection (service == nil).
func TestSOCKS4Docker_Negative(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker-based integration test in short mode")
	}

	err := test.RunTest(t, test.Testcase{
		Description: "SOCKS4 negative test: no detection on SOCKS5-only server",
		Port:        1080,
		Protocol:    plugins.TCP,
		Expected: func(service *plugins.Service) bool {
			// SOCKS4 plugin must NOT detect a SOCKS5-only server.
			return service == nil
		},
		RunConfig: dockertest.RunOptions{
			Repository:   "serjs/go-socks5-proxy",
			Tag:          "latest",
			ExposedPorts: []string{"1080/tcp"},
		},
	}, &SOCKS4Plugin{})
	require.NoError(t, err)
}
