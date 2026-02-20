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

package socks5

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

// mockConn implements net.Conn for testing without real network calls.
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

// TestValidateSOCKS5Response tests all code paths in the validateSOCKS5Response
// function including all four valid method codes and all error conditions.
func TestValidateSOCKS5Response(t *testing.T) {
	tests := []struct {
		name           string
		response       []byte
		expectedMethod byte
		expectError    bool
	}{
		{"valid no-auth", []byte{0x05, 0x00}, 0x00, false},
		{"valid gssapi", []byte{0x05, 0x01}, 0x01, false},
		{"valid username-password", []byte{0x05, 0x02}, 0x02, false},
		{"valid no-acceptable", []byte{0x05, 0xFF}, 0xFF, false},
		{"empty response", []byte{}, 0, true},
		{"single byte", []byte{0x05}, 0, true},
		{"wrong version", []byte{0x04, 0x00}, 0, true},
		{"unknown method 0x03", []byte{0x05, 0x03}, 0, true},
		{"unknown method 0x80", []byte{0x05, 0x80}, 0, true},
		{"oversized valid", []byte{0x05, 0x00, 0xFF, 0xFF}, 0x00, false},
		{"socks4 reply version", []byte{0x00, 0x5A}, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			method, err := validateSOCKS5Response(tt.response)
			if tt.expectError {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedMethod, method)
			}
		})
	}
}

// TestMethodName tests all branches of the methodName switch including the default
// case for unknown method codes.
func TestMethodName(t *testing.T) {
	tests := []struct {
		method   byte
		expected string
	}{
		{0x00, "no-auth"},
		{0x01, "gssapi"},
		{0x02, "username-password"},
		{0xFF, "no-acceptable"},
		{0x03, "unknown(0x03)"},
		{0x80, "unknown(0x80)"},
	}
	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			assert.Equal(t, tt.expected, methodName(tt.method))
		})
	}
}

func TestSOCKS5Plugin_Name(t *testing.T) {
	p := &SOCKS5Plugin{}
	assert.Equal(t, SOCKS5, p.Name())
}

func TestSOCKS5Plugin_Type(t *testing.T) {
	p := &SOCKS5Plugin{}
	assert.Equal(t, plugins.TCP, p.Type())
}

func TestSOCKS5Plugin_Priority(t *testing.T) {
	p := &SOCKS5Plugin{}
	assert.Equal(t, 400, p.Priority())
}

// TestSOCKS5Plugin_PortPriority verifies that the plugin prioritizes all four
// SOCKS-relevant ports (1080, 9050, 9150, 1081) and deprioritizes unrelated ports.
func TestSOCKS5Plugin_PortPriority(t *testing.T) {
	tests := []struct {
		name     string
		port     uint16
		expected bool
	}{
		{"socks default 1080", 1080, true},
		{"tor 9050", 9050, true},
		{"tor browser 9150", 9150, true},
		{"alternate 1081", 1081, true},
		{"http 8080", 8080, false},
		{"https 443", 443, false},
	}
	p := &SOCKS5Plugin{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, p.PortPriority(tt.port))
		})
	}
}

// TestBuildSOCKS5CPE verifies the CPE string format for SOCKS5 proxies.
func TestBuildSOCKS5CPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:*:socks5_proxy:*:*:*:*:*:*:*:*", buildSOCKS5CPE())
}

// TestSOCKS5Plugin_Run exercises the full Run() path via mockConn, covering all
// valid method responses, all invalid responses, and real-world Shodan vectors.
func TestSOCKS5Plugin_Run(t *testing.T) {
	tests := []struct {
		name            string
		response        []byte
		expectNil       bool
		expectError     bool
		selectedMethod  string
		anonymousAccess bool
	}{
		// Valid method responses
		{"no-auth detected", []byte{0x05, 0x00}, false, false, "no-auth", true},
		{"gssapi detected", []byte{0x05, 0x01}, false, false, "gssapi", false},
		{"username-password detected", []byte{0x05, 0x02}, false, false, "username-password", false},
		{"no-acceptable detected", []byte{0x05, 0xFF}, false, false, "no-acceptable", false},
		// Invalid / non-SOCKS5 responses
		{"empty response", []byte{}, true, false, "", false},
		{"too short response", []byte{0x05}, true, false, "", false},
		{"wrong version", []byte{0x04, 0x00}, true, false, "", false},
		{"unknown method", []byte{0x05, 0x03}, true, false, "", false},
		// Shodan vectors - real-world response patterns
		{"shodan: open socks5 proxy port 1080", []byte{0x05, 0x00}, false, false, "no-auth", true},
		{"shodan: tor socks5 no-acceptable", []byte{0x05, 0xFF}, false, false, "no-acceptable", false},
		{"shodan: authenticated socks5", []byte{0x05, 0x02}, false, false, "username-password", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn := &mockConn{readData: tt.response}
			p := &SOCKS5Plugin{}
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
			assert.Equal(t, "socks5", service.Protocol)
			assert.Equal(t, "tcp", service.Transport)

			metadata := service.Metadata()
			require.NotNil(t, metadata)
			socks5Meta, ok := metadata.(plugins.ServiceSOCKS5)
			require.True(t, ok, "metadata should be ServiceSOCKS5")

			assert.Equal(t, tt.selectedMethod, socks5Meta.SelectedMethod)
			assert.Equal(t, tt.anonymousAccess, socks5Meta.AnonymousAccess)
			assert.Len(t, socks5Meta.OfferedMethods, 3)
			assert.Contains(t, socks5Meta.OfferedMethods, "no-auth")
			assert.Contains(t, socks5Meta.OfferedMethods, "gssapi")
			assert.Contains(t, socks5Meta.OfferedMethods, "username-password")
			assert.NotEmpty(t, socks5Meta.CPEs)
			assert.Contains(t, socks5Meta.CPEs, "cpe:2.3:a:*:socks5_proxy:*:*:*:*:*:*:*:*")
		})
	}
}

// TestSOCKS5Plugin_SendsCorrectGreeting verifies the plugin sends exactly the
// RFC 1928 greeting bytes: VER=0x05, NMETHODS=0x03, METHODS=[0x00, 0x01, 0x02].
func TestSOCKS5Plugin_SendsCorrectGreeting(t *testing.T) {
	conn := &mockConn{readData: []byte{0x05, 0x00}}
	p := &SOCKS5Plugin{}
	target := plugins.Target{Host: "test.local"}

	_, _ = p.Run(conn, 2*time.Second, target)

	assert.Equal(t, []byte{0x05, 0x03, 0x00, 0x01, 0x02}, conn.writeData)
}

// TestSOCKS5Docker verifies detection against a real SOCKS5 server running in Docker.
func TestSOCKS5Docker(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker-based integration test in short mode")
	}

	err := test.RunTest(t, test.Testcase{
		Description: "SOCKS5 no-auth proxy detection",
		Port:        1080,
		Protocol:    plugins.TCP,
		Expected: func(service *plugins.Service) bool {
			if service == nil {
				return false
			}
			if service.Protocol != "socks5" {
				return false
			}
			metadata := service.Metadata()
			if metadata == nil {
				return false
			}
			socks5Meta, ok := metadata.(plugins.ServiceSOCKS5)
			if !ok {
				return false
			}
			return socks5Meta.AnonymousAccess
		},
		RunConfig: dockertest.RunOptions{
			Repository:   "serjs/go-socks5-proxy",
			Tag:          "latest",
			ExposedPorts: []string{"1080/tcp"},
		},
	}, &SOCKS5Plugin{})
	require.NoError(t, err)
}
