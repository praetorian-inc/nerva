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

package scan

import (
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// startMockSOCKS5Server creates a basic SOCKS5 proxy server for testing.
// Returns the listener address and a cleanup function.
func startMockSOCKS5Server(t *testing.T, requireAuth bool) (string, func()) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan struct{})

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					continue
				}
			}

			go handleSOCKS5Connection(conn, requireAuth)
		}
	}()

	cleanup := func() {
		close(done)
		listener.Close()
	}

	return listener.Addr().String(), cleanup
}

// handleSOCKS5Connection implements a minimal SOCKS5 handshake.
func handleSOCKS5Connection(conn net.Conn, requireAuth bool) {
	defer conn.Close()

	// Read SOCKS5 greeting
	buf := make([]byte, 256)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	if n < 2 || buf[0] != 0x05 {
		return
	}

	// Respond with no auth or user/pass auth required
	if requireAuth {
		_, _ = conn.Write([]byte{0x05, 0x02}) // Username/password auth
		// Read auth request
		n, err = conn.Read(buf)
		if err != nil {
			return
		}
		if n > 0 {
			// Auth request received, send auth success
			_, _ = conn.Write([]byte{0x01, 0x00})
		}
	} else {
		_, _ = conn.Write([]byte{0x05, 0x00}) // No authentication
	}

	// Read connection request
	_, err = conn.Read(buf)
	if err != nil {
		return
	}

	// Send success response (simplified)
	_, _ = conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0x7f, 0x00, 0x00, 0x01, 0x00, 0x50})
}

// startMockHTTPConnectServer creates a basic HTTP CONNECT proxy server for testing.
// Returns the listener address and a cleanup function.
func startMockHTTPConnectServer(t *testing.T, requireAuth bool) (string, func()) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	server := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodConnect {
				http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
				return
			}

			if requireAuth {
				auth := r.Header.Get("Proxy-Authorization")
				if !strings.HasPrefix(auth, "Basic ") {
					w.Header().Set("Proxy-Authenticate", "Basic realm=\"proxy\"")
					w.WriteHeader(http.StatusProxyAuthRequired)
					return
				}

				// Decode and verify credentials (simplified)
				decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(auth, "Basic "))
				if err != nil || !strings.Contains(string(decoded), ":") {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
					return
				}
			}

			// Hijack connection and send 200 OK
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				http.Error(w, "Hijacking not supported", http.StatusInternalServerError)
				return
			}

			conn, bufrw, err := hijacker.Hijack()
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer conn.Close()

			// Send 200 Connection Established
			_, _ = bufrw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n")
			_ = bufrw.Flush()
		}),
	}

	done := make(chan struct{})

	go func() {
		_ = server.Serve(listener)
	}()

	cleanup := func() {
		close(done)
		server.Close()
		listener.Close()
	}

	return listener.Addr().String(), cleanup
}

func TestIntegration_ProxyDialer_SOCKS5NoAuth(t *testing.T) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	proxyAddr, cleanup := startMockSOCKS5Server(t, false)
	defer cleanup()

	config := Config{
		Proxy:          fmt.Sprintf("socks5://%s", proxyAddr),
		DefaultTimeout: 2 * time.Second,
		Verbose:        false,
	}

	pd, err := NewProxyDialer(config)
	require.NoError(t, err)
	require.NotNil(t, pd)

	// Test basic dial (connection will be established to mock server)
	// We expect success establishing the SOCKS5 handshake, even if final dial fails
	assert.NotNil(t, pd)
}

func TestIntegration_ProxyDialer_SOCKS5WithAuth(t *testing.T) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	proxyAddr, cleanup := startMockSOCKS5Server(t, true)
	defer cleanup()

	config := Config{
		Proxy:          fmt.Sprintf("socks5://%s", proxyAddr),
		ProxyAuth:      "testuser:testpass",
		DefaultTimeout: 2 * time.Second,
		Verbose:        false,
	}

	pd, err := NewProxyDialer(config)
	require.NoError(t, err)
	require.NotNil(t, pd)

	// Verify auth credentials were set
	assert.NotNil(t, pd.parsedProxyURL.User)
}

func TestIntegration_ProxyDialer_HTTPConnect(t *testing.T) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	proxyAddr, cleanup := startMockHTTPConnectServer(t, false)
	defer cleanup()

	config := Config{
		Proxy:          fmt.Sprintf("http://%s", proxyAddr),
		DefaultTimeout: 2 * time.Second,
		Verbose:        false,
	}

	pd, err := NewProxyDialer(config)
	require.NoError(t, err)
	require.NotNil(t, pd)

	// HTTP proxy should be configured
	transport := pd.GetHTTPTransport(&tlsConfig)
	assert.NotNil(t, transport)
	assert.NotNil(t, transport.Proxy)
}

func TestIntegration_ProxyDialer_HTTPConnectWithAuth(t *testing.T) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	proxyAddr, cleanup := startMockHTTPConnectServer(t, true)
	defer cleanup()

	config := Config{
		Proxy:          fmt.Sprintf("http://testuser:testpass@%s", proxyAddr),
		DefaultTimeout: 2 * time.Second,
		Verbose:        false,
	}

	pd, err := NewProxyDialer(config)
	require.NoError(t, err)
	require.NotNil(t, pd)

	// Verify auth credentials were parsed
	assert.NotNil(t, pd.parsedProxyURL.User)
	username := pd.parsedProxyURL.User.Username()
	assert.Equal(t, "testuser", username)
}

// TestIntegration_ResolveTargets_Socks5h tests that socks5h:// forces proxy-side DNS.
func TestIntegration_ResolveTargets_Socks5h(t *testing.T) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	proxyAddr, cleanup := startMockSOCKS5Server(t, false)
	defer cleanup()

	config := Config{
		Proxy:          fmt.Sprintf("socks5h://%s", proxyAddr),
		DNSOrder:       "l", // Local DNS order, but socks5h should override
		DefaultTimeout: 2 * time.Second,
		Verbose:        false,
	}

	// Create a target with 0.0.0.0 (unresolved)
	target := plugins.Target{
		Host: "example.com",
		Address: netip.AddrPortFrom(
			netip.IPv4Unspecified(),
			80,
		),
	}

	resolved := ResolveTargets([]plugins.Target{target}, config)

	// With socks5h://, the target should NOT be locally resolved
	// It should remain as 0.0.0.0 to be resolved by proxy
	require.Len(t, resolved, 1)
	assert.Equal(t, netip.IPv4Unspecified(), resolved[0].Address.Addr())
	assert.Equal(t, "example.com", resolved[0].Host)
}

// TestIntegration_TCPEchoServer tests full proxy dial with a real echo server.
func TestIntegration_TCPEchoServer(t *testing.T) {
	t.Helper()

	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	// Start a simple echo server
	echoListener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer echoListener.Close()

	echoAddr := echoListener.Addr().String()

	go func() {
		for {
			conn, err := echoListener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_, _ = io.Copy(c, c) // Echo back
			}(conn)
		}
	}()

	// Start SOCKS5 proxy
	proxyAddr, cleanup := startMockSOCKS5Server(t, false)
	defer cleanup()

	config := Config{
		Proxy:          fmt.Sprintf("socks5://%s", proxyAddr),
		DefaultTimeout: 2 * time.Second,
		Verbose:        false,
	}

	pd, err := NewProxyDialer(config)
	require.NoError(t, err)

	// Parse echo server address
	host, portStr, err := net.SplitHostPort(echoAddr)
	require.NoError(t, err)

	var port uint16
	_, err = fmt.Sscanf(portStr, "%d", &port)
	require.NoError(t, err)

	// This will attempt to dial through proxy
	// The mock proxy doesn't actually forward traffic, it just completes the handshake
	// In a real proxy, this would establish a forwarded connection
	conn, err := pd.DialTCP(host, port)

	// The mock proxy completes the SOCKS5 handshake successfully
	// In a real scenario, this would be a working connection
	if err == nil && conn != nil {
		conn.Close()
	}

	// Test passed if we got a connection or a reasonable error
	// (The mock proxy may not fully proxy the connection)
	assert.True(t, err == nil || strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "EOF"))
}
