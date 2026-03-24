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
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/proxy"
)

// sanitizeProxyURL removes credentials from proxy URLs for safe logging.
// This prevents credential leakage in verbose logs and error messages.
func sanitizeProxyURL(proxyURL string) string {
	u, err := url.Parse(proxyURL)
	if err != nil {
		return "[invalid-url]"
	}
	// Remove userinfo (credentials) from URL
	u.User = nil
	return u.String()
}

// ProxyDialer centralizes proxy dialing logic to eliminate code duplication
// between DialTCP, DialTLS, and DialUDP methods.
type ProxyDialer struct {
	proxyURL       string
	timeout        time.Duration
	dnsOrder       string
	verbose        bool
	udpWarnOnce    sync.Once
	parsedProxyURL *url.URL
	baseDialer     *net.Dialer
}

// NewProxyDialer creates a ProxyDialer from a Config.
// Returns error for invalid proxy URLs or unsupported schemes.
func NewProxyDialer(config Config) (*ProxyDialer, error) {
	if config.Proxy == "" {
		return nil, fmt.Errorf("proxy URL is empty")
	}

	proxyURL, err := url.Parse(config.Proxy)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy URL: %w", err)
	}

	// Normalize socks5h:// to socks5:// (both resolve via proxy)
	scheme := strings.ToLower(proxyURL.Scheme)
	if scheme == "socks5h" {
		scheme = "socks5"
		proxyURL.Scheme = scheme
	}

	// Validate supported schemes
	switch scheme {
	case "socks5", "http", "https":
		// Supported
	default:
		return nil, fmt.Errorf("unsupported proxy scheme: %s (supported: socks5, socks5h, http, https)", proxyURL.Scheme)
	}

	// Handle authentication: URL userinfo takes priority over ProxyAuth
	if proxyURL.User == nil && config.ProxyAuth != "" {
		parts := strings.SplitN(config.ProxyAuth, ":", 2)
		if len(parts) == 2 {
			proxyURL.User = url.UserPassword(parts[0], parts[1])
		} else {
			proxyURL.User = url.User(parts[0])
		}
	}

	baseDialer := &net.Dialer{
		Timeout: config.DefaultTimeout,
	}

	return &ProxyDialer{
		proxyURL:       config.Proxy,
		timeout:        config.DefaultTimeout,
		dnsOrder:       config.DNSOrder,
		verbose:        config.Verbose,
		parsedProxyURL: proxyURL,
		baseDialer:     baseDialer,
	}, nil
}

// dialHTTPConnect implements HTTP CONNECT tunneling for HTTP/HTTPS proxy schemes.
func (pd *ProxyDialer) dialHTTPConnect(ctx context.Context, network, addr string) (net.Conn, error) {
	// 1. Connect to the proxy server
	proxyAddr := pd.parsedProxyURL.Host
	if pd.parsedProxyURL.Port() == "" {
		if pd.parsedProxyURL.Scheme == "https" {
			proxyAddr = net.JoinHostPort(pd.parsedProxyURL.Hostname(), "443")
		} else {
			proxyAddr = net.JoinHostPort(pd.parsedProxyURL.Hostname(), "8080")
		}
	}

	var conn net.Conn
	var err error
	if pd.parsedProxyURL.Scheme == "https" {
		// TLS connection to proxy
		conn, err = tls.DialWithDialer(pd.baseDialer, "tcp", proxyAddr, &tls.Config{
			InsecureSkipVerify: true,
		})
	} else {
		conn, err = pd.baseDialer.DialContext(ctx, "tcp", proxyAddr)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to connect to HTTP proxy: %w", err)
	}

	// 2. Send CONNECT request
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n", addr, addr)

	// Add proxy auth if configured
	if pd.parsedProxyURL.User != nil {
		username := pd.parsedProxyURL.User.Username()
		password, _ := pd.parsedProxyURL.User.Password()
		auth := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
		connectReq += fmt.Sprintf("Proxy-Authorization: Basic %s\r\n", auth)
	}
	connectReq += "\r\n"

	conn.SetDeadline(time.Now().Add(pd.timeout))
	_, err = conn.Write([]byte(connectReq))
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to send CONNECT: %w", err)
	}

	// 3. Read response
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	conn.SetDeadline(time.Time{})
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to read CONNECT response: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != 200 {
		conn.Close()
		return nil, fmt.Errorf("HTTP CONNECT failed: %s", resp.Status)
	}

	return conn, nil
}

// DialContext performs context-aware dialing through the proxy.
func (pd *ProxyDialer) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	scheme := strings.ToLower(pd.parsedProxyURL.Scheme)

	// Route to HTTP CONNECT for http/https proxy schemes
	if scheme == "http" || scheme == "https" {
		return pd.dialHTTPConnect(ctx, network, addr)
	}

	// SOCKS5 path (existing code)
	proxyDialer, err := proxy.FromURL(pd.parsedProxyURL, pd.baseDialer)
	if err != nil {
		// Sanitize proxy URL in error message to avoid credential leakage
		return nil, fmt.Errorf("failed to create proxy dialer for %s: %w", sanitizeProxyURL(pd.proxyURL), err)
	}

	// Use ContextDialer if available for cancellation support
	if cd, ok := proxyDialer.(proxy.ContextDialer); ok {
		return cd.DialContext(ctx, network, addr)
	}

	// Fallback to standard Dial
	return proxyDialer.Dial(network, addr)
}

// DialTCP dials a TCP connection through the proxy.
// Handles DNS fallback based on dnsOrder configuration.
func (pd *ProxyDialer) DialTCP(host string, port uint16) (net.Conn, error) {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	conn, err := pd.DialContext(context.Background(), "tcp", addr)
	if err != nil && pd.dnsOrder == "pl" && host != "" {
		// Proxy dial failed, fallback to local resolution
		if pd.verbose {
			log.Printf("proxy dial failed, falling back to local DNS resolution for %s\n", addr)
		}
		return resolveLocalFallback(host, port, "tcp", pd.baseDialer)
	}

	return conn, err
}

// DialTLS dials a TLS connection through the proxy.
// Wraps the TCP connection with TLS after connecting through proxy.
func (pd *ProxyDialer) DialTLS(host string, port uint16, tlsConfig *tls.Config) (net.Conn, error) {
	// First establish TCP connection through proxy
	tcpConn, err := pd.DialTCP(host, port)
	if err != nil {
		return nil, err
	}

	// Wrap with TLS
	tlsConn := tls.Client(tcpConn, tlsConfig)
	_ = tcpConn.SetDeadline(time.Now().Add(pd.timeout))
	err = tlsConn.Handshake()
	_ = tcpConn.SetDeadline(time.Time{})
	if err != nil {
		tcpConn.Close()
		return nil, err
	}

	return tlsConn, nil
}

// DialUDP dials a UDP connection through the proxy.
// Note: UDP through SOCKS5 has limitations. A warning is logged once per ProxyDialer instance.
func (pd *ProxyDialer) DialUDP(host string, port uint16) (net.Conn, error) {
	// Log UDP limitation warning once per instance
	pd.udpWarnOnce.Do(func() {
		if pd.verbose {
			log.Println("Warning: UDP through SOCKS5 proxy has limited support. Not all SOCKS5 servers support UDP.")
		}
	})

	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))

	proxyDialer, err := proxy.FromURL(pd.parsedProxyURL, pd.baseDialer)
	if err != nil {
		// Sanitize proxy URL in error message to avoid credential leakage
		return nil, fmt.Errorf("failed to create proxy dialer for %s: %w", sanitizeProxyURL(pd.proxyURL), err)
	}

	var conn net.Conn
	// Try ContextDialer first (supports UDP)
	if cd, ok := proxyDialer.(proxy.ContextDialer); ok {
		conn, err = cd.DialContext(context.Background(), "udp", addr)
	} else {
		conn, err = proxyDialer.Dial("udp", addr)
	}

	if err != nil && pd.dnsOrder == "pl" && host != "" {
		// Proxy dial failed, fallback to local resolution
		if pd.verbose {
			log.Printf("proxy dial failed, falling back to local DNS resolution for %s\n", addr)
		}
		return resolveLocalFallback(host, port, "udp", pd.baseDialer)
	}

	return conn, err
}

// GetHTTPTransport returns an http.Transport configured to use the proxy.
// This is useful for HTTP clients that need to route through the proxy.
func (pd *ProxyDialer) GetHTTPTransport(tlsConfig *tls.Config) *http.Transport {
	proxyFunc := func(req *http.Request) (*url.URL, error) {
		return pd.parsedProxyURL, nil
	}

	transport := &http.Transport{
		Proxy:           proxyFunc,
		TLSClientConfig: tlsConfig,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return pd.DialContext(ctx, network, addr)
		},
	}

	return transport
}
