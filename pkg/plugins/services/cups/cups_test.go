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

package cups

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TestExtractServerHeader tests extracting the Server header from raw HTTP responses.
func TestExtractServerHeader(t *testing.T) {
	tests := []struct {
		name           string
		httpResponse   string
		expectedHeader string
	}{
		{
			name: "cups_server_header",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/html\r\n" +
				"Server: CUPS/2.3.1 IPP/2.1\r\n" +
				"\r\n" +
				"<html>body</html>",
			expectedHeader: "CUPS/2.3.1 IPP/2.1",
		},
		{
			name: "cups_server_header_simple",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Server: CUPS/2.4.2\r\n" +
				"\r\n",
			expectedHeader: "CUPS/2.4.2",
		},
		{
			name: "cups_server_header_with_packaging_suffix",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/html\r\n" +
				"Server: CUPS/2.4.2-163+eb63a8052\r\n" +
				"\r\n",
			expectedHeader: "CUPS/2.4.2-163+eb63a8052",
		},
		{
			name: "no_server_header",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n" +
				"body",
			expectedHeader: "",
		},
		{
			name: "apache_server_header",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Server: Apache/2.4.51\r\n" +
				"\r\n",
			expectedHeader: "Apache/2.4.51",
		},
		{
			name:           "empty_response",
			httpResponse:   "",
			expectedHeader: "",
		},
		{
			name: "server_header_case_insensitive_key",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"server: CUPS/2.3.1\r\n" +
				"\r\n",
			expectedHeader: "CUPS/2.3.1",
		},
		{
			name: "multiple_headers_server_present",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Server: CUPS/2.3.1\r\n" +
				"Content-Type: text/html\r\n" +
				"X-Frame-Options: DENY\r\n" +
				"\r\n",
			expectedHeader: "CUPS/2.3.1",
		},
		{
			name: "body_after_blank_line_ignored",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Type: text/html\r\n" +
				"\r\n" +
				"Server: NotAHeader/1.0\r\n",
			expectedHeader: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractServerHeader([]byte(tt.httpResponse))
			assert.Equal(t, tt.expectedHeader, result)
		})
	}
}

// TestParseCUPSVersion tests version extraction from Server header values.
func TestParseCUPSVersion(t *testing.T) {
	tests := []struct {
		name            string
		serverHeader    string
		expectedVersion string
	}{
		{
			name:            "cups_2.3.1_simple",
			serverHeader:    "CUPS/2.3.1",
			expectedVersion: "2.3.1",
		},
		{
			name:            "cups_2.4.2_with_packaging_suffix",
			serverHeader:    "CUPS/2.4.2-163+eb63a8052",
			expectedVersion: "2.4.2",
		},
		{
			name:            "cups_1.7_two_part_version",
			serverHeader:    "CUPS/1.7",
			expectedVersion: "1.7",
		},
		{
			name:            "cups_with_ipp_version",
			serverHeader:    "CUPS/2.3.1 IPP/2.1",
			expectedVersion: "2.3.1",
		},
		{
			name:            "cups_lowercase",
			serverHeader:    "cups/2.3.1",
			expectedVersion: "2.3.1",
		},
		{
			name:            "cups_2.0_no_patch",
			serverHeader:    "CUPS/2.0",
			expectedVersion: "2.0",
		},
		{
			name:            "apache_not_cups",
			serverHeader:    "Apache/2.4",
			expectedVersion: "",
		},
		{
			name:            "nginx_not_cups",
			serverHeader:    "nginx/1.18.0",
			expectedVersion: "",
		},
		{
			name:            "empty_header",
			serverHeader:    "",
			expectedVersion: "",
		},
		{
			name:            "cups_no_version",
			serverHeader:    "CUPS",
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseCUPSVersion(tt.serverHeader)
			assert.Equal(t, tt.expectedVersion, result)
		})
	}
}

// TestBuildCUPSCPE tests CPE generation for CUPS.
func TestBuildCUPSCPE(t *testing.T) {
	tests := []struct {
		name        string
		version     string
		expectedCPE string
	}{
		{
			name:        "cups_2.3.1_with_version",
			version:     "2.3.1",
			expectedCPE: "cpe:2.3:a:apple:cups:2.3.1:*:*:*:*:*:*:*",
		},
		{
			name:        "cups_2.4.2_with_version",
			version:     "2.4.2",
			expectedCPE: "cpe:2.3:a:apple:cups:2.4.2:*:*:*:*:*:*:*",
		},
		{
			name:        "cups_1.7_with_version",
			version:     "1.7",
			expectedCPE: "cpe:2.3:a:apple:cups:1.7:*:*:*:*:*:*:*",
		},
		{
			name:        "cups_unknown_version_wildcard",
			version:     "",
			expectedCPE: "cpe:2.3:a:apple:cups:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildCUPSCPE(tt.version)
			assert.Equal(t, tt.expectedCPE, cpe)
		})
	}
}

// TestBuildCUPSHTTPRequest tests HTTP request building.
func TestBuildCUPSHTTPRequest(t *testing.T) {
	tests := []struct {
		name             string
		host             string
		expectedContains []string
	}{
		{
			name: "standard_cups_port",
			host: "192.168.1.10:631",
			expectedContains: []string{
				"GET / HTTP/1.1\r\n",
				"Host: 192.168.1.10:631\r\n",
				"User-Agent: nerva/1.0\r\n",
				"Connection: close\r\n",
				"\r\n\r\n",
			},
		},
		{
			name: "localhost_cups_port",
			host: "localhost:631",
			expectedContains: []string{
				"GET / HTTP/1.1\r\n",
				"Host: localhost:631\r\n",
				"\r\n\r\n",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			request := buildCUPSHTTPRequest(tt.host)
			for _, exp := range tt.expectedContains {
				assert.Contains(t, request, exp)
			}
		})
	}
}

// TestPluginMetadata tests TCP plugin metadata methods.
func TestPluginMetadata(t *testing.T) {
	plugin := &CUPSPlugin{}

	assert.Equal(t, "cups", plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, 100, plugin.Priority())
	assert.True(t, plugin.PortPriority(631), "Port 631 should be prioritized")
	assert.False(t, plugin.PortPriority(80), "Port 80 should not be prioritized")
	assert.False(t, plugin.PortPriority(443), "Port 443 should not be prioritized")
}

// TestTLSPluginMetadata tests TLS plugin metadata methods.
func TestTLSPluginMetadata(t *testing.T) {
	plugin := &CUPSTLSPlugin{}

	assert.Equal(t, "cups", plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, 101, plugin.Priority())
	assert.True(t, plugin.PortPriority(631), "Port 631 should be prioritized")
	assert.False(t, plugin.PortPriority(80), "Port 80 should not be prioritized")
}

// TestPluginsDifferentTransports verifies plain and TLS plugins use different transports.
func TestPluginsDifferentTransports(t *testing.T) {
	plainPlugin := &CUPSPlugin{}
	tlsPlugin := &CUPSTLSPlugin{}

	assert.Equal(t, plugins.TCP, plainPlugin.Type(), "Plain plugin should use TCP transport")
	assert.Equal(t, plugins.TCPTLS, tlsPlugin.Type(), "TLS plugin should use TCPTLS transport")

	assert.True(t, plainPlugin.PortPriority(631), "Both plugins should prioritize port 631")
	assert.True(t, tlsPlugin.PortPriority(631), "Both plugins should prioritize port 631")
}

// TestFullHTTPResponseParsing tests parsing a complete HTTP response for CUPS detection.
func TestFullHTTPResponseParsing(t *testing.T) {
	tests := []struct {
		name            string
		httpResponse    string
		expectCUPS      bool
		expectedVersion string
	}{
		{
			name: "cups_2.3.1_full_response",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Content-Language: en\r\n" +
				"Content-Type: text/html; charset=UTF-8\r\n" +
				"Server: CUPS/2.3.1 IPP/2.1\r\n" +
				"X-Frame-Options: DENY\r\n" +
				"\r\n" +
				"<!DOCTYPE HTML>",
			expectCUPS:      true,
			expectedVersion: "2.3.1",
		},
		{
			name: "cups_2.4.2_debian_full_response",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Server: CUPS/2.4.2-163+eb63a8052 IPP/2.1\r\n" +
				"\r\n",
			expectCUPS:      true,
			expectedVersion: "2.4.2",
		},
		{
			name: "apache_not_cups",
			httpResponse: "HTTP/1.1 200 OK\r\n" +
				"Server: Apache/2.4.51\r\n" +
				"\r\n" +
				"<html></html>",
			expectCUPS:      false,
			expectedVersion: "",
		},
		{
			name:            "empty_response",
			httpResponse:    "",
			expectCUPS:      false,
			expectedVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			serverHeader := extractServerHeader([]byte(tt.httpResponse))
			isCUPS := strings.Contains(strings.ToLower(serverHeader), "cups")
			assert.Equal(t, tt.expectCUPS, isCUPS)

			if tt.expectCUPS {
				version := parseCUPSVersion(serverHeader)
				assert.Equal(t, tt.expectedVersion, version)
			}
		})
	}
}

// TestExtractHTTPStatusCode tests HTTP status code extraction from raw responses.
func TestExtractHTTPStatusCode(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     int
	}{
		{
			name:     "200 OK",
			response: "HTTP/1.1 200 OK\r\nServer: CUPS/2.4.2\r\n\r\n",
			want:     200,
		},
		{
			name:     "401 Unauthorized",
			response: "HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm=\"CUPS\"\r\nServer: CUPS/2.4.2\r\n\r\n",
			want:     401,
		},
		{
			name:     "403 Forbidden",
			response: "HTTP/1.1 403 Forbidden\r\nServer: CUPS/2.4.2\r\n\r\n",
			want:     403,
		},
		{
			name:     "empty response",
			response: "",
			want:     0,
		},
		{
			name:     "malformed status line",
			response: "not-http\r\n\r\n",
			want:     0,
		},
		{
			name:     "HTTP 1.0",
			response: "HTTP/1.0 200 OK\r\n\r\n",
			want:     200,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHTTPStatusCode([]byte(tt.response))
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestCUPSSecurityFindings tests that the cups-remote-access finding is produced
// when target.Misconfigs is true and HTTP 200 is returned, and suppressed otherwise.
func TestCUPSSecurityFindings(t *testing.T) {
	tests := []struct {
		name          string
		misconfigs    bool
		serverHeader  string
		statusCode    int
		wantAnon      bool
		wantFindings  int
		wantFindingID string
		wantSeverity  plugins.Severity
	}{
		{
			name:          "misconfigs=true anonymous (200) → finding produced",
			misconfigs:    true,
			serverHeader:  "CUPS/2.4.2 IPP/2.1",
			statusCode:    200,
			wantAnon:      true,
			wantFindings:  1,
			wantFindingID: "cups-remote-access",
			wantSeverity:  plugins.SeverityHigh,
		},
		{
			name:         "misconfigs=false anonymous (200) → no finding",
			misconfigs:   false,
			serverHeader: "CUPS/2.4.2 IPP/2.1",
			statusCode:   200,
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:          "misconfigs=true with version → finding produced",
			misconfigs:    true,
			serverHeader:  "CUPS/2.3.1 IPP/2.1",
			statusCode:    200,
			wantAnon:      true,
			wantFindings:  1,
			wantFindingID: "cups-remote-access",
			wantSeverity:  plugins.SeverityHigh,
		},
		{
			name:         "misconfigs=true auth_required (401) → no finding",
			misconfigs:   true,
			serverHeader: "CUPS/2.4.2 IPP/2.1",
			statusCode:   401,
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:         "misconfigs=true forbidden (403) → no finding",
			misconfigs:   true,
			serverHeader: "CUPS/2.4.2 IPP/2.1",
			statusCode:   403,
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:          "misconfigs=true no_version → finding with no version in evidence",
			misconfigs:    true,
			serverHeader:  "CUPS",
			statusCode:    200,
			wantAnon:      true,
			wantFindings:  1,
			wantFindingID: "cups-remote-access",
			wantSeverity:  plugins.SeverityHigh,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("failed to start mock server: %v", err)
			}
			defer listener.Close()

			serverPort := listener.Addr().(*net.TCPAddr).Port

			statusLine := fmt.Sprintf("HTTP/1.1 %d", tt.statusCode)
			switch tt.statusCode {
			case 200:
				statusLine += " OK"
			case 401:
				statusLine += " Unauthorized"
			case 403:
				statusLine += " Forbidden"
			}

			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					go func(c net.Conn) {
						defer c.Close()
						buf := make([]byte, 4096)
						_, _ = c.Read(buf)
						response := statusLine + "\r\nServer: " + tt.serverHeader + "\r\nContent-Type: text/html\r\n\r\n"
						_, _ = c.Write([]byte(response))
					}(conn)
				}
			}()

			conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
			if err != nil {
				t.Fatalf("failed to connect to mock server: %v", err)
			}
			defer conn.Close()

			addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
			addrPort := netip.MustParseAddrPort(addrStr)
			target := plugins.Target{
				Host:       "127.0.0.1",
				Address:    addrPort,
				Misconfigs: tt.misconfigs,
			}

			plugin := &CUPSPlugin{}
			service, err := plugin.Run(conn, 5*time.Second, target)
			if err != nil {
				t.Fatalf("Run() returned unexpected error: %v", err)
			}
			if service == nil {
				t.Fatal("Run() returned nil, want non-nil service")
			}

			assert.Equal(t, tt.wantAnon, service.AnonymousAccess, "AnonymousAccess mismatch")
			assert.Len(t, service.SecurityFindings, tt.wantFindings, "SecurityFindings count mismatch")
			if tt.wantFindings > 0 {
				assert.Equal(t, tt.wantFindingID, service.SecurityFindings[0].ID, "finding ID mismatch")
				assert.Equal(t, tt.wantSeverity, service.SecurityFindings[0].Severity, "finding severity mismatch")
			}
		})
	}
}

// TestCUPSSecurityFindingFields validates all SecurityFinding fields are populated correctly.
func TestCUPSSecurityFindingFields(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: CUPS/2.4.2 IPP/2.1\r\nContent-Type: text/html\r\n\r\n"))
			}(conn)
		}
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &CUPSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	assert.Len(t, service.SecurityFindings, 1, "expected 1 security finding")
	if len(service.SecurityFindings) == 0 {
		return
	}
	f := service.SecurityFindings[0]
	assert.Equal(t, "cups-remote-access", f.ID, "finding ID mismatch")
	assert.Equal(t, plugins.SeverityHigh, f.Severity, "finding severity mismatch")
	assert.NotEmpty(t, f.Description, "Description must be non-empty")
	assert.NotEmpty(t, f.Evidence, "Evidence must be non-empty")
	assert.Contains(t, f.Evidence, "127.0.0.1", "Evidence must contain target address")
}

// TestCUPSNonCUPSServerNoFinding verifies that a non-CUPS HTTP server
// does not produce a service or finding even with misconfigs enabled.
func TestCUPSNonCUPSServerNoFinding(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				_, _ = c.Write([]byte("HTTP/1.1 200 OK\r\nServer: Apache/2.4.51\r\nContent-Type: text/html\r\n\r\n"))
			}(conn)
		}
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &CUPSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	assert.NoError(t, err, "Run() should not error for non-CUPS server")
	assert.Nil(t, service, "Run() should return nil for non-CUPS server")
}

// TestCUPSDockerRemoteAccess is a Docker integration test that verifies the
// cups-remote-access finding is produced against a real CUPS container.
func TestCUPSDockerRemoteAccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "olbat/cupsd",
		Tag:        "2026-06-01",
	})
	if err != nil {
		t.Fatalf("could not start CUPS container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	port := resource.GetPort("631/tcp")
	addr := fmt.Sprintf("127.0.0.1:%s", port)

	time.Sleep(5 * time.Second)

	var service *plugins.Service
	retryErr := pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", addr, 5*time.Second)
		if dialErr != nil {
			return dialErr
		}
		defer conn.Close()

		addrPort := netip.MustParseAddrPort(addr)
		target := plugins.Target{
			Host:       "127.0.0.1",
			Address:    addrPort,
			Misconfigs: true,
		}

		svc, runErr := (&CUPSPlugin{}).Run(conn, 5*time.Second, target)
		if runErr != nil {
			return runErr
		}
		if svc == nil {
			return fmt.Errorf("CUPS not yet ready")
		}
		service = svc
		return nil
	})
	if retryErr != nil {
		t.Fatalf("CUPS plugin never connected: %s", retryErr)
	}

	assert.True(t, service.AnonymousAccess, "expected AnonymousAccess=true for exposed CUPS")
	assert.NotEmpty(t, service.SecurityFindings, "expected SecurityFindings for exposed CUPS")
	if len(service.SecurityFindings) > 0 {
		assert.Equal(t, "cups-remote-access", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityHigh, service.SecurityFindings[0].Severity)
		assert.Contains(t, service.SecurityFindings[0].Evidence, "127.0.0.1")
	}
}
