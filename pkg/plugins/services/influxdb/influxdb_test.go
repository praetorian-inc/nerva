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

package influxdb

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TestCleanVersionString tests version string cleanup (removing prerelease and build metadata)
func TestCleanVersionString(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"standard_version_1x", "1.8.10", "1.8.10"},
		{"standard_version_2x", "2.7.10", "2.7.10"},
		{"standard_version_3x", "3.0.0", "3.0.0"},
		{"prerelease_rc", "3.0.0-rc1", "3.0.0"},
		{"prerelease_beta", "2.8.0-beta1", "2.8.0"},
		{"prerelease_alpha", "1.9.0-alpha1", "1.9.0"},
		{"build_metadata", "2.7.10+arm64", "2.7.10"},
		{"prerelease_and_build", "3.0.0-rc1+arm64", "3.0.0"},
		{"custom_build", "2.7.10-custom-build+linux", "2.7.10"},
		{"empty_version", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := cleanVersionString(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestBuildInfluxDBCPE tests CPE generation for InfluxDB
func TestBuildInfluxDBCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "version_1x",
			version:  "1.8.10",
			expected: "cpe:2.3:a:influxdata:influxdb:1.8.10:*:*:*:*:*:*:*",
		},
		{
			name:     "version_2x",
			version:  "2.7.10",
			expected: "cpe:2.3:a:influxdata:influxdb:2.7.10:*:*:*:*:*:*:*",
		},
		{
			name:     "version_3x",
			version:  "3.0.0",
			expected: "cpe:2.3:a:influxdata:influxdb:3.0.0:*:*:*:*:*:*:*",
		},
		{
			name:     "prerelease_rc",
			version:  "3.0.0-rc1",
			expected: "cpe:2.3:a:influxdata:influxdb:3.0.0-rc1:*:*:*:*:*:*:*",
		},
		{
			name:     "empty_version_uses_wildcard",
			version:  "",
			expected: "cpe:2.3:a:influxdata:influxdb:*:*:*:*:*:*:*:*",
		},
		{
			name:     "version_2_0",
			version:  "2.0.9",
			expected: "cpe:2.3:a:influxdata:influxdb:2.0.9:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildInfluxDBCPE(tt.version)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestExtractHTTPHeaders tests HTTP header extraction
func TestExtractHTTPHeaders(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected map[string]string
	}{
		{
			name: "influxdb_ping_headers",
			response: []byte("HTTP/1.1 204 No Content\r\n" +
				"Content-Type: application/json\r\n" +
				"X-Influxdb-Build: OSS\r\n" +
				"X-Influxdb-Version: 2.7.10\r\n" +
				"X-Request-Id: abc123\r\n" +
				"\r\n"),
			expected: map[string]string{
				"content-type":       "application/json",
				"x-influxdb-build":   "OSS",
				"x-influxdb-version": "2.7.10",
				"x-request-id":       "abc123",
			},
		},
		{
			name: "influxdb_1x_headers",
			response: []byte("HTTP/1.1 204 No Content\r\n" +
				"X-Influxdb-Version: 1.8.10\r\n" +
				"\r\n"),
			expected: map[string]string{
				"x-influxdb-version": "1.8.10",
			},
		},
		{
			name: "missing_version_header",
			response: []byte("HTTP/1.1 204 No Content\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n"),
			expected: map[string]string{
				"content-type": "application/json",
			},
		},
		{
			name:     "empty_response",
			response: []byte(""),
			expected: map[string]string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHTTPHeaders(tt.response)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// TestExtractHTTPBody tests HTTP body extraction
func TestExtractHTTPBody(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected []byte
	}{
		{
			name: "json_body",
			response: []byte("HTTP/1.1 200 OK\r\n" +
				"Content-Type: application/json\r\n" +
				"\r\n" +
				`{"name":"influxdb","version":"2.7.10"}`),
			expected: []byte(`{"name":"influxdb","version":"2.7.10"}`),
		},
		{
			name: "empty_body",
			response: []byte("HTTP/1.1 204 No Content\r\n" +
				"X-Influxdb-Version: 2.7.10\r\n" +
				"\r\n"),
			expected: nil,
		},
		{
			name:     "no_header_separator",
			response: []byte("not an http response"),
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHTTPBody(tt.response)
			assert.Equal(t, tt.expected, got)
		})
	}
}

// Mock HTTP response builders for testing

// buildMockInfluxDBPingResponse creates a mock HTTP /ping response from InfluxDB
// buildMockInfluxDBHealthResponse creates a mock HTTP /health response from InfluxDB 2.x+
// buildMockPrometheusResponse creates a mock HTTP response from Prometheus (false positive test)
// buildMock404Response creates a mock HTTP 404 response (for InfluxDB 1.x /health endpoint)
// buildMockInvalidJSONResponse creates a mock response with invalid JSON
// buildMockMissingVersionHeaderResponse creates a mock response without X-Influxdb-Version
// buildMockGrafanaHealthResponse creates a mock /health response from Grafana (false positive test)
// Note: Full integration tests with net.Conn mocking would go here
// For now, we've tested the core logic functions (cleanVersionString, buildInfluxDBCPE,
// extractHTTPHeaders, extractHTTPBody) and provided mock response builders for future
// integration test expansion.

// buildInfluxDBPingResponse constructs a mock HTTP /ping response for InfluxDB.
// If withVersion is true, it includes the X-Influxdb-Version header.
func buildInfluxDBPingResponse(statusLine, version string) string {
	resp := statusLine + "\r\n"
	resp += "Content-Type: application/json\r\n"
	if version != "" {
		resp += "X-Influxdb-Version: " + version + "\r\n"
	}
	resp += "\r\n"
	return resp
}

// buildInfluxDBQueryResponse constructs a mock HTTP /query response.
// status should be "200 OK" for unauthenticated access, "401 Unauthorized" for auth required.
func buildInfluxDBQueryResponse(statusCode int) string {
	if statusCode == 200 {
		return "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\r\n{\"results\":[]}"
	}
	return "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\n\r\n{\"error\":\"authorization failed\"}"
}

// handleInfluxDBMockConn serves mock HTTP responses for InfluxDB plugin testing.
// It reads successive HTTP requests and responds based on the path.
func handleInfluxDBMockConn(conn net.Conn, version string, queryAuth bool) {
	defer conn.Close()

	buf := make([]byte, 4096)
	reqCount := 0
	for {
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		req := string(buf[:n])
		reqCount++

		if containsInflux(req, "/ping") {
			pingResp := buildInfluxDBPingResponse("HTTP/1.1 204 No Content", version)
			_, _ = conn.Write([]byte(pingResp))
		} else if containsInflux(req, "/query") {
			authCode := 200
			if queryAuth {
				authCode = 401
			}
			_, _ = conn.Write([]byte(buildInfluxDBQueryResponse(authCode)))
		}
	}
}

func containsInflux(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestCheckInfluxDBAuth_ConnectionError verifies that checkInfluxDBAuth returns false when
// the server closes the connection immediately.
func TestCheckInfluxDBAuth_ConnectionError(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	go func() {
		serverConn.Close() // close immediately
	}()

	addrStr := "127.0.0.1:8086"
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:    "127.0.0.1",
		Address: addrPort,
	}

	got := checkInfluxDBAuth(clientConn, target, 5*time.Second)
	clientConn.Close()
	assert.False(t, got, "expected false when connection is immediately closed")
}

// TestCheckInfluxDBAuth_EmptyResponse verifies that checkInfluxDBAuth returns false when
// the server sends an empty response.
func TestCheckInfluxDBAuth_EmptyResponse(t *testing.T) {
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
				// Send empty response and close
				_, _ = c.Write([]byte{})
			}(conn)
		}
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:    "127.0.0.1",
		Address: addrPort,
	}

	got := checkInfluxDBAuth(conn, target, 5*time.Second)
	assert.False(t, got, "expected false for empty response")
}

// TestCheckInfluxDBAuth_HTTP10_200 verifies that checkInfluxDBAuth returns true when
// the server responds with HTTP/1.0 200.
func TestCheckInfluxDBAuth_HTTP10_200(t *testing.T) {
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
				_, _ = c.Write([]byte("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"results\":[]}"))
			}(conn)
		}
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:    "127.0.0.1",
		Address: addrPort,
	}

	got := checkInfluxDBAuth(conn, target, 5*time.Second)
	assert.True(t, got, "expected true for HTTP/1.0 200 response")
}

// TestInfluxDBSecurityFindingFields validates all SecurityFinding fields are populated correctly.
func TestInfluxDBSecurityFindingFields(t *testing.T) {
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
			go handleInfluxDBMockConn(conn, "2.7.10", false)
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

	plugin := &InfluxDBPlugin{}
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
	assert.Equal(t, "influxdb-no-auth", f.ID, "finding ID mismatch")
	assert.Equal(t, plugins.SeverityHigh, f.Severity, "finding severity mismatch")
	assert.NotEmpty(t, f.Description, "Description must be non-empty")
	assert.NotEmpty(t, f.Evidence, "Evidence must be non-empty")
}

// TestInfluxDBDockerNoAuth is a Docker integration test that verifies anonymous access
// detection against a real InfluxDB 1.8 container with auth disabled.
func TestInfluxDBDockerNoAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "influxdb",
		Tag:        "1.8",
		Env:        []string{"INFLUXDB_HTTP_AUTH_ENABLED=false"},
	})
	if err != nil {
		t.Fatalf("could not start influxdb container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	port := resource.GetPort("8086/tcp")
	addr := fmt.Sprintf("127.0.0.1:%s", port)

	time.Sleep(10 * time.Second)

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

		svc, runErr := (&InfluxDBPlugin{}).Run(conn, 5*time.Second, target)
		if runErr != nil {
			return runErr
		}
		if svc == nil {
			return fmt.Errorf("influxdb not yet ready")
		}
		service = svc
		return nil
	})
	if retryErr != nil {
		t.Fatalf("influxdb plugin never connected: %s", retryErr)
	}

	assert.True(t, service.AnonymousAccess, "expected AnonymousAccess=true for no-auth InfluxDB")
	assert.NotEmpty(t, service.SecurityFindings, "expected SecurityFindings for no-auth InfluxDB")
	if len(service.SecurityFindings) > 0 {
		assert.Equal(t, "influxdb-no-auth", service.SecurityFindings[0].ID)
	}
}

// TestInfluxDBDockerWithAuth is a Docker integration test that verifies no anonymous access
// is detected when InfluxDB 1.8 has authentication enabled.
func TestInfluxDBDockerWithAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "influxdb",
		Tag:        "1.8",
		Env: []string{
			"INFLUXDB_HTTP_AUTH_ENABLED=true",
			"INFLUXDB_ADMIN_USER=admin",
			"INFLUXDB_ADMIN_PASSWORD=password123",
		},
	})
	if err != nil {
		t.Fatalf("could not start influxdb container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	port := resource.GetPort("8086/tcp")
	addr := fmt.Sprintf("127.0.0.1:%s", port)

	time.Sleep(10 * time.Second)

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

		svc, runErr := (&InfluxDBPlugin{}).Run(conn, 5*time.Second, target)
		if runErr != nil {
			return runErr
		}
		if svc == nil {
			return fmt.Errorf("influxdb not yet ready")
		}
		service = svc
		return nil
	})
	if retryErr != nil {
		t.Fatalf("influxdb plugin never connected: %s", retryErr)
	}

	assert.False(t, service.AnonymousAccess, "expected AnonymousAccess=false for auth-enabled InfluxDB")
	assert.Empty(t, service.SecurityFindings, "expected no SecurityFindings for auth-enabled InfluxDB")
}

// TestCheckInfluxDBAuth_Returns200 tests that checkInfluxDBAuth returns true on HTTP 200.
func TestCheckInfluxDBAuth_Returns200(t *testing.T) {
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
				_, _ = c.Write([]byte(buildInfluxDBQueryResponse(200)))
			}(conn)
		}
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:    "127.0.0.1",
		Address: addrPort,
	}

	got := checkInfluxDBAuth(conn, target, 5*time.Second)
	assert.True(t, got, "expected checkInfluxDBAuth to return true for HTTP 200")
}

// TestCheckInfluxDBAuth_Returns401 tests that checkInfluxDBAuth returns false on HTTP 401.
func TestCheckInfluxDBAuth_Returns401(t *testing.T) {
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
				_, _ = c.Write([]byte(buildInfluxDBQueryResponse(401)))
			}(conn)
		}
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:    "127.0.0.1",
		Address: addrPort,
	}

	got := checkInfluxDBAuth(conn, target, 5*time.Second)
	assert.False(t, got, "expected checkInfluxDBAuth to return false for HTTP 401")
}

// TestInfluxDBSecurityFindings tests the full Run() flow with misconfigs enabled.
func TestInfluxDBSecurityFindings(t *testing.T) {
	tests := []struct {
		name          string
		misconfigs    bool
		version       string    // non-empty = server responds as InfluxDB
		queryAuth     bool      // true = query endpoint returns 401
		wantAnon      bool
		wantFindings  int
		wantFindingID string
		wantSeverity  plugins.Severity
	}{
		{
			name:          "misconfigs=true no auth required → finding produced",
			misconfigs:    true,
			version:       "2.7.10",
			queryAuth:     false,
			wantAnon:      true,
			wantFindings:  1,
			wantFindingID: "influxdb-no-auth",
			wantSeverity:  plugins.SeverityHigh,
		},
		{
			name:         "misconfigs=true auth required → no finding",
			misconfigs:   true,
			version:      "2.7.10",
			queryAuth:    true,
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:         "misconfigs=false no auth required → no finding",
			misconfigs:   false,
			version:      "2.7.10",
			queryAuth:    false,
			wantAnon:     false,
			wantFindings: 0,
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

			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					go handleInfluxDBMockConn(conn, tt.version, tt.queryAuth)
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

			plugin := &InfluxDBPlugin{}
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
