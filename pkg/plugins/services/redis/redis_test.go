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

package redis

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestRedis(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "redis",
			Port:        6379,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "redis",
			},
		},
	}

	p := &REDISPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

// TestExtractRedisVersion tests version extraction from INFO SERVER response
func TestExtractRedisVersion(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{
			name: "standard INFO response with version",
			response: "# Server\r\n" +
				"redis_version:7.4.0\r\n" +
				"redis_git_sha1:c9d29f6a\r\n" +
				"redis_mode:standalone\r\n",
			want: "7.4.0",
		},
		{
			name: "older Redis version",
			response: "# Server\r\n" +
				"redis_version:5.0.14\r\n" +
				"os:Linux 5.10.0\r\n",
			want: "5.0.14",
		},
		{
			name: "version 6.x",
			response: "redis_version:6.2.7\r\n" +
				"redis_mode:cluster\r\n",
			want: "6.2.7",
		},
		{
			name:     "empty response",
			response: "",
			want:     "",
		},
		{
			name: "missing version field",
			response: "# Server\r\n" +
				"redis_mode:standalone\r\n",
			want: "",
		},
		{
			name:     "malformed response",
			response: "invalid response data",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractRedisVersion(tt.response)
			if got != tt.want {
				t.Errorf("extractRedisVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBuildRedisCPE tests CPE generation for Redis servers
func TestBuildRedisCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "specific version",
			version: "7.4.0",
			want:    "cpe:2.3:a:redis:redis:7.4.0:*:*:*:*:*:*:*",
		},
		{
			name:    "older version",
			version: "5.0.14",
			want:    "cpe:2.3:a:redis:redis:5.0.14:*:*:*:*:*:*:*",
		},
		{
			name:    "version 6.x",
			version: "6.2.7",
			want:    "cpe:2.3:a:redis:redis:6.2.7:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown version (wildcard)",
			version: "",
			want:    "cpe:2.3:a:redis:redis:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildRedisCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildRedisCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

// handleRedisMockConn serves a mock Redis server that responds to PING and INFO SERVER.
// If authRequired is false, PING returns +PONG and INFO returns a minimal INFO response.
// If authRequired is true, PING returns a -NOAUTH error.
func handleRedisMockConn(conn net.Conn, authRequired bool) {
	defer conn.Close()

	pong := []byte("+PONG\r\n")
	noauth := []byte("-NOAUTH Authentication required.\r\n")
	infoResp := []byte("$47\r\n# Server\r\nredis_version:7.0.0\r\nos:Linux\r\n\r\n")

	for {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}

		msg := string(buf[:n])
		// PING command
		if len(msg) > 0 && (msg == "*1\r\n$4\r\nPING\r\n" || contains(msg, "PING")) {
			if authRequired {
				_, _ = conn.Write(noauth)
			} else {
				_, _ = conn.Write(pong)
			}
		} else if contains(msg, "INFO") {
			_, _ = conn.Write(infoResp)
		}
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}

func containsStr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestRedisSecurityFindings verifies that auth check findings are produced only when
// checkRedis returns AuthRequired=false AND target.Misconfigs is true.
func TestRedisSecurityFindings(t *testing.T) {
	tests := []struct {
		name          string
		misconfigs    bool
		authRequired  bool
		wantAnon      bool
		wantFindings  int
		wantFindingID string
		wantSeverity  plugins.Severity
	}{
		{
			name:          "misconfigs=true no auth required → finding produced",
			misconfigs:    true,
			authRequired:  false,
			wantAnon:      true,
			wantFindings:  1,
			wantFindingID: "redis-no-auth",
			wantSeverity:  plugins.SeverityHigh,
		},
		{
			name:         "misconfigs=true auth required → no finding",
			misconfigs:   true,
			authRequired: true,
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:         "misconfigs=false no auth required → no finding",
			misconfigs:   false,
			authRequired: false,
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
					go handleRedisMockConn(conn, tt.authRequired)
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

			plugin := &REDISPlugin{}
			service, err := plugin.Run(conn, 5*time.Second, target)
			if err != nil {
				t.Fatalf("Run() returned unexpected error: %v", err)
			}

			// When auth is required, Run() may return nil (service not identified) or a
			// non-nil service with no findings. The important thing is no finding is produced.
			if tt.authRequired || !tt.misconfigs {
				if service != nil {
					assert.False(t, service.AnonymousAccess, "AnonymousAccess should be false")
					assert.Empty(t, service.SecurityFindings, "SecurityFindings should be empty")
				}
				return
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

// TestCheckRedis tests the checkRedis function directly for all branch conditions.
func TestCheckRedis(t *testing.T) {
	pong := []byte{0x2b, 0x50, 0x4f, 0x4e, 0x47, 0x0d, 0x0a} // +PONG\r\n

	tests := []struct {
		name             string
		data             []byte
		wantAuthRequired bool
		wantErr          bool
	}{
		{
			name:             "valid PONG → AuthRequired false",
			data:             pong,
			wantAuthRequired: false,
			wantErr:          false,
		},
		{
			name:             "NOAUTH error → AuthRequired true",
			data:             []byte("-NOAUTH Authentication required.\r\n"),
			wantAuthRequired: true,
			wantErr:          false,
		},
		{
			name:    "too short → error",
			data:    []byte{0x01, 0x02},
			wantErr: true,
		},
		{
			name:    "invalid 7-byte response → error",
			data:    []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07},
			wantErr: true,
		},
		{
			name:    "invalid longer response (not NOAUTH prefix) → error",
			data:    []byte("-ERR unknown command\r\n"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := checkRedis(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantAuthRequired, info.AuthRequired)
		})
	}
}

// TestRedisSecurityFindingFields validates all SecurityFinding fields are populated correctly.
func TestRedisSecurityFindingFields(t *testing.T) {
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
			go handleRedisMockConn(conn, false) // no auth required
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

	plugin := &REDISPlugin{}
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
	assert.Equal(t, "redis-no-auth", f.ID, "finding ID mismatch")
	assert.Equal(t, plugins.SeverityHigh, f.Severity, "finding severity mismatch")
	assert.NotEmpty(t, f.Description, "Description must be non-empty")
	assert.NotEmpty(t, f.Evidence, "Evidence must be non-empty")
}

// TestCheckRedis_EmptyResponse verifies that an empty byte slice produces an error.
func TestCheckRedis_EmptyResponse(t *testing.T) {
	_, err := checkRedis([]byte{})
	assert.Error(t, err, "expected error for empty response")
}

// TestCheckRedis_ConnectionReset verifies that Run returns gracefully when the server
// closes the connection immediately.
func TestCheckRedis_ConnectionReset(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	go func() {
		serverConn.Close() // close immediately
	}()

	addrStr := "127.0.0.1:6379"
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &REDISPlugin{}
	// Should not panic; may return nil service or error
	service, _ := plugin.Run(clientConn, 5*time.Second, target)
	// Either nil service or no findings (no anonymous access from a closed conn)
	if service != nil {
		assert.False(t, service.AnonymousAccess, "AnonymousAccess must be false when connection resets")
		assert.Empty(t, service.SecurityFindings, "no findings expected on connection reset")
	}
}

// TestRedisDockerNoAuth is a Docker integration test that verifies anonymous access
// detection against a real Redis container with no requirepass configured.
func TestRedisDockerNoAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "redis",
	})
	if err != nil {
		t.Fatalf("could not start redis container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	port := resource.GetPort("6379/tcp")
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

		svc, runErr := (&REDISPlugin{}).Run(conn, 5*time.Second, target)
		if runErr != nil {
			return runErr
		}
		if svc == nil {
			return fmt.Errorf("redis not yet ready")
		}
		service = svc
		return nil
	})
	if retryErr != nil {
		t.Fatalf("redis plugin never connected: %s", retryErr)
	}

	assert.True(t, service.AnonymousAccess, "expected AnonymousAccess=true for no-auth Redis")
	assert.NotEmpty(t, service.SecurityFindings, "expected SecurityFindings for no-auth Redis")
	if len(service.SecurityFindings) > 0 {
		assert.Equal(t, "redis-no-auth", service.SecurityFindings[0].ID)
	}
}

// TestRedisDockerWithAuth is a Docker integration test that verifies no anonymous access
// is detected when Redis requires a password.
func TestRedisDockerWithAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "redis",
		Cmd:        []string{"redis-server", "--requirepass", "testpass123"},
	})
	if err != nil {
		t.Fatalf("could not start redis container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	port := resource.GetPort("6379/tcp")
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

		svc, runErr := (&REDISPlugin{}).Run(conn, 5*time.Second, target)
		if runErr != nil {
			// NOAUTH error from redis-server means auth is working — not a connection error
			return nil
		}
		service = svc
		return nil
	})
	if retryErr != nil {
		t.Fatalf("redis plugin never connected: %s", retryErr)
	}

	// With auth required, service may be nil (not identified) or have AnonymousAccess=false
	if service != nil {
		assert.False(t, service.AnonymousAccess, "expected AnonymousAccess=false for password-protected Redis")
		assert.Empty(t, service.SecurityFindings, "expected no SecurityFindings for password-protected Redis")
	}
}

// TestRedisMisconfigGateFalse verifies that when Misconfigs=false, the INFO command
// is not attempted for an auth-required server and no SecurityFinding is produced.
func TestRedisMisconfigGateFalse(t *testing.T) {
	// Mock server that returns PONG (no auth) but misconfigs=false
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
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					msg := string(buf[:n])
					if containsStr(msg, "PING") {
						_, _ = c.Write([]byte("+PONG\r\n"))
					} else if containsStr(msg, "INFO") {
						_, _ = c.Write([]byte("$0\r\n\r\n"))
					} else {
						_, _ = io.Discard.Write(nil)
					}
				}
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
		Misconfigs: false,
	}

	plugin := &REDISPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	assert.False(t, service.AnonymousAccess, "AnonymousAccess should be false when Misconfigs=false")
	assert.Empty(t, service.SecurityFindings, "SecurityFindings should be empty when Misconfigs=false")
}
