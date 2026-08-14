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

package redissentinel

import (
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// handleSentinelMockConn serves canned RESP responses for PING and INFO commands,
// simulating either a Redis Sentinel instance, a regular Redis instance, or an
// auth-required instance depending on the provided mode.
func handleSentinelMockConn(conn net.Conn, mode string) {
	defer conn.Close()

	pong := []byte("+PONG\r\n")
	noauth := []byte("-NOAUTH Authentication required.\r\n")

	sentinelSection := "# Sentinel\r\nsentinel_masters:2\r\nsentinel_tilt:0\r\n"
	sentinelSectionResp := append([]byte(fmt.Sprintf("$%d\r\n", len(sentinelSection))), append([]byte(sentinelSection), '\r', '\n')...)

	serverSection := "# Server\r\nredis_version:7.0.5\r\nredis_mode:sentinel\r\n"
	serverSectionResp := append([]byte(fmt.Sprintf("$%d\r\n", len(serverSection))), append([]byte(serverSection), '\r', '\n')...)

	nilBulkString := []byte("$-1\r\n")

	sentinelInfo := "# Server\r\n" +
		"redis_version:7.0.5\r\n" +
		"redis_mode:sentinel\r\n" +
		"\r\n" +
		"# Sentinel\r\n" +
		"sentinel_masters:2\r\n" +
		"sentinel_tilt:0\r\n"
	sentinelInfoResp := append([]byte(fmt.Sprintf("$%d\r\n", len(sentinelInfo))), append([]byte(sentinelInfo), '\r', '\n')...)

	plainRedisInfo := "# Server\r\n" +
		"redis_version:7.0.5\r\n" +
		"redis_mode:standalone\r\n"
	plainRedisInfoResp := append([]byte(fmt.Sprintf("$%d\r\n", len(plainRedisInfo))), append([]byte(plainRedisInfo), '\r', '\n')...)

	for {
		buf := make([]byte, 4096)
		n, err := conn.Read(buf)
		if err != nil {
			return
		}
		msg := string(buf[:n])

		switch {
		case containsSubstr(msg, "PING"):
			if mode == "noauth-required" {
				_, _ = conn.Write(noauth)
			} else {
				_, _ = conn.Write(pong)
			}
		case containsSubstr(msg, "sentinel"):
			switch mode {
			case "sentinel":
				_, _ = conn.Write(sentinelSectionResp)
			case "plain-redis":
				_, _ = conn.Write(nilBulkString)
			}
		case containsSubstr(msg, "server"):
			switch mode {
			case "sentinel", "plain-redis":
				_, _ = conn.Write(serverSectionResp)
			}
		case containsSubstr(msg, "INFO"):
			switch mode {
			case "sentinel":
				_, _ = conn.Write(sentinelInfoResp)
			case "plain-redis":
				_, _ = conn.Write(plainRedisInfoResp)
			}
		}
	}
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func startMockServer(t *testing.T, mode string) (net.Conn, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go handleSentinelMockConn(conn, mode)
		}
	}()

	serverPort := listener.Addr().(*net.TCPAddr).Port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		listener.Close()
		t.Fatalf("failed to connect to mock server: %v", err)
	}

	cleanup := func() {
		conn.Close()
		listener.Close()
	}
	return conn, cleanup
}

func TestRedisSentinelDetection_Positive(t *testing.T) {
	conn, cleanup := startMockServer(t, "sentinel")
	defer cleanup()

	addrPort := netip.MustParseAddrPort(conn.LocalAddr().String())
	target := plugins.Target{Host: "127.0.0.1", Address: addrPort}

	plugin := &RedisSentinelPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want a detected Sentinel service")
	}

	assert.Equal(t, "redis-sentinel", service.Protocol)
	assert.Equal(t, "7.0.5", service.Version)

	payload, ok := service.Metadata().(plugins.ServiceRedisSentinel)
	if !ok {
		t.Fatalf("expected ServiceRedisSentinel metadata, got %T", service.Metadata())
	}
	assert.Equal(t, 2, payload.SentinelMasters)
	assert.Contains(t, payload.CPEs, "cpe:2.3:a:redis:redis:7.0.5:*:*:*:*:*:*:*")
}

func TestRedisSentinelDetection_NegativePlainRedis(t *testing.T) {
	conn, cleanup := startMockServer(t, "plain-redis")
	defer cleanup()

	addrPort := netip.MustParseAddrPort(conn.LocalAddr().String())
	target := plugins.Target{Host: "127.0.0.1", Address: addrPort}

	plugin := &RedisSentinelPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	assert.NoError(t, err)
	assert.Nil(t, service, "plain Redis (no Sentinel section) must not be detected as Sentinel")
}

func TestRedisSentinelDetection_NegativeAuthRequired(t *testing.T) {
	conn, cleanup := startMockServer(t, "noauth-required")
	defer cleanup()

	addrPort := netip.MustParseAddrPort(conn.LocalAddr().String())
	target := plugins.Target{Host: "127.0.0.1", Address: addrPort}

	plugin := &RedisSentinelPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	assert.NoError(t, err)
	assert.Nil(t, service, "auth-required instance must not be detected (cannot distinguish from Redis)")
}

func TestRedisSentinelDetection_TooShortResponse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{0x01, 0x02})
	}()

	serverPort := listener.Addr().(*net.TCPAddr).Port
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrPort := netip.MustParseAddrPort(conn.LocalAddr().String())
	target := plugins.Target{Host: "127.0.0.1", Address: addrPort}

	plugin := &RedisSentinelPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	assert.NoError(t, err)
	assert.Nil(t, service, "too-short response must not be detected")
}

func TestRedisSentinelDetection_ConnectionReset(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	go func() {
		serverConn.Close()
	}()

	addrPort := netip.MustParseAddrPort("127.0.0.1:26379")
	target := plugins.Target{Host: "127.0.0.1", Address: addrPort}

	plugin := &RedisSentinelPlugin{}
	// Should not panic; may return nil service or error.
	service, _ := plugin.Run(clientConn, 5*time.Second, target)
	assert.Nil(t, service, "connection reset must not produce a detected service")
}

func TestExtractRedisVersion(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{
			name:     "standard INFO response with version",
			response: "# Server\r\nredis_version:7.4.0\r\nredis_mode:sentinel\r\n",
			want:     "7.4.0",
		},
		{
			name:     "empty response",
			response: "",
			want:     "",
		},
		{
			name:     "missing version field",
			response: "# Server\r\nredis_mode:sentinel\r\n",
			want:     "",
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

func TestBuildRedisCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "specific version",
			version: "7.0.5",
			want:    "cpe:2.3:a:redis:redis:7.0.5:*:*:*:*:*:*:*",
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

func TestExtractSentinelMasters(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     int
	}{
		{
			name:     "valid count",
			response: "# Sentinel\r\nsentinel_masters:3\r\nsentinel_tilt:0\r\n",
			want:     3,
		},
		{
			name:     "zero masters",
			response: "# Sentinel\r\nsentinel_masters:0\r\n",
			want:     0,
		},
		{
			name:     "missing field",
			response: "# Server\r\nredis_version:7.0.5\r\n",
			want:     0,
		},
		{
			name:     "malformed value",
			response: "sentinel_masters:notanumber\r\n",
			want:     0,
		},
		{
			name:     "empty response",
			response: "",
			want:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSentinelMasters(tt.response)
			if got != tt.want {
				t.Errorf("extractSentinelMasters() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestCheckRedisResponse(t *testing.T) {
	tests := []struct {
		name             string
		data             []byte
		wantAuthRequired bool
		wantErr          bool
	}{
		{
			name:             "valid PONG -> AuthRequired false",
			data:             []byte("+PONG\r\n"),
			wantAuthRequired: false,
			wantErr:          false,
		},
		{
			name:             "NOAUTH error -> AuthRequired true",
			data:             []byte("-NOAUTH Authentication required.\r\n"),
			wantAuthRequired: true,
			wantErr:          false,
		},
		{
			name:    "too short -> error",
			data:    []byte{0x01, 0x02},
			wantErr: true,
		},
		{
			name:    "empty -> error",
			data:    []byte{},
			wantErr: true,
		},
		{
			name:    "invalid response -> error",
			data:    []byte("-ERR unknown command\r\n"),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authRequired, err := checkRedisResponse(tt.data)
			if tt.wantErr {
				assert.Error(t, err)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantAuthRequired, authRequired)
		})
	}
}

// TestRedisSentinelDocker is a Docker integration test that verifies detection
// against a real Redis Sentinel instance running via the official redis image
// in --sentinel mode.
func TestRedisSentinelDocker(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "redis-sentinel",
			Port:        26379,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil && res.Protocol == "redis-sentinel"
			},
			RunConfig: dockertest.RunOptions{
				Repository: "redis",
				Cmd: []string{
					"sh", "-c",
					"touch /tmp/sentinel.conf && redis-server /tmp/sentinel.conf --sentinel --port 26379",
				},
				ExposedPorts: []string{"26379/tcp"},
			},
		},
	}

	p := &RedisSentinelPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}
