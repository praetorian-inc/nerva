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

package memcached

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestMemcached(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "memcached",
			Port:        11211,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "memcached",
			},
		},
	}

	p := &MEMCACHEDPlugin{}

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

// TestCheckMemcachedVersionResponse tests validation of version command responses
func TestCheckMemcachedVersionResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		wantOK   bool
	}{
		{
			name:     "valid version response",
			response: []byte("VERSION 1.6.22\r\n"),
			wantOK:   true,
		},
		{
			name:     "valid version response with different version",
			response: []byte("VERSION 1.5.22\r\n"),
			wantOK:   true,
		},
		{
			name:     "valid version response with older version",
			response: []byte("VERSION 1.4.39\r\n"),
			wantOK:   true,
		},
		{
			name:     "response too short",
			response: []byte("VER"),
			wantOK:   false,
		},
		{
			name:     "missing VERSION prefix",
			response: []byte("1.6.22\r\n"),
			wantOK:   false,
		},
		{
			name:     "missing CRLF suffix",
			response: []byte("VERSION 1.6.22"),
			wantOK:   false,
		},
		{
			name:     "ERROR response",
			response: []byte("ERROR\r\n"),
			wantOK:   false,
		},
		{
			name:     "empty response",
			response: []byte(""),
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOK, _ := checkMemcachedVersionResponse(tt.response)
			if gotOK != tt.wantOK {
				t.Errorf("checkMemcachedVersionResponse() gotOK = %v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}

// TestCheckMemcachedStatsResponse tests validation of stats command responses
func TestCheckMemcachedStatsResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		wantOK   bool
	}{
		{
			name: "valid stats response",
			response: []byte("STAT pid 1162\r\n" +
				"STAT version 1.6.22\r\n" +
				"STAT uptime 5022\r\n" +
				"END\r\n"),
			wantOK: true,
		},
		{
			name: "valid stats response with many fields",
			response: []byte("STAT pid 1162\r\n" +
				"STAT uptime 5022\r\n" +
				"STAT time 1415208270\r\n" +
				"STAT version 1.5.22\r\n" +
				"STAT curr_connections 5\r\n" +
				"STAT total_connections 6\r\n" +
				"END\r\n"),
			wantOK: true,
		},
		{
			name:     "response too short",
			response: []byte("STAT pid 1\r\n"),
			wantOK:   false,
		},
		{
			name:     "missing STAT lines",
			response: []byte("END\r\n"),
			wantOK:   false,
		},
		{
			name:     "missing END suffix",
			response: []byte("STAT pid 1162\r\n" + "STAT version 1.6.22\r\n"),
			wantOK:   false,
		},
		{
			name:     "empty response",
			response: []byte(""),
			wantOK:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotOK, _ := checkMemcachedStatsResponse(tt.response)
			if gotOK != tt.wantOK {
				t.Errorf("checkMemcachedStatsResponse() gotOK = %v, want %v", gotOK, tt.wantOK)
			}
		})
	}
}

// TestExtractMemcachedVersion tests version extraction from version command response
func TestExtractMemcachedVersion(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     string
	}{
		{
			name:     "standard version response",
			response: []byte("VERSION 1.6.22\r\n"),
			want:     "1.6.22",
		},
		{
			name:     "version 1.5.x",
			response: []byte("VERSION 1.5.22\r\n"),
			want:     "1.5.22",
		},
		{
			name:     "version 1.4.x",
			response: []byte("VERSION 1.4.39\r\n"),
			want:     "1.4.39",
		},
		{
			name:     "version with extra whitespace",
			response: []byte("VERSION   1.6.22  \r\n"),
			want:     "1.6.22",
		},
		{
			name:     "empty response",
			response: []byte(""),
			want:     "",
		},
		{
			name:     "missing VERSION prefix",
			response: []byte("1.6.22\r\n"),
			want:     "",
		},
		{
			name:     "ERROR response",
			response: []byte("ERROR\r\n"),
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractMemcachedVersion(tt.response)
			if got != tt.want {
				t.Errorf("extractMemcachedVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestExtractVersionFromStats tests version extraction from stats command response
func TestExtractVersionFromStats(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		want     string
	}{
		{
			name: "standard stats response",
			response: []byte("STAT pid 1162\r\n" +
				"STAT version 1.6.22\r\n" +
				"STAT uptime 5022\r\n" +
				"END\r\n"),
			want: "1.6.22",
		},
		{
			name: "version at end",
			response: []byte("STAT pid 1162\r\n" +
				"STAT uptime 5022\r\n" +
				"STAT curr_connections 5\r\n" +
				"STAT version 1.5.22\r\n" +
				"END\r\n"),
			want: "1.5.22",
		},
		{
			name: "version at beginning",
			response: []byte("STAT version 1.4.39\r\n" +
				"STAT pid 1162\r\n" +
				"STAT uptime 5022\r\n" +
				"END\r\n"),
			want: "1.4.39",
		},
		{
			name: "no version field",
			response: []byte("STAT pid 1162\r\n" +
				"STAT uptime 5022\r\n" +
				"END\r\n"),
			want: "",
		},
		{
			name:     "empty response",
			response: []byte(""),
			want:     "",
		},
		{
			name: "malformed version line",
			response: []byte("STAT pid 1162\r\n" +
				"STAT version\r\n" +
				"END\r\n"),
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractVersionFromStats(tt.response)
			if got != tt.want {
				t.Errorf("extractVersionFromStats() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestBuildMemcachedCPE tests CPE generation for Memcached servers
func TestBuildMemcachedCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "specific version 1.6.x",
			version: "1.6.22",
			want:    "cpe:2.3:a:memcached:memcached:1.6.22:*:*:*:*:*:*:*",
		},
		{
			name:    "version 1.5.x",
			version: "1.5.22",
			want:    "cpe:2.3:a:memcached:memcached:1.5.22:*:*:*:*:*:*:*",
		},
		{
			name:    "version 1.4.x",
			version: "1.4.39",
			want:    "cpe:2.3:a:memcached:memcached:1.4.39:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown version (wildcard)",
			version: "",
			want:    "cpe:2.3:a:memcached:memcached:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version with patch number",
			version: "1.6.17",
			want:    "cpe:2.3:a:memcached:memcached:1.6.17:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildMemcachedCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildMemcachedCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestMemcachedSecurityFindings verifies that security findings are set on a detected Memcached service.
func TestMemcachedSecurityFindings(t *testing.T) {
	// Start mock TCP server on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer listener.Close()

	tcpAddr := listener.Addr().(*net.TCPAddr)
	serverPort := tcpAddr.Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Read the request
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		// Write a valid Memcached version response
		_, _ = conn.Write([]byte("VERSION 1.6.22\r\n"))
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &MEMCACHEDPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if !service.AnonymousAccess {
		t.Error("expected AnonymousAccess to be true")
	}
	if len(service.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(service.SecurityFindings))
	}
	if service.SecurityFindings[0].ID != "memcached-no-auth" {
		t.Errorf("expected finding ID 'memcached-no-auth', got %q", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityHigh {
		t.Errorf("expected severity high, got %s", service.SecurityFindings[0].Severity)
	}
}

// TestMemcachedSecurityFindingsLive spins up a real Memcached container and verifies
// that the plugin detects anonymous access and emits the memcached-no-auth finding.
func TestMemcachedSecurityFindingsLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "memcached",
	})
	if err != nil {
		t.Fatalf("could not start memcached container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	rawAddr := resource.GetHostPort("11211/tcp")

	// GetHostPort may return "localhost:PORT"; normalise to 127.0.0.1 so
	// netip.ParseAddrPort succeeds.
	host, port, err := net.SplitHostPort(rawAddr)
	if err != nil {
		t.Fatalf("could not split host:port %q: %v", rawAddr, err)
	}
	if host == "localhost" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	targetAddr := net.JoinHostPort(host, port)

	err = pool.Retry(func() error {
		time.Sleep(3 * time.Second)
		conn, dialErr := net.DialTimeout("tcp", targetAddr, 5*time.Second)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})
	if err != nil {
		t.Fatalf("failed to connect to memcached container: %s", err)
	}

	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("failed to open connection to memcached container: %s", err)
	}
	defer conn.Close()

	addrPort := netip.MustParseAddrPort(targetAddr)
	target := plugins.Target{
		Host:       addrPort.Addr().String(),
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &MEMCACHEDPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if !service.AnonymousAccess {
		t.Error("expected AnonymousAccess to be true")
	}
	if len(service.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(service.SecurityFindings))
	}
	if service.SecurityFindings[0].ID != "memcached-no-auth" {
		t.Errorf("expected finding ID 'memcached-no-auth', got %q", service.SecurityFindings[0].ID)
	}
	if service.SecurityFindings[0].Severity != plugins.SeverityHigh {
		t.Errorf("expected severity high, got %s", service.SecurityFindings[0].Severity)
	}
}

// TestMemcachedNoSecurityFindingsWithoutFlag verifies that no findings are set when Misconfigs is false.
func TestMemcachedNoSecurityFindingsWithoutFlag(t *testing.T) {
	// Start mock TCP server on random port
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Failed to start mock server: %v", err)
	}
	defer listener.Close()

	tcpAddr := listener.Addr().(*net.TCPAddr)
	serverPort := tcpAddr.Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 1024)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("VERSION 1.6.22\r\n"))
	}()

	time.Sleep(10 * time.Millisecond)

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: false,
	}

	plugin := &MEMCACHEDPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	if service.AnonymousAccess {
		t.Error("expected AnonymousAccess to be false when Misconfigs is false")
	}
	if len(service.SecurityFindings) != 0 {
		t.Errorf("expected 0 findings, got %d", len(service.SecurityFindings))
	}
}
