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

package postgres

import (
	"encoding/binary"
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

// TestParseParameterStatus tests parsing of PostgreSQL ParameterStatus messages
func TestParseParameterStatus(t *testing.T) {
	tests := []struct {
		name      string
		msg       []byte
		wantName  string
		wantValue string
		wantErr   bool
	}{
		{
			name: "server_version parameter",
			msg: []byte{
				0x53,                   // Message type 'S'
				0x00, 0x00, 0x00, 0x1D, // Length: 29 bytes
				// "server_version\0"
				0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x76,
				0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x00,
				// "14.5\0"
				0x31, 0x34, 0x2e, 0x35, 0x00,
			},
			wantName:  "server_version",
			wantValue: "14.5",
			wantErr:   false,
		},
		{
			name: "application_name parameter",
			msg: []byte{
				0x53,                   // Message type 'S'
				0x00, 0x00, 0x00, 0x19, // Length: 25 bytes
				// "application_name\0"
				0x61, 0x70, 0x70, 0x6c, 0x69, 0x63, 0x61, 0x74,
				0x69, 0x6f, 0x6e, 0x5f, 0x6e, 0x61, 0x6d, 0x65, 0x00,
				// "psql\0"
				0x70, 0x73, 0x71, 0x6c, 0x00,
			},
			wantName:  "application_name",
			wantValue: "psql",
			wantErr:   false,
		},
		{
			name: "client_encoding parameter",
			msg: []byte{
				0x53,                   // Message type 'S'
				0x00, 0x00, 0x00, 0x17, // Length: 23 bytes
				// "client_encoding\0"
				0x63, 0x6c, 0x69, 0x65, 0x6e, 0x74, 0x5f, 0x65,
				0x6e, 0x63, 0x6f, 0x64, 0x69, 0x6e, 0x67, 0x00,
				// "UTF8\0"
				0x55, 0x54, 0x46, 0x38, 0x00,
			},
			wantName:  "client_encoding",
			wantValue: "UTF8",
			wantErr:   false,
		},
		{
			name:      "message too short",
			msg:       []byte{0x53, 0x00},
			wantName:  "",
			wantValue: "",
			wantErr:   true,
		},
		{
			name: "wrong message type",
			msg: []byte{
				0x52, // Wrong type ('R' instead of 'S')
				0x00, 0x00, 0x00, 0x08,
				0x00, 0x00, 0x00, 0x00,
			},
			wantName:  "",
			wantValue: "",
			wantErr:   true,
		},
		{
			name: "missing null terminators",
			msg: []byte{
				0x53,                   // Message type 'S'
				0x00, 0x00, 0x00, 0x10, // Length
				// "server_version" (no null terminator)
				0x73, 0x65, 0x72, 0x76, 0x65, 0x72, 0x5f, 0x76,
				0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e,
			},
			wantName:  "",
			wantValue: "",
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotName, gotValue, err := parseParameterStatus(tt.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseParameterStatus() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotName != tt.wantName {
				t.Errorf("parseParameterStatus() gotName = %v, want %v", gotName, tt.wantName)
			}
			if gotValue != tt.wantValue {
				t.Errorf("parseParameterStatus() gotValue = %v, want %v", gotValue, tt.wantValue)
			}
		})
	}
}

// TestBuildPostgreSQLCPE tests CPE generation for PostgreSQL
func TestBuildPostgreSQLCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "version 14.5",
			version: "14.5",
			want:    "cpe:2.3:a:postgresql:postgresql:14.5:*:*:*:*:*:*:*",
		},
		{
			name:    "version 16.1",
			version: "16.1",
			want:    "cpe:2.3:a:postgresql:postgresql:16.1:*:*:*:*:*:*:*",
		},
		{
			name:    "version 17.2",
			version: "17.2",
			want:    "cpe:2.3:a:postgresql:postgresql:17.2:*:*:*:*:*:*:*",
		},
		{
			name:    "version 9.6.24",
			version: "9.6.24",
			want:    "cpe:2.3:a:postgresql:postgresql:9.6.24:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:postgresql:postgresql:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildPostgreSQLCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildPostgreSQLCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPostgreSQL(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "postgresql",
			Port:        5432,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "postgres",
				Env: []string{
					"POSTGRES_PASSWORD=secret",
					"POSTGRES_USER=user_name",
					"POSTGRES_DB=dbname",
					"listen_addresses = '*'",
				},
			},
		},
	}

	p := &POSTGRESPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%s", err.Error())
			}
		})
	}
}

// buildAuthOKPacket constructs a PostgreSQL AuthenticationOk packet:
// 'R' (0x52) + length 8 (big-endian int32) + auth type 0 (big-endian int32)
func buildAuthOKPacket() []byte {
	pkt := []byte{AuthReq, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}
	return pkt
}

// buildAuthMD5Packet constructs a PostgreSQL AuthenticationMD5Password packet.
func buildAuthMD5Packet() []byte {
	// Type 'R' + length 12 + auth type 5 (MD5) + 4-byte salt
	pkt := make([]byte, 17)
	pkt[0] = AuthReq
	binary.BigEndian.PutUint32(pkt[1:5], 12)
	binary.BigEndian.PutUint32(pkt[5:9], 5) // MD5
	// salt bytes 9-13
	return pkt
}

// TestPostgreSQLSecurityFindings verifies security finding detection through a mock TCP server.
func TestPostgreSQLSecurityFindings(t *testing.T) {
	tests := []struct {
		name          string
		misconfigs    bool
		authOK        bool // true = server sends AuthOK (no auth needed)
		wantAnon      bool
		wantFindings  int
		wantFindingID string
		wantSeverity  plugins.Severity
	}{
		{
			name:          "misconfigs=true successfulAuth=true → finding produced",
			misconfigs:    true,
			authOK:        true,
			wantAnon:      true,
			wantFindings:  1,
			wantFindingID: "postgresql-no-auth",
			wantSeverity:  plugins.SeverityCritical,
		},
		{
			name:         "misconfigs=true successfulAuth=false (auth required) → no finding",
			misconfigs:   true,
			authOK:       false,
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:         "misconfigs=false successfulAuth=true → no finding",
			misconfigs:   false,
			authOK:       true,
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
					go func(c net.Conn) {
						defer c.Close()
						// Read the startup packet (client sends first)
						buf := make([]byte, 4096)
						_, _ = c.Read(buf)
						// Respond with either AuthOK or MD5 auth request
						if tt.authOK {
							_, _ = c.Write(buildAuthOKPacket())
						} else {
							_, _ = c.Write(buildAuthMD5Packet())
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
				Misconfigs: tt.misconfigs,
			}

			plugin := &POSTGRESPlugin{}
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

// TestPostgreSQLSecurityFindingFields validates all SecurityFinding fields are populated correctly.
func TestPostgreSQLSecurityFindingFields(t *testing.T) {
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
				_, _ = c.Write(buildAuthOKPacket())
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

	plugin := &POSTGRESPlugin{}
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
	assert.Equal(t, "postgresql-no-auth", f.ID, "finding ID mismatch")
	assert.Equal(t, plugins.SeverityCritical, f.Severity, "finding severity mismatch")
	assert.NotEmpty(t, f.Description, "Description must be non-empty")
	assert.NotEmpty(t, f.Evidence, "Evidence must be non-empty")
}

// TestSuccessfulAuth_ExactBoundary tests successfulAuth with exactly 9 bytes and correct AuthOK.
func TestSuccessfulAuth_ExactBoundary(t *testing.T) {
	// Exactly 9 bytes: type 'R' + length 8 + auth type 0
	data := []byte{AuthReq, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00}
	assert.Equal(t, 9, len(data), "test data must be exactly 9 bytes")
	assert.True(t, successfulAuth(data), "9-byte AuthOK must return true")
}

// TestPostgreSQLSecurityFindings_AuthSASL verifies that a SASL auth response (type 10) does not
// produce a finding (auth is required).
func TestPostgreSQLSecurityFindings_AuthSASL(t *testing.T) {
	// Build an AuthenticationSASL packet: 'R' + length 8 + auth type 10 (0x0A)
	saslPkt := []byte{AuthReq, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x0A}

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
				_, _ = c.Write(saslPkt)
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

	plugin := &POSTGRESPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	assert.False(t, service.AnonymousAccess, "AnonymousAccess must be false for SASL auth")
	assert.Empty(t, service.SecurityFindings, "no findings expected when SASL auth is required")
}

// TestPostgreSQLDockerWithPassword is a Docker integration test that verifies no anonymous
// access is detected when PostgreSQL requires a password.
func TestPostgreSQLDockerWithPassword(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Env:        []string{"POSTGRES_PASSWORD=secretpassword"},
	})
	if err != nil {
		t.Fatalf("could not start postgres container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	port := resource.GetPort("5432/tcp")
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

		svc, runErr := (&POSTGRESPlugin{}).Run(conn, 5*time.Second, target)
		if runErr != nil {
			return runErr
		}
		if svc == nil {
			return fmt.Errorf("postgres not yet ready")
		}
		service = svc
		return nil
	})
	if retryErr != nil {
		t.Fatalf("postgres plugin never connected: %s", retryErr)
	}

	assert.False(t, service.AnonymousAccess, "expected AnonymousAccess=false for password-protected PostgreSQL")
	assert.Empty(t, service.SecurityFindings, "expected no SecurityFindings for password-protected PostgreSQL")
}

// TestPostgreSQLDockerTrustAuth is a Docker integration test that verifies anonymous access
// detection against a real PostgreSQL container configured with trust authentication.
func TestPostgreSQLDockerTrustAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "postgres",
		Env:        []string{"POSTGRES_HOST_AUTH_METHOD=trust"},
	})
	if err != nil {
		t.Fatalf("could not start postgres container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	port := resource.GetPort("5432/tcp")
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

		svc, runErr := (&POSTGRESPlugin{}).Run(conn, 5*time.Second, target)
		if runErr != nil {
			return runErr
		}
		if svc == nil {
			return fmt.Errorf("postgres not yet ready")
		}
		service = svc
		return nil
	})
	if retryErr != nil {
		t.Fatalf("postgres plugin never connected: %s", retryErr)
	}

	assert.True(t, service.AnonymousAccess, "expected AnonymousAccess=true for trust-auth PostgreSQL")
	assert.NotEmpty(t, service.SecurityFindings, "expected SecurityFindings for trust-auth PostgreSQL")
	if len(service.SecurityFindings) > 0 {
		assert.Equal(t, "postgresql-no-auth", service.SecurityFindings[0].ID)
	}
}

// TestSuccessfulAuth tests the successfulAuth helper directly.
func TestSuccessfulAuth(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{
			name: "valid AuthOK → true",
			data: buildAuthOKPacket(),
			want: true,
		},
		{
			name: "MD5 auth challenge → false",
			data: buildAuthMD5Packet(),
			want: false,
		},
		{
			name: "too short → false",
			data: []byte{AuthReq, 0x00},
			want: false,
		},
		{
			name: "wrong first byte → false",
			data: []byte{0x45, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00},
			want: false,
		},
		{
			name: "wrong length field → false",
			data: []byte{AuthReq, 0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00},
			want: false,
		},
		{
			name: "wrong auth type (SASL, not 0) → false",
			data: []byte{AuthReq, 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x0A},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := successfulAuth(tt.data)
			assert.Equal(t, tt.want, got)
		})
	}
}
