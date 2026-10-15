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

package mssql

import (
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// TestBuildMSSQLCPE_WithVersion tests CPE generation with a known version
func TestBuildMSSQLCPE_WithVersion(t *testing.T) {
	testcases := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "SQL Server 2019",
			version:  "15.0.2000",
			expected: "cpe:2.3:a:microsoft:sql_server:15.0.2000:*:*:*:*:*:*:*",
		},
		{
			name:     "SQL Server 2017",
			version:  "14.0.1000",
			expected: "cpe:2.3:a:microsoft:sql_server:14.0.1000:*:*:*:*:*:*:*",
		},
		{
			name:     "SQL Server 2016",
			version:  "13.0.5026",
			expected: "cpe:2.3:a:microsoft:sql_server:13.0.5026:*:*:*:*:*:*:*",
		},
		{
			name:     "SQL Server 2014",
			version:  "12.0.6024",
			expected: "cpe:2.3:a:microsoft:sql_server:12.0.6024:*:*:*:*:*:*:*",
		},
	}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			result := buildMSSQLCPE(tc.version)

			if result != tc.expected {
				t.Errorf("Expected %s, got %s", tc.expected, result)
			}
		})
	}
}

// TestBuildMSSQLCPE_WithoutVersion tests CPE generation with unknown version (wildcard)
func TestBuildMSSQLCPE_WithoutVersion(t *testing.T) {
	version := ""
	expected := "cpe:2.3:a:microsoft:sql_server:*:*:*:*:*:*:*:*"

	result := buildMSSQLCPE(version)

	if result != expected {
		t.Errorf("Expected %s, got %s", expected, result)
	}
}

func TestMSSQL(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "mssql",
			Port:        1433,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "mcr.microsoft.com/mssql/server",
				Tag:        "2019-latest",
				Env: []string{
					"ACCEPT_EULA=Y",
					"SA_PASSWORD=yourStrong(!)Password",
				},
			},
		},
	}

	p := &MSSQLPlugin{}

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

func buildMockPreloginResponse() []byte {
	return []byte{
		0x04, 0x01, 0x00, 0x30, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x00, 0x1F, 0x00, 0x06,
		0x01, 0x00, 0x25, 0x00, 0x01,
		0x02, 0x00, 0x26, 0x00, 0x01,
		0x03, 0x00, 0x27, 0x00, 0x00,
		0x04, 0x00, 0x27, 0x00, 0x01,
		0x05, 0x00, 0x28, 0x00, 0x00,
		0xFF,
		0x0F, 0x00, 0x07, 0xD0, 0x00, 0x00,
		0x00,
		0x00,
		0x00,
	}
}

func buildMockLoginAck() []byte {
	return []byte{
		0x04, 0x01, 0x00, 0x15, 0x00, 0x00, 0x01, 0x00,
		0xAD, 0x0A, 0x00,
		0x01,
		0x04, 0x00, 0x00, 0x74,
		0x00,
		0x0F, 0x00, 0x07, 0xD0,
	}
}

func buildMockLoginError() []byte {
	return []byte{
		0x04, 0x01, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00,
		0xAA,
	}
}

func startMockTDS(t *testing.T, unauth bool, expectLogin bool) (string, func()) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		buf := make([]byte, 4096)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		if _, err := conn.Write(buildMockPreloginResponse()); err != nil {
			return
		}
		if !expectLogin {
			return
		}
		if _, err := conn.Read(buf); err != nil {
			return
		}
		if unauth {
			_, _ = conn.Write(buildMockLoginAck())
			return
		}
		_, _ = conn.Write(buildMockLoginError())
	}()

	return listener.Addr().String(), func() { _ = listener.Close() }
}

func TestMSSQLSecurityFindings(t *testing.T) {
	tests := []struct {
		name         string
		misconfigs   bool
		unauth       bool
		wantAnon     bool
		wantFinding  bool
		wantFindings int
	}{
		{
			name:         "Misconfigs=true unauthenticated LOGINACK emits mssql-no-auth",
			misconfigs:   true,
			unauth:       true,
			wantAnon:     true,
			wantFinding:  true,
			wantFindings: 1,
		},
		{
			name:         "Misconfigs=true auth required ERROR does not emit mssql-no-auth",
			misconfigs:   true,
			unauth:       false,
			wantAnon:     false,
			wantFinding:  false,
			wantFindings: 0,
		},
		{
			name:         "Misconfigs=false does not emit finding",
			misconfigs:   false,
			unauth:       true,
			wantAnon:     false,
			wantFinding:  false,
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, cleanup := startMockTDS(t, tt.unauth, tt.misconfigs)
			defer cleanup()

			conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
			require.NoError(t, err)
			defer conn.Close()

			addrPort := netip.MustParseAddrPort(addr)
			target := plugins.Target{
				Host:       "127.0.0.1",
				Address:    addrPort,
				Misconfigs: tt.misconfigs,
			}

			plugin := &MSSQLPlugin{}
			service, err := plugin.Run(conn, 5*time.Second, target)
			require.NoError(t, err)
			require.NotNil(t, service, "fingerprint must succeed")

			assert.Equal(t, tt.wantAnon, service.AnonymousAccess, "AnonymousAccess mismatch")
			assert.Len(t, service.SecurityFindings, tt.wantFindings, "SecurityFindings count mismatch")

			hasID := false
			for _, f := range service.SecurityFindings {
				if f.ID == "mssql-no-auth" {
					hasID = true
					assert.Equal(t, plugins.SeverityCritical, f.Severity)
					assert.NotContains(t, strings.ToLower(f.Evidence), "password")
					assert.NotContains(t, strings.ToLower(f.Evidence), "sa")
					assert.NotContains(t, f.Evidence, "@")
				}
			}
			assert.Equal(t, tt.wantFinding, hasID, "mssql-no-auth presence mismatch")
		})
	}
}
