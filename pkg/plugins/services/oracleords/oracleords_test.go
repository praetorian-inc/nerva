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

package oracleords

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestParseORDSVersion(t *testing.T) {
	tests := []struct {
		name     string
		server   string
		expected string
	}{
		{
			name:     "valid version token",
			server:   "Oracle-REST-Data-Services/24.1.0",
			expected: "24.1.0",
		},
		{
			name:     "valid version with two components",
			server:   "Oracle-REST-Data-Services/22.4",
			expected: "22.4",
		},
		{
			name:     "empty server header",
			server:   "",
			expected: "",
		},
		{
			name:     "unrelated server header",
			server:   "Jetty(12.0.1)",
			expected: "",
		},
		{
			name:     "garbage input with product name but no version",
			server:   "Oracle-REST-Data-Services/",
			expected: "",
		},
		{
			name:     "garbage input with non-numeric version",
			server:   "Oracle-REST-Data-Services/abc",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseORDSVersion(tt.server)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBodyHasAPEX(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "contains apex (case-insensitive)",
			body:     "Welcome to APEX Application Builder",
			expected: true,
		},
		{
			name:     "contains lowercase apex",
			body:     "loading apex resources",
			expected: true,
		},
		{
			name:     "contains static /i/ reference",
			body:     `<link rel="stylesheet" href="/i/themes/theme.css">`,
			expected: true,
		},
		{
			name:     "contains f?p= application URL",
			body:     `<a href="f?p=100:1:12345">Login</a>`,
			expected: true,
		},
		{
			name:     "no APEX markers",
			body:     "<html><body>hello world</body></html>",
			expected: false,
		},
		{
			name:     "empty body",
			body:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := bodyHasAPEX(tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildORDSCPEs(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		apex     bool
		expected []string
	}{
		{
			name:     "with version, no APEX",
			version:  "24.1.0",
			apex:     false,
			expected: []string{"cpe:2.3:a:oracle:rest_data_services:24.1.0:*:*:*:*:*:*:*"},
		},
		{
			name:    "empty version, with APEX",
			version: "",
			apex:    true,
			expected: []string{
				"cpe:2.3:a:oracle:rest_data_services:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:oracle:application_express:*:*:*:*:*:*:*:*",
			},
		},
		{
			name:     "empty version, no APEX",
			version:  "",
			apex:     false,
			expected: []string{"cpe:2.3:a:oracle:rest_data_services:*:*:*:*:*:*:*:*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildORDSCPEs(tt.version, tt.apex)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluateORDS(t *testing.T) {
	tests := []struct {
		name              string
		evidence          []ordsEvidence
		expectedVersion   string
		expectedAPEX      bool
		expectedDetect    bool
		expectedAnonymous bool
	}{
		{
			name: "Server header with version",
			evidence: []ordsEvidence{
				{path: "/ords/", statusCode: http.StatusOK, server: "Oracle-REST-Data-Services/24.1.0"},
			},
			expectedVersion:   "24.1.0",
			expectedAPEX:      false,
			expectedDetect:    true,
			expectedAnonymous: true,
		},
		{
			name: "APEX header signal",
			evidence: []ordsEvidence{
				{path: "/", statusCode: http.StatusOK, hasAPEXHeader: true},
			},
			expectedVersion:   "",
			expectedAPEX:      true,
			expectedDetect:    true,
			expectedAnonymous: true,
		},
		{
			name: "ORDS header signal",
			evidence: []ordsEvidence{
				{path: "/", statusCode: http.StatusOK, hasORDSHeader: true},
			},
			expectedVersion:   "",
			expectedAPEX:      false,
			expectedDetect:    true,
			expectedAnonymous: true,
		},
		{
			name: "ords path with Jetty and non-404 status",
			evidence: []ordsEvidence{
				{path: "/ords/", statusCode: http.StatusOK, server: "Jetty(12.0.1)"},
			},
			expectedVersion:   "",
			expectedAPEX:      false,
			expectedDetect:    true,
			expectedAnonymous: true,
		},
		{
			name: "ords path 404 with bare Jetty does not trigger",
			evidence: []ordsEvidence{
				{path: "/ords/", statusCode: http.StatusNotFound, server: "Jetty(12.0.1)"},
			},
			expectedVersion:   "",
			expectedAPEX:      false,
			expectedDetect:    false,
			expectedAnonymous: false,
		},
		{
			name: "bare Jetty on root path does not trigger",
			evidence: []ordsEvidence{
				{path: "/", statusCode: http.StatusOK, server: "Jetty(12.0.1)"},
			},
			expectedVersion:   "",
			expectedAPEX:      false,
			expectedDetect:    false,
			expectedAnonymous: false,
		},
		{
			name: "body APEX marker on root path does not flag APEX",
			evidence: []ordsEvidence{
				{path: "/", statusCode: http.StatusOK, server: "Oracle-REST-Data-Services/24.1.0", body: "apex resources at /i/"},
			},
			expectedVersion:   "24.1.0",
			expectedAPEX:      false,
			expectedDetect:    true,
			expectedAnonymous: true,
		},
		{
			name: "body APEX marker on /ords path flags APEX",
			evidence: []ordsEvidence{
				{path: "/ords/", statusCode: http.StatusOK, server: "Oracle-REST-Data-Services/24.1.0", body: "apex resources at /i/"},
			},
			expectedVersion:   "24.1.0",
			expectedAPEX:      true,
			expectedDetect:    true,
			expectedAnonymous: true,
		},
		{
			name:              "no evidence",
			evidence:          []ordsEvidence{},
			expectedVersion:   "",
			expectedAPEX:      false,
			expectedDetect:    false,
			expectedAnonymous: false,
		},
		{
			name: "401 response carrying ORDS Server header is detected but not anonymous",
			evidence: []ordsEvidence{
				{path: "/ords/", statusCode: http.StatusUnauthorized, server: "Oracle-REST-Data-Services/24.1.0"},
			},
			expectedVersion:   "24.1.0",
			expectedAPEX:      false,
			expectedDetect:    true,
			expectedAnonymous: false,
		},
		{
			name: "403 response carrying ORDS/APEX headers is detected but not anonymous",
			evidence: []ordsEvidence{
				{path: "/", statusCode: http.StatusForbidden, hasORDSHeader: true},
			},
			expectedVersion:   "",
			expectedAPEX:      false,
			expectedDetect:    true,
			expectedAnonymous: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, apex, detected, anonymous := evaluateORDS(tt.evidence)
			assert.Equal(t, tt.expectedVersion, version)
			assert.Equal(t, tt.expectedAPEX, apex)
			assert.Equal(t, tt.expectedDetect, detected)
			assert.Equal(t, tt.expectedAnonymous, anonymous)
		})
	}
}

// parseTestServerAddr parses httptest server URL into netip.AddrPort
func parseTestServerAddr(t *testing.T, serverURL string) netip.AddrPort {
	t.Helper()
	hostPort := strings.TrimPrefix(serverURL, "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
}

func TestORDSPlugin_Run_PositiveViaServerHeaderVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Oracle-REST-Data-Services/24.1.0")
		switch r.URL.Path {
		case "/ords/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "ORDS landing page")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}

	plugin := &ORDSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ordsService plugins.ServiceOracleORDS
	err = json.Unmarshal(service.Raw, &ordsService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.True(t, ordsService.AICapable)
	require.Len(t, ordsService.CPEs, 1)
	assert.Contains(t, ordsService.CPEs, "cpe:2.3:a:oracle:rest_data_services:24.1.0:*:*:*:*:*:*:*")
}

func TestORDSPlugin_Run_PositiveViaAPEXHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ords/":
			w.Header().Set("X-APEX-STATUS-CODE", "200")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "APEX application")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}

	plugin := &ORDSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ordsService plugins.ServiceOracleORDS
	err = json.Unmarshal(service.Raw, &ordsService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.True(t, ordsService.APEX)
	assert.Contains(t, ordsService.CPEs, "cpe:2.3:a:oracle:application_express:*:*:*:*:*:*:*:*")
}

func TestORDSPlugin_Run_RootBodyAPEXWordDoesNotFlagAPEX(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ORDS is detected via the Server header; the root body happens to
		// mention "apex"/"/i/" but that must NOT flag APEX since it is not
		// served under an /ords-prefixed path.
		w.Header().Set("Server", "Oracle-REST-Data-Services/24.1.0")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `<html><body>see /i/ apex-unrelated content</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}

	plugin := &ORDSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ordsService plugins.ServiceOracleORDS
	err = json.Unmarshal(service.Raw, &ordsService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.False(t, ordsService.APEX)
	assert.NotContains(t, ordsService.CPEs, "cpe:2.3:a:oracle:application_express:*:*:*:*:*:*:*:*")
}

func TestORDSPlugin_Run_OrdsPathBodyAPEXFlagsAPEX(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Oracle-REST-Data-Services/24.1.0")
		switch r.URL.Path {
		case "/ords/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `<html><body>APEX Application Builder f?p=100:1</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}

	plugin := &ORDSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ordsService plugins.ServiceOracleORDS
	err = json.Unmarshal(service.Raw, &ordsService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.True(t, ordsService.APEX)
	assert.Contains(t, ordsService.CPEs, "cpe:2.3:a:oracle:application_express:*:*:*:*:*:*:*:*")
}

func TestORDSPlugin_Run_BareJettyDoesNotTrigger(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Jetty(12.0.1)")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "hello")
		default:
			// /ords/ and /ords/_/landing return 404, no ORDS/APEX markers.
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}

	plugin := &ORDSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestORDSPlugin_Metadata(t *testing.T) {
	plugin := &ORDSPlugin{}
	assert.Equal(t, OracleORDS, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(8080))
	assert.False(t, plugin.PortPriority(8443))
	assert.False(t, plugin.PortPriority(80))
}

func TestORDSTLSPlugin_Run_PositiveViaServerHeaderVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Oracle-REST-Data-Services/22.4.3")
		switch r.URL.Path {
		case "/ords/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "ORDS landing page")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}

	plugin := &ORDSTLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ordsService plugins.ServiceOracleORDS
	err = json.Unmarshal(service.Raw, &ordsService)
	require.NoError(t, err)
	assert.True(t, ordsService.AICapable)
	assert.Contains(t, ordsService.CPEs, "cpe:2.3:a:oracle:rest_data_services:22.4.3:*:*:*:*:*:*:*")
}

func TestORDSTLSPlugin_Metadata(t *testing.T) {
	plugin := &ORDSTLSPlugin{}
	assert.Equal(t, OracleORDS, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(8443))
	assert.False(t, plugin.PortPriority(8080))
}

func TestORDSSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Oracle-REST-Data-Services/24.1.0")
		switch r.URL.Path {
		case "/ords/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "ORDS landing page")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	t.Run("with Misconfigs=true yields AnonymousAccess and finding", func(t *testing.T) {
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := parseTestServerAddr(t, server.URL)
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		target := plugins.Target{
			Host:       addr.Addr().String(),
			Address:    addr,
			Misconfigs: true,
		}

		plugin := &ORDSPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-ords-exposed", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityLow, service.SecurityFindings[0].Severity)
	})

	t.Run("with Misconfigs=false yields no SecurityFindings", func(t *testing.T) {
		server := httptest.NewServer(handler)
		defer server.Close()

		addr := parseTestServerAddr(t, server.URL)
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		target := plugins.Target{
			Host:       addr.Addr().String(),
			Address:    addr,
			Misconfigs: false,
		}

		plugin := &ORDSPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})

	t.Run("401 auth-challenge with ORDS evidence and Misconfigs=true yields no finding", func(t *testing.T) {
		// ORDS is identified via the Server header, but the response is an
		// auth challenge (401), so the surface is detected but must NOT be
		// flagged as anonymously accessible, even with Misconfigs=true.
		authChallengeHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Oracle-REST-Data-Services/24.1.0")
			switch r.URL.Path {
			case "/ords/":
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, "Authentication required")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})
		server := httptest.NewServer(authChallengeHandler)
		defer server.Close()

		addr := parseTestServerAddr(t, server.URL)
		conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
		require.NoError(t, err)
		defer conn.Close()

		target := plugins.Target{
			Host:       addr.Addr().String(),
			Address:    addr,
			Misconfigs: true,
		}

		plugin := &ORDSPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service, "ORDS should still be detected from the Server header")

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}
