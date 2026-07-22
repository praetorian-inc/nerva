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

package oracleagile

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

// parseTestServerAddr parses an httptest server URL into a netip.AddrPort.
func parseTestServerAddr(t *testing.T, serverURL string) netip.AddrPort {
	t.Helper()
	hostPort := strings.TrimPrefix(serverURL, "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
}

// ---------------------------------------------------------------------------
// Unit tests for hasAgileMarker
// ---------------------------------------------------------------------------

func TestHasAgileMarker(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "branded product name in body",
			body:     `<html><body>Welcome to Agile Product Lifecycle Management</body></html>`,
			expected: true,
		},
		{
			name:     "lowercase branded product name",
			body:     `<html><body>welcome to agile product lifecycle management</body></html>`,
			expected: true,
		},
		{
			name:     "PLMServlet reference",
			body:     `<form action="/Agile/PLMServlet" method="post">`,
			expected: true,
		},
		{
			name:     "PCMServlet reference",
			body:     `<form action="/Agile/PCMServlet" method="POST">`,
			expected: true,
		},
		{
			name:     "ExternalServlet reference",
			body:     `<a href="/Agile/ExternalServlet?cmd=view">View</a>`,
			expected: true,
		},
		{
			name:     "Agile static asset path",
			body:     `<link rel="stylesheet" href="/Agile/static/css/login.css">`,
			expected: true,
		},
		{
			name:     "bare probe path echo is not a marker (self-referential guard)",
			body:     `Error: /Agile/default/login-cms.jsp not found`,
			expected: false,
		},
		{
			name:     "generic login page with no Agile markers",
			body:     `<html><body><h1>Login</h1><form action="/login">`,
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
			result := hasAgileMarker(tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests for extractAgileVersion
// ---------------------------------------------------------------------------

func TestExtractAgileVersion(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantVersion   string
		wantBuild     string
	}{
		{
			name:        "9.3.6 (Build 47)",
			body:        `<span>Version: 9.3.6 (Build 47)</span>`,
			wantVersion: "9.3.6",
			wantBuild:   "47",
		},
		{
			name:        "9.3.1.2 (Build 09)",
			body:        `Version 9.3.1.2 (Build 09) - Oracle Corporation`,
			wantVersion: "9.3.1.2",
			wantBuild:   "09",
		},
		{
			name:        "9.3 (Build 1) — two-segment version",
			body:        `Agile PLM 9.3 (Build 1)`,
			wantVersion: "9.3",
			wantBuild:   "1",
		},
		{
			name:        "no version in body",
			body:        `<html><body>Welcome to Agile Product Lifecycle Management</body></html>`,
			wantVersion: "",
			wantBuild:   "",
		},
		{
			name:        "malformed version string",
			body:        `Version: abc.xyz (Build 10)`,
			wantVersion: "",
			wantBuild:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, build := extractAgileVersion(tt.body)
			assert.Equal(t, tt.wantVersion, version)
			assert.Equal(t, tt.wantBuild, build)
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests for buildAgilePLMCPE
// ---------------------------------------------------------------------------

func TestBuildAgilePLMCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "known version 9.3.6",
			version:  "9.3.6",
			expected: "cpe:2.3:a:oracle:agile_plm:9.3.6:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version produces wildcard CPE",
			version:  "",
			expected: "cpe:2.3:a:oracle:agile_plm:*:*:*:*:*:*:*:*",
		},
		{
			name:     "four-segment version 9.3.1.2",
			version:  "9.3.1.2",
			expected: "cpe:2.3:a:oracle:agile_plm:9.3.1.2:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildAgilePLMCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests for extractTitle
// ---------------------------------------------------------------------------

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "simple title",
			body:     `<html><head><title>Oracle Agile PLM</title></head></html>`,
			expected: "Oracle Agile PLM",
		},
		{
			name:     "no title element",
			body:     `<html><head></head><body>content</body></html>`,
			expected: "",
		},
		{
			name:     "empty body",
			body:     "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractTitle(tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests for evaluateAgile
// ---------------------------------------------------------------------------

func TestEvaluateAgile(t *testing.T) {
	tests := []struct {
		name          string
		ev            agileEvidence
		wantDetected  bool
		wantVersion   string
		wantBuild     string
	}{
		{
			name: "200 with branded body marker is detected with version extracted",
			ev: agileEvidence{
				statusCode: http.StatusOK,
				body:       `<html>Agile Product Lifecycle Management 9.3.6 (Build 47)</html>`,
			},
			wantDetected: true,
			wantVersion:  "9.3.6",
			wantBuild:    "47",
		},
		{
			name: "200 with PLMServlet marker is detected",
			ev: agileEvidence{
				statusCode: http.StatusOK,
				body:       `<form action="/Agile/PLMServlet">`,
			},
			wantDetected: true,
			wantVersion:  "",
			wantBuild:    "",
		},
		{
			name: "200 with /Agile/static/ marker is detected",
			ev: agileEvidence{
				statusCode: http.StatusOK,
				body:       `<link href="/Agile/static/css/login.css">`,
			},
			wantDetected: true,
			wantVersion:  "",
			wantBuild:    "",
		},
		{
			name: "404 with marker body is not detected",
			ev: agileEvidence{
				statusCode: http.StatusNotFound,
				body:       `Agile Product Lifecycle Management`,
			},
			wantDetected: false,
		},
		{
			name: "200 with no Agile marker is not detected",
			ev: agileEvidence{
				statusCode: http.StatusOK,
				body:       `generic login page`,
			},
			wantDetected: false,
		},
		{
			name: "302 with marker in body is detected",
			ev: agileEvidence{
				statusCode: http.StatusFound,
				body:       `Agile Product Lifecycle Management`,
			},
			wantDetected: true,
			wantVersion:  "",
			wantBuild:    "",
		},
		{
			name: "zero status code is not detected",
			ev: agileEvidence{
				statusCode: 0,
				body:       `Agile Product Lifecycle Management`,
			},
			wantDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, build, detected := evaluateAgile(tt.ev)
			assert.Equal(t, tt.wantDetected, detected)
			if tt.wantDetected {
				assert.Equal(t, tt.wantVersion, version)
				assert.Equal(t, tt.wantBuild, build)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Integration tests using httptest
// ---------------------------------------------------------------------------

func TestAgilePLMPlugin_Run_PositiveWithVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Agile/default/login-cms.jsp":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `<html><body>Agile Product Lifecycle Management<br>Version 9.3.6 (Build 47)</body></html>`)
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

	plugin := &AgilePLMPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var agileService plugins.ServiceOracleAgilePLM
	err = json.Unmarshal(service.Raw, &agileService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.Equal(t, "47", agileService.Build)
	require.Len(t, agileService.CPEs, 1)
	assert.Contains(t, agileService.CPEs[0], "9.3.6")
}

func TestAgilePLMPlugin_Run_PositiveNoVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Agile/default/login-cms.jsp":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `<html><body><form action="/Agile/PLMServlet"></form></body></html>`)
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

	plugin := &AgilePLMPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var agileService plugins.ServiceOracleAgilePLM
	err = json.Unmarshal(service.Raw, &agileService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.Equal(t, "", agileService.Build)
	require.Len(t, agileService.CPEs, 1)
	assert.Contains(t, agileService.CPEs[0], ":*:")
}

func TestAgilePLMPlugin_Run_Negative(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
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

	plugin := &AgilePLMPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestAgilePLMPlugin_Run_NegativeNoMarker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Agile/default/login-cms.jsp":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "generic login page")
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

	plugin := &AgilePLMPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestAgilePLMPlugin_Run_NegativeEchoedPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Agile/default/login-cms.jsp":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Error: /Agile/default/login-cms.jsp not found")
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

	plugin := &AgilePLMPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service, "self-referential guard must prevent detection when only the probe path is echoed")
}

// ---------------------------------------------------------------------------
// Metadata tests
// ---------------------------------------------------------------------------

func TestAgilePLMPlugin_Metadata(t *testing.T) {
	plugin := &AgilePLMPlugin{}
	assert.Equal(t, OracleAgilePLM, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.False(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(8080))
}

func TestAgilePLMTLSPlugin_Metadata(t *testing.T) {
	plugin := &AgilePLMTLSPlugin{}
	assert.Equal(t, OracleAgilePLM, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(8080))
}

// ---------------------------------------------------------------------------
// Security findings tests
// ---------------------------------------------------------------------------

func TestAgilePLMSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/Agile/default/login-cms.jsp":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, `<html><body>Agile Product Lifecycle Management</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	t.Run("with Misconfigs=true", func(t *testing.T) {
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

		plugin := &AgilePLMPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-agile-plm-exposed", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityLow, service.SecurityFindings[0].Severity)
	})

	t.Run("with Misconfigs=false", func(t *testing.T) {
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

		plugin := &AgilePLMPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}
