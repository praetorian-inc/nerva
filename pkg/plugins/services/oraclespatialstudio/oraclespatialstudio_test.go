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

package oraclespatialstudio

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

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "simple title",
			body:     `<html><head><title>Oracle Spatial Studio</title></head></html>`,
			expected: "Oracle Spatial Studio",
		},
		{
			name:     "title with whitespace",
			body:     `<html><head><title>  Spatial Studio  </title></head></html>`,
			expected: "Spatial Studio",
		},
		{
			name:     "no title element",
			body:     `<html><body>Spatial Studio</body></html>`,
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

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "version in JSON response",
			body:     `{"application":"Oracle Spatial Studio","version":"23.3.0"}`,
			expected: "23.3.0",
		},
		{
			name:     "version with more segments",
			body:     `{"version":"22.1.0.0.0","status":"ok"}`,
			expected: "22.1.0.0.0",
		},
		{
			name:     "no version field",
			body:     `{"application":"Oracle Spatial Studio"}`,
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
			result := extractVersion(tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLocationPointsToSpatialStudio(t *testing.T) {
	tests := []struct {
		name     string
		location string
		expected bool
	}{
		{
			name:     "exact spatialstudio path",
			location: "/spatialstudio",
			expected: true,
		},
		{
			name:     "spatialstudio path with trailing slash",
			location: "/spatialstudio/",
			expected: true,
		},
		{
			name:     "absolute URL with spatialstudio path",
			location: "http://host/spatialstudio/login",
			expected: true,
		},
		{
			name:     "unrelated path",
			location: "/some/other",
			expected: false,
		},
		{
			name:     "empty location",
			location: "",
			expected: false,
		},
		{
			name:     "spatialstudio in query string only",
			location: "/login?next=/spatialstudio",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := locationPointsToSpatialStudio(tt.location)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildSpatialStudioCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with version",
			version:  "23.3.0",
			expected: "cpe:2.3:a:oracle:spatial_studio:23.3.0:*:*:*:*:*:*:*",
		},
		{
			name:     "without version",
			version:  "",
			expected: "cpe:2.3:a:oracle:spatial_studio:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildSpatialStudioCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluateSpatialStudio(t *testing.T) {
	tests := []struct {
		name     string
		evidence []spatialEvidence
		expected bool
	}{
		{
			name: "spatialstudio path with Spatial Studio body",
			evidence: []spatialEvidence{
				{
					path:       "/spatialstudio",
					statusCode: http.StatusOK,
					body:       `<html><head><title>Oracle Spatial Studio</title></head><body>Welcome to Spatial Studio</body></html>`,
				},
			},
			expected: true,
		},
		{
			name: "spatialstudio path with Oracle JET markers",
			evidence: []spatialEvidence{
				{
					path:       "/spatialstudio",
					statusCode: http.StatusOK,
					body:       `<html><head><script src="oraclejet/js/libs/oj/v12.1.0/debug/ojcore.js"></script></head><body><oj-module></oj-module></body></html>`,
				},
			},
			expected: true,
		},
		{
			name: "spatialstudio API with spatialstudio in body",
			evidence: []spatialEvidence{
				{
					path:       "/spatialstudio/api/v1/",
					statusCode: http.StatusOK,
					body:       `{"application":"spatialstudio","version":"23.3.0"}`,
				},
			},
			expected: true,
		},
		{
			name: "redirect to spatialstudio path",
			evidence: []spatialEvidence{
				{
					path:       "/",
					statusCode: http.StatusFound,
					location:   "/spatialstudio/",
					body:       "",
				},
			},
			expected: true,
		},
		{
			name: "308 Permanent Redirect to spatialstudio",
			evidence: []spatialEvidence{
				{
					path:       "/spatialstudio",
					statusCode: http.StatusPermanentRedirect,
					location:   "/spatialstudio/",
					body:       "",
				},
			},
			expected: true,
		},
		{
			name: "spatialstudio path returns 404 does not trigger",
			evidence: []spatialEvidence{
				{
					path:       "/spatialstudio",
					statusCode: http.StatusNotFound,
					body:       `<html><body>Not Found</body></html>`,
				},
			},
			expected: false,
		},
		{
			name: "spatialstudio API returns 404 does not trigger",
			evidence: []spatialEvidence{
				{
					path:       "/spatialstudio/api/v1/",
					statusCode: http.StatusNotFound,
					body:       `{"error":"not found","spatialstudio":"none"}`,
				},
			},
			expected: false,
		},
		{
			name: "soft-404 echoing path in body does not trigger",
			evidence: []spatialEvidence{
				{
					path:       "/spatialstudio",
					statusCode: http.StatusOK,
					body:       `<html><body>The requested resource /spatialstudio was not found</body></html>`,
				},
			},
			expected: false,
		},
		{
			name: "200 on spatialstudio path with no product markers does not trigger",
			evidence: []spatialEvidence{
				{
					path:       "/spatialstudio",
					statusCode: http.StatusOK,
					body:       `<html><body>hello world</body></html>`,
				},
			},
			expected: false,
		},
		{
			name:     "no evidence at all",
			evidence: []spatialEvidence{},
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, _, detected := evaluateSpatialStudio(tt.evidence)
			assert.Equal(t, tt.expected, detected)
		})
	}
}

func TestEvaluateSpatialStudio_TitleFromMatchedResponseOnly(t *testing.T) {
	t.Run("title captured from matching response", func(t *testing.T) {
		title, _, detected := evaluateSpatialStudio([]spatialEvidence{
			{
				path:       "/spatialstudio",
				statusCode: http.StatusOK,
				body:       `<html><head><title>Spatial Studio Login</title></head><body>Oracle Spatial Studio</body></html>`,
			},
		})
		assert.True(t, detected)
		assert.Equal(t, "Spatial Studio Login", title)
	})

	t.Run("title not captured from non-matching response", func(t *testing.T) {
		title, _, detected := evaluateSpatialStudio([]spatialEvidence{
			{
				path:       "/spatialstudio/oauth/v1/",
				statusCode: http.StatusOK,
				body:       `<html><head><title>Generic App</title></head><body>hello</body></html>`,
			},
			{
				path:       "/spatialstudio",
				statusCode: http.StatusOK,
				body:       `<html><head><title>Spatial Studio</title></head><body>Oracle Spatial Studio</body></html>`,
			},
		})
		assert.True(t, detected)
		assert.Equal(t, "Spatial Studio", title)
	})
}

func TestEvaluateSpatialStudio_VersionExtraction(t *testing.T) {
	t.Run("version extracted from API response", func(t *testing.T) {
		_, version, detected := evaluateSpatialStudio([]spatialEvidence{
			{
				path:       "/spatialstudio/api/v1/",
				statusCode: http.StatusOK,
				body:       `{"application":"spatialstudio","version":"23.3.0"}`,
			},
		})
		assert.True(t, detected)
		assert.Equal(t, "23.3.0", version)
	})

	t.Run("no version when not in body", func(t *testing.T) {
		_, version, detected := evaluateSpatialStudio([]spatialEvidence{
			{
				path:       "/spatialstudio",
				statusCode: http.StatusOK,
				body:       `<html><body>Spatial Studio</body></html>`,
			},
		})
		assert.True(t, detected)
		assert.Equal(t, "", version)
	})
}

// parseTestServerAddr parses httptest server URL into netip.AddrPort.
func parseTestServerAddr(t *testing.T, serverURL string) netip.AddrPort {
	t.Helper()
	hostPort := strings.TrimPrefix(serverURL, "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
}

func TestSpatialStudioPlugin_Run_PositiveViaLoginPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/spatialstudio":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle Spatial Studio</title><script src="oraclejet/js/libs/oj/debug/ojcore.js"></script></head><body>Oracle Spatial Studio<oj-module></oj-module></body></html>`)
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

	plugin := &SpatialStudioPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var svc plugins.ServiceSpatialStudio
	err = json.Unmarshal(service.Raw, &svc)
	require.NoError(t, err)
	assert.Equal(t, "Oracle Spatial Studio", svc.Title)
	require.Len(t, svc.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:spatial_studio:*:*:*:*:*:*:*:*", svc.CPEs[0])
}

func TestSpatialStudioPlugin_Run_PositiveViaAPI(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/spatialstudio/api/v1/":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"application":"spatialstudio","version":"23.3.0"}`)
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

	plugin := &SpatialStudioPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var svc plugins.ServiceSpatialStudio
	err = json.Unmarshal(service.Raw, &svc)
	require.NoError(t, err)
	assert.Equal(t, "23.3.0", svc.Version)
	require.Len(t, svc.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:spatial_studio:23.3.0:*:*:*:*:*:*:*", svc.CPEs[0])
}

func TestSpatialStudioPlugin_Run_NegativeAllReturn404(t *testing.T) {
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

	plugin := &SpatialStudioPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestSpatialStudioPlugin_Run_NegativeGenericPathNoMarker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<html><body>hello world</body></html>`)
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

	plugin := &SpatialStudioPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestSpatialStudioPlugin_Metadata(t *testing.T) {
	plugin := &SpatialStudioPlugin{}
	assert.Equal(t, OracleSpatialStudio, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(4040))
	assert.False(t, plugin.PortPriority(80))
	assert.False(t, plugin.PortPriority(443))
}

func TestSpatialStudioTLSPlugin_Run_PositiveViaLoginPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/spatialstudio":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle Spatial Studio</title></head><body>Oracle Spatial Studio<oj-module></oj-module></body></html>`)
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

	plugin := &SpatialStudioTLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var svc plugins.ServiceSpatialStudio
	err = json.Unmarshal(service.Raw, &svc)
	require.NoError(t, err)
	require.Len(t, svc.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:spatial_studio:*:*:*:*:*:*:*:*", svc.CPEs[0])
}

func TestSpatialStudioTLSPlugin_Metadata(t *testing.T) {
	plugin := &SpatialStudioTLSPlugin{}
	assert.Equal(t, OracleSpatialStudio, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(4040))
}

func TestSpatialStudioSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/spatialstudio":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body>Oracle Spatial Studio</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	t.Run("with Misconfigs=true yields finding but no AnonymousAccess", func(t *testing.T) {
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

		plugin := &SpatialStudioPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-spatial-studio-login-exposed", service.SecurityFindings[0].ID)
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

		plugin := &SpatialStudioPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

func TestServiceSpatialStudio_Type(t *testing.T) {
	s := plugins.ServiceSpatialStudio{Title: "test", Version: "1.0"}
	assert.Equal(t, "oracle_spatial_studio", s.Type())
}
