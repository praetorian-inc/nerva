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

package oraclehttp

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

func TestMatchesOHSServer(t *testing.T) {
	tests := []struct {
		name     string
		server   string
		expected bool
	}{
		{
			name:     "Oracle-HTTP-Server with version",
			server:   "Oracle-HTTP-Server/2.4.52",
			expected: true,
		},
		{
			name:     "Oracle-Application-Server",
			server:   "Oracle-Application-Server/10g",
			expected: true,
		},
		{
			name:     "Oracle-iPlanet-Web-Server",
			server:   "Oracle-iPlanet-Web-Server/7.0",
			expected: true,
		},
		{
			name:     "Sun-Java-System-Web-Server",
			server:   "Sun-Java-System-Web-Server/7.0",
			expected: true,
		},
		{
			name:     "Sun-ONE-Web-Server",
			server:   "Sun-ONE-Web-Server/6.1",
			expected: true,
		},
		{
			name:     "Netscape-Enterprise",
			server:   "Netscape-Enterprise/6.0",
			expected: true,
		},
		{
			name:     "case-insensitive match",
			server:   "oracle-http-server/2.4.52",
			expected: true,
		},
		{
			name:     "Apache does not match",
			server:   "Apache/2.4.52",
			expected: false,
		},
		{
			name:     "nginx does not match",
			server:   "nginx",
			expected: false,
		},
		{
			name:     "empty server header",
			server:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesOHSServer(tt.server)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestIsIPlanetLineage(t *testing.T) {
	tests := []struct {
		name     string
		server   string
		expected bool
	}{
		{
			name:     "Oracle-iPlanet-Web-Server matches",
			server:   "Oracle-iPlanet-Web-Server/7.0",
			expected: true,
		},
		{
			name:     "Sun-Java-System-Web-Server matches",
			server:   "Sun-Java-System-Web-Server/7.0",
			expected: true,
		},
		{
			name:     "Sun-ONE-Web-Server matches",
			server:   "Sun-ONE-Web-Server/6.1",
			expected: true,
		},
		{
			name:     "Netscape-Enterprise matches",
			server:   "Netscape-Enterprise/6.0",
			expected: true,
		},
		{
			name:     "Oracle-HTTP-Server does not match iPlanet lineage",
			server:   "Oracle-HTTP-Server/2.4.52",
			expected: false,
		},
		{
			name:     "empty server header",
			server:   "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isIPlanetLineage(tt.server)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestParseOHSVersion(t *testing.T) {
	tests := []struct {
		name     string
		server   string
		expected string
	}{
		{
			name:     "Oracle-HTTP-Server with version",
			server:   "Oracle-HTTP-Server/2.4.52",
			expected: "2.4.52",
		},
		{
			name:     "Oracle-iPlanet-Web-Server with version",
			server:   "Oracle-iPlanet-Web-Server/7.0",
			expected: "7.0",
		},
		{
			name:     "Oracle-Application-Server-11g generation-suffixed banner",
			server:   "Oracle-Application-Server-11g/11.1.1.0.0 Oracle-HTTP-Server",
			expected: "11.1.1.0.0",
		},
		{
			name:     "Oracle-Application-Server-10g generation-suffixed banner",
			server:   "Oracle-Application-Server-10g/9.0.4.0.0",
			expected: "9.0.4.0.0",
		},
		{
			name:     "version stripped from header",
			server:   "Oracle-HTTP-Server",
			expected: "",
		},
		{
			name:     "no version present at all",
			server:   "Oracle-HTTP-Server/",
			expected: "",
		},
		{
			name:     "unrelated server header",
			server:   "Apache/2.4.52",
			expected: "",
		},
		{
			name:     "empty server header",
			server:   "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseOHSVersion(tt.server)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestOHSVendor(t *testing.T) {
	tests := []struct {
		name     string
		server   string
		expected string
	}{
		{
			name:     "Oracle-HTTP-Server yields Oracle vendor",
			server:   "Oracle-HTTP-Server/2.4.52",
			expected: "Oracle",
		},
		{
			name:     "Oracle-Application-Server yields Oracle vendor",
			server:   "Oracle-Application-Server/10g",
			expected: "Oracle",
		},
		{
			name:     "Oracle-iPlanet-Web-Server yields Oracle/Sun vendor",
			server:   "Oracle-iPlanet-Web-Server/7.0",
			expected: "Oracle/Sun",
		},
		{
			name:     "Sun-ONE-Web-Server yields Oracle/Sun vendor",
			server:   "Sun-ONE-Web-Server/6.1",
			expected: "Oracle/Sun",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ohsVendor(tt.server)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildOHSCPEs(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		iplanet  bool
		expected []string
	}{
		{
			name:     "with version, not iPlanet",
			version:  "2.4.52",
			iplanet:  false,
			expected: []string{"cpe:2.3:a:oracle:http_server:2.4.52:*:*:*:*:*:*:*"},
		},
		{
			name:    "empty version, iPlanet lineage",
			version: "",
			iplanet: true,
			expected: []string{
				"cpe:2.3:a:oracle:http_server:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:oracle:iplanet_web_server:*:*:*:*:*:*:*:*",
			},
		},
		{
			name:     "empty version, not iPlanet",
			version:  "",
			iplanet:  false,
			expected: []string{"cpe:2.3:a:oracle:http_server:*:*:*:*:*:*:*:*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildOHSCPEs(tt.version, tt.iplanet)
			assert.Equal(t, tt.expected, result)
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

func TestOHSPlugin_Run_PositiveOracleHTTPServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Oracle-HTTP-Server/2.4.52")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "hello")
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

	plugin := &OHSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ohsService plugins.ServiceOracleHTTPServer
	err = json.Unmarshal(service.Raw, &ohsService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.Equal(t, "Oracle-HTTP-Server/2.4.52", ohsService.Server)
	assert.Equal(t, "Oracle", ohsService.Vendor)
	assert.False(t, ohsService.FusionMiddleware)
	assert.Equal(t, "2.4.52", service.Version)
	require.Len(t, ohsService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:http_server:2.4.52:*:*:*:*:*:*:*", ohsService.CPEs[0])
}

// TestOHSPlugin_Run_PositiveGenerationSuffixedOASBanner verifies the fix for
// generation-suffixed Oracle Application Server banners (e.g.
// "Oracle-Application-Server-11g/11.1.1.0.0"), which previously yielded no
// version because the "-11g" suffix broke the version regex.
func TestOHSPlugin_Run_PositiveGenerationSuffixedOASBanner(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Oracle-Application-Server-11g/11.1.1.0.0 Oracle-HTTP-Server")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "hello")
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

	plugin := &OHSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ohsService plugins.ServiceOracleHTTPServer
	err = json.Unmarshal(service.Raw, &ohsService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.Equal(t, "11.1.1.0.0", service.Version)
	require.Len(t, ohsService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:http_server:11.1.1.0.0:*:*:*:*:*:*:*", ohsService.CPEs[0])
}

func TestOHSPlugin_Run_PositiveIPlanet(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Oracle-iPlanet-Web-Server/7.0")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "hello")
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

	plugin := &OHSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ohsService plugins.ServiceOracleHTTPServer
	err = json.Unmarshal(service.Raw, &ohsService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.Equal(t, "Oracle/Sun", ohsService.Vendor)
	require.Len(t, ohsService.CPEs, 2)
	// The iPlanet lineage version belongs to iplanet_web_server, not
	// http_server: http_server stays an unversioned coarse family marker.
	assert.Contains(t, ohsService.CPEs, "cpe:2.3:a:oracle:http_server:*:*:*:*:*:*:*:*")
	assert.Contains(t, ohsService.CPEs, "cpe:2.3:a:oracle:iplanet_web_server:7.0:*:*:*:*:*:*:*")
}

func TestOHSPlugin_Run_FusionMiddlewareHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Oracle-HTTP-Server/2.4.52")
		w.Header().Set("X-ORACLE-DMS-ECID", "abc123")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "hello")
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

	plugin := &OHSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ohsService plugins.ServiceOracleHTTPServer
	err = json.Unmarshal(service.Raw, &ohsService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.True(t, ohsService.FusionMiddleware)
}

func TestOHSPlugin_Run_NegativeApache(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Apache/2.4.52")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "hello")
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

	plugin := &OHSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestOHSPlugin_Run_NegativeNginx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "hello")
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

	plugin := &OHSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestOHSPlugin_Metadata(t *testing.T) {
	plugin := &OHSPlugin{}
	assert.Equal(t, OracleHTTPServer, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(7777))
	assert.False(t, plugin.PortPriority(4443))
	assert.False(t, plugin.PortPriority(80))
}

func TestOHSTLSPlugin_Run_PositiveOracleHTTPServer(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Oracle-HTTP-Server/2.4.52")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "hello")
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

	plugin := &OHSTLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var ohsService plugins.ServiceOracleHTTPServer
	err = json.Unmarshal(service.Raw, &ohsService)
	require.NoError(t, err)
	require.Len(t, ohsService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:http_server:2.4.52:*:*:*:*:*:*:*", ohsService.CPEs[0])
}

func TestOHSTLSPlugin_Metadata(t *testing.T) {
	plugin := &OHSTLSPlugin{}
	assert.Equal(t, OracleHTTPServer, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(4443))
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(7777))
}

func TestOHSSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Oracle-HTTP-Server/2.4.52")
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "hello")
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

		plugin := &OHSPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-http-server-exposed", service.SecurityFindings[0].ID)
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

		plugin := &OHSPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})

	t.Run("401 response still detects the service but yields no AnonymousAccess or finding", func(t *testing.T) {
		unauthorizedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Oracle-HTTP-Server/2.4.52")
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, "unauthorized")
		})
		server := httptest.NewServer(unauthorizedHandler)
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

		plugin := &OHSPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service, "the Server header alone must still detect the service on a 401")

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}
