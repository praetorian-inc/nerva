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

package glassfish

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

// dialTestServer dials the httptest server via plain TCP and builds a plugins.Target
// pointing at it, mirroring the oraclehttp/oracleidentity test harness pattern.
func dialTestServer(t *testing.T, serverURL string, misconfigs bool) (net.Conn, plugins.Target) {
	t.Helper()
	addr := parseTestServerAddr(t, serverURL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(serverURL, "http://"), 5*time.Second)
	require.NoError(t, err)
	target := plugins.Target{
		Host:       addr.Addr().String(),
		Address:    addr,
		Misconfigs: misconfigs,
	}
	return conn, target
}

// ---------------------------------------------------------------------------
// Unit-level tests (helpers called directly)
// ---------------------------------------------------------------------------

func TestParseXPoweredBy(t *testing.T) {
	tests := []struct {
		name            string
		xpb             string
		expectedProduct string
		expectedVersion string
		expectedJDK     string
	}{
		{
			name:            "modern GlassFish with version and JDK",
			xpb:             "Servlet/3.0 (GlassFish Server Open Source Edition 4.1.1 Java/Oracle Corporation/1.8)",
			expectedProduct: "glassfish",
			expectedVersion: "4.1.1",
			expectedJDK:     "1.8",
		},
		{
			name:            "Payara with version and JDK",
			xpb:             "Servlet/3.1 (Payara Server 5.2021.1 Java/AdoptOpenJDK/11.0.2)",
			expectedProduct: "payara",
			expectedVersion: "5.2021.1",
			expectedJDK:     "11.0.2",
		},
		{
			name:            "missing JDK segment",
			xpb:             "Servlet/3.0 (GlassFish Server Open Source Edition 5.0)",
			expectedProduct: "glassfish",
			expectedVersion: "5.0",
			expectedJDK:     "",
		},
		{
			name:            "bare Servlet with no branded parenthetical",
			xpb:             "Servlet/3.0",
			expectedProduct: "",
			expectedVersion: "",
			expectedJDK:     "",
		},
		{
			name:            "empty header",
			xpb:             "",
			expectedProduct: "",
			expectedVersion: "",
			expectedJDK:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			product, version, jdk := parseXPoweredBy(tt.xpb)
			assert.Equal(t, tt.expectedProduct, product)
			assert.Equal(t, tt.expectedVersion, version)
			assert.Equal(t, tt.expectedJDK, jdk)
		})
	}
}

func TestParseServerVersion(t *testing.T) {
	tests := []struct {
		name     string
		server   string
		expected string
	}{
		{
			name:     "legacy Sun GlassFish with v-prefixed version",
			server:   "Sun GlassFish Enterprise Server v2.1",
			expected: "2.1",
		},
		{
			name:     "Eclipse GlassFish slash form",
			server:   "Eclipse GlassFish/7.0.0",
			expected: "7.0.0",
		},
		{
			name:     "Payara Server space form",
			server:   "Payara Server 5.2021.1",
			expected: "5.2021.1",
		},
		{
			name:     "stripped version on branded header",
			server:   "Eclipse GlassFish",
			expected: "",
		},
		{
			name:     "unbranded server header",
			server:   "Apache-Coyote/1.1",
			expected: "",
		},
		{
			name:     "empty header",
			server:   "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseServerVersion(tt.server)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestClassifyProduct(t *testing.T) {
	tests := []struct {
		name     string
		server   string
		xpb      string
		expected string
	}{
		{
			name:     "payara via server header",
			server:   "Payara Server 5.2021.1",
			xpb:      "",
			expected: "payara",
		},
		{
			name:     "payara via x-powered-by",
			server:   "",
			xpb:      "Servlet/3.1 (Payara Server 5.2021.1)",
			expected: "payara",
		},
		{
			name:     "glassfish via server header",
			server:   "GlassFish Server Open Source Edition 4.1.1",
			xpb:      "",
			expected: "glassfish",
		},
		{
			name:     "unbranded headers yield empty string",
			server:   "Apache-Coyote/1.1",
			xpb:      "Servlet/3.0",
			expected: "",
		},
		{
			name:     "payara takes precedence when both branded",
			server:   "GlassFish Server Open Source Edition 4.1.1",
			xpb:      "Servlet/3.1 (Payara Server 5.2021.1)",
			expected: "payara",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := classifyProduct(tt.server, tt.xpb)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildGlassFishCPEs(t *testing.T) {
	tests := []struct {
		name     string
		product  string
		version  string
		expected []string
	}{
		{
			name:     "glassfish with version",
			product:  "glassfish",
			version:  "4.1.1",
			expected: []string{"cpe:2.3:a:oracle:glassfish_server:4.1.1:*:*:*:*:*:*:*"},
		},
		{
			name:     "payara with version",
			product:  "payara",
			version:  "5.2021.1",
			expected: []string{"cpe:2.3:a:payara:payara:5.2021.1:*:*:*:*:*:*:*"},
		},
		{
			name:     "glassfish with empty version wildcards",
			product:  "glassfish",
			version:  "",
			expected: []string{"cpe:2.3:a:oracle:glassfish_server:*:*:*:*:*:*:*:*"},
		},
		{
			name:     "payara with empty version wildcards",
			product:  "payara",
			version:  "",
			expected: []string{"cpe:2.3:a:payara:payara:*:*:*:*:*:*:*:*"},
		},
		{
			name:     "eclipse glassfish emits eclipse CPE",
			product:  "eclipse",
			version:  "7.0.0",
			expected: []string{"cpe:2.3:a:eclipse:glassfish:7.0.0:*:*:*:*:*:*:*"},
		},
		{
			name:     "eclipse with empty version wildcards",
			product:  "eclipse",
			version:  "",
			expected: []string{"cpe:2.3:a:eclipse:glassfish:*:*:*:*:*:*:*:*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildGlassFishCPEs(tt.product, tt.version)
			assert.Equal(t, tt.expected, result)
			assert.Len(t, result, 1, "exactly one product CPE must be emitted")
		})
	}
}

// ---------------------------------------------------------------------------
// Positive detection tests (via httptest server + plugin.Run)
// ---------------------------------------------------------------------------

func TestGlassFishPlugin_Run_PositiveModernXPoweredBy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case rootPath:
			w.Header().Set("X-Powered-By", "Servlet/3.0 (GlassFish Server Open Source Edition 4.1.1 Java/Oracle Corporation/1.8)")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL, false)
	defer conn.Close()

	plugin := &GlassFishPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var gf plugins.ServiceGlassFish
	require.NoError(t, json.Unmarshal(service.Raw, &gf))
	assert.Equal(t, "glassfish", gf.Product)
	assert.Equal(t, "1.8", gf.JDK)
	assert.Equal(t, "4.1.1", service.Version)
	assert.Equal(t, plugins.ProtoGlassFish, service.Protocol)
}

func TestGlassFishPlugin_Run_PositivePayaraServerHeader(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case rootPath:
			w.Header().Set("Server", "Payara Server 5.2021.1")
			w.Header().Set("X-Powered-By", "Servlet/3.1 (Payara Server 5.2021.1)")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL, false)
	defer conn.Close()

	plugin := &GlassFishPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var gf plugins.ServiceGlassFish
	require.NoError(t, json.Unmarshal(service.Raw, &gf))
	assert.Equal(t, "payara", gf.Product)
	assert.Equal(t, "5.2021.1", service.Version)
	assert.Equal(t, plugins.ProtoPayara, service.Protocol)
}

func TestGlassFishPlugin_Run_PositiveLegacySunGlassFish(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case rootPath:
			w.Header().Set("Server", "Sun GlassFish Enterprise Server v2.1")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL, false)
	defer conn.Close()

	plugin := &GlassFishPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var gf plugins.ServiceGlassFish
	require.NoError(t, json.Unmarshal(service.Raw, &gf))
	assert.Equal(t, "glassfish", gf.Product)
	assert.Equal(t, "2.1", service.Version)
	assert.Equal(t, plugins.ProtoGlassFish, service.Protocol)
}

func TestGlassFishPlugin_Run_PositiveEclipseGlassFish(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case rootPath:
			w.Header().Set("Server", "Eclipse GlassFish/7.0.0")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL, false)
	defer conn.Close()

	plugin := &GlassFishPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var gf plugins.ServiceGlassFish
	require.NoError(t, json.Unmarshal(service.Raw, &gf))
	assert.Equal(t, "eclipse", gf.Product)
	assert.Equal(t, "7.0.0", service.Version)
	require.Len(t, gf.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:eclipse:glassfish:7.0.0:*:*:*:*:*:*:*", gf.CPEs[0])
}

func TestGlassFishPlugin_Run_PositiveAdminConsoleCorroboration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case rootPath:
			w.WriteHeader(http.StatusNotFound)
		case adminPath:
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html><title>GlassFish Server Open Source Edition - Admin Console</title></html>")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL, false)
	defer conn.Close()

	plugin := &GlassFishPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var gf plugins.ServiceGlassFish
	require.NoError(t, json.Unmarshal(service.Raw, &gf))
	assert.True(t, gf.AdminConsole)
	assert.Equal(t, "glassfish", gf.Product)
}

// TestGlassFishPlugin_Run_AdminConsoleViaXPoweredBy verifies that admin-console
// corroboration in evaluate also honors a branded X-Powered-By header alone
// (not just Server/body): a 2xx admin-console page with no Server header and no
// product text in the body, but a branded X-Powered-By, must still set
// AdminConsole=true and fire the Medium admin-console-exposed finding.
func TestGlassFishPlugin_Run_AdminConsoleViaXPoweredBy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case rootPath:
			w.WriteHeader(http.StatusNotFound)
		case adminPath:
			w.Header().Set("X-Powered-By", "Servlet/4.0 (GlassFish Server Open Source Edition 5.1.0 Java/Oracle Corporation/1.8)")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html><body>Welcome</body></html>")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL, true)
	defer conn.Close()

	plugin := &GlassFishPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var gf plugins.ServiceGlassFish
	require.NoError(t, json.Unmarshal(service.Raw, &gf))
	assert.True(t, gf.AdminConsole, "X-Powered-By alone must corroborate the admin console")

	var found bool
	for _, f := range service.SecurityFindings {
		if f.ID == "glassfish-payara-admin-console-exposed" {
			found = true
			assert.Equal(t, plugins.SeverityMedium, f.Severity)
		}
	}
	assert.True(t, found, "expected glassfish-payara-admin-console-exposed finding")
}

// ---------------------------------------------------------------------------
// Negative / false-positive guard tests
// ---------------------------------------------------------------------------

func TestGlassFishPlugin_Run_NegativeBareXPoweredBy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case rootPath:
			w.Header().Set("X-Powered-By", "Servlet/3.0")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL, false)
	defer conn.Close()

	plugin := &GlassFishPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service, "bare Servlet/x X-Powered-By without a branded token must not be detected")
}

func TestGlassFishPlugin_Run_NegativeApacheTomcat(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case rootPath:
			w.Header().Set("Server", "Apache-Coyote/1.1")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL, false)
	defer conn.Close()

	plugin := &GlassFishPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestGlassFishPlugin_Run_NegativeJetty(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case rootPath:
			w.Header().Set("Server", "Jetty(9.4.12.v20180830)")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL, false)
	defer conn.Close()

	plugin := &GlassFishPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestGlassFishPlugin_Run_NegativeBareAdminConsole200(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case rootPath:
			w.WriteHeader(http.StatusNotFound)
		case adminPath:
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html><body>Welcome</body></html>")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL, false)
	defer conn.Close()

	plugin := &GlassFishPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service, "bare 200 on /common/index.jsf without a branded marker must not be detected")
}

// ---------------------------------------------------------------------------
// CPE correctness
// ---------------------------------------------------------------------------

func TestGlassFishPlugin_CPECorrectness(t *testing.T) {
	t.Run("GlassFish host emits exactly one oracle:glassfish_server CPE", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case rootPath:
				w.Header().Set("X-Powered-By", "Servlet/3.0 (GlassFish Server Open Source Edition 4.1.1 Java/Oracle Corporation/1.8)")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "hello")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		conn, target := dialTestServer(t, server.URL, false)
		defer conn.Close()

		plugin := &GlassFishPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		var gf plugins.ServiceGlassFish
		require.NoError(t, json.Unmarshal(service.Raw, &gf))
		require.Len(t, gf.CPEs, 1)
		assert.Equal(t, "cpe:2.3:a:oracle:glassfish_server:4.1.1:*:*:*:*:*:*:*", gf.CPEs[0])
	})

	t.Run("Payara host emits exactly one payara:payara CPE", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case rootPath:
				w.Header().Set("Server", "Payara Server 5.2021.1")
				w.Header().Set("X-Powered-By", "Servlet/3.1 (Payara Server 5.2021.1)")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "hello")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		conn, target := dialTestServer(t, server.URL, false)
		defer conn.Close()

		plugin := &GlassFishPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		var gf plugins.ServiceGlassFish
		require.NoError(t, json.Unmarshal(service.Raw, &gf))
		require.Len(t, gf.CPEs, 1)
		assert.Equal(t, "cpe:2.3:a:payara:payara:5.2021.1:*:*:*:*:*:*:*", gf.CPEs[0])
	})
}

// ---------------------------------------------------------------------------
// Misconfigs gating
// ---------------------------------------------------------------------------

func TestGlassFishSecurityFindings(t *testing.T) {
	exposedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case rootPath:
			w.Header().Set("X-Powered-By", "Servlet/3.0 (GlassFish Server Open Source Edition 4.1.1 Java/Oracle Corporation/1.8)")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	t.Run("Misconfigs=false yields no SecurityFindings and no AnonymousAccess", func(t *testing.T) {
		server := httptest.NewServer(exposedHandler)
		defer server.Close()

		conn, target := dialTestServer(t, server.URL, false)
		defer conn.Close()

		plugin := &GlassFishPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})

	t.Run("Misconfigs=true with 2xx branded root yields glassfish-payara-exposed (Low)", func(t *testing.T) {
		server := httptest.NewServer(exposedHandler)
		defer server.Close()

		conn, target := dialTestServer(t, server.URL, true)
		defer conn.Close()

		plugin := &GlassFishPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "glassfish-payara-exposed", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityLow, service.SecurityFindings[0].Severity)
	})

	t.Run("Misconfigs=true with branded 2xx admin console yields glassfish-payara-admin-console-exposed (Medium)", func(t *testing.T) {
		adminHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case rootPath:
				w.Header().Set("X-Powered-By", "Servlet/3.0 (GlassFish Server Open Source Edition 4.1.1 Java/Oracle Corporation/1.8)")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "hello")
			case adminPath:
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "<html><title>GlassFish Server Open Source Edition - Admin Console</title></html>")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})
		server := httptest.NewServer(adminHandler)
		defer server.Close()

		conn, target := dialTestServer(t, server.URL, true)
		defer conn.Close()

		plugin := &GlassFishPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1, "admin-console finding must take precedence, not be duplicated alongside the exposed finding")
		assert.Equal(t, "glassfish-payara-admin-console-exposed", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityMedium, service.SecurityFindings[0].Severity)
	})

	t.Run("non-2xx root yields no findings even with Misconfigs=true", func(t *testing.T) {
		unauthorizedHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case rootPath:
				w.Header().Set("Server", "Sun GlassFish Enterprise Server v2.1")
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, "unauthorized")
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})
		server := httptest.NewServer(unauthorizedHandler)
		defer server.Close()

		conn, target := dialTestServer(t, server.URL, true)
		defer conn.Close()

		plugin := &GlassFishPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service, "the branded Server header alone must still detect the service on a 401")

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

// ---------------------------------------------------------------------------
// TLS plugin variant
// ---------------------------------------------------------------------------

// TestGlassFishTLSPlugin_Run_PositiveModernXPoweredBy mirrors the TCP positive
// detection test but exercises GlassFishTLSPlugin.Run, following the
// oraclehttp/OHSTLSPlugin test pattern of reusing a plain (non-TLS) httptest
// server and connection: the plugin's custom Transport wraps the raw conn
// directly, so no actual TLS handshake is required to exercise the detection
// and CPE logic. CheckTLS gracefully no-ops on a non-*tls.Conn.
func TestGlassFishTLSPlugin_Run_PositiveModernXPoweredBy(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case rootPath:
			w.Header().Set("X-Powered-By", "Servlet/3.0 (GlassFish Server Open Source Edition 4.1.1 Java/Oracle Corporation/1.8)")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL, true)
	defer conn.Close()

	plugin := &GlassFishTLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var gf plugins.ServiceGlassFish
	require.NoError(t, json.Unmarshal(service.Raw, &gf))
	assert.Equal(t, "glassfish", gf.Product)
	assert.Equal(t, "4.1.1", service.Version)
	assert.True(t, service.TLS)
	assert.True(t, service.AnonymousAccess)
	require.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "glassfish-payara-exposed", service.SecurityFindings[0].ID)
}

// ---------------------------------------------------------------------------
// Plugin metadata
// ---------------------------------------------------------------------------

func TestGlassFishPlugin_Metadata(t *testing.T) {
	plugin := &GlassFishPlugin{}
	assert.Equal(t, "glassfish", plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(DefaultHTTPPort))
	assert.True(t, plugin.PortPriority(AdminPort))
	assert.False(t, plugin.PortPriority(80))
}

func TestGlassFishTLSPlugin_Metadata(t *testing.T) {
	plugin := &GlassFishTLSPlugin{}
	assert.Equal(t, "glassfish", plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(DefaultHTTPSPort))
	assert.True(t, plugin.PortPriority(AdminPort))
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(80))
}
