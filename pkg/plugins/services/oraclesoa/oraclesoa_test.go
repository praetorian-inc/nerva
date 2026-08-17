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

package oraclesoa

import (
	"crypto/tls"
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

func dialTestServer(t *testing.T, serverURL string) (net.Conn, plugins.Target) {
	t.Helper()
	addr := parseTestServerAddr(t, serverURL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(serverURL, "http://"), 5*time.Second)
	require.NoError(t, err)
	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}
	return conn, target
}

// dialTLSTestServer mirrors dialTestServer but completes a real TLS handshake
// against an httptest.NewTLSServer, so TLSPlugin.Run receives the *tls.Conn a
// scanner hands it in production. plugins.CheckTLS type-asserts conn.(*tls.Conn)
// and returns nil for anything else, so without a genuine TLS conn the whole
// CheckTLS branch of TLSPlugin.Run silently does nothing.
func dialTLSTestServer(t *testing.T, serverURL string) (*tls.Conn, plugins.Target) {
	t.Helper()
	hostPort := strings.TrimPrefix(serverURL, "https://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	addr := netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))

	conn, err := tls.Dial("tcp", hostPort, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test-only self-signed httptest cert
	require.NoError(t, err)
	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}
	return conn, target
}

// hasFindingID reports whether findings contains a finding with the given ID.
func hasFindingID(findings []plugins.SecurityFinding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestContainsAny(t *testing.T) {
	assert.True(t, containsAny("Welcome to the ORACLE SOA platform", []string{"Welcome to the Oracle SOA"}))
	assert.False(t, containsAny("generic page", []string{"Oracle Service Bus"}))
}

func TestDetectSOAInfra(t *testing.T) {
	tests := []struct {
		name              string
		handler           http.HandlerFunc
		expectedAnonymous bool
		expectedDetect    bool
	}{
		{
			name: "2xx with soa-infra marker",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "Welcome to the Oracle SOA Platform")
			},
			expectedAnonymous: true,
			expectedDetect:    true,
		},
		{
			name: "non-2xx with marker: detected but not anonymous",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(403)
				fmt.Fprint(w, "Oracle SOA Platform")
			},
			expectedAnonymous: false,
			expectedDetect:    true,
		},
		{
			name: "no marker",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, "generic response")
			},
			expectedAnonymous: false,
			expectedDetect:    false,
		},
		{
			name: "reflected requested path only, no product marker -> NOT detected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(403)
				fmt.Fprintf(w, "%s forbidden", strings.TrimPrefix(r.URL.Path, "/"))
			},
			expectedAnonymous: false,
			expectedDetect:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			anonymous, detected := detectSOAInfra(server.Client(), server.URL, "")
			assert.Equal(t, tt.expectedDetect, detected)
			assert.Equal(t, tt.expectedAnonymous, anonymous)
		})
	}
}

func TestDetectSOA(t *testing.T) {
	tests := []struct {
		name            string
		handler         http.HandlerFunc
		expectedProduct string
		expectedDetect  bool
	}{
		{
			name: "soa via /soa-infra",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/soa-infra":
					fmt.Fprint(w, "Welcome to the Oracle SOA Platform")
				default:
					w.WriteHeader(404)
				}
			},
			expectedProduct: "soa",
			expectedDetect:  true,
		},
		{
			name: "osb via /sbconsole",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/sbconsole":
					fmt.Fprint(w, "Oracle Service Bus Console")
				default:
					w.WriteHeader(404)
				}
			},
			expectedProduct: "osb",
			expectedDetect:  true,
		},
		{
			name: "osb via /servicebus (12c/14c console)",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/servicebus":
					fmt.Fprint(w, "Oracle Service Bus Console")
				default:
					w.WriteHeader(404)
				}
			},
			expectedProduct: "osb",
			expectedDetect:  true,
		},
		{
			name: "/servicebus reflects the request path only, no genuine marker -> NOT detected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/servicebus":
					fmt.Fprintf(w, "<html><body>404 Not Found: %s</body></html>", r.URL.Path)
				default:
					w.WriteHeader(404)
				}
			},
			expectedProduct: "",
			expectedDetect:  false,
		},
		{
			name: "soa via /soa/composer",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/soa/composer":
					fmt.Fprint(w, "Oracle SOA Composer")
				default:
					w.WriteHeader(404)
				}
			},
			expectedProduct: "soa",
			expectedDetect:  true,
		},
		{
			name: "soa via /bpm/workspace",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/bpm/workspace":
					fmt.Fprint(w, "Business Process Workspace")
				default:
					w.WriteHeader(404)
				}
			},
			expectedProduct: "soa",
			expectedDetect:  true,
		},
		{
			name: "bare WebLogic auth cookie with no product marker -> NOT detected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				http.SetCookie(w, &http.Cookie{Name: "_WL_AUTHCOOKIE_JSESSIONID", Value: "abc123"})
				fmt.Fprint(w, "generic weblogic response")
			},
			expectedProduct: "",
			expectedDetect:  false,
		},
		{
			name: "no match at all",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
			},
			expectedProduct: "",
			expectedDetect:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			product, _, detected := detectSOA(server.Client(), server.URL, "")
			assert.Equal(t, tt.expectedDetect, detected)
			assert.Equal(t, tt.expectedProduct, product)
		})
	}
}

func TestBuildSOACPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:oracle:soa_suite:*:*:*:*:*:*:*:*", buildSOACPE("soa"))
	assert.Equal(t, "cpe:2.3:a:oracle:service_bus:*:*:*:*:*:*:*:*", buildSOACPE("osb"))
}

func TestPlugin_Run_SOAInfraDetection_Misconfigs(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/soa-infra":
			fmt.Fprint(w, "Welcome to the Oracle SOA Platform")
		default:
			w.WriteHeader(404)
		}
	})

	t.Run("Misconfigs=true and 2xx yields AnonymousAccess and finding", func(t *testing.T) {
		server := httptest.NewServer(handler)
		defer server.Close()

		conn, target := dialTestServer(t, server.URL)
		defer conn.Close()
		target.Misconfigs = true

		plugin := &Plugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-soa-infra-unauthenticated", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityMedium, service.SecurityFindings[0].Severity)

		var payload plugins.ServiceOracleSOA
		require.NoError(t, json.Unmarshal(service.Raw, &payload))
		assert.Equal(t, "soa", payload.Product)
		require.Len(t, payload.CPEs, 1)
		assert.Equal(t, "cpe:2.3:a:oracle:soa_suite:*:*:*:*:*:*:*:*", payload.CPEs[0])
	})

	t.Run("Misconfigs=false yields no AnonymousAccess or findings", func(t *testing.T) {
		server := httptest.NewServer(handler)
		defer server.Close()

		conn, target := dialTestServer(t, server.URL)
		defer conn.Close()
		target.Misconfigs = false

		plugin := &Plugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

func TestPlugin_Run_OSBDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/sbconsole":
			fmt.Fprint(w, "Oracle Service Bus Console")
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()
	target.Misconfigs = true

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.False(t, service.AnonymousAccess)
	assert.Empty(t, service.SecurityFindings)

	var payload plugins.ServiceOracleSOA
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "osb", payload.Product)
	assert.Equal(t, "cpe:2.3:a:oracle:service_bus:*:*:*:*:*:*:*:*", payload.CPEs[0])
}

func TestPlugin_Run_OSBDetection_ServiceBusPath(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/servicebus":
			fmt.Fprint(w, "Oracle Service Bus Console")
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()
	target.Misconfigs = true

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleSOA
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "osb", payload.Product)
	assert.Equal(t, "cpe:2.3:a:oracle:service_bus:*:*:*:*:*:*:*:*", payload.CPEs[0])
}

func TestPlugin_Run_ServiceBusPath_ReflectedOnly_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/servicebus":
			fmt.Fprintf(w, "<html><body>404 Not Found: %s</body></html>", r.URL.Path)
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

// TestPlugin_Run_SOAInfraReflectedPath_NotDetected pins the reason "soa-infra"
// was dropped from soaInfraMarkers: /soa-infra is the very path being requested,
// so any catch-all or error page that echoes the requested URI would otherwise
// be misdetected as Oracle SOA. Because the reflection here is served at 200,
// that misdetection would additionally satisfy the is2xx gate and emit a false
// oracle-soa-infra-unauthenticated finding, so the Misconfigs=true path is
// pinned explicitly alongside the plain detection result.
func TestPlugin_Run_SOAInfraReflectedPath_NotDetected(t *testing.T) {
	// Tomcat-style catch-all that echoes the requested URI back at HTTP 200.
	reflector := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html><body><h1>The requested resource [%s] is not available</h1></body></html>", r.URL.Path)
	})

	t.Run("no detection and no anonymous access on a 2xx reflection", func(t *testing.T) {
		server := httptest.NewServer(reflector)
		defer server.Close()

		product, anonymous, detected := detectSOA(server.Client(), server.URL, "")
		assert.False(t, detected, "an echoed request path is not a product marker")
		assert.Equal(t, "", product)
		assert.False(t, anonymous, "a 2xx reflection must not be reported as anonymous access")
	})

	// anonymous is the sole gate on the finding, so a nil service proves no
	// false oracle-soa-infra-unauthenticated finding reaches the caller.
	for _, misconfigs := range []bool{false, true} {
		t.Run(fmt.Sprintf("Plugin.Run with Misconfigs=%t yields no service and no finding", misconfigs), func(t *testing.T) {
			server := httptest.NewServer(reflector)
			defer server.Close()

			conn, target := dialTestServer(t, server.URL)
			defer conn.Close()
			target.Misconfigs = misconfigs

			plugin := &Plugin{}
			service, err := plugin.Run(conn, 5*time.Second, target)
			require.NoError(t, err)
			assert.Nil(t, service, "a reflected request path must not be detected as Oracle SOA")
		})
	}
}

// TestPlugin_Run_LaterProbeMatchesAfterOversizedEarlierResponses covers the
// sequential-probe path that the connection drain exists for. All five probes
// share one injected keep-alive connection, and net/http can only reuse that
// connection when a response body is consumed to EOF. Here the first four
// probes return bodies larger than maxBody and carry no marker, so only the
// io.Copy(io.Discard, body) drain that follows the bounded read keeps the
// connection alive long enough for the fifth probe to match.
func TestPlugin_Run_LaterProbeMatchesAfterOversizedEarlierResponses(t *testing.T) {
	oversized := strings.Repeat("x", int(maxBody)+64*1024)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/bpm/workspace" {
			fmt.Fprint(w, "Business Process Workspace")
			return
		}
		fmt.Fprint(w, oversized)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()
	target.Misconfigs = true

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service, "the last probe must still be reachable after four oversized non-matching responses")

	var payload plugins.ServiceOracleSOA
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "soa", payload.Product)
	assert.Equal(t, "cpe:2.3:a:oracle:soa_suite:*:*:*:*:*:*:*:*", payload.CPEs[0])
	assert.False(t, service.AnonymousAccess, "/bpm/workspace is a sign-in gate, not an anonymous surface")
	assert.Empty(t, service.SecurityFindings)
}

func TestPlugin_Run_WeblogicCookieOnly_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "_WL_AUTHCOOKIE_JSESSIONID", Value: "abc123"})
		fmt.Fprint(w, "generic weblogic response")
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestPlugin_Run_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

// TestTLSPlugin_Run_PositiveDetection drives TLSPlugin.Run over a real
// *tls.Conn against an httptest TLS server with Misconfigs enabled, so
// plugins.CheckTLS(conn) actually executes rather than short-circuiting on its
// plain-conn type assertion. httptest presents a self-signed certificate, so
// CheckTLS must contribute tls-self-signed, and because the SOA Infrastructure
// landing page is the surface that matched, that TLS finding has to coexist
// with the SOA anonymous finding rather than replace it.
func TestTLSPlugin_Run_PositiveDetection(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/soa-infra":
			fmt.Fprint(w, "Welcome to the Oracle SOA Platform")
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()

	conn, target := dialTLSTestServer(t, server.URL)
	defer conn.Close()
	target.Misconfigs = true

	plugin := &TLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service, "detection must succeed over a real *tls.Conn")

	var payload plugins.ServiceOracleSOA
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "soa", payload.Product)
	require.Len(t, payload.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:soa_suite:*:*:*:*:*:*:*:*", payload.CPEs[0])

	assert.True(t, service.TLS)
	assert.Equal(t, "tcptls", service.Transport)

	assert.True(t, service.AnonymousAccess)
	assert.True(t, hasFindingID(service.SecurityFindings, "oracle-soa-infra-unauthenticated"),
		"the SOA anonymous finding must survive the CheckTLS append")
	assert.True(t, hasFindingID(service.SecurityFindings, "tls-self-signed"),
		"httptest's self-signed certificate must yield a CheckTLS finding alongside it")
	assert.Greater(t, len(service.SecurityFindings), 1)
}

func TestTLSPlugin_Run_NotDetected(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404)
	}))
	defer server.Close()

	conn, target := dialTLSTestServer(t, server.URL)
	defer conn.Close()
	target.Misconfigs = true

	plugin := &TLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service, "no product marker means no service, even though CheckTLS would have findings")
}

func TestPlugin_PortPriority(t *testing.T) {
	plugin := &Plugin{}
	tests := []struct {
		port     uint16
		expected bool
	}{
		{8001, true},
		{7001, true},
		{443, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, plugin.PortPriority(tt.port))
	}
}

func TestTLSPlugin_PortPriority(t *testing.T) {
	plugin := &TLSPlugin{}
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(8001))
}

func TestPlugin_Metadata(t *testing.T) {
	plugin := &Plugin{}
	assert.Equal(t, SOA, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
}

func TestTLSPlugin_Metadata(t *testing.T) {
	plugin := &TLSPlugin{}
	assert.Equal(t, SOA, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
}
