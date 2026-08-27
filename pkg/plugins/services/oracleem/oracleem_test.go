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

package oracleem

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
// scanner would hand it in production and plugins.CheckTLS(conn) - which
// type-asserts conn.(*tls.Conn) - actually runs instead of short-circuiting on
// a plaintext conn.
func dialTLSTestServer(t *testing.T, serverURL string) (*tls.Conn, plugins.Target) {
	t.Helper()
	hostPort := strings.TrimPrefix(serverURL, "https://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	addr := netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))

	conn, err := tls.Dial("tcp", hostPort, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	target := plugins.Target{
		Host:    addr.Addr().String(),
		Address: addr,
	}
	return conn, target
}

// noRedirectClient mirrors production's createHTTPClient: redirects are not
// followed, so the Cloud Control logon 3xx Location header stays observable on
// the response.
func noRedirectClient(server *httptest.Server) *http.Client {
	client := server.Client()
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return client
}

// hasFindingID reports whether findings contains an entry with the given ID.
func hasFindingID(findings []plugins.SecurityFinding, id string) bool {
	for _, f := range findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "simple title",
			body:     `<html><head><title>Database Express</title></head></html>`,
			expected: "Database Express",
		},
		{
			name:     "no title element",
			body:     `<html><body>hi</body></html>`,
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractTitle(tt.body))
		})
	}
}

func TestContainsAny(t *testing.T) {
	assert.True(t, containsAny("Oracle ENTERPRISE MANAGER Cloud Control", []string{"Oracle Enterprise Manager"}))
	assert.False(t, containsAny("generic page", []string{"Database Express"}))
}

func TestLocationPath(t *testing.T) {
	tests := []struct {
		name     string
		location string
		expected string
	}{
		{
			name:     "simple path",
			location: "/em/faces/logon/logon.jspx",
			expected: "/em/faces/logon/logon.jspx",
		},
		{
			name:     "path with query string reflecting logon path",
			location: "/foo?next=/em/faces/logon",
			expected: "/foo",
		},
		{
			name:     "no location header",
			location: "",
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			header := http.Header{}
			if tt.location != "" {
				header.Set("Location", tt.location)
			}
			resp := &http.Response{Header: header}
			assert.Equal(t, tt.expected, locationPath(resp))
		})
	}
}

func TestExtractAgentVersion(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "agentVersion marker",
			body:     `<EMResponse agentVersion="13.5.0.0.0"></EMResponse>`,
			expected: "13.5.0.0.0",
		},
		{
			name:     "emdVersion marker",
			body:     `emdVersion: v12.1.0.5.0`,
			expected: "12.1.0.5.0",
		},
		{
			name:     "no version marker",
			body:     `<EMResponse><AgentState>up</AgentState></EMResponse>`,
			expected: "",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractAgentVersion(tt.body))
		})
	}
}

func TestDetectAgent(t *testing.T) {
	tests := []struct {
		name              string
		handler           http.HandlerFunc
		expectedVersion   string
		expectedAnonymous bool
		expectedDetect    bool
	}{
		{
			name: "2xx with agent marker and version",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<EMResponse agentVersion="13.5.0.0.0"><AgentState>up</AgentState></EMResponse>`)
			},
			expectedVersion:   "13.5.0.0.0",
			expectedAnonymous: true,
			expectedDetect:    true,
		},
		{
			name: "non-2xx with agent marker: detected but not anonymous",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
				fmt.Fprint(w, `<EMResponse><AgentState>error</AgentState></EMResponse>`)
			},
			expectedVersion:   "",
			expectedAnonymous: false,
			expectedDetect:    true,
		},
		{
			name: "no agent marker",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html>not em</html>`)
			},
			expectedVersion:   "",
			expectedAnonymous: false,
			expectedDetect:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			version, anonymous, detected := detectAgent(server.Client(), server.URL, "")
			assert.Equal(t, tt.expectedDetect, detected)
			assert.Equal(t, tt.expectedAnonymous, anonymous)
			assert.Equal(t, tt.expectedVersion, version)
		})
	}
}

func TestDetectConsoleOrExpress(t *testing.T) {
	tests := []struct {
		name              string
		handler           http.HandlerFunc
		expectedComponent string
		expectedDetect    bool
	}{
		{
			name: "Database Express title",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html><head><title>Database Express</title></head></html>`)
			},
			expectedComponent: "express",
			expectedDetect:    true,
		},
		{
			name: "logon redirect Location path",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/em/faces/logon/logon.jspx")
				w.WriteHeader(302)
			},
			expectedComponent: "console",
			expectedDetect:    true,
		},
		{
			name: "login path reflected only in query string, not real path -> NOT console",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/foo?next=/em/faces/logon")
				w.WriteHeader(302)
				fmt.Fprint(w, `<html><head><title>Generic Redirect</title></head></html>`)
			},
			expectedComponent: "",
			expectedDetect:    false,
		},
		{
			name: "no markers at all",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html><body>hi</body></html>`)
			},
			expectedComponent: "",
			expectedDetect:    false,
		},
		{
			name: "bare 'Oracle Enterprise Manager' text with no logon redirect or agent XML -> NOT detected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html><head><title>Welcome</title></head><body>Powered by Oracle Enterprise Manager</body></html>`)
			},
			expectedComponent: "",
			expectedDetect:    false,
		},
		{
			// The regression the body clause guards: Go's own http.Redirect writes
			// exactly this shape, so any server redirecting to a logon path echoes
			// that path into its body. Without a corroborating EM product marker
			// that is not a console.
			name: "logon path echoed in body with no EM product marker -> NOT console",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<a href="/em/faces/logon">Found</a>.`)
			},
			expectedComponent: "",
			expectedDetect:    false,
		},
		{
			// Mirror image of the case above: the product marker is necessary but
			// not sufficient either. ("Oracle Enterprise Manager" alone is covered
			// by the bare-marker case above; this pins the other marker.)
			name: "oracle.sysman marker with no logon path -> NOT console",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html><body><script src="/oracle.sysman/js/app.js"></script></body></html>`)
			},
			expectedComponent: "",
			expectedDetect:    false,
		},
		{
			name: "logon path in body corroborated by 'Oracle Enterprise Manager' marker -> console",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html><body>Oracle Enterprise Manager<a href="/em/faces/logon">Sign In</a></body></html>`)
			},
			expectedComponent: "console",
			expectedDetect:    true,
		},
		{
			name: "logon path in body corroborated by 'oracle.sysman' marker -> console",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html><body><script src="/oracle.sysman/js/app.js"></script><a href="/em/faces/logon">Sign In</a></body></html>`)
			},
			expectedComponent: "console",
			expectedDetect:    true,
		},
		{
			// The regression the status gate guards: "Database Express" is matched
			// as a substring, so an error page from middleware fronting EM (WebLogic
			// or OHS) that merely names the product must not be reported as Express.
			name: "Database Express on a 404 error page -> NOT express",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(404)
				fmt.Fprint(w, `<html><head><title>Error 404--Not Found</title></head><body>No context bound to /em/ for Database Express</body></html>`)
			},
			expectedComponent: "",
			expectedDetect:    false,
		},
		{
			// Same gate on the server-error side, and with the marker in the
			// <title> rather than the body, so neither express clause survives a
			// 5xx.
			name: "Database Express title on a 500 error page -> NOT express",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(500)
				fmt.Fprint(w, `<html><head><title>Database Express</title></head><body>Internal Server Error</body></html>`)
			},
			expectedComponent: "",
			expectedDetect:    false,
		},
		{
			// The gate is on the error status, not on 2xx: a redirect carrying the
			// Express title is still Express (pinned by the ordering case below).
			name: "Database Express title on a 200 -> express",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(200)
				fmt.Fprint(w, `<html><head><title>Oracle Database Express Edition</title></head></html>`)
			},
			expectedComponent: "express",
			expectedDetect:    true,
		},
		{
			// A 4xx that IS a genuine console still classifies: the status gate is
			// scoped to the express branch only.
			name: "logon path plus EM marker on a 403 -> still console",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(403)
				fmt.Fprint(w, `<html><body>Oracle Enterprise Manager<a href="/em/faces/logon">Sign In</a></body></html>`)
			},
			expectedComponent: "console",
			expectedDetect:    true,
		},
		{
			// The express branch is evaluated before the console clause, so a
			// Database Express title wins even on a response carrying the otherwise
			// sufficient logon Location path.
			name: "Database Express title wins over a logon redirect",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/em/faces/logon/logon.jspx")
				w.WriteHeader(302)
				fmt.Fprint(w, `<html><head><title>Database Express</title></head></html>`)
			},
			expectedComponent: "express",
			expectedDetect:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			component, detected := detectConsoleOrExpress(noRedirectClient(server), server.URL, "")
			assert.Equal(t, tt.expectedDetect, detected)
			assert.Equal(t, tt.expectedComponent, component)
		})
	}
}

// TestDetectUpload covers the OMS upload receiver probe. Detection requires an
// EM-specific receiver banner in the /empbs/upload body: a bare 200 on that
// path proves nothing, since any server can serve 200 on an arbitrary path.
func TestDetectUpload(t *testing.T) {
	tests := []struct {
		name           string
		handler        http.HandlerFunc
		expectedDetect bool
	}{
		{
			name: "Http Receiver Servlet active banner",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html><body>Http Receiver Servlet active!</body></html>`)
			},
			expectedDetect: true,
		},
		{
			name: "Http XML File receiver banner",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `Oracle Http XML File receiver`)
			},
			expectedDetect: true,
		},
		{
			name: "bare 200 with no receiver banner -> NOT detected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<html><body>OK</body></html>`)
			},
			expectedDetect: false,
		},
		{
			name: "empty 200 body -> NOT detected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			},
			expectedDetect: false,
		},
		{
			name: "404 with no receiver banner -> NOT detected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusNotFound)
			},
			expectedDetect: false,
		},
		{
			// The banner alone is not enough: the real receiver answers 200, so a
			// banner on an error status is more likely an error page echoing the
			// servlet name. This is the contrast to detectAgent, which matches its
			// XML markers at any status and gates only the anonymous flag on 2xx.
			name: "receiver banner on 401 -> NOT detected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(w, `<html><body>Http Receiver Servlet active!</body></html>`)
			},
			expectedDetect: false,
		},
		{
			name: "receiver banner on 500 -> NOT detected",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `Oracle Http XML File receiver`)
			},
			expectedDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(tt.handler)
			defer server.Close()

			assert.Equal(t, tt.expectedDetect, detectUpload(noRedirectClient(server), server.URL, ""))
		})
	}
}

// uploadBannerHandler serves the OMS upload receiver banner on /empbs/upload
// and 404s everything else.
func uploadBannerHandler(order *[]string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if order != nil {
			*order = append(*order, r.URL.Path)
		}
		if r.URL.Path == "/empbs/upload" {
			fmt.Fprint(w, `<html><body>Http Receiver Servlet active!</body></html>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}
}

// TestDetectEM_ProbeOrderByPort pins the probe ordering detectEM derives from
// the target port. The handler matches nothing, so every probe runs and the
// full ordering is observable: the surface most likely to answer on that port
// must be probed first, because all probes share the single injected keep-alive
// connection and a server that closes it after the first probe kills the rest.
func TestDetectEM_ProbeOrderByPort(t *testing.T) {
	tests := []struct {
		name          string
		port          uint16
		expectedOrder []string
	}{
		{
			name:          "agent port probes the agent first",
			port:          portAgent,
			expectedOrder: []string{"/emd/main/", "/em/", "/empbs/upload"},
		},
		{
			name:          "HTTP upload port probes upload first",
			port:          portUploadHTTP,
			expectedOrder: []string{"/empbs/upload", "/emd/main/", "/em/"},
		},
		{
			name:          "HTTPS upload port probes upload first",
			port:          portUploadHTTPS,
			expectedOrder: []string{"/empbs/upload", "/emd/main/", "/em/"},
		},
		{
			name:          "HTTP console port probes console/express first",
			port:          portConsoleHTTP,
			expectedOrder: []string{"/em/", "/emd/main/", "/empbs/upload"},
		},
		{
			name:          "HTTPS console port probes console/express first",
			port:          portConsoleHTTPS,
			expectedOrder: []string{"/em/", "/emd/main/", "/empbs/upload"},
		},
		{
			name:          "express port probes console/express first",
			port:          portExpress,
			expectedOrder: []string{"/em/", "/emd/main/", "/empbs/upload"},
		},
		{
			name:          "unrelated port falls back to console/express first",
			port:          8080,
			expectedOrder: []string{"/em/", "/emd/main/", "/empbs/upload"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var order []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, r.URL.Path)
				w.WriteHeader(http.StatusNotFound)
			}))
			defer server.Close()

			component, version, anonymous, detected := detectEM(noRedirectClient(server), server.URL, "", tt.port)
			assert.False(t, detected)
			assert.Equal(t, "", component)
			assert.Equal(t, "", version)
			assert.False(t, anonymous)
			assert.Equal(t, tt.expectedOrder, order, "probe order must be driven by the target port")
		})
	}
}

// TestDetectEM_FirstMatchingProbeWins proves the port-derived ordering actually
// short-circuits: when the surface expected on that port answers, detectEM
// stops after a single request instead of probing the other surfaces.
func TestDetectEM_FirstMatchingProbeWins(t *testing.T) {
	tests := []struct {
		name              string
		port              uint16
		handler           http.HandlerFunc
		expectedComponent string
		expectedOrder     []string
	}{
		{
			name: "agent answers on the agent port",
			port: portAgent,
			handler: func(w http.ResponseWriter, r *http.Request) {
				fmt.Fprint(w, `<EMResponse agentVersion="13.5.0.0.0"><AgentState>up</AgentState></EMResponse>`)
			},
			expectedComponent: "agent",
			expectedOrder:     []string{"/emd/main/"},
		},
		{
			name:              "upload receiver answers on the HTTP upload port",
			port:              portUploadHTTP,
			handler:           uploadBannerHandler(nil),
			expectedComponent: "oms-upload",
			expectedOrder:     []string{"/empbs/upload"},
		},
		{
			name:              "upload receiver answers on the HTTPS upload port",
			port:              portUploadHTTPS,
			handler:           uploadBannerHandler(nil),
			expectedComponent: "oms-upload",
			expectedOrder:     []string{"/empbs/upload"},
		},
		{
			name: "console answers on the console port",
			port: portConsoleHTTP,
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "/em/faces/logon/logon.jspx")
				w.WriteHeader(http.StatusFound)
			},
			expectedComponent: "console",
			expectedOrder:     []string{"/em/"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var order []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, r.URL.Path)
				tt.handler(w, r)
			}))
			defer server.Close()

			component, _, _, detected := detectEM(noRedirectClient(server), server.URL, "", tt.port)
			require.True(t, detected)
			assert.Equal(t, tt.expectedComponent, component)
			assert.Equal(t, tt.expectedOrder, order, "a matching first probe must short-circuit the remaining probes")
		})
	}
}

// TestDetectEM_FallsThroughToSurfaceOnNonDefaultPort covers the other half of
// the ordering contract: ordering is a preference, not a gate. Every probe
// still runs in sequence, so an EM surface published on another component's
// default port is detected as itself.
func TestDetectEM_FallsThroughToSurfaceOnNonDefaultPort(t *testing.T) {
	tests := []struct {
		name              string
		port              uint16
		handler           http.HandlerFunc
		expectedComponent string
		expectedVersion   string
		expectedAnonymous bool
		expectedOrder     []string
	}{
		{
			name: "agent on the console port is still detected as agent",
			port: portConsoleHTTP,
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/emd/main/" {
					fmt.Fprint(w, `<EMResponse agentVersion="13.5.0.0.0"><AgentState>up</AgentState></EMResponse>`)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			},
			expectedComponent: "agent",
			expectedVersion:   "13.5.0.0.0",
			expectedAnonymous: true,
			expectedOrder:     []string{"/em/", "/emd/main/"},
		},
		{
			name:              "upload receiver on the agent port is still detected as oms-upload",
			port:              portAgent,
			handler:           uploadBannerHandler(nil),
			expectedComponent: "oms-upload",
			expectedOrder:     []string{"/emd/main/", "/em/", "/empbs/upload"},
		},
		{
			name: "console on the upload port is still detected as console",
			port: portUploadHTTP,
			handler: func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/em/" {
					w.Header().Set("Location", "/em/faces/logon/logon.jspx")
					w.WriteHeader(http.StatusFound)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			},
			expectedComponent: "console",
			expectedOrder:     []string{"/empbs/upload", "/emd/main/", "/em/"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var order []string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				order = append(order, r.URL.Path)
				tt.handler(w, r)
			}))
			defer server.Close()

			component, version, anonymous, detected := detectEM(noRedirectClient(server), server.URL, "", tt.port)
			require.True(t, detected, "ordering is a preference, not a gate: all probes must still run")
			assert.Equal(t, tt.expectedComponent, component)
			assert.Equal(t, tt.expectedVersion, version)
			assert.Equal(t, tt.expectedAnonymous, anonymous)
			assert.Equal(t, tt.expectedOrder, order)
		})
	}
}

func TestBuildEMCPE(t *testing.T) {
	assert.Equal(t, []string{"cpe:2.3:a:oracle:enterprise_manager_base_platform:13.5.0.0.0:*:*:*:*:*:*:*"}, buildEMCPE("console", "13.5.0.0.0"))
	assert.Equal(t, []string{"cpe:2.3:a:oracle:enterprise_manager_base_platform:*:*:*:*:*:*:*:*"}, buildEMCPE("console", ""))
	assert.Equal(t, []string{"cpe:2.3:a:oracle:enterprise_manager_base_platform:13.5.0.0.0:*:*:*:*:*:*:*"}, buildEMCPE("agent", "13.5.0.0.0"))
	// oms-upload is part of an Enterprise Manager install, so it maps to the
	// base platform like console/agent, not to the database CPEs.
	assert.Equal(t, []string{"cpe:2.3:a:oracle:enterprise_manager_base_platform:*:*:*:*:*:*:*:*"}, buildEMCPE("oms-upload", ""))
	assert.Equal(t, []string{
		"cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:database:*:*:*:*:*:*:*:*",
	}, buildEMCPE("express", "13.5.0.0.0"))
	assert.Equal(t, []string{
		"cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:database:*:*:*:*:*:*:*:*",
	}, buildEMCPE("express", ""))
}

func TestPlugin_Run_AgentDetection_Misconfigs(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<EMResponse agentVersion="13.5.0.0.0"><AgentState>up</AgentState></EMResponse>`)
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
		assert.Equal(t, "oracle-em-agent-unauthenticated", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityMedium, service.SecurityFindings[0].Severity)

		var payload plugins.ServiceOracleEM
		require.NoError(t, json.Unmarshal(service.Raw, &payload))
		assert.Equal(t, "agent", payload.Component)
		require.Len(t, payload.CPEs, 1)
		assert.Equal(t, "cpe:2.3:a:oracle:enterprise_manager_base_platform:13.5.0.0.0:*:*:*:*:*:*:*", payload.CPEs[0])
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

func TestPlugin_Run_AgentDetection_NonAnonymous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, `<EMResponse><AgentState>error</AgentState></EMResponse>`)
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
}

func TestPlugin_Run_ConsoleDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/em/faces/logon/logon.jspx")
		w.WriteHeader(302)
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

	var payload plugins.ServiceOracleEM
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "console", payload.Component)
}

func TestPlugin_Run_ExpressDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>Database Express</title></head></html>`)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleEM
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "express", payload.Component)
	assert.Equal(t, []string{
		"cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:database:*:*:*:*:*:*:*:*",
	}, payload.CPEs)
}

func TestPlugin_Run_UploadDetection(t *testing.T) {
	server := httptest.NewServer(uploadBannerHandler(nil))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleEM
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "oms-upload", payload.Component)
	assert.Equal(t, []string{"cpe:2.3:a:oracle:enterprise_manager_base_platform:*:*:*:*:*:*:*:*"}, payload.CPEs)
}

// TestPlugin_Run_UploadBare200NotDetected guards the marker requirement end to
// end: /empbs/upload answering 200 without an EM receiver banner is not an
// Enterprise Manager surface.
func TestPlugin_Run_UploadBare200NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/empbs/upload" {
			fmt.Fprint(w, `<html><body>OK</body></html>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

// TestPlugin_Run_UploadBannerNon2xxNotDetected guards the 2xx requirement end to
// end: the EM receiver banner served on an error status is an error page echoing
// the servlet name, not a live receiver, so no service must be reported.
func TestPlugin_Run_UploadBannerNon2xxNotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/empbs/upload" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `<html><body>Http Receiver Servlet active!</body></html>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

// TestPlugin_Run_UploadNoAnonymousAccessUnderMisconfigs is the regression guard
// for anonymous access staying exclusive to the agent status endpoint on a 2xx.
// The OMS upload receiver is an ingest endpoint rather than a data-exposure
// surface, so a 2xx banner there must never set AnonymousAccess nor raise the
// agent finding, even with misconfiguration reporting enabled.
func TestPlugin_Run_UploadNoAnonymousAccessUnderMisconfigs(t *testing.T) {
	server := httptest.NewServer(uploadBannerHandler(nil))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()
	target.Misconfigs = true

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleEM
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	require.Equal(t, "oms-upload", payload.Component)

	assert.False(t, service.AnonymousAccess, "oms-upload is an ingest endpoint, not an anonymous data-exposure surface")
	assert.Empty(t, service.SecurityFindings)
	assert.False(t, hasFindingID(service.SecurityFindings, "oracle-em-agent-unauthenticated"))
}

// TestPlugin_Run_UsesTargetPortForProbeOrder proves runEM wires
// target.Address.Port() into detectEM's ordering, rather than detectEM's port
// argument only being reachable from direct unit calls.
func TestPlugin_Run_UsesTargetPortForProbeOrder(t *testing.T) {
	var order []string
	server := httptest.NewServer(uploadBannerHandler(&order))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()
	// The scanner-reported port, not the ephemeral port httptest listens on.
	target.Address = netip.AddrPortFrom(target.Address.Addr(), portUploadHTTP)

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.Equal(t, []string{"/empbs/upload"}, order, "Run must pass the target port through to the probe ordering")

	var payload plugins.ServiceOracleEM
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "oms-upload", payload.Component)
}

func TestPlugin_Run_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>generic server</body></html>`)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestPlugin_Run_GenericMarkerTextNotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><head><title>Welcome</title></head><body>Powered by Oracle Enterprise Manager</body></html>`)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &Plugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestTLSPlugin_Run_AgentDetection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<EMResponse agentVersion="13.5.0.0.0"><AgentState>up</AgentState></EMResponse>`)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()
	target.Misconfigs = true

	plugin := &TLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.True(t, service.AnonymousAccess)
	require.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "oracle-em-agent-unauthenticated", service.SecurityFindings[0].ID)
}

// TestTLSPlugin_Run_UploadDetection covers the shared runEM path from the TLS
// variant: the oms-upload component must be reported with tcptls transport and
// still leave AnonymousAccess unset under Misconfigs.
func TestTLSPlugin_Run_UploadDetection(t *testing.T) {
	server := httptest.NewServer(uploadBannerHandler(nil))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()
	target.Misconfigs = true

	plugin := &TLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.True(t, service.TLS)
	assert.Equal(t, "tcptls", service.Transport)
	assert.False(t, service.AnonymousAccess)
	assert.Empty(t, service.SecurityFindings)

	var payload plugins.ServiceOracleEM
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "oms-upload", payload.Component)
}

// TestTLSPlugin_Run_RealTLSConnCoexistingFindings drives TLSPlugin.Run over a
// real *tls.Conn so plugins.CheckTLS(conn) actually produces findings instead
// of short-circuiting on its plain-conn type assertion. Under Misconfigs the
// agent anonymous finding runEM appends and the TLS findings TLSPlugin.Run
// appends afterwards must coexist, not overwrite one another.
func TestTLSPlugin_Run_RealTLSConnCoexistingFindings(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/emd/main/" {
			fmt.Fprint(w, `<EMResponse agentVersion="13.5.0.0.0"><AgentState>up</AgentState></EMResponse>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	conn, target := dialTLSTestServer(t, server.URL)
	defer conn.Close()
	target.Misconfigs = true
	target.Address = netip.AddrPortFrom(target.Address.Addr(), portAgent)

	plugin := &TLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service, "detection must succeed over a real *tls.Conn")

	assert.True(t, service.TLS)
	assert.Equal(t, "tcptls", service.Transport)
	assert.Equal(t, "13.5.0.0.0", service.Version)
	assert.True(t, service.AnonymousAccess)

	assert.True(t, hasFindingID(service.SecurityFindings, "oracle-em-agent-unauthenticated"),
		"the agent anonymous finding must survive the CheckTLS append")
	assert.True(t, hasFindingID(service.SecurityFindings, "tls-self-signed"),
		"httptest's self-signed certificate must yield a CheckTLS finding alongside it")
	assert.Greater(t, len(service.SecurityFindings), 1)
}

func TestTLSPlugin_Run_NotDetected(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `<html><body>generic server</body></html>`)
	}))
	defer server.Close()

	conn, target := dialTestServer(t, server.URL)
	defer conn.Close()

	plugin := &TLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestPlugin_PortPriority(t *testing.T) {
	plugin := &Plugin{}
	tests := []struct {
		port     uint16
		expected bool
	}{
		// Cleartext EM surfaces: Management Agent, HTTP Cloud Control console
		// and the HTTP OMS upload receiver.
		{3872, true},
		{7802, true},
		{4889, true},
		// 7803 (Cloud Control console), 5500 (EM Express) and 4903 (OMS upload
		// receiver) are HTTPS and belong exclusively to the TLS variant.
		{7803, false},
		{5500, false},
		{4903, false},
		{443, false},
		{80, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, plugin.PortPriority(tt.port), "port %d", tt.port)
	}
}

func TestTLSPlugin_PortPriority(t *testing.T) {
	plugin := &TLSPlugin{}
	tests := []struct {
		port     uint16
		expected bool
	}{
		{7803, true},
		{5500, true},
		{3872, true},
		{4903, true},
		{443, true},
		// The cleartext console (7802) and upload receiver (4889) belong
		// exclusively to the TCP variant.
		{7802, false},
		{4889, false},
		{80, false},
		{8080, false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.expected, plugin.PortPriority(tt.port), "port %d", tt.port)
	}
}

func TestPlugin_Metadata(t *testing.T) {
	plugin := &Plugin{}
	assert.Equal(t, EM, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
}

func TestTLSPlugin_Metadata(t *testing.T) {
	plugin := &TLSPlugin{}
	assert.Equal(t, EM, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
}
