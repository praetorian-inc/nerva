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

package oraclesbc

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
// httptest servers listen on 127.0.0.1, so net.SplitHostPort gives "127.0.0.1".
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
// Unit tests — hasSBCCookie
// ---------------------------------------------------------------------------

func TestHasSBCCookie(t *testing.T) {
	tests := []struct {
		name      string
		setCookie string
		expected  bool
	}{
		{
			name:      "usersessionid cookie present",
			setCookie: "usersessionid=abc123; Path=/",
			expected:  true,
		},
		{
			name:      "activeTabs cookie present",
			setCookie: "activeTabs=1; Path=/",
			expected:  true,
		},
		{
			name:      "both cookies present",
			setCookie: "usersessionid=xyz; activeTabs=1; Path=/",
			expected:  true,
		},
		{
			name:      "unrelated cookie does not match",
			setCookie: "JSESSIONID=abc123; Path=/",
			expected:  false,
		},
		{
			name:      "empty Set-Cookie header",
			setCookie: "",
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasSBCCookie(tt.setCookie)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests — hasAcmeWebReqMarker
// ---------------------------------------------------------------------------

func TestHasAcmeWebReqMarker(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "acmeWebReq tag present",
			body:     `<?xml version="1.0"?><acmeWebReq version="1"><status>OK</status></acmeWebReq>`,
			expected: true,
		},
		{
			name:     "acmeWebReq tag absent",
			body:     `<html><body><p>Login</p></body></html>`,
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
			result := hasAcmeWebReqMarker(tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests — hasAcmePacketMarker
// ---------------------------------------------------------------------------

func TestHasAcmePacketMarker(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		expected bool
	}{
		{
			name:     "lowercase acme packet",
			s:        "welcome to the acme packet management console",
			expected: true,
		},
		{
			name:     "uppercase ACME PACKET",
			s:        "ACME PACKET Session Border Controller",
			expected: true,
		},
		{
			name:     "mixed-case Session Border Controller",
			s:        "Session Border Controller login",
			expected: true,
		},
		{
			name:     "uppercase SESSION BORDER CONTROLLER",
			s:        "SESSION BORDER CONTROLLER",
			expected: true,
		},
		{
			name:     "enterprise communications broker",
			s:        "Enterprise Communications Broker",
			expected: true,
		},
		{
			name:     "lowercase enterprise communications broker",
			s:        "enterprise communications broker version 9",
			expected: true,
		},
		{
			name:     "oracle communications",
			s:        "Oracle Communications SBC",
			expected: true,
		},
		{
			name:     "lowercase oracle communications",
			s:        "oracle communications session border",
			expected: true,
		},
		{
			name:     "unrelated generic string",
			s:        "Welcome to the corporate login portal",
			expected: false,
		},
		{
			name:     "empty string",
			s:        "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasAcmePacketMarker(tt.s)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests — extractSBCVersion
// ---------------------------------------------------------------------------

func TestExtractSBCVersion(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "Acme token SCZ8.4.0",
			body:     `<html><body>Version SCZ8.4.0 build 42</body></html>`,
			expected: "SCZ8.4.0",
		},
		{
			name:     "Acme token ECZ9.1.0",
			body:     `<title>Acme Packet ECZ9.1.0</title>`,
			expected: "ECZ9.1.0",
		},
		{
			name:     "nnSCZ740-style title version",
			body:     `<title>nnSCZ7.4.0 Oracle Communications</title>`,
			expected: "SCZ7.4.0",
		},
		{
			name:     "generic dotted version no longer matched",
			body:     `<p>Firmware 9.0.0 release</p>`,
			expected: "",
		},
		{
			name:     "no version present returns empty string",
			body:     `<html><body>No version info here</body></html>`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractSBCVersion(tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests — buildSBCCPEs
// ---------------------------------------------------------------------------

func TestBuildSBCCPEs(t *testing.T) {
	t.Run("with version string returns three versioned CPEs", func(t *testing.T) {
		cpes := buildSBCCPEs("8.4.0")
		require.Len(t, cpes, 3)
		assert.Contains(t, cpes[0], "communications_session_border_controller:8.4.0")
		assert.Contains(t, cpes[1], "enterprise_session_border_controller:8.4.0")
		assert.Contains(t, cpes[2], "enterprise_communications_broker:8.4.0")
	})

	t.Run("empty version uses wildcard asterisk for all three CPEs", func(t *testing.T) {
		cpes := buildSBCCPEs("")
		require.Len(t, cpes, 3)
		assert.Contains(t, cpes[0], "communications_session_border_controller:*")
		assert.Contains(t, cpes[1], "enterprise_session_border_controller:*")
		assert.Contains(t, cpes[2], "enterprise_communications_broker:*")
	})

	t.Run("with Acme-prefixed version normalizes for CPE", func(t *testing.T) {
		cpes := buildSBCCPEs("SCZ8.4.0")
		require.Len(t, cpes, 3)
		assert.Contains(t, cpes[0], "communications_session_border_controller:8.4.0")
		assert.Contains(t, cpes[1], "enterprise_session_border_controller:8.4.0")
		assert.Contains(t, cpes[2], "enterprise_communications_broker:8.4.0")
	})
}

// ---------------------------------------------------------------------------
// Unit tests — normalizeSBCVersion
// ---------------------------------------------------------------------------

func TestNormalizeSBCVersion(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{name: "SCZ prefix removed", version: "SCZ8.4.0", expected: "8.4.0"},
		{name: "ECZ prefix removed", version: "ECZ9.1.0", expected: "9.1.0"},
		{name: "already normalized", version: "8.4.0", expected: "8.4.0"},
		{name: "empty string", version: "", expected: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, normalizeSBCVersion(tt.version))
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests — hasAcmeGuiParams
// ---------------------------------------------------------------------------

func TestHasAcmeGuiParams(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name: "all five params present returns true",
			body: `<form>
<input type="hidden" name="parentKey" value="" />
<input type="hidden" name="clientfilename" value="login.jsf" />
<input type="hidden" name="category" value="security" />
<input type="hidden" name="object" value="session" />
<input type="hidden" name="type" value="text/xml" />
</form>`,
			expected: true,
		},
		{
			name: "exactly three params present returns true",
			body: `<form>
<input type="hidden" name="parentKey" value="" />
<input type="hidden" name="category" value="security" />
<input type="hidden" name="object" value="session" />
</form>`,
			expected: true,
		},
		{
			name: "exactly two params present returns false",
			// parentKey and object only (2/5); no type, category, or clientfilename
			body: `<form>
<input name="parentKey" value="" />
<input name="object" value="session" />
</form>`,
			expected: false,
		},
		{
			name:     "zero params present returns false",
			body:     `<html><body><p>Login to corporate portal</p></body></html>`,
			expected: false,
		},
		{
			name:     "empty body returns false",
			body:     "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := hasAcmeGuiParams(tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Unit tests — evaluateSBC (all branches)
// ---------------------------------------------------------------------------

func TestEvaluateSBC(t *testing.T) {
	tests := []struct {
		name            string
		rest            sbcEvidence
		root            sbcEvidence
		expectedVersion string
		expectedRestAPI bool
		expectedDetect  bool
	}{
		// ---- POSITIVE: restChallenge + branding ----
		{
			name: "restChallenge 401 + branding in root body triggers detection",
			rest: sbcEvidence{
				path:       "/rest/v1.1/auth/token",
				statusCode: http.StatusUnauthorized,
			},
			root: sbcEvidence{
				body: `<html><body>Acme Packet SBC Login</body></html>`,
			},
			expectedRestAPI: true,
			expectedDetect:  true,
		},
		// ---- POSITIVE: restChallenge + cookie ----
		{
			name: "restChallenge 401 + SBC cookie triggers detection",
			rest: sbcEvidence{
				path:       "/rest/v1.1/auth/token",
				statusCode: http.StatusUnauthorized,
				setCookie:  "usersessionid=abc; Path=/",
			},
			expectedRestAPI: true,
			expectedDetect:  true,
		},
		// ---- POSITIVE: restChallenge + xml ----
		{
			name: "restChallenge 401 + acmeWebReq XML in root body triggers detection",
			rest: sbcEvidence{
				path:       "/rest/v1.1/auth/token",
				statusCode: http.StatusUnauthorized,
			},
			root: sbcEvidence{
				body: `<acmeWebReq version="1"><status>OK</status></acmeWebReq>`,
			},
			expectedRestAPI: true,
			expectedDetect:  true,
		},
		// ---- POSITIVE: cookie + xml (no restChallenge) ----
		{
			name: "cookie + acmeWebReq XML without restChallenge triggers detection",
			rest: sbcEvidence{
				path:       "/rest/v1.1/auth/token",
				statusCode: http.StatusOK, // NOT 401
			},
			root: sbcEvidence{
				body:      `<acmeWebReq version="1"/>`,
				setCookie: "usersessionid=xyz; Path=/",
			},
			expectedRestAPI: false,
			expectedDetect:  true,
		},
		// ---- POSITIVE: cookie + branding (no restChallenge) ----
		{
			name: "cookie + branding without restChallenge triggers detection",
			rest: sbcEvidence{
				path:       "/rest/v1.1/auth/token",
				statusCode: http.StatusOK,
			},
			root: sbcEvidence{
				body:      "Oracle Communications Session Border Controller",
				setCookie: "activeTabs=1; Path=/",
			},
			expectedRestAPI: false,
			expectedDetect:  true,
		},
		// ---- POSITIVE: xml + branding (no cookie, no restChallenge) ----
		{
			name: "xml + branding without cookie or restChallenge triggers detection",
			rest: sbcEvidence{
				path:       "/rest/v1.1/auth/token",
				statusCode: http.StatusOK,
				body:       `<acmeWebReq version="1"/>`,
			},
			root: sbcEvidence{
				body: "acme packet management gui",
			},
			expectedRestAPI: false,
			expectedDetect:  true,
		},
		// ---- POSITIVE: version extracted from root body ----
		{
			name: "version extracted from root body when detected",
			rest: sbcEvidence{
				path:       "/rest/v1.1/auth/token",
				statusCode: http.StatusUnauthorized,
			},
			root: sbcEvidence{
				body: `<html><title>SCZ8.4.0 Acme Packet</title><body>Oracle Communications</body></html>`,
			},
			expectedVersion: "SCZ8.4.0",
			expectedRestAPI: true,
			expectedDetect:  true,
		},
		// ---- NEGATIVE: bare 401 on auth/token with no markers ----
		{
			name: "bare 401 on auth/token with no markers must NOT trigger",
			rest: sbcEvidence{
				path:       "/rest/v1.1/auth/token",
				statusCode: http.StatusUnauthorized,
				body:       "Unauthorized",
			},
			root: sbcEvidence{
				body: "generic login page",
			},
			expectedRestAPI: true,
			expectedDetect:  false,
		},
		// ---- NEGATIVE: branding-only (no cookie, no xml, no restChallenge) ----
		{
			name: "branding-only without corroboration must NOT trigger",
			rest: sbcEvidence{
				path:       "/rest/v1.1/auth/token",
				statusCode: http.StatusOK,
			},
			root: sbcEvidence{
				body: "Acme Packet Enterprise Communications Broker",
			},
			expectedRestAPI: false,
			expectedDetect:  false,
		},
		// ---- NEGATIVE: cookie-only (no xml, no branding, no restChallenge) ----
		{
			name: "cookie-only without corroboration must NOT trigger",
			rest: sbcEvidence{
				path:       "/rest/v1.1/auth/token",
				statusCode: http.StatusOK,
				setCookie:  "usersessionid=abc; Path=/",
			},
			root: sbcEvidence{
				body: "generic login portal",
			},
			expectedRestAPI: false,
			expectedDetect:  false,
		},
		// ---- NEGATIVE: empty evidence ----
		{
			name:            "empty evidence must NOT trigger",
			rest:            sbcEvidence{},
			root:            sbcEvidence{},
			expectedRestAPI: false,
			expectedDetect:  false,
		},
		// ---- NEGATIVE: 200 on auth/token path with no markers ----
		{
			name: "200 on auth/token path with no other markers must NOT trigger",
			rest: sbcEvidence{
				path:       "/rest/v1.1/auth/token",
				statusCode: http.StatusOK,
				body:       "token issued",
			},
			root: sbcEvidence{
				body: "welcome",
			},
			expectedRestAPI: false,
			expectedDetect:  false,
		},
		// ---- POSITIVE: restChallenge 401 + guiParams (no branding, no cookie, no xml) ----
		{
			name: "restChallenge 401 + guiParams (>=3 params, no branding/cookie/xml) triggers detection",
			rest: sbcEvidence{
				path:       "/rest/v1.0/auth/token",
				statusCode: http.StatusUnauthorized,
			},
			root: sbcEvidence{
				body: `<form>
<input type="hidden" name="parentKey" value="" />
<input type="hidden" name="clientfilename" value="login.jsf" />
<input type="hidden" name="category" value="security" />
</form>`,
			},
			expectedRestAPI: true,
			expectedDetect:  true,
		},
		// ---- POSITIVE: guiParams (>=3) + branding, no rest challenge ----
		{
			name: "guiParams (>=3) + branding without restChallenge triggers detection",
			rest: sbcEvidence{
				path:       "/rest/v1.0/auth/token",
				statusCode: http.StatusOK,
			},
			root: sbcEvidence{
				body: `<html><body>
<p>Oracle Communications Session Border Controller</p>
<form>
<input type="hidden" name="parentKey" value="" />
<input type="hidden" name="clientfilename" value="login.jsf" />
<input type="hidden" name="category" value="security" />
</form>
</body></html>`,
			},
			expectedRestAPI: false,
			expectedDetect:  true,
		},
		// ---- NEGATIVE: guiParams alone (no branding, no cookie, no restChallenge) ----
		{
			name: "guiParams alone without branding/cookie/restChallenge must NOT trigger",
			rest: sbcEvidence{
				path:       "/rest/v1.0/auth/token",
				statusCode: http.StatusOK,
			},
			root: sbcEvidence{
				body: `<form>
<input type="hidden" name="parentKey" value="" />
<input type="hidden" name="clientfilename" value="login.jsf" />
<input type="hidden" name="category" value="security" />
<input type="hidden" name="object" value="session" />
<input type="hidden" name="type" value="text/xml" />
</form>`,
			},
			expectedRestAPI: false,
			expectedDetect:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, restAPI, detected := evaluateSBC(tt.rest, tt.root)
			assert.Equal(t, tt.expectedDetect, detected, "detected mismatch")
			assert.Equal(t, tt.expectedRestAPI, restAPI, "restAPI mismatch")
			if tt.expectedVersion != "" {
				assert.Equal(t, tt.expectedVersion, version, "version mismatch")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Integration tests — SBCPlugin.Run (TCP)
// ---------------------------------------------------------------------------

func TestSBCPlugin_Run(t *testing.T) {
	t.Run("PositiveRestChallengePlusBranding", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/rest/v1.1/auth/token":
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, `{"error":"Unauthorized"}`)
			case "/":
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<html><head><title>SCZ8.4.0 Acme Packet</title></head>`+
					`<body>Oracle Communications Session Border Controller login</body></html>`)
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

		plugin := &SBCPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		var sbcService plugins.ServiceOracleSBC
		err = json.Unmarshal(service.Raw, &sbcService)
		require.NoError(t, err, "failed to unmarshal service payload")

		assert.True(t, sbcService.RestAPI, "RestAPI should be true when 401 challenge present")
		require.Len(t, sbcService.CPEs, 3)
		assert.Contains(t, sbcService.CPEs[0], "communications_session_border_controller")
		assert.Contains(t, sbcService.CPEs[0], "8.4.0")
		assert.Contains(t, sbcService.CPEs[1], "enterprise_session_border_controller")
		assert.Contains(t, sbcService.CPEs[1], "8.4.0")
		assert.Contains(t, sbcService.CPEs[2], "enterprise_communications_broker")
		assert.Contains(t, sbcService.CPEs[2], "8.4.0")
		assert.Equal(t, "oracle_sbc", service.Protocol)
	})

	t.Run("PositiveWebGuiCookiesPlusXml", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/rest/v1.1/auth/token":
				// Returns 200, no 401 challenge, no branding
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, `{"token":"ok"}`)
			case "/":
				// Sets SBC cookie + acmeWebReq XML + branding
				w.Header().Set("Set-Cookie", "usersessionid=sessionabc; Path=/")
				w.Header().Set("Content-Type", "text/html")
				fmt.Fprintf(w, `<html><body><acmeWebReq version="1"/>Oracle Communications</body></html>`)
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

		plugin := &SBCPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		var sbcService plugins.ServiceOracleSBC
		err = json.Unmarshal(service.Raw, &sbcService)
		require.NoError(t, err)

		assert.False(t, sbcService.RestAPI, "RestAPI should be false when no 401 challenge")
		require.Len(t, sbcService.CPEs, 3)
	})

	t.Run("Negative_bare401", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/rest/v1.1/auth/token":
				w.WriteHeader(http.StatusUnauthorized)
				fmt.Fprintf(w, "Unauthorized")
			case "/":
				w.WriteHeader(http.StatusOK)
				fmt.Fprintf(w, "<html><body>Corporate Login Portal</body></html>")
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

		plugin := &SBCPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		assert.Nil(t, service, "bare 401 with no markers must not be detected")
	})

	t.Run("Negative_unrelatedService", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "hello")
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

		plugin := &SBCPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		assert.Nil(t, service, "generic 200 with hello must not be detected")
	})
}

// ---------------------------------------------------------------------------
// Plugin metadata tests
// ---------------------------------------------------------------------------

func TestSBCMetadata(t *testing.T) {
	t.Run("SBCPlugin TCP metadata", func(t *testing.T) {
		plugin := &SBCPlugin{}
		assert.Equal(t, OracleSBC, plugin.Name())
		assert.Equal(t, plugins.TCP, plugin.Type())
		assert.Equal(t, -1, plugin.Priority())
		// TCP PortPriority always false
		assert.False(t, plugin.PortPriority(443))
		assert.False(t, plugin.PortPriority(8443))
		assert.False(t, plugin.PortPriority(80))
	})

	t.Run("SBCTLSPlugin TCPTLS metadata", func(t *testing.T) {
		plugin := &SBCTLSPlugin{}
		assert.Equal(t, OracleSBC, plugin.Name())
		assert.Equal(t, plugins.TCPTLS, plugin.Type())
		assert.Equal(t, -1, plugin.Priority())
		// TLS PortPriority true for 443 and 8443, false for others
		assert.True(t, plugin.PortPriority(443))
		assert.True(t, plugin.PortPriority(8443))
		assert.False(t, plugin.PortPriority(80))
	})
}

// ---------------------------------------------------------------------------
// Security findings tests
// ---------------------------------------------------------------------------

func TestSBCSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/rest/v1.1/auth/token":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprintf(w, `{"error":"Unauthorized"}`)
		case "/":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><body>Acme Packet Session Border Controller</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	t.Run("with Misconfigs=true yields AnonymousAccess and oracle-sbc-exposed finding", func(t *testing.T) {
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

		plugin := &SBCPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-sbc-exposed", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityLow, service.SecurityFindings[0].Severity)
	})

	t.Run("with Misconfigs=false yields no SecurityFindings and AnonymousAccess false", func(t *testing.T) {
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

		plugin := &SBCPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

// ---------------------------------------------------------------------------
// ServiceOracleSBC.Type() tests
// ---------------------------------------------------------------------------

func TestServiceOracleSBCType(t *testing.T) {
	t.Run("Product sbc returns oracle_sbc", func(t *testing.T) {
		s := plugins.ServiceOracleSBC{Product: "sbc"}
		assert.Equal(t, "oracle_sbc", s.Type())
	})

	t.Run("Product ecb returns oracle_ecb", func(t *testing.T) {
		s := plugins.ServiceOracleSBC{Product: "ecb"}
		assert.Equal(t, "oracle_ecb", s.Type())
	})
}
