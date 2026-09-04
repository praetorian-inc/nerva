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

// ordsLandingAPEXCard is the APEX launcher card from the landing page of a live
// ORDS 26.2.3 instance with APEX NOT installed (note card--disabled). It is the
// reason the APEX product gate must be an allowlist: this markup alone accounts
// for most of the fifteen "apex" occurrences on an APEX-free instance.
const ordsLandingAPEXCard = `<li id="cards__apex_card" class="card card--disabled" role="region" ` +
	`data-i18n data-i18n.aria-labelledby="card_title_apex"> ` +
	`<div class="card-image card-image--apex"> ` +
	`<h2 class="card__title" data-i18n data-i18n.inner-text="card_title_apex"></h2> ` +
	`<p class="card__description" data-i18n data-i18n.inner-text="card_description_apex"></p> ` +
	`</div> <form id="apex-submit-form" class="card-actions" data-feature="apex"> ` +
	`<label for="apex-card-actions__input-text"></label> ` +
	`<input id="apex-card-actions__input-text" name="apex-input"> ` +
	`<button id="apex-cdb-button" disabled></button> ` +
	`<a role="button" id="apexhelpbutton" aria-controls="cards__apex_card"></a> ` +
	`</form> </li> ` +
	`<link rel="stylesheet" href="lib/css/font-apex/css/font-apex.min.css">`

func TestBodyHasAPEXProduct(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "APEX application URL",
			body:     `<a href="f?p=4550:1:0::NO">Sign In</a>`,
			expected: true,
		},
		{
			name:     "APEX PL/SQL gateway procedure",
			body:     `<form action="wwv_flow.accept" method="post">`,
			expected: true,
		},
		{
			name:     "APEX library asset",
			body:     `<script src="/i/libraries/apex/minified/desktop.min.js?v=24.1.5"></script>`,
			expected: true,
		},
		{
			name:     "APEX UI asset",
			body:     `<img src="/i/apex_ui/img/favicons/app-icon.png">`,
			expected: true,
		},
		{
			name:     "APEX images on the Oracle CDN",
			body:     `<script src="https://static.oracle.com/cdn/apex/23.2.0/libraries/apex/minified/core.min.js"></script>`,
			expected: true,
		},
		{
			name:     "uppercase markers still match",
			body:     `<FORM ACTION="WWV_FLOW.ACCEPT">`,
			expected: true,
		},
		{
			name:     "ORDS landing page APEX launcher card is not APEX",
			body:     ordsLandingAPEXCard,
			expected: false,
		},
		{
			name:     "font-apex icon stylesheet alone is not APEX",
			body:     `<link rel="stylesheet" href="lib/css/font-apex/css/font-apex.min.css">`,
			expected: false,
		},
		{
			name:     "bare /i/ path alone is not APEX",
			body:     `<script src="/i/2.0/app.js"></script>`,
			expected: false,
		},
		{
			name:     "the word apex alone is not APEX",
			body:     "apex resources at /i/",
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
			result := bodyHasAPEXProduct(tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildORDSCPEs(t *testing.T) {
	tests := []struct {
		name     string
		res      ordsResult
		expected []string
	}{
		{
			name:     "with version, no APEX",
			res:      ordsResult{version: "24.1.0"},
			expected: []string{"cpe:2.3:a:oracle:rest_data_services:24.1.0:*:*:*:*:*:*:*"},
		},
		{
			name: "empty version, with APEX of unknown version",
			res:  ordsResult{apex: true},
			expected: []string{
				"cpe:2.3:a:oracle:rest_data_services:*:*:*:*:*:*:*:*",
				"cpe:2.3:a:oracle:application_express:*:*:*:*:*:*:*:*",
			},
		},
		{
			name:     "empty version, no APEX",
			res:      ordsResult{},
			expected: []string{"cpe:2.3:a:oracle:rest_data_services:*:*:*:*:*:*:*:*"},
		},
		{
			name: "APEX version lands in the application_express CPE",
			res:  ordsResult{version: "26.2", apex: true, apexVersion: "24.1.5"},
			expected: []string{
				"cpe:2.3:a:oracle:rest_data_services:26.2:*:*:*:*:*:*:*",
				"cpe:2.3:a:oracle:application_express:24.1.5:*:*:*:*:*:*:*",
			},
		},
		{
			name:     "APEX version is dropped when APEX itself was not detected",
			res:      ordsResult{version: "26.2", apexVersion: "24.1.5"},
			expected: []string{"cpe:2.3:a:oracle:rest_data_services:26.2:*:*:*:*:*:*:*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildORDSCPEs(tt.res)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestEvaluateORDS(t *testing.T) {
	tests := []struct {
		name                string
		evidence            []ordsEvidence
		expectedVersion     string
		expectedAPEX        bool
		expectedDetect      bool
		expectedAnonymous   bool
		expectedAPEXVersion string
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
				{path: "/ords/", statusCode: http.StatusOK, server: "Oracle-REST-Data-Services/24.1.0", body: `<a href="f?p=4550:1">Sign In</a>`},
			},
			expectedVersion:   "24.1.0",
			expectedAPEX:      true,
			expectedDetect:    true,
			expectedAnonymous: true,
		},
		{
			name: "weak /i/ body marker no longer flags APEX",
			evidence: []ordsEvidence{
				{path: "/ords/", statusCode: http.StatusOK, server: "Oracle-REST-Data-Services/24.1.0", body: "apex resources at /i/"},
			},
			expectedVersion:   "24.1.0",
			expectedAPEX:      false,
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
			res := evaluateORDS(tt.evidence)
			assert.Equal(t, tt.expectedVersion, res.version)
			assert.Equal(t, tt.expectedAPEX, res.apex)
			assert.Equal(t, tt.expectedDetect, res.detected)
			assert.Equal(t, tt.expectedAnonymous, res.anonymous)
			assert.Equal(t, tt.expectedAPEXVersion, res.apexVersion)
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

// realSDWConfigJS is the opening of the Database Actions / SQL Developer Web
// client config as shipped in ORDS 26.2.3 (WEB-INF/lib/ords-sdw-client-*.jar,
// sdw-content/en/js/config.js), served at /ords/_sdw/js/config.js.
const realSDWConfigJS = `define({"meta":{"productName":"SQL Developer","companyName":"Oracle",` +
	`"productVersion":"26.2.0","productPath":"_sdw/","signInPath":"sign-in/",` +
	`"signOutPath":"sign-out/","landingPath":"/sql-developer"},` +
	`"service":{"name":"Database Actions","version":""}})`

func TestParseSDWProductVersion(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "ORDS 26.2.3 config reports the 26.2 train",
			body:     realSDWConfigJS,
			expected: "26.2",
		},
		{
			name:     "two-component version",
			body:     `define({"meta":{"productName":"SQL Developer","productVersion":"23.4"}})`,
			expected: "23.4",
		},
		{
			name:     "whitespace around JSON separators",
			body:     `{ "productName" : "SQL Developer" , "productVersion" : "24.1.0" }`,
			expected: "24.1",
		},
		{
			name:     "OAuth admin console config is not a version source",
			body:     `define({meta:{productName:'ORDS OAuth Administration',productVersion:'1.0.0'}});`,
			expected: "",
		},
		{
			name:     "SQL Developer config without a version",
			body:     `define({"meta":{"productName":"SQL Developer","productPath":"_sdw/"}})`,
			expected: "",
		},
		{
			name:     "non-numeric version",
			body:     `{"productName":"SQL Developer","productVersion":"latest"}`,
			expected: "",
		},
		{
			name:     "unrelated body",
			body:     "<html><body>not ORDS</body></html>",
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
			assert.Equal(t, tt.expected, parseSDWProductVersion(tt.body))
		})
	}
}

func TestParseAPEXVersion(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "cache-busting parameter on an APEX asset",
			body:     `<script src="/i/libraries/apex/minified/desktop.min.js?v=24.1.5"></script>`,
			expected: "24.1.5",
		},
		{
			name:     "five-component cache-busting version",
			body:     `<script src="/i/libraries/apex/minified/desktop_all.min.js?v=18.1.0.00.45"></script>`,
			expected: "18.1.0.00.45",
		},
		{
			name:     "versioned images directory",
			body:     `<link rel="stylesheet" href="/i/24.1.5/app_ui/css/Core.min.css">`,
			expected: "24.1.5",
		},
		{
			name:     "Oracle CDN images directory",
			body:     `<script src="https://static.oracle.com/cdn/apex/23.2.0/libraries/apex/minified/core.min.js"></script>`,
			expected: "23.2.0",
		},
		{
			name:     "cache-busting parameter wins over the images directory",
			body:     `<link href="/i/24.1.5/app_ui/css/Core.min.css?v=24.1.5"><script src="/i/2.0/x.js"></script>`,
			expected: "24.1.5",
		},
		{
			name:     "unversioned APEX markup",
			body:     `<a href="f?p=4550:1"><img src="/i/apex_ui/img/favicons/app-icon.png"></a>`,
			expected: "",
		},
		{
			name:     "a ?v= outside an /i/ reference is not an APEX version",
			body:     `<script src="/static/js/app.js?v=1.2.3"></script>`,
			expected: "",
		},
		{
			name:     "empty body",
			body:     "",
			expected: "",
		},
		{
			name:     "unrelated versioned asset under /i/ is not an APEX version",
			body:     `<a href="f?p=4550:1">Sign In</a><script src="/i/2.0/app.js"></script>`,
			expected: "",
		},
		{
			name:     "unrelated cache-busted asset under /i/ is not an APEX version",
			body:     `<script src="/i/vendor/analytics.js?v=3.4.5"></script>`,
			expected: "",
		},
		{
			name: "APEX asset wins over an unrelated versioned asset on the same page",
			body: `<a href="f?p=4550:1">Sign In</a>` +
				`<script src="/i/2.0/app.js"></script>` +
				`<link rel="stylesheet" href="/i/24.1.5/app_ui/css/Core.min.css">`,
			expected: "24.1.5",
		},
		{
			name:     "versioned themes subtree",
			body:     `<link rel="stylesheet" href="/i/23.2.0/themes/theme_42/23.2/css/Core.min.css">`,
			expected: "23.2.0",
		},
		{
			name:     "unversioned images directory with cache-busting parameter",
			body:     `<link href="/i/themes/theme_42/1.4/css/Core.min.css?v=18.1.0.00.45">`,
			expected: "18.1.0.00.45",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseAPEXVersion(tt.body))
		})
	}
}

// TestDetectORDS_SDWConfigProbeGating covers when the Database Actions config
// probe is issued: only once ORDS is detected and no Server-header version was
// found.
func TestDetectORDS_SDWConfigProbeGating(t *testing.T) {
	tests := []struct {
		name            string
		handler         http.HandlerFunc
		expectedVersion string
		expectedDetect  bool
		expectSDWProbe  bool
	}{
		{
			name: "modern ORDS with no Server header takes the version from the SDW config",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/ords/":
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `<html><body><a href="f?p=4550:1">Sign in</a></body></html>`)
				case sdwConfigPath:
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, realSDWConfigJS)
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			},
			expectedVersion: "26.2",
			expectedDetect:  true,
			expectSDWProbe:  true,
		},
		{
			name: "an authenticated SDW config leaves the version empty and keeps detection",
			handler: func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/ords/":
					w.WriteHeader(http.StatusOK)
					fmt.Fprint(w, `<html><body><a href="f?p=4550:1">Sign in</a></body></html>`)
				default:
					w.WriteHeader(http.StatusUnauthorized)
				}
			},
			expectedVersion: "",
			expectedDetect:  true,
			expectSDWProbe:  true,
		},
		{
			name: "a Server-header version suppresses the SDW config probe",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "Oracle-REST-Data-Services/24.1.0")
				if r.URL.Path == "/ords/" {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.WriteHeader(http.StatusNotFound)
			},
			expectedVersion: "24.1.0",
			expectedDetect:  true,
			expectSDWProbe:  false,
		},
		{
			name: "a non-ORDS host is never probed for the SDW config",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Server", "nginx")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "<html><body>hello world</body></html>")
			},
			expectedVersion: "",
			expectedDetect:  false,
			expectSDWProbe:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var sdwProbed bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == sdwConfigPath {
					sdwProbed = true
				}
				tt.handler(w, r)
			}))
			defer server.Close()

			conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
			require.NoError(t, err)
			defer conn.Close()

			res := detectORDS(createHTTPClient(conn, 5*time.Second), server.URL, "")
			assert.Equal(t, tt.expectedDetect, res.detected)
			assert.Equal(t, tt.expectedVersion, res.version)
			assert.Equal(t, tt.expectSDWProbe, sdwProbed)
		})
	}
}

// TestORDSPlugin_Run_ModernORDSVersionsInCPEs is the end-to-end shape of the
// LAB-5060 gap: an ORDS instance that emits no Server, X-ORDS-* or X-Powered-By
// header still yields both an ORDS and an APEX version.
func TestORDSPlugin_Run_ModernORDSVersionsInCPEs(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ords/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><head>`+
				`<script src="/i/libraries/apex/minified/desktop.min.js?v=24.1.5"></script>`+
				`</head><body><a href="f?p=4550:1">Sign in</a></body></html>`)
		case sdwConfigPath:
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, realSDWConfigJS)
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

	service, err := (&ORDSPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Equal(t, "26.2", service.Version)

	var ordsService plugins.ServiceOracleORDS
	require.NoError(t, json.Unmarshal(service.Raw, &ordsService))
	assert.True(t, ordsService.APEX)
	assert.Equal(t, "24.1.5", ordsService.APEXVersion)
	assert.Equal(t, []string{
		"cpe:2.3:a:oracle:rest_data_services:26.2:*:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:application_express:24.1.5:*:*:*:*:*:*:*",
	}, ordsService.CPEs)
}

func TestORDSPlugin_Run_APEXFreeORDSEmitsNoAPEXCPE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ords/_/landing":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><ul>`+ordsLandingAPEXCard+`</ul></body></html>`)
		case sdwConfigPath:
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, realSDWConfigJS)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{Host: addr.Addr().String(), Address: addr}

	service, err := (&ORDSPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service, "ORDS must still be detected from the landing page alone")
	assert.Equal(t, "26.2", service.Version)

	var ordsService plugins.ServiceOracleORDS
	require.NoError(t, json.Unmarshal(service.Raw, &ordsService))
	assert.False(t, ordsService.APEX, "APEX is not installed; the launcher card must not flag it")
	assert.Empty(t, ordsService.APEXVersion)
	assert.Equal(t, []string{"cpe:2.3:a:oracle:rest_data_services:26.2:*:*:*:*:*:*:*"}, ordsService.CPEs)
}

func TestORDSPlugin_Run_UnrelatedVersionedAssetDoesNotVersionAPEX(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ords/" {
			w.Header().Set("Server", "Oracle-REST-Data-Services/24.1.0")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><script src="/i/2.0/app.js"></script></body></html>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{Host: addr.Addr().String(), Address: addr}

	service, err := (&ORDSPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	var ordsService plugins.ServiceOracleORDS
	require.NoError(t, json.Unmarshal(service.Raw, &ordsService))
	assert.False(t, ordsService.APEX)
	assert.Empty(t, ordsService.APEXVersion)
	assert.Equal(t, []string{"cpe:2.3:a:oracle:rest_data_services:24.1.0:*:*:*:*:*:*:*"}, ordsService.CPEs)
}

func TestORDSPlugin_Run_APEXPageWithUnrelatedVersionedAssetHasNoAPEXVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ords/" {
			w.WriteHeader(http.StatusOK)
			// Genuine APEX markup, so the APEX product gate opens, alongside an
			// unrelated versioned asset that merely shares the "/i/" prefix.
			fmt.Fprint(w, `<html><body><a href="f?p=4550:1">Sign In</a>`+
				`<script src="/i/2.0/app.js"></script></body></html>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{Host: addr.Addr().String(), Address: addr}

	service, err := (&ORDSPlugin{}).Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	var ordsService plugins.ServiceOracleORDS
	require.NoError(t, json.Unmarshal(service.Raw, &ordsService))
	assert.True(t, ordsService.APEX, "f?p= is genuine APEX evidence")
	assert.Empty(t, ordsService.APEXVersion, "an unrelated /i/ asset must not supply the APEX version")
	assert.Contains(t, ordsService.CPEs, "cpe:2.3:a:oracle:application_express:*:*:*:*:*:*:*:*")
}
