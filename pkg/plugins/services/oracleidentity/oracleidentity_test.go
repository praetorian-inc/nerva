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

package oracleidentity

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
			body:     `<html><head><title>Oracle Identity Self Service</title></head></html>`,
			expected: "Oracle Identity Self Service",
		},
		{
			name:     "title with surrounding whitespace",
			body:     `<html><head><title>  Some Title  </title></head></html>`,
			expected: "Some Title",
		},
		{
			name:     "no title element",
			body:     `<html><head></head><body>hello</body></html>`,
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

func TestIsRedirect(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected bool
	}{
		{name: "301 moved permanently", code: http.StatusMovedPermanently, expected: true},
		{name: "302 found", code: http.StatusFound, expected: true},
		{name: "303 see other", code: http.StatusSeeOther, expected: true},
		{name: "307 temporary redirect", code: http.StatusTemporaryRedirect, expected: true},
		{name: "200 OK is not a redirect", code: http.StatusOK, expected: false},
		{name: "404 not found is not a redirect", code: http.StatusNotFound, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isRedirect(tt.code)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasOAMCookie(t *testing.T) {
	tests := []struct {
		name      string
		setCookie string
		expected  bool
	}{
		{
			name:      "OAM_ID cookie present",
			setCookie: "OAM_ID=abc123; Path=/",
			expected:  true,
		},
		{
			name:      "OAMAuthnCookie_ prefix present",
			setCookie: "OAMAuthnCookie_myserver_443=xyz; Path=/",
			expected:  true,
		},
		{
			name:      "OAM_REQ cookie present",
			setCookie: "OAM_REQ=deadbeef; Path=/",
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
			result := hasOAMCookie(tt.setCookie)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestHasOAMMarker(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		expected bool
	}{
		{
			name:     "contains oracle access manager text",
			s:        "Welcome to Oracle Access Manager",
			expected: true,
		},
		{
			name:     "contains /oam/ path",
			s:        "/oam/pages/login.jsp",
			expected: true,
		},
		{
			name:     "contains obrareq token",
			s:        "redirected via obrareq handler",
			expected: true,
		},
		{
			name:     "no OAM markers",
			s:        "/generic/login.jsp",
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
			result := hasOAMMarker(tt.s)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildOAMCPE(t *testing.T) {
	result := buildOAMCPE()
	assert.Equal(t, "cpe:2.3:a:oracle:access_manager:*:*:*:*:*:*:*:*", result)
}

func TestEvaluateOAM(t *testing.T) {
	tests := []struct {
		name            string
		evidence        []oamEvidence
		expectedOpenSSO bool
		expectedDetect  bool
	}{
		{
			name: "OAM_ID cookie signal",
			evidence: []oamEvidence{
				{path: "/oam/server/obrareq.cgi", statusCode: http.StatusOK, setCookie: "OAM_ID=abc123; Path=/"},
			},
			expectedOpenSSO: false,
			expectedDetect:  true,
		},
		{
			name: "obrareq.cgi redirect to OAM marker location",
			evidence: []oamEvidence{
				{path: "/oam/server/obrareq.cgi", statusCode: http.StatusFound, location: "/oam/pages/login.jsp"},
			},
			expectedOpenSSO: false,
			expectedDetect:  true,
		},
		{
			name: "obrareq.cgi 200 body with OAM marker",
			evidence: []oamEvidence{
				{path: "/oam/server/obrareq.cgi", statusCode: http.StatusOK, body: "Oracle Access Manager"},
			},
			expectedOpenSSO: false,
			expectedDetect:  true,
		},
		{
			name: "bare 200/redirect on obrareq.cgi without marker is not sufficient",
			evidence: []oamEvidence{
				{path: "/oam/server/obrareq.cgi", statusCode: http.StatusOK, body: "generic login page"},
			},
			expectedOpenSSO: false,
			expectedDetect:  false,
		},
		{
			name: "obrareq.cgi 404 does not trigger even with marker text elsewhere",
			evidence: []oamEvidence{
				{path: "/oam/server/obrareq.cgi", statusCode: http.StatusNotFound, body: "Oracle Access Manager"},
			},
			expectedOpenSSO: false,
			expectedDetect:  false,
		},
		{
			name: "opensso responds non-404 sets OpenSSO enrichment alongside detection",
			evidence: []oamEvidence{
				{path: "/oam/server/obrareq.cgi", statusCode: http.StatusOK, setCookie: "OAM_ID=abc123; Path=/"},
				{path: "/oam/server/opensso/sessionservice", statusCode: http.StatusOK, body: "session service"},
			},
			expectedOpenSSO: true,
			expectedDetect:  true,
		},
		{
			name: "opensso 404 does not set OpenSSO",
			evidence: []oamEvidence{
				{path: "/oam/server/obrareq.cgi", statusCode: http.StatusOK, setCookie: "OAM_ID=abc123; Path=/"},
				{path: "/oam/server/opensso/sessionservice", statusCode: http.StatusNotFound},
			},
			expectedOpenSSO: false,
			expectedDetect:  true,
		},
		{
			name:            "no evidence at all",
			evidence:        []oamEvidence{},
			expectedOpenSSO: false,
			expectedDetect:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			openSSO, detected := evaluateOAM(tt.evidence)
			assert.Equal(t, tt.expectedOpenSSO, openSSO)
			assert.Equal(t, tt.expectedDetect, detected)
		})
	}
}

func TestTitleIsOracleIdentity(t *testing.T) {
	tests := []struct {
		name     string
		title    string
		expected bool
	}{
		{
			name:     "Oracle Identity Self Service title",
			title:    "Oracle Identity Self Service",
			expected: true,
		},
		{
			name:     "System Administration title",
			title:    "System Administration",
			expected: true,
		},
		{
			name:     "unrelated title",
			title:    "Welcome",
			expected: false,
		},
		{
			name:     "empty title",
			title:    "",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := titleIsOracleIdentity(tt.title)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBodyHasADFRef(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{
			name:     "contains /afr/ reference",
			body:     `<script src="/afr/adf-richclient.js"></script>`,
			expected: true,
		},
		{
			name:     "no ADF reference",
			body:     "<html><body>hello</body></html>",
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
			result := bodyHasADFRef(tt.body)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestBuildOIMCPE(t *testing.T) {
	result := buildOIMCPE()
	assert.Equal(t, "cpe:2.3:a:oracle:identity_manager:*:*:*:*:*:*:*:*", result)
}

func TestEvaluateOIM(t *testing.T) {
	tests := []struct {
		name           string
		evidence       []oimEvidence
		expectedLegacy bool
		expectedDetect bool
	}{
		{
			name: "Oracle Identity Self Service title signal",
			evidence: []oimEvidence{
				{path: "/identity", statusCode: http.StatusOK, body: `<html><head><title>Oracle Identity Self Service</title></head></html>`},
			},
			expectedLegacy: false,
			expectedDetect: true,
		},
		{
			name: "System Administration title signal",
			evidence: []oimEvidence{
				{path: "/sysadmin", statusCode: http.StatusOK, body: `<html><head><title>System Administration</title></head></html>`},
			},
			expectedLegacy: false,
			expectedDetect: true,
		},
		{
			name: "ADF static reference signal",
			evidence: []oimEvidence{
				{path: "/identity", statusCode: http.StatusOK, body: `<script src="/afr/adf-richclient.js"></script>`},
			},
			expectedLegacy: false,
			expectedDetect: true,
		},
		{
			name: "governance path responds non-404",
			evidence: []oimEvidence{
				{path: "/iam/governance/", statusCode: http.StatusOK, body: "governance console"},
			},
			expectedLegacy: false,
			expectedDetect: true,
		},
		{
			name: "governance path 404 does not trigger",
			evidence: []oimEvidence{
				{path: "/iam/governance/", statusCode: http.StatusNotFound},
			},
			expectedLegacy: false,
			expectedDetect: false,
		},
		{
			name: "xlWebApp responds non-404 sets Legacy alongside detection",
			evidence: []oimEvidence{
				{path: "/identity", statusCode: http.StatusOK, body: `<html><head><title>Oracle Identity Self Service</title></head></html>`},
				{path: "/xlWebApp", statusCode: http.StatusOK, body: "legacy console"},
			},
			expectedLegacy: true,
			expectedDetect: true,
		},
		{
			name: "xlWebApp 404 does not set Legacy",
			evidence: []oimEvidence{
				{path: "/identity", statusCode: http.StatusOK, body: `<html><head><title>Oracle Identity Self Service</title></head></html>`},
				{path: "/xlWebApp", statusCode: http.StatusNotFound},
			},
			expectedLegacy: false,
			expectedDetect: true,
		},
		{
			name:           "no evidence at all",
			evidence:       []oimEvidence{},
			expectedLegacy: false,
			expectedDetect: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			legacy, detected := evaluateOIM(tt.evidence)
			assert.Equal(t, tt.expectedLegacy, legacy)
			assert.Equal(t, tt.expectedDetect, detected)
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

func TestOAMPlugin_Run_PositiveViaRedirectAndCookie(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oam/server/obrareq.cgi":
			w.Header().Set("Set-Cookie", "OAM_ID=abc123; Path=/")
			w.Header().Set("Location", "/oam/pages/login.jsp")
			w.WriteHeader(http.StatusFound)
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

	plugin := &OAMPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var oamService plugins.ServiceOracleOAM
	err = json.Unmarshal(service.Raw, &oamService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.False(t, oamService.OpenSSO)
	require.Len(t, oamService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:access_manager:*:*:*:*:*:*:*:*", oamService.CPEs[0])
}

func TestOAMPlugin_Run_PositiveWithOpenSSOEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oam/server/obrareq.cgi":
			w.Header().Set("Set-Cookie", "OAM_ID=abc123; Path=/")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Oracle Access Manager")
		case "/oam/server/opensso/sessionservice":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "session service")
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

	plugin := &OAMPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var oamService plugins.ServiceOracleOAM
	err = json.Unmarshal(service.Raw, &oamService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.True(t, oamService.OpenSSO)
	require.Len(t, oamService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:access_manager:*:*:*:*:*:*:*:*", oamService.CPEs[0])
}

func TestOAMPlugin_Run_Negative(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oam/server/obrareq.cgi":
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

	plugin := &OAMPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestOAMPlugin_Metadata(t *testing.T) {
	plugin := &OAMPlugin{}
	assert.Equal(t, OracleOAM, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, 100, plugin.Priority())
	assert.True(t, plugin.PortPriority(14100))
	assert.False(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(80))
}

func TestOAMTLSPlugin_Run_PositiveViaCookie(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oam/server/obrareq.cgi":
			w.Header().Set("Set-Cookie", "OAM_ID=abc123; Path=/")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Oracle Access Manager")
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

	plugin := &OAMTLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var oamService plugins.ServiceOracleOAM
	err = json.Unmarshal(service.Raw, &oamService)
	require.NoError(t, err)
	require.Len(t, oamService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:access_manager:*:*:*:*:*:*:*:*", oamService.CPEs[0])
}

func TestOAMTLSPlugin_Metadata(t *testing.T) {
	plugin := &OAMTLSPlugin{}
	assert.Equal(t, OracleOAM, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, 100, plugin.Priority())
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(14100))
}

func TestOIMPlugin_Run_PositiveViaTitle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle Identity Self Service</title></head></html>`)
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

	plugin := &OIMPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var oimService plugins.ServiceOracleOIM
	err = json.Unmarshal(service.Raw, &oimService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.False(t, oimService.Legacy)
	require.Len(t, oimService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:identity_manager:*:*:*:*:*:*:*:*", oimService.CPEs[0])
}

func TestOIMPlugin_Run_PositiveWithLegacyXLWebApp(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle Identity Self Service</title></head></html>`)
		case "/xlWebApp":
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "legacy xlWebApp console")
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

	plugin := &OIMPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var oimService plugins.ServiceOracleOIM
	err = json.Unmarshal(service.Raw, &oimService)
	require.NoError(t, err, "failed to unmarshal service payload")
	assert.True(t, oimService.Legacy)
	require.Len(t, oimService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:identity_manager:*:*:*:*:*:*:*:*", oimService.CPEs[0])
}

func TestOIMPlugin_Run_Negative(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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

	plugin := &OIMPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestOIMPlugin_Metadata(t *testing.T) {
	plugin := &OIMPlugin{}
	assert.Equal(t, OracleOIM, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, 100, plugin.Priority())
	assert.True(t, plugin.PortPriority(14000))
	assert.False(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(80))
}

func TestOIMTLSPlugin_Run_PositiveViaTitle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle Identity Self Service</title></head></html>`)
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

	plugin := &OIMTLSPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var oimService plugins.ServiceOracleOIM
	err = json.Unmarshal(service.Raw, &oimService)
	require.NoError(t, err)
	require.Len(t, oimService.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:identity_manager:*:*:*:*:*:*:*:*", oimService.CPEs[0])
}

func TestOIMTLSPlugin_Metadata(t *testing.T) {
	plugin := &OIMTLSPlugin{}
	assert.Equal(t, OracleOIM, plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, 100, plugin.Priority())
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(14000))
}

func TestOAMSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oam/server/obrareq.cgi":
			w.Header().Set("Set-Cookie", "OAM_ID=abc123; Path=/")
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "Oracle Access Manager")
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

		plugin := &OAMPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-oam-exposed", service.SecurityFindings[0].ID)
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

		plugin := &OAMPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

func TestOIMSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/identity":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintf(w, `<html><head><title>Oracle Identity Self Service</title></head></html>`)
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

		plugin := &OIMPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-oim-exposed", service.SecurityFindings[0].ID)
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

		plugin := &OIMPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)

		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}
