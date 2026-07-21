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

package oraclejdesiebel

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
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

// ---------------------------------------------------------------------------
// Test harness helpers (pattern copied from oracleidentity_test.go, extended
// to also support TLS test servers and raw-listener robustness tests).
// ---------------------------------------------------------------------------

// parseTestServerAddr parses an http(s)test server URL into netip.AddrPort.
func parseTestServerAddr(t *testing.T, serverURL string) netip.AddrPort {
	t.Helper()
	hostPort := strings.TrimPrefix(strings.TrimPrefix(serverURL, "https://"), "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
}

// dialTestServer dials the given httptest server URL over plain TCP and
// returns both the connection and the parsed netip.AddrPort.
func dialTestServer(t *testing.T, serverURL string) (net.Conn, netip.AddrPort) {
	t.Helper()
	addr := parseTestServerAddr(t, serverURL)
	hostPort := strings.TrimPrefix(strings.TrimPrefix(serverURL, "https://"), "http://")
	conn, err := net.DialTimeout("tcp", hostPort, 5*time.Second)
	require.NoError(t, err)
	return conn, addr
}

// newTarget builds a plugins.Target from a parsed address.
func newTarget(addr netip.AddrPort, misconfigs bool) plugins.Target {
	return plugins.Target{Host: addr.Addr().String(), Address: addr, Misconfigs: misconfigs}
}

// newRawListener returns a raw TCP listener on an ephemeral loopback port, for
// tests that need to emit malformed/hanging responses that httptest cannot
// produce.
func newRawListener(t *testing.T) *net.TCPListener {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	require.NoError(t, err)
	return ln
}

// targetForListener builds a plugins.Target pointing at a raw listener.
func targetForListener(ln net.Listener) plugins.Target {
	tcpAddr := ln.Addr().(*net.TCPAddr)
	return plugins.Target{
		Host:    "127.0.0.1",
		Address: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", tcpAddr.Port)),
	}
}

// ---------------------------------------------------------------------------
// GROUP 1 — Pure-helper table tests
// ---------------------------------------------------------------------------

func TestIsAuthChallenge(t *testing.T) {
	tests := []struct {
		name     string
		code     int
		expected bool
	}{
		{name: "401 StatusUnauthorized", code: http.StatusUnauthorized, expected: true},
		{name: "407 StatusProxyAuthRequired", code: http.StatusProxyAuthRequired, expected: true},
		{name: "200 OK", code: http.StatusOK, expected: false},
		{name: "403 Forbidden", code: http.StatusForbidden, expected: false},
		{name: "404 Not Found", code: http.StatusNotFound, expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isAuthChallenge(tt.code))
		})
	}
}

func TestHasJDEMarker(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		expected bool
	}{
		{name: "jdeLoginAction marker", s: "...jdeLoginAction=LOGIN...", expected: true},
		{name: "html4login marker", s: "var x=html4login;", expected: true},
		{name: "companyDislaimerHTML marker (Oracle misspelling)", s: "companyDislaimerHTML", expected: true},
		{name: "RENDER_MAFLET marker", s: "RENDER_MAFLET=E1Menu", expected: true},
		{name: `"jd edwards" text`, s: "Welcome to JD Edwards", expected: true},
		{name: `"enterpriseone" text`, s: "Oracle EnterpriseOne login", expected: true},
		{name: "case-insensitivity", s: "JDELOGINACTION", expected: true},
		{name: "reflective token E1Menu alone", s: "E1Menu", expected: false},
		{name: "reflective token /jde/owhtml alone", s: "/jde/owhtml", expected: false},
		{name: "reflective token /jde/images/logo.png alone", s: "/jde/images/logo.png", expected: false},
		{name: "empty string", s: "", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasJDEMarker(tt.s))
		})
	}
}

func TestIsAISEnvelope(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		ctype    string
		expected bool
	}{
		{name: "json content-type with aisVersion", body: `{"aisVersion":"9.2.5.3"}`, ctype: "application/json", expected: true},
		{name: "leading brace with tokenrequest, no ctype", body: `{"tokenrequest":{}}`, ctype: "", expected: true},
		{name: "json content-type but no AIS token", body: `{"foo":"bar"}`, ctype: "application/json", expected: false},
		{name: "html, not json, no leading brace", body: `<html>aisVersion</html>`, ctype: "text/html", expected: false},
		{name: "empty body and ctype", body: "", ctype: "", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isAISEnvelope(tt.body, tt.ctype))
		})
	}
}

func TestParseJDEToolsRelease(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{name: "labeled E1 Tools Release", body: "E1 Tools Release 9.2.9.0", expected: "9.2.9.0"},
		{name: "labeled Tools Release, 2-dot", body: "Tools Release: 9.2.6", expected: "9.2.6"},
		{name: "AIS quad", body: `{"aisVersion":"9.2.5.3"}`, expected: "9.2.5.3"},
		{name: "bare-quad, valid 9.2 prefix", body: "...E1 build 9.2.6.0 running", expected: "9.2.6.0"},
		{name: "bare-quad rejected, not 8.98/9.1/9.2", body: "version 1.2.3.4 here", expected: ""},
		{name: "P1-1 capture is digits/dots only, no injection", body: "E1 Tools Release 9.2.9.2:evil:cpe", expected: "9.2.9.2"},
		{name: "generic page, no version", body: "generic page no version", expected: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseJDEToolsRelease(tt.body))
		})
	}
}

func TestEvaluateJDE(t *testing.T) {
	tests := []struct {
		name            string
		evs             []jdeEvidence
		expectedAIS     bool
		expectedAnon    bool
		expectedVersion string
		expectedDetect  bool
	}{
		{
			name: "single marker in body",
			evs: []jdeEvidence{
				{path: "/jde/E1Menu.maf", statusCode: 200, body: "jdeLoginAction"},
			},
			expectedAIS: false, expectedAnon: true, expectedVersion: "", expectedDetect: true,
		},
		{
			name: "Location marker on redirect",
			evs: []jdeEvidence{
				{path: "/jde/E1Menu.maf", statusCode: 302, location: "/sso?app=JD Edwards"},
			},
			expectedAIS: false, expectedAnon: true, expectedVersion: "", expectedDetect: true,
		},
		{
			name: "jderest path with AIS JSON envelope",
			evs: []jdeEvidence{
				{path: "/jderest/defaultconfig", statusCode: 200, body: `{"aisVersion":"9.2.5.3"}`, ctype: "application/json"},
			},
			expectedAIS: true, expectedAnon: true, expectedVersion: "9.2.5.3", expectedDetect: true,
		},
		{
			name: "P0-4: 401 challenge with marker detected but not anonymous",
			evs: []jdeEvidence{
				{path: "/jde/E1Menu.maf", statusCode: 401, body: "jdeLoginAction"},
			},
			expectedAIS: false, expectedAnon: false, expectedVersion: "", expectedDetect: true,
		},
		{
			name: "AIS envelope only counts on a jderest path",
			evs: []jdeEvidence{
				{path: "/jde/owhtml", statusCode: 200, body: `{"aisVersion":"9.2.5.3"}`, ctype: "application/json"},
			},
			expectedAIS: false, expectedAnon: false, expectedVersion: "9.2.5.3", expectedDetect: false,
		},
		{
			name: "reflective echo only, no detect",
			evs: []jdeEvidence{
				{path: "/jde/E1Menu.maf", statusCode: 200, body: "E1Menu jde /jde/images/"},
			},
			expectedAIS: false, expectedAnon: false, expectedVersion: "", expectedDetect: false,
		},
		{
			name: "two evs: marker on first, tools release version on second",
			evs: []jdeEvidence{
				{path: "/jde/E1Menu.maf", statusCode: 200, body: "jdeLoginAction"},
				{path: "/jde/owhtml", statusCode: 200, body: "E1 Tools Release 9.2.9.0"},
			},
			expectedAIS: false, expectedAnon: true, expectedVersion: "9.2.9.0", expectedDetect: true,
		},
		{
			name:            "empty evidence",
			evs:             []jdeEvidence{},
			expectedAIS:     false,
			expectedAnon:    false,
			expectedVersion: "",
			expectedDetect:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ais, anonymous, version, detected := evaluateJDE(tt.evs)
			assert.Equal(t, tt.expectedAIS, ais)
			assert.Equal(t, tt.expectedAnon, anonymous)
			assert.Equal(t, tt.expectedVersion, version)
			assert.Equal(t, tt.expectedDetect, detected)
		})
	}
}

func TestBuildJDECPEs(t *testing.T) {
	t.Run("no tools version: app CPE only", func(t *testing.T) {
		result := buildJDECPEs("")
		require.Len(t, result, 1)
		assert.Equal(t, "cpe:2.3:a:oracle:jd_edwards_enterpriseone:*:*:*:*:*:*:*:*", result[0])
	})
	t.Run("tools version present: app + tools CPE", func(t *testing.T) {
		result := buildJDECPEs("9.2.9.0")
		require.Len(t, result, 2)
		assert.Equal(t, "cpe:2.3:a:oracle:jd_edwards_enterpriseone:*:*:*:*:*:*:*:*", result[0])
		assert.Equal(t, "cpe:2.3:a:oracle:jd_edwards_enterpriseone_tools:9.2.9.0:*:*:*:*:*:*:*", result[1])
	})
}

func TestHasSiebelCookie(t *testing.T) {
	tests := []struct {
		name      string
		setCookie string
		expected  bool
	}{
		{name: "_sn cookie", setCookie: "_sn=abc; Path=/", expected: true},
		{name: "_sweEntryPoint cookie", setCookie: "_sweEntryPoint=xyz; Path=/", expected: true},
		{name: "LB cookie is not a trigger", setCookie: "BIGipServerSiebel_pool=...", expected: false},
		{name: "unrelated cookie", setCookie: "JSESSIONID=abc", expected: false},
		{name: "empty", setCookie: "", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasSiebelCookie(tt.setCookie))
		})
	}
}

func TestHasSiebelStrongMarker(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		expected bool
	}{
		{name: "swecommon_top.js", s: "src=swecommon_top.js", expected: true},
		{name: "swecommon.js", s: "swecommon.js", expected: true},
		{name: "SWELogin.swt", s: "SWELogin.swt", expected: true},
		{name: "SiebWebMainWindow", s: "OT='SiebWebMainWindow'", expected: true},
		{name: "top._swescript", s: "top._swescript = window", expected: true},
		{name: "SWEClearHistoryGotoURL", s: "SWEClearHistoryGotoURL(...)", expected: true},
		{name: "start.swe + SWEHo (unsent param)", s: "start.swe?SWECmd=Start&SWEHo=host", expected: true},
		{name: "start.swe + SWEView", s: "start.swe?...SWEView=...", expected: true},
		{name: "start.swe + SWEApplet", s: "start.swe?...SWEApplet=...", expected: true},
		{name: "start.swe + SWEHtmlID", s: "start.swe?...SWEHtmlID=...", expected: true},
		{name: "reflective: SWECmd is in our probe URL", s: "start.swe?SWECmd=Start", expected: false},
		{name: "bare start.swe echo", s: "GotoUrl('start.swe')", expected: false},
		{name: "empty", s: "", expected: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasSiebelStrongMarker(tt.s))
		})
	}
}

func TestParseSiebelBuild(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{name: "primary regex", body: ".../enu/23021/scripts/siebel/...", expected: "23021"},
		{name: "public/ + files", body: ".../public/enu/230211/files/...", expected: "230211"},
		{name: "loose fallback, no lang segment", body: ".../230210/scripts/siebel", expected: "230210"},
		{name: "no build path", body: "no build path", expected: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseSiebelBuild(tt.body))
		})
	}
}

func TestParseSiebelVersion(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{name: "dotted marketing version", body: "Siebel version 8.1.1", expected: "8.1.1"},
		{name: "IP-year form keeps IP prefix", body: "Siebel build IP2023", expected: "IP2023"},
		{name: "critical: build folder must NOT become a version", body: ".../enu/23021/scripts/", expected: ""},
		{name: "generic page", body: "generic page", expected: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseSiebelVersion(tt.body))
		})
	}
}

func TestBuildSiebelCPE(t *testing.T) {
	t.Run("no version: wildcard", func(t *testing.T) {
		result := buildSiebelCPE("")
		require.Len(t, result, 1)
		assert.Equal(t, "cpe:2.3:a:oracle:siebel_crm:*:*:*:*:*:*:*:*", result[0])
	})
	t.Run("version present", func(t *testing.T) {
		result := buildSiebelCPE("23.3")
		require.Len(t, result, 1)
		assert.Equal(t, "cpe:2.3:a:oracle:siebel_crm:23.3:*:*:*:*:*:*:*", result[0])
	})
}

func TestEvaluateSiebel(t *testing.T) {
	tests := []struct {
		name            string
		evs             []siebelEvidence
		expectedBuild   string
		expectedVersion string
		expectedAnon    bool
		expectedDetect  bool
	}{
		{
			name: "cookie signal",
			evs: []siebelEvidence{
				{statusCode: 200, setCookie: "_sn=abc; Path=/"},
			},
			expectedBuild: "", expectedVersion: "", expectedAnon: true, expectedDetect: true,
		},
		{
			name: "sweEntryPoint cookie signal",
			evs: []siebelEvidence{
				{statusCode: 200, setCookie: "_sweEntryPoint=x"},
			},
			expectedBuild: "", expectedVersion: "", expectedAnon: true, expectedDetect: true,
		},
		{
			name: "body marker signal",
			evs: []siebelEvidence{
				{statusCode: 200, body: "swecommon_top.js"},
			},
			expectedBuild: "", expectedVersion: "", expectedAnon: true, expectedDetect: true,
		},
		{
			name: "P0-4: 401 challenge with cookie detected but not anonymous",
			evs: []siebelEvidence{
				{statusCode: 401, setCookie: "_sn=abc"},
			},
			expectedBuild: "", expectedVersion: "", expectedAnon: false, expectedDetect: true,
		},
		{
			name: "reflective echo only, no detect",
			evs: []siebelEvidence{
				{statusCode: 200, body: "start.swe?SWECmd=Start"},
			},
			expectedBuild: "", expectedVersion: "", expectedAnon: false, expectedDetect: false,
		},
		{
			name: "build parsed but NOT detected (no marker/cookie)",
			evs: []siebelEvidence{
				{statusCode: 200, body: ".../enu/23021/scripts/siebel/"},
			},
			expectedBuild: "23021", expectedVersion: "", expectedAnon: false, expectedDetect: false,
		},
		{
			name: "marketing version captured alongside marker",
			evs: []siebelEvidence{
				{statusCode: 200, body: "swecommon_top.js ... Siebel version 8.1.1"},
			},
			expectedBuild: "", expectedVersion: "8.1.1", expectedAnon: true, expectedDetect: true,
		},
		{
			name:            "empty evidence",
			evs:             []siebelEvidence{},
			expectedBuild:   "",
			expectedVersion: "",
			expectedAnon:    false,
			expectedDetect:  false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			build, version, anonymous, detected := evaluateSiebel(tt.evs)
			assert.Equal(t, tt.expectedBuild, build)
			assert.Equal(t, tt.expectedVersion, version)
			assert.Equal(t, tt.expectedAnon, anonymous)
			assert.Equal(t, tt.expectedDetect, detected)
		})
	}
}

// ---------------------------------------------------------------------------
// GROUP 2 — Run-level integration via httptest.NewServer
// ---------------------------------------------------------------------------

func TestJDEPlugin_Run_PositiveViaLoginMarker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jde/E1Menu.maf":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "jdeLoginAction")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, addr := dialTestServer(t, server.URL)
	defer conn.Close()
	target := newTarget(addr, false)

	plugin := &JDEPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.Equal(t, "oracle_jde", service.Protocol)
	assert.Equal(t, "tcp", service.Transport)
	assert.False(t, service.TLS)
	assert.Equal(t, "", service.Version)

	var payload plugins.ServiceOracleJDE
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.False(t, payload.AIS)
	require.Len(t, payload.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:jd_edwards_enterpriseone:*:*:*:*:*:*:*:*", payload.CPEs[0])
}

func TestJDEPlugin_Run_PositiveViaAISEnvelope(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jderest/defaultconfig":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `{"aisVersion":"9.2.5.3"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, addr := dialTestServer(t, server.URL)
	defer conn.Close()
	target := newTarget(addr, false)

	plugin := &JDEPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.Equal(t, "9.2.5.3", service.Version)

	var payload plugins.ServiceOracleJDE
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.True(t, payload.AIS)
	require.Len(t, payload.CPEs, 2)
	assert.Equal(t, "cpe:2.3:a:oracle:jd_edwards_enterpriseone:*:*:*:*:*:*:*:*", payload.CPEs[0])
	assert.Equal(t, "cpe:2.3:a:oracle:jd_edwards_enterpriseone_tools:9.2.5.3:*:*:*:*:*:*:*", payload.CPEs[1])
}

func TestJDEPlugin_Run_Negative(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, addr := dialTestServer(t, server.URL)
	defer conn.Close()
	target := newTarget(addr, false)

	plugin := &JDEPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

// TestJDEPlugin_Run_SelfReferenceOnly_NoDetect is a CRITICAL false-positive
// guard: every probed path echoes its own request path back in the body, so
// only reflective tokens (e.g. "E1Menu", "jde", "/jde/images/") are present.
// This must NOT be detected as JDE.
func TestJDEPlugin_Run_SelfReferenceOnly_NoDetect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, r.URL.Path)
	}))
	defer server.Close()

	conn, addr := dialTestServer(t, server.URL)
	defer conn.Close()
	target := newTarget(addr, false)

	plugin := &JDEPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service, "reflected probe tokens must NOT detect as JDE")
}

func TestJDEPlugin_Run_VersionAbsentOnlyAppCPE(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jde/E1Menu.maf":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "html4login")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, addr := dialTestServer(t, server.URL)
	defer conn.Close()
	target := newTarget(addr, false)

	plugin := &JDEPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Equal(t, "", service.Version)

	var payload plugins.ServiceOracleJDE
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	require.Len(t, payload.CPEs, 1)
}

// TestJDEPlugin_Run_AuthChallengeNoAnonymous is a P0-4 test: detection off a
// 401 challenge response must not set AnonymousAccess or SecurityFindings.
func TestJDEPlugin_Run_AuthChallengeNoAnonymous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jde/E1Menu.maf":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, "jdeLoginAction")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, addr := dialTestServer(t, server.URL)
	defer conn.Close()
	target := newTarget(addr, true)

	plugin := &JDEPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service, "should still be detected")
	assert.False(t, service.AnonymousAccess)
	assert.Empty(t, service.SecurityFindings)
}

// TestJDEPlugin_Run_RedirectNotFollowed is a P0-2 test: the client must not
// chase the Location header of a 302 response.
func TestJDEPlugin_Run_RedirectNotFollowed(t *testing.T) {
	var ssoHit bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jde/E1Menu.maf":
			w.Header().Set("Location", "/sso/login?app=JD Edwards")
			w.WriteHeader(http.StatusFound)
		case "/sso/login":
			ssoHit = true
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, addr := dialTestServer(t, server.URL)
	defer conn.Close()
	target := newTarget(addr, true)

	plugin := &JDEPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service, "Location marker must be detected")
	assert.True(t, service.AnonymousAccess, "302 is not an auth challenge, so anonymous access applies")
	assert.False(t, ssoHit, "redirect must not be followed")
}

func TestJDESecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jde/E1Menu.maf":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "jdeLoginAction")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	t.Run("with Misconfigs=true yields AnonymousAccess and finding", func(t *testing.T) {
		server := httptest.NewServer(handler)
		defer server.Close()

		conn, addr := dialTestServer(t, server.URL)
		defer conn.Close()
		target := newTarget(addr, true)

		plugin := &JDEPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-jde-exposed", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityLow, service.SecurityFindings[0].Severity)
	})

	t.Run("with Misconfigs=false yields no SecurityFindings", func(t *testing.T) {
		server := httptest.NewServer(handler)
		defer server.Close()

		conn, addr := dialTestServer(t, server.URL)
		defer conn.Close()
		target := newTarget(addr, false)

		plugin := &JDEPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

func TestJDETLSPlugin_Run_Positive(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jde/E1Menu.maf":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "enterpriseone")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	hostPort := strings.TrimPrefix(server.URL, "https://")
	rawConn, err := net.DialTimeout("tcp", hostPort, 5*time.Second)
	require.NoError(t, err)
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, tlsConn.Handshake())
	defer tlsConn.Close()

	target := newTarget(addr, true)

	plugin := &JDETLSPlugin{}
	service, err := plugin.Run(tlsConn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.Equal(t, "tcptls", service.Transport)
	assert.True(t, service.TLS)
}

// ---------------------------------------------------------------------------
// Siebel Run-level integration
// ---------------------------------------------------------------------------

func TestSiebelPlugin_Run_PositiveViaCookie(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start.swe":
			w.Header().Set("Set-Cookie", "_sn=abc; Path=/")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, addr := dialTestServer(t, server.URL)
	defer conn.Close()
	target := newTarget(addr, false)

	plugin := &SiebelPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.Equal(t, "oracle_siebel", service.Protocol)
	assert.Equal(t, "tcp", service.Transport)

	var payload plugins.ServiceOracleSiebel
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "", payload.Build)
	require.Len(t, payload.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:siebel_crm:*:*:*:*:*:*:*:*", payload.CPEs[0])
}

func TestSiebelPlugin_Run_PositiveViaSWEMarkerWithBuild(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start.swe":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "swecommon_top.js ... /enu/23021/scripts/siebel/x.js")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, addr := dialTestServer(t, server.URL)
	defer conn.Close()
	target := newTarget(addr, false)

	plugin := &SiebelPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.Equal(t, "", service.Version)

	var payload plugins.ServiceOracleSiebel
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Equal(t, "23021", payload.Build)
	require.Len(t, payload.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:siebel_crm:*:*:*:*:*:*:*:*", payload.CPEs[0], "build folder must NEVER become a CPE version")
}

func TestSiebelPlugin_Run_Negative(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "hello")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, addr := dialTestServer(t, server.URL)
	defer conn.Close()
	target := newTarget(addr, false)

	plugin := &SiebelPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

// TestSiebelPlugin_Run_SelfReferenceOnly_NoDetect is a CRITICAL false-positive
// guard: every probed path echoes its own request URI (including the SWECmd
// query param the plugin itself sent) back in the body. This must NOT be
// detected as Siebel.
func TestSiebelPlugin_Run_SelfReferenceOnly_NoDetect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, r.URL.RequestURI())
	}))
	defer server.Close()

	conn, addr := dialTestServer(t, server.URL)
	defer conn.Close()
	target := newTarget(addr, false)

	plugin := &SiebelPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service, "start.swe+SWECmd echo alone must NOT detect as Siebel")
}

// TestSiebelPlugin_Run_AuthChallengeNoAnonymous is a P0-4 test.
func TestSiebelPlugin_Run_AuthChallengeNoAnonymous(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start.swe":
			w.Header().Set("Set-Cookie", "_sn=abc")
			w.WriteHeader(http.StatusUnauthorized)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, addr := dialTestServer(t, server.URL)
	defer conn.Close()
	target := newTarget(addr, true)

	plugin := &SiebelPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service, "should still be detected")
	assert.False(t, service.AnonymousAccess)
	assert.Empty(t, service.SecurityFindings)
}

func TestSiebelSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start.swe":
			w.Header().Set("Set-Cookie", "_sweEntryPoint=x")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})

	t.Run("with Misconfigs=true yields AnonymousAccess and finding", func(t *testing.T) {
		server := httptest.NewServer(handler)
		defer server.Close()

		conn, addr := dialTestServer(t, server.URL)
		defer conn.Close()
		target := newTarget(addr, true)

		plugin := &SiebelPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.True(t, service.AnonymousAccess)
		require.Len(t, service.SecurityFindings, 1)
		assert.Equal(t, "oracle-siebel-exposed", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityLow, service.SecurityFindings[0].Severity)
	})

	t.Run("with Misconfigs=false yields no SecurityFindings", func(t *testing.T) {
		server := httptest.NewServer(handler)
		defer server.Close()

		conn, addr := dialTestServer(t, server.URL)
		defer conn.Close()
		target := newTarget(addr, false)

		plugin := &SiebelPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		require.NotNil(t, service)

		assert.False(t, service.AnonymousAccess)
		assert.Empty(t, service.SecurityFindings)
	})
}

func TestSiebelTLSPlugin_Run_Positive(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/start.swe":
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "SWELogin.swt")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	addr := parseTestServerAddr(t, server.URL)
	hostPort := strings.TrimPrefix(server.URL, "https://")
	rawConn, err := net.DialTimeout("tcp", hostPort, 5*time.Second)
	require.NoError(t, err)
	defer rawConn.Close()

	tlsConn := tls.Client(rawConn, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, tlsConn.Handshake())
	defer tlsConn.Close()

	target := newTarget(addr, true)

	plugin := &SiebelTLSPlugin{}
	service, err := plugin.Run(tlsConn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service)

	assert.Equal(t, "tcptls", service.Transport)
	assert.True(t, service.TLS)
}

// ---------------------------------------------------------------------------
// GROUP 3 — Robustness (P0-3 / P0-1 / P0-2): hostile & malformed responses
// ---------------------------------------------------------------------------

func TestRun_ConnectionError_ReturnsNilNil(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	server.Close()
	conn.Close()

	target := newTarget(addr, false)

	testPlugins := []plugins.Plugin{&JDEPlugin{}, &JDETLSPlugin{}, &SiebelPlugin{}, &SiebelTLSPlugin{}}
	for _, p := range testPlugins {
		t.Run(fmt.Sprintf("%s/%s", p.Name(), p.Type()), func(t *testing.T) {
			service, err := p.Run(conn, 5*time.Second, target)
			require.NoError(t, err)
			assert.Nil(t, service)
		})
	}
}

// TestRun_MalformedResponse_ReturnsNilNil (P0) uses a raw net.Listener because
// httptest.ResponseWriter validates headers/status and cannot emit an invalid
// HTTP response.
func TestRun_MalformedResponse_ReturnsNilNil(t *testing.T) {
	ln := newRawListener(t)
	defer ln.Close()

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		_, _ = c.Read(buf)
		_, _ = c.Write([]byte("HTTP/1.1 999 \r\n\r\n\x00garbage"))
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := targetForListener(ln)

	plugin := &JDEPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestRun_EmptyBody_NoDetect(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	t.Run("JDE", func(t *testing.T) {
		conn, addr := dialTestServer(t, server.URL)
		defer conn.Close()
		target := newTarget(addr, false)

		plugin := &JDEPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		assert.Nil(t, service)
	})

	t.Run("Siebel", func(t *testing.T) {
		conn, addr := dialTestServer(t, server.URL)
		defer conn.Close()
		target := newTarget(addr, false)

		plugin := &SiebelPlugin{}
		service, err := plugin.Run(conn, 5*time.Second, target)
		require.NoError(t, err)
		assert.Nil(t, service)
	})
}

// TestRun_OversizedBody_NoHangNoPanic (P0-1) writes a body larger than
// maxResponseSize with a valid marker placed AFTER the cap, proving the
// io.LimitReader truncates the body before the marker is ever seen, and that
// this does not hang or panic.
func TestRun_OversizedBody_NoHangNoPanic(t *testing.T) {
	filler := strings.Repeat("a", int(maxResponseSize)+1024)
	marker := "jdeLoginAction"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/jde/E1Menu.maf":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, filler)
			_, _ = io.WriteString(w, marker)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	conn, addr := dialTestServer(t, server.URL)
	defer conn.Close()
	target := newTarget(addr, false)

	plugin := &JDEPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	// Completing this call at all (rather than hanging forever) already
	// proves the LimitReader bounds the read. No hang, no panic, and the
	// truncated body means the marker beyond the cap is never observed.
	require.NoError(t, err)
	assert.Nil(t, service, "marker written beyond the 10MiB LimitReader cap must be truncated away")
}

// TestRun_HangPastTimeout_ReturnsNilNil (P0-3) proves Run bounds its total
// wait via the per-request client timeout rather than hanging until the
// server eventually responds (or forever).
func TestRun_HangPastTimeout_ReturnsNilNil(t *testing.T) {
	ln := newRawListener(t)
	defer ln.Close()

	stop := make(chan struct{})
	defer close(stop)

	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 4096)
		_, _ = c.Read(buf) // absorb the request, then hang: never respond
		<-stop
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	timeout := 150 * time.Millisecond
	target := targetForListener(ln)

	plugin := &JDEPlugin{}
	start := time.Now()
	service, err := plugin.Run(conn, timeout, target)
	elapsed := time.Since(start)

	require.NoError(t, err)
	assert.Nil(t, service)
	assert.Less(t, elapsed, 2*time.Second, "Run must bound total wait via the per-request client timeout, not hang until the server responds")
}

// ---------------------------------------------------------------------------
// GROUP 4 — Plugin metadata
// ---------------------------------------------------------------------------

func TestJDEPlugin_Metadata(t *testing.T) {
	plugin := &JDEPlugin{}
	assert.Equal(t, "oracle_jde", plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(80))
	assert.False(t, plugin.PortPriority(443))
}

func TestJDETLSPlugin_Metadata(t *testing.T) {
	plugin := &JDETLSPlugin{}
	assert.Equal(t, "oracle_jde", plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(80))
}

func TestSiebelPlugin_Metadata(t *testing.T) {
	plugin := &SiebelPlugin{}
	assert.Equal(t, "oracle_siebel", plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(80))
	assert.False(t, plugin.PortPriority(443))
}

func TestSiebelTLSPlugin_Metadata(t *testing.T) {
	plugin := &SiebelTLSPlugin{}
	assert.Equal(t, "oracle_siebel", plugin.Name())
	assert.Equal(t, plugins.TCPTLS, plugin.Type())
	assert.Equal(t, -1, plugin.Priority())
	assert.True(t, plugin.PortPriority(443))
	assert.False(t, plugin.PortPriority(80))
}

// ---------------------------------------------------------------------------
// GROUP 5 — Service payload Type() round-trip
// ---------------------------------------------------------------------------

func TestServiceOracleJDE_Type(t *testing.T) {
	assert.Equal(t, plugins.ProtoOracleJDE, plugins.ServiceOracleJDE{}.Type())
	assert.Equal(t, "oracle_jde", plugins.ServiceOracleJDE{}.Type())
}

func TestServiceOracleSiebel_Type(t *testing.T) {
	assert.Equal(t, plugins.ProtoOracleSiebel, plugins.ServiceOracleSiebel{}.Type())
	assert.Equal(t, "oracle_siebel", plugins.ServiceOracleSiebel{}.Type())
}
