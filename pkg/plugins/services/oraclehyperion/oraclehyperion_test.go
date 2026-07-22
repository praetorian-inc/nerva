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

package oraclehyperion

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

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// parseTestServerAddr parses httptest server URL into netip.AddrPort. Copied
// verbatim from oracleidentity_test.go to mirror the harness used elsewhere in
// this codebase.
func parseTestServerAddr(t *testing.T, serverURL string) netip.AddrPort {
	t.Helper()
	hostPort := strings.TrimPrefix(serverURL, "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
}

// hEv builds a hyperionEvidence value the same way detectHyperion does:
// title is always extractTitle(body). cookie is wrapped in a single-element
// setCookies slice (matching the []string field), mirroring how a single
// Set-Cookie header would be captured by detectHyperion.
func hEv(path string, status int, location, body, cookie string) hyperionEvidence {
	return hyperionEvidence{
		path:       path,
		statusCode: status,
		location:   location,
		body:       body,
		setCookies: []string{cookie},
		title:      extractTitle(body),
	}
}

// runPlugin dials the httptest server, builds a plugins.Target and runs the
// given plugin, mirroring the oracleidentity_test.go e2e harness.
func runPlugin(t *testing.T, plugin plugins.Plugin, serverURL string, misconfigs bool) (*plugins.Service, error) {
	t.Helper()
	addr := parseTestServerAddr(t, serverURL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(serverURL, "http://"), 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	target := plugins.Target{
		Host:       addr.Addr().String(),
		Address:    addr,
		Misconfigs: misconfigs,
	}
	return plugin.Run(conn, 5*time.Second, target)
}

// startGarbageServer starts a raw (non-HTTP) TCP listener that accepts one
// connection and writes the given bytes before closing. Used to exercise the
// doGet error branch when the peer sends a malformed HTTP response.
func startGarbageServer(t *testing.T, garbage []byte) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(garbage)
	}()

	return listener.Addr().(*net.TCPAddr).Port
}

// startAgentLoopback starts a loopback TCP listener with the given
// per-connection behavior and returns its port. The Accept loop mirrors
// cassandra_test.go: it returns (and the goroutine exits) as soon as
// listener.Close() causes Accept to error, so no goroutine is leaked under
// -race.
func startAgentLoopback(t *testing.T, behavior func(conn net.Conn)) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go behavior(conn)
		}
	}()

	return listener.Addr().(*net.TCPAddr).Port
}

// dialAgent dials the loopback agent port and returns the connection plus a
// ready-to-use plugins.Target. target.Address.Port() is fixed at
// EssbaseAgentPort (1423) so the returned Target passes the port gate added
// in LAB-5054/PR#383 (EssbaseAgentPlugin.Run only proceeds when
// target.Address.Port() == EssbaseAgentPort). The loopback listener itself
// can still be any ephemeral port: the dialed conn is passed to Run directly,
// and only target.Address.Port() is inspected by the gate.
func dialAgent(t *testing.T, port int) (net.Conn, plugins.Target) {
	t.Helper()
	addrStr := fmt.Sprintf("127.0.0.1:%d", port)
	conn, err := net.DialTimeout("tcp", addrStr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	target := plugins.Target{
		Host:    "127.0.0.1",
		Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), EssbaseAgentPort),
	}
	return conn, target
}

// dialAgentAtTargetPort behaves like dialAgent but builds target.Address
// using the caller-supplied targetPort instead of the fixed EssbaseAgentPort.
// It exists solely to exercise the port gate's negative path: a target whose
// Address.Port() is NOT EssbaseAgentPort.
func dialAgentAtTargetPort(t *testing.T, listenPort int, targetPort uint16) (net.Conn, plugins.Target) {
	t.Helper()
	addrStr := fmt.Sprintf("127.0.0.1:%d", listenPort)
	conn, err := net.DialTimeout("tcp", addrStr, 5*time.Second)
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })

	target := plugins.Target{
		Host:    "127.0.0.1",
		Address: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), targetPort),
	}
	return conn, target
}

// ---------------------------------------------------------------------------
// 1a-1d: shared HTTP helper functions
// ---------------------------------------------------------------------------

func TestExtractTitle(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{name: "plain title", body: `<title>EPM</title>`, expected: "EPM"},
		{
			name:     "attributed title tag (widened regex)",
			body:     `<title id="x" class="y">Enterprise Performance Management System Workspace</title>`,
			expected: "Enterprise Performance Management System Workspace",
		},
		{name: "whitespace trimmed", body: `<title>  W  </title>`, expected: "W"},
		{name: "no title", body: `<html><body>hi</body></html>`, expected: ""},
		{name: "empty body", body: "", expected: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, extractTitle(tt.body))
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
		{name: "308 permanent redirect", code: http.StatusPermanentRedirect, expected: true},
		{name: "200 is not a redirect", code: http.StatusOK, expected: false},
		{name: "404 is not a redirect", code: http.StatusNotFound, expected: false},
		{name: "500 is not a redirect", code: http.StatusInternalServerError, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isRedirect(tt.code))
		})
	}
}

func TestIsAnonymousExposure(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		location string
		expected bool
	}{
		{name: "200 with no location", status: 200, location: "", expected: true},
		{name: "204 boundary", status: 204, location: "", expected: true},
		{name: "299 boundary", status: 299, location: "", expected: true},
		{name: "302 with location", status: 302, location: "/login", expected: true},
		{name: "302 without location is not anonymous exposure", status: 302, location: "", expected: false},
		{name: "301 with location", status: 301, location: "/x", expected: true},
		{name: "308 with location", status: 308, location: "/somewhere", expected: true},
		{name: "308 without location is not anonymous exposure", status: 308, location: "", expected: false},
		{name: "403 branded is not anonymous exposure", status: 403, location: "Hyperion Shared Services", expected: false},
		{name: "404 is not anonymous exposure", status: 404, location: "", expected: false},
		{name: "500 is not anonymous exposure", status: 500, location: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isAnonymousExposure(tt.status, tt.location))
		})
	}
}

func TestHasWorkspaceTitleMarker(t *testing.T) {
	tests := []struct {
		name     string
		title    string
		expected bool
	}{
		{
			name:     "branded workspace title (case-insensitive)",
			title:    "enterprise PERFORMANCE management System Workspace",
			expected: true,
		},
		{name: "Workspace alone is not sufficient", title: "Workspace", expected: false},
		{name: "empty title", title: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasWorkspaceTitleMarker(tt.title))
		})
	}
}

func TestHasWorkspaceBodyMarker(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{name: "BpmMainFrame marker", body: "var f = BpmMainFrame;", expected: true},
		{name: "bpmui marker", body: `<script src="/bpmui/init.js"></script>`, expected: true},
		{name: "com.hyperion. marker", body: "com.hyperion.workspace.Init();", expected: true},
		{name: "workspace.taskbar marker", body: "workspace.taskbar.render();", expected: true},
		{name: "generic body has no marker", body: "<html><body>hello</body></html>", expected: false},
		{name: "empty body", body: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasWorkspaceBodyMarker(tt.body))
		})
	}
}

func TestHasSharedServicesMarker(t *testing.T) {
	tests := []struct {
		name     string
		s        string
		expected bool
	}{
		{name: "Hyperion + Shared Services", s: "Welcome to Hyperion Shared Services", expected: true},
		{name: "Hyperion + Foundation Services", s: "Hyperion Foundation Services console", expected: true},
		{name: "Hyperion alone is not sufficient", s: "Hyperion", expected: false},
		{name: "Shared Services alone is not sufficient", s: "Shared Services", expected: false},
		{name: "bare /interop/ path echo is not a marker", s: "/interop/", expected: false},
		{name: "empty string", s: "", expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasSharedServicesMarker(tt.s))
		})
	}
}

func TestHasEPMCookie(t *testing.T) {
	tests := []struct {
		name       string
		setCookies []string
		expected   bool
	}{
		{name: "EPM_ROOT cookie", setCookies: []string{"EPM_ROOT=abc; Path=/"}, expected: true},
		{name: "EPMwvSess cookie", setCookies: []string{"EPMwvSess=xyz"}, expected: true},
		{name: "unrelated cookie", setCookies: []string{"JSESSIONID=abc123; Path=/"}, expected: false},
		{name: "empty Set-Cookie header", setCookies: []string{""}, expected: false},
		{
			name:       "cookie name ending in EPM_ROOT is not a trigger",
			setCookies: []string{"notEPM_ROOT=x; Path=/"},
			expected:   false,
		},
		{
			name:       "EPM_ROOT= inside another cookie value is not a trigger",
			setCookies: []string{"foo=EPM_ROOT=x"},
			expected:   false,
		},
		{
			name:       "real EPM_ROOT across multiple Set-Cookie headers",
			setCookies: []string{"JSESSIONID=x", "EPM_ROOT=abc; Path=/"},
			expected:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasEPMCookie(tt.setCookies))
		})
	}
}

// ---------------------------------------------------------------------------
// 1e: evaluateHyperion - the detection core
// ---------------------------------------------------------------------------

func TestEvaluateHyperion(t *testing.T) {
	const brandedTitle = `<title>Enterprise Performance Management System Workspace</title>`

	tests := []struct {
		name         string
		evs          []hyperionEvidence
		wantSS       bool
		wantPlanning bool
		wantAPS      bool
		wantDetected bool
		wantAnon     bool
	}{
		{
			name:         "S1 branded title on 200",
			evs:          []hyperionEvidence{hEv("/workspace/index.jsp", http.StatusOK, "", brandedTitle, "")},
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name:         "S2 body JS marker on 200",
			evs:          []hyperionEvidence{hEv("/workspace/index.jsp", http.StatusOK, "", "var x=BpmMainFrame;", "")},
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name:         "S3 shared-services body on 200",
			evs:          []hyperionEvidence{hEv("/interop/", http.StatusOK, "", "Hyperion Shared Services", "")},
			wantSS:       true,
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name:         "S3 via redirect Location",
			evs:          []hyperionEvidence{hEv("/interop/", http.StatusFound, "/x?app=Hyperion Shared Services", "", "")},
			wantSS:       true,
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name:         "S4 EPM cookie on 302 with Location",
			evs:          []hyperionEvidence{hEv("/workspace/index.jsp", http.StatusFound, "/login", "", "EPM_ROOT=a; Path=/")},
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name:         "S3 branded but on 403 is detected without anon exposure",
			evs:          []hyperionEvidence{hEv("/interop/", http.StatusForbidden, "", "Hyperion Foundation Services", "")},
			wantSS:       true,
			wantDetected: true,
			wantAnon:     false,
		},
		{
			name:         "S4 cookie on 302 without Location is detected without anon exposure",
			evs:          []hyperionEvidence{hEv("/workspace/index.jsp", http.StatusFound, "", "", "EPMwvSess=a")},
			wantDetected: true,
			wantAnon:     false,
		},
		{
			name:         "reflective path echo (self-reference) is not a marker",
			evs:          []hyperionEvidence{hEv("/workspace/index.jsp", http.StatusOK, "", "you requested /workspace/index.jsp", "")},
			wantDetected: false,
		},
		{
			name:         "bare 200 no marker",
			evs:          []hyperionEvidence{hEv("/workspace/index.jsp", http.StatusOK, "", "generic", "")},
			wantDetected: false,
		},
		{
			name:         "bare 302 no marker",
			evs:          []hyperionEvidence{hEv("/workspace/index.jsp", http.StatusFound, "/login", "", "")},
			wantDetected: false,
		},
		{
			name: "Planning enrichment requires a co-occurring strong signal",
			evs: []hyperionEvidence{
				hEv("/workspace/index.jsp", http.StatusOK, "", brandedTitle, ""),
				hEv("/HyperionPlanning/", http.StatusOK, "", "Oracle Hyperion Planning", ""),
			},
			wantPlanning: true,
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name:         "Planning body alone sets planning even though detected stays false",
			evs:          []hyperionEvidence{hEv("/HyperionPlanning/", http.StatusOK, "", "Oracle Hyperion Planning", "")},
			wantPlanning: true,
			wantDetected: false,
		},
		{
			name: "Planning on 404 is not enriched (co-occurring strong signal still detects)",
			evs: []hyperionEvidence{
				hEv("/workspace/index.jsp", http.StatusOK, "", brandedTitle, ""),
				hEv("/HyperionPlanning/", http.StatusNotFound, "", "Oracle Hyperion Planning", ""),
			},
			wantPlanning: false,
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name: "APS enrichment alongside a strong signal",
			evs: []hyperionEvidence{
				hEv("/workspace/index.jsp", http.StatusOK, "", brandedTitle, ""),
				hEv("/aps/JAPI", http.StatusOK, "", "Analytic Provider Services", ""),
			},
			wantAPS:      true,
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name: "APS on 404 is not enriched",
			evs: []hyperionEvidence{
				hEv("/workspace/index.jsp", http.StatusOK, "", brandedTitle, ""),
				hEv("/aps/JAPI", http.StatusNotFound, "", "Analytic Provider Services", ""),
			},
			wantAPS:      false,
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name: "empty evidence",
			evs:  []hyperionEvidence{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ss, planning, aps, detected, anon := evaluateHyperion(tt.evs)
			assert.Equal(t, tt.wantSS, ss, "sharedServices")
			assert.Equal(t, tt.wantPlanning, planning, "planning")
			assert.Equal(t, tt.wantAPS, aps, "aps")
			assert.Equal(t, tt.wantDetected, detected, "detected")
			assert.Equal(t, tt.wantAnon, anon, "anonExposure")
		})
	}
}

// ---------------------------------------------------------------------------
// 1f: evaluateEssbaseREST
// ---------------------------------------------------------------------------

func TestEvaluateEssbaseREST(t *testing.T) {
	tests := []struct {
		name         string
		ev           essbaseRESTEvidence
		wantREST     bool
		wantVersion  string
		wantDetected bool
		wantAnon     bool
	}{
		{
			name:         "name and 5-group version",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":"21.6.0.0.0"}`},
			wantREST:     true,
			wantVersion:  "21.6.0.0.0",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name:         "name and 4-group version (regex boundary)",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":"21.2.3.0"}`},
			wantREST:     true,
			wantVersion:  "21.2.3.0",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			// CURRENT behavior: detection is gated ONLY on the name field, not
			// on the version regex. A name-only body is still detected, with
			// version left empty (the CPE builder emits the wildcard version).
			name:         "name present, version absent: still detected, version stays empty",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase"}`},
			wantREST:     true,
			wantVersion:  "",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			// essbaseRestVersion now accepts 2-5 dot-separated components
			// (`(\d+(?:\.\d+){1,4})`), so a 3-component version is captured.
			name:         "name and 3-group version (now captured)",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":"21.2.3"}`},
			wantREST:     true,
			wantVersion:  "21.2.3",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			// 2-component version is the new lower bound (1 initial digit run
			// plus a minimum of 1 additional `.digits` group).
			name:         "name and 2-group version (new lower bound)",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":"21.2"}`},
			wantREST:     true,
			wantVersion:  "21.2",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			// The version capture is restricted to digits/dots immediately
			// followed by a closing quote; attacker-controlled bytes after the
			// digits (e.g. CPE separators) make the whole regex miss, so
			// version stays empty rather than being truncated.
			name:         "attacker-controlled version with CPE separators fails the digits-only capture",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":"1.2.3.4:*:evil"}`},
			wantREST:     true,
			wantVersion:  "",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name:         "no name gate: a generic product string is not sufficient",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"product":"Essbase 21c"}`},
			wantREST:     false,
			wantVersion:  "",
			wantDetected: false,
			wantAnon:     false,
		},
		{
			name:         "malformed non-JSON body",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `not json`},
			wantREST:     false,
			wantVersion:  "",
			wantDetected: false,
			wantAnon:     false,
		},
		{
			name:         "empty body",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: ``},
			wantREST:     false,
			wantVersion:  "",
			wantDetected: false,
			wantAnon:     false,
		},
		{
			name:         "name and version but on 403 is detected without anon exposure",
			ev:           essbaseRESTEvidence{statusCode: http.StatusForbidden, body: `{"name":"Essbase","version":"21.6.0.0.0"}`},
			wantREST:     true,
			wantVersion:  "21.6.0.0.0",
			wantDetected: true,
			wantAnon:     false,
		},
		{
			name:         "name and version on 302 with Location is anon exposure",
			ev:           essbaseRESTEvidence{statusCode: http.StatusFound, location: "/login", body: `{"name":"Essbase","version":"21.6.0.0.0"}`},
			wantREST:     true,
			wantVersion:  "21.6.0.0.0",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			// Regression: an HTML page whose body merely happens to contain the
			// literal substring "name":"Essbase" (e.g. an error/docs page) must
			// NOT be detected. Without the JSON-envelope gate (a JSON
			// Content-Type or a body starting with '{'), this text/html response
			// would previously false-positive on the bare essbaseRestName regex
			// match.
			name: "HTML page with embedded name:Essbase substring is not detected (JSON-envelope gate)",
			ev: essbaseRESTEvidence{
				statusCode: http.StatusOK,
				ctype:      "text/html",
				body:       `<html><body>Error: unknown field "name":"Essbase" in request</body></html>`,
			},
			wantREST:     false,
			wantVersion:  "",
			wantDetected: false,
			wantAnon:     false,
		},
		{
			// Positive control for the same gate: a JSON Content-Type header
			// (rather than a body-prefix '{') also satisfies isJSON.
			name: "JSON Content-Type header satisfies the JSON-envelope gate",
			ev: essbaseRESTEvidence{
				statusCode: http.StatusOK,
				ctype:      "application/json; charset=utf-8",
				body:       `{"name":"Essbase","version":"21.6.0.0.0"}`,
			},
			wantREST:     true,
			wantVersion:  "21.6.0.0.0",
			wantDetected: true,
			wantAnon:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rest, version, detected, anon := evaluateEssbaseREST(tt.ev)
			assert.Equal(t, tt.wantREST, rest, "rest")
			assert.Equal(t, tt.wantVersion, version, "version")
			assert.Equal(t, tt.wantDetected, detected, "detected")
			assert.Equal(t, tt.wantAnon, anon, "anonExposure")
		})
	}
}

// ---------------------------------------------------------------------------
// 1g-1h: CPE and finding builders
// ---------------------------------------------------------------------------

func TestBuildHyperionCPE(t *testing.T) {
	const base = "cpe:2.3:a:oracle:hyperion:*:*:*:*:*:*:*:*"
	const planning = "cpe:2.3:a:oracle:hyperion_planning:*:*:*:*:*:*:*:*"

	tests := []struct {
		name     string
		planning bool
		expected []string
	}{
		{name: "no planning", planning: false, expected: []string{base}},
		{name: "planning true adds a second CPE", planning: true, expected: []string{base, planning}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildHyperionCPE(tt.planning)
			assert.Equal(t, tt.expected, result)
			assert.Len(t, result, len(tt.expected))
		})
	}
}

func TestBuildEssbaseCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected []string
	}{
		{
			name:     "empty version emits wildcard",
			version:  "",
			expected: []string{"cpe:2.3:a:oracle:essbase:*:*:*:*:*:*:*:*"},
		},
		{
			name:     "version embedded exactly",
			version:  "21.6.0.0.0",
			expected: []string{"cpe:2.3:a:oracle:essbase:21.6.0.0.0:*:*:*:*:*:*:*"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildEssbaseCPE(tt.version))
		})
	}
}

func TestHyperionFinding(t *testing.T) {
	f := hyperionFinding()
	assert.Equal(t, "oracle-hyperion-exposed", f.ID)
	assert.Equal(t, plugins.SeverityLow, f.Severity)
	assert.NotEmpty(t, f.Description)
	assert.NotEmpty(t, f.Evidence)
	// Evidence is a fixed, hand-written string, never a dynamic response body.
	assert.Equal(t, "Oracle Hyperion EPM web endpoints responded without credentials", f.Evidence)
}

func TestEssbaseRestFinding(t *testing.T) {
	f := essbaseRestFinding()
	assert.Equal(t, "oracle-essbase-rest-exposed", f.ID)
	assert.Equal(t, plugins.SeverityLow, f.Severity)
	assert.NotEmpty(t, f.Description)
	assert.NotEmpty(t, f.Evidence)
	assert.Equal(t, "Oracle Essbase REST /about returned an Essbase-branded JSON document without credentials", f.Evidence)
}

// ---------------------------------------------------------------------------
// 1i-1j: Agent 1423 classifier and its sub-functions
// ---------------------------------------------------------------------------

func TestIsEssbaseAgent(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		expected bool
	}{
		{name: "empty (silence)", response: []byte{}, expected: false},
		{name: "short 3 bytes even if binary", response: []byte{0x00, 0x01, 0x02}, expected: false},
		{name: "HTTP status line", response: []byte("HTTP/1.1 200 OK"), expected: false},
		{name: "printable ASCII banner", response: []byte("220 svc ready\r\n"), expected: false},
		{
			name:     "mostly-printable, <25% non-printable",
			response: []byte("AAAAAAAAAAAAAAAAAAA\x00"), // 1/20 = 5%
			expected: false,
		},
		{
			name:     "exactly 4 bytes, all non-printable (boundary)",
			response: []byte{0x00, 0x01, 0x02, 0x03},
			expected: true,
		},
		{
			name:     "binary blob >=25% non-printable",
			response: []byte{0xDE, 0xAD, 'A', 'B'}, // 2/4 = 50%
			expected: true,
		},
		{
			name:     "binary with CR/LF whitespace not counted as non-printable",
			response: []byte{0xDE, 0xAD, 0xBE, '\n'}, // 3/4 non-printable
			expected: true,
		},
		{
			// TLS handshake record (0x16 0x03 ...): a TLS-fronted service on
			// 1423 answering the plaintext probe with a binary TLS record must
			// not be misclassified as the Agent.
			name:     "TLS handshake record is excluded",
			response: []byte{0x16, 0x03, 0x01, 0x00, 0x10, 0xAB, 0xCD, 0xEF, 0x01, 0x02},
			expected: false,
		},
		{
			// TLS alert record (0x15 0x03 ...): same exclusion, different
			// content-type byte.
			name:     "TLS alert record is excluded",
			response: []byte{0x15, 0x03, 0x03, 0x00, 0x02, 0x02, 0x28},
			expected: false,
		},
		{
			name:     "SSH banner is excluded",
			response: []byte("SSH-2.0-x"),
			expected: false,
		},
		{
			// A non-excluded binary blob (>=25% non-printable, len>=4, and not
			// matching any of the TLS/SSH/HTTP/printable-ASCII exclusions) must
			// still be classified true: the new exclusions must not regress the
			// existing positive signal.
			name:     "non-excluded binary blob still classified true",
			response: []byte{0x01, 0x02, 0xFF, 'A', 'B', 0xFE},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isEssbaseAgent(tt.response))
		})
	}
}

// TestHasBinaryContent covers the len==0 guard and boundary ratios that are
// not reachable through isEssbaseAgent (the minAgentResponse length gate
// short-circuits first).
func TestHasBinaryContent(t *testing.T) {
	tests := []struct {
		name     string
		b        []byte
		expected bool
	}{
		{name: "empty slice (len==0 guard)", b: []byte{}, expected: false},
		{name: "all printable", b: []byte("hello world"), expected: false},
		{name: ">=25% binary", b: []byte{0x00, 0x01, 'A', 'B'}, expected: true},
		{name: "<25% binary", b: []byte("AAAAAAAAAAAAAAAAAAA\x00"), expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasBinaryContent(tt.b))
		})
	}
}

// TestIsPrintableASCII covers the empty-input path (not reachable through
// isEssbaseAgent, which gates on length first).
func TestIsPrintableASCII(t *testing.T) {
	tests := []struct {
		name     string
		b        []byte
		expected bool
	}{
		{name: "empty slice", b: []byte{}, expected: true},
		{name: "printable with tab/CR/LF", b: []byte("abc\t\r\n"), expected: true},
		{name: "single non-printable byte", b: []byte{0x00}, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isPrintableASCII(tt.b))
		})
	}
}

func TestHasHTTPPrefix(t *testing.T) {
	tests := []struct {
		name     string
		b        []byte
		expected bool
	}{
		{name: "HTTP status line", b: []byte("HTTP/1.0 200 OK"), expected: true},
		{name: "GET request line is not an HTTP response prefix", b: []byte("GET /"), expected: false},
		{name: "empty slice", b: []byte{}, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasHTTPPrefix(tt.b))
		})
	}
}

func TestBuildEssbaseAgentProbe(t *testing.T) {
	assert.Equal(t, []byte("GET / HTTP/1.0\r\n\r\n"), buildEssbaseAgentProbe())
}

// ---------------------------------------------------------------------------
// 2a: Hyperion positives (one per strong marker)
// ---------------------------------------------------------------------------

func TestHyperionPlugin_Run_PositiveViaWorkspaceTitle(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspace/index.jsp":
			fmt.Fprint(w, `<html><head><title id="x" class="y">Enterprise Performance Management System Workspace</title></head></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, false)
	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleHyperion
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.False(t, payload.SharedServices)
	assert.False(t, payload.Planning)
	assert.False(t, payload.APS)
	assert.Equal(t, []string{"cpe:2.3:a:oracle:hyperion:*:*:*:*:*:*:*:*"}, payload.CPEs)
}

func TestHyperionPlugin_Run_PositiveViaBodyJSMarker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspace/index.jsp":
			fmt.Fprint(w, `<script>var f = BpmMainFrame;</script>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, false)
	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleHyperion
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Len(t, payload.CPEs, 1)
}

func TestHyperionPlugin_Run_PositiveViaSharedServices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/interop/":
			fmt.Fprint(w, "Hyperion Foundation Services console")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, false)
	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleHyperion
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.True(t, payload.SharedServices)
	assert.Equal(t, []string{"cpe:2.3:a:oracle:hyperion:*:*:*:*:*:*:*:*"}, payload.CPEs)
}

func TestHyperionPlugin_Run_PositiveViaEPMCookie(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspace/index.jsp":
			w.Header().Set("Set-Cookie", "EPMwvSess=xyz; Path=/")
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, false)
	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleHyperion
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Len(t, payload.CPEs, 1)
}

func TestHyperionPlugin_Run_EnrichPlanning(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspace/index.jsp":
			fmt.Fprint(w, `<title>Enterprise Performance Management System Workspace</title>`)
		case "/HyperionPlanning/":
			fmt.Fprint(w, "Oracle Hyperion Planning")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, false)
	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleHyperion
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.True(t, payload.Planning)
	assert.Equal(t, []string{
		"cpe:2.3:a:oracle:hyperion:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:hyperion_planning:*:*:*:*:*:*:*:*",
	}, payload.CPEs)
}

func TestHyperionPlugin_Run_EnrichAPS(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspace/index.jsp":
			fmt.Fprint(w, `<title>Enterprise Performance Management System Workspace</title>`)
		case "/aps/JAPI":
			fmt.Fprint(w, "Analytic Provider Services")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, false)
	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleHyperion
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.True(t, payload.APS)
	// APS adds no CPE of its own.
	assert.Len(t, payload.CPEs, 1)
}

// ---------------------------------------------------------------------------
// 2b: Hyperion negatives + self-reference
// ---------------------------------------------------------------------------

func TestHyperionPlugin_Run_NegativeGeneric(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "hello")
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, false)
	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestHyperionPlugin_Run_NegativeAll404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, false)
	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestHyperionPlugin_Run_NegativePathEcho(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "you requested %s", r.URL.Path)
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, false)
	require.NoError(t, err)
	assert.Nil(t, service, "a self-referential echo of the requested path must never be a false positive")
}

func TestHyperionPlugin_Run_EmptyBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspace/index.jsp":
			w.WriteHeader(http.StatusOK)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, false)
	require.NoError(t, err)
	assert.Nil(t, service)
}

// ---------------------------------------------------------------------------
// 2c: Essbase REST positives / negatives
// ---------------------------------------------------------------------------

func TestEssbasePlugin_Run_PositiveWithVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/essbase/rest/v1/about":
			fmt.Fprint(w, `{"name":"Essbase","version":"21.6.0.0.0"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &EssbasePlugin{}, server.URL, false)
	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleEssbase
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.True(t, payload.REST)
	assert.Equal(t, "21.6.0.0.0", service.Version)
	assert.Equal(t, []string{"cpe:2.3:a:oracle:essbase:21.6.0.0.0:*:*:*:*:*:*:*"}, payload.CPEs)
}

func TestEssbasePlugin_Run_MalformedJSON(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/essbase/rest/v1/about":
			fmt.Fprint(w, "<html>not json</html>")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &EssbasePlugin{}, server.URL, false)
	require.NoError(t, err)
	assert.Nil(t, service)
}

// TestEssbasePlugin_Run_HTMLPageEmbeddedNameSubstring is a regression test for
// the JSON-envelope gate exercised through the real HTTP path (real
// Content-Type header via detectEssbaseREST, not a hand-built
// essbaseRESTEvidence). An HTML error/docs page whose body happens to contain
// the literal substring "name":"Essbase", served with Content-Type: text/html
// and not starting with '{', must NOT be detected. Before the fix this was a
// false positive on the bare essbaseRestName regex match.
func TestEssbasePlugin_Run_HTMLPageEmbeddedNameSubstring(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/essbase/rest/v1/about":
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprint(w, `<html><body>Error: unknown field "name":"Essbase" in request</body></html>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &EssbasePlugin{}, server.URL, false)
	require.NoError(t, err)
	assert.Nil(t, service, "an HTML page merely containing the name:Essbase substring must never be detected")
}

// TestEssbasePlugin_Run_NameNoVersion verifies CURRENT behavior: a
// "name":"Essbase" body with no version is still detected, with a wildcard
// CPE and an empty service.Version. This deliberately diverges from the
// original ticket prose that expected "no detection"; the code was fixed to
// decouple detection (name gate only) from the best-effort version parse.
func TestEssbasePlugin_Run_NameNoVersion(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/essbase/rest/v1/about":
			fmt.Fprint(w, `{"name":"Essbase"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &EssbasePlugin{}, server.URL, false)
	require.NoError(t, err)
	require.NotNil(t, service, "name-only body must still be DETECTED with a wildcard CPE")

	var payload plugins.ServiceOracleEssbase
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.True(t, payload.REST)
	assert.Equal(t, "", service.Version)
	assert.Equal(t, []string{"cpe:2.3:a:oracle:essbase:*:*:*:*:*:*:*:*"}, payload.CPEs)
}

func TestEssbasePlugin_Run_BareOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/essbase/rest/v1/about":
			fmt.Fprint(w, "OK")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &EssbasePlugin{}, server.URL, false)
	require.NoError(t, err)
	assert.Nil(t, service)
}

// ---------------------------------------------------------------------------
// 2d: Anonymous gating (P0-6) - Hyperion & Essbase REST
// ---------------------------------------------------------------------------

func TestHyperion_Gating_MisconfigsFalse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspace/index.jsp":
			fmt.Fprint(w, `<title>Enterprise Performance Management System Workspace</title>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, false)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.False(t, service.AnonymousAccess)
	assert.Empty(t, service.SecurityFindings)
}

func TestHyperion_Gating_Misconfigs2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspace/index.jsp":
			fmt.Fprint(w, `<title>Enterprise Performance Management System Workspace</title>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, true)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.True(t, service.AnonymousAccess)
	require.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "oracle-hyperion-exposed", service.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityLow, service.SecurityFindings[0].Severity)
}

func TestHyperion_Gating_Misconfigs3xxLocation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspace/index.jsp":
			w.Header().Set("Set-Cookie", "EPM_ROOT=abc; Path=/")
			w.Header().Set("Location", "/login")
			w.WriteHeader(http.StatusFound)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, true)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.True(t, service.AnonymousAccess)
	require.Len(t, service.SecurityFindings, 1)
}

func TestHyperion_Gating_Misconfigs403Marker(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/interop/":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Hyperion Shared Services")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, true)
	require.NoError(t, err)
	require.NotNil(t, service, "the branded 403 still proves detection")
	assert.False(t, service.AnonymousAccess, "a 403 response must not count as anonymous exposure")
	assert.Empty(t, service.SecurityFindings)
}

func TestEssbaseREST_Gating_MisconfigsFalse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/essbase/rest/v1/about":
			fmt.Fprint(w, `{"name":"Essbase","version":"21.6.0.0.0"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &EssbasePlugin{}, server.URL, false)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.False(t, service.AnonymousAccess)
	assert.Empty(t, service.SecurityFindings)
}

func TestEssbaseREST_Gating_Misconfigs2xx(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/essbase/rest/v1/about":
			fmt.Fprint(w, `{"name":"Essbase","version":"21.6.0.0.0"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &EssbasePlugin{}, server.URL, true)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.True(t, service.AnonymousAccess)
	require.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "oracle-essbase-rest-exposed", service.SecurityFindings[0].ID)
}

func TestEssbaseREST_Gating_Misconfigs403(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/essbase/rest/v1/about":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `{"name":"Essbase","version":"21.6.0.0.0"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &EssbasePlugin{}, server.URL, true)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.False(t, service.AnonymousAccess)
	assert.Empty(t, service.SecurityFindings)
}

// ---------------------------------------------------------------------------
// 2e: TLS variants + CheckTLS
// ---------------------------------------------------------------------------

func TestHyperionTLSPlugin_Run_Positive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspace/index.jsp":
			fmt.Fprint(w, `<title>Enterprise Performance Management System Workspace</title>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionTLSPlugin{}, server.URL, false)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.True(t, service.TLS)
	assert.Equal(t, "tcptls", service.Transport)

	var payload plugins.ServiceOracleHyperion
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Len(t, payload.CPEs, 1)
}

func TestHyperionTLSPlugin_Run_Gating(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspace/index.jsp":
			fmt.Fprint(w, `<title>Enterprise Performance Management System Workspace</title>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionTLSPlugin{}, server.URL, true)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.True(t, service.AnonymousAccess)
	// CheckTLS(conn) on a plain (non-tls.Conn) connection returns nil, so no
	// TLS finding is appended: exactly the anonymous-exposure finding.
	require.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "oracle-hyperion-exposed", service.SecurityFindings[0].ID)
}

func TestEssbaseTLSPlugin_Run_Positive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/essbase/rest/v1/about":
			fmt.Fprint(w, `{"name":"Essbase","version":"21.6.0.0.0"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &EssbaseTLSPlugin{}, server.URL, false)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.True(t, service.TLS)
	assert.Equal(t, "tcptls", service.Transport)
	assert.Equal(t, "21.6.0.0.0", service.Version)
}

func TestEssbaseTLSPlugin_Run_Gating(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/essbase/rest/v1/about":
			fmt.Fprint(w, `{"name":"Essbase","version":"21.6.0.0.0"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &EssbaseTLSPlugin{}, server.URL, true)
	require.NoError(t, err)
	require.NotNil(t, service)
	assert.True(t, service.AnonymousAccess)
	require.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "oracle-essbase-rest-exposed", service.SecurityFindings[0].ID)
}

// ---------------------------------------------------------------------------
// 2f: Robustness (HTTP path)
// ---------------------------------------------------------------------------

func TestHyperionPlugin_Run_ConnectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)

	server.Close()
	conn.Close()

	target := plugins.Target{Host: addr.Addr().String(), Address: addr}
	plugin := &HyperionPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestHyperionPlugin_Run_MalformedHTTP(t *testing.T) {
	port := startGarbageServer(t, []byte("\x00\xff not http"))
	addr := netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port))
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	target := plugins.Target{Host: "127.0.0.1", Address: addr}
	plugin := &HyperionPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestEssbasePlugin_Run_ConnectionError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)

	server.Close()
	conn.Close()

	target := plugins.Target{Host: addr.Addr().String(), Address: addr}
	plugin := &EssbasePlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestHyperionPlugin_Run_RedirectNotFollowed(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspace/index.jsp":
			w.Header().Set("Location", "/real")
			w.WriteHeader(http.StatusFound)
		case "/real":
			fmt.Fprint(w, `<title>Enterprise Performance Management System Workspace</title>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	service, err := runPlugin(t, &HyperionPlugin{}, server.URL, false)
	require.NoError(t, err)
	assert.Nil(t, service, "the branded /real response must never be fetched since redirects are not followed")
}

// ---------------------------------------------------------------------------
// 3: Essbase Agent (TCP 1423) loopback integration
// ---------------------------------------------------------------------------

// agentTestTimeout is a short read deadline so the silence case fails fast
// instead of blocking for a full production timeout. Assertions below use
// bound-based timing (elapsed < N*agentTestTimeout), not fixed wall-clock
// values, to avoid -race flakiness.
const agentTestTimeout = 300 * time.Millisecond

func TestEssbaseAgent_Run_SilentServer(t *testing.T) {
	port := startAgentLoopback(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf) // best-effort drain of the probe
		// Hold the connection open (write nothing) well past the client's
		// read deadline so Recv observes a genuine timeout, not EOF.
		time.Sleep(4 * agentTestTimeout)
	})
	conn, target := dialAgent(t, port)

	start := time.Now()
	plugin := &EssbaseAgentPlugin{}
	service, err := plugin.Run(conn, agentTestTimeout, target)
	elapsed := time.Since(start)

	assert.Nil(t, service)
	assert.NoError(t, err)
	assert.Less(t, elapsed, 3*agentTestTimeout, "Run should return promptly once the read deadline fires")
}

func TestEssbaseAgent_Run_BinaryBlob(t *testing.T) {
	port := startAgentLoopback(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
		// Keep the connection open briefly after the write so the close does
		// not race the client's read of the buffered bytes.
		time.Sleep(50 * time.Millisecond)
	})
	conn, target := dialAgent(t, port)

	plugin := &EssbaseAgentPlugin{}
	service, err := plugin.Run(conn, agentTestTimeout, target)

	require.NoError(t, err)
	require.NotNil(t, service)

	var payload plugins.ServiceOracleEssbase
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.True(t, payload.AgentListener)
	assert.Equal(t, []string{"cpe:2.3:a:oracle:essbase:*:*:*:*:*:*:*:*"}, payload.CPEs)
	assert.Equal(t, "", service.Version)
	assert.Equal(t, plugins.ProtoOracleEssbase, service.Protocol)
	assert.False(t, service.AnonymousAccess)
	assert.Empty(t, service.SecurityFindings)
}

func TestEssbaseAgent_Run_HTTPResponse(t *testing.T) {
	port := startAgentLoopback(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("HTTP/1.0 200 OK\r\n\r\n"))
		time.Sleep(50 * time.Millisecond)
	})
	conn, target := dialAgent(t, port)

	plugin := &EssbaseAgentPlugin{}
	service, err := plugin.Run(conn, agentTestTimeout, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestEssbaseAgent_Run_ASCIIBanner(t *testing.T) {
	port := startAgentLoopback(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte("220 essbase-ish banner\r\n"))
		time.Sleep(50 * time.Millisecond)
	})
	conn, target := dialAgent(t, port)

	plugin := &EssbaseAgentPlugin{}
	service, err := plugin.Run(conn, agentTestTimeout, target)

	require.NoError(t, err)
	assert.Nil(t, service)
}

func TestEssbaseAgent_Run_BinaryBlob_MisconfigsTrue(t *testing.T) {
	port := startAgentLoopback(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
		time.Sleep(50 * time.Millisecond)
	})
	conn, target := dialAgent(t, port)
	target.Misconfigs = true

	plugin := &EssbaseAgentPlugin{}
	service, err := plugin.Run(conn, agentTestTimeout, target)

	require.NoError(t, err)
	require.NotNil(t, service)
	// The agent path never sets AnonymousAccess or a SecurityFinding,
	// regardless of Misconfigs: confidence is too low to make a security
	// claim, and nothing was accessed or authenticated.
	assert.False(t, service.AnonymousAccess)
	assert.Empty(t, service.SecurityFindings)
}

// TestEssbaseAgent_Run_ConnectionClosedImmediately is a regression test for
// the fix described in the file header: Run() swallows ALL SendRecv errors
// (including the ReadError that results from an EOF on an immediately-closed
// peer) and always returns (nil, nil), never (nil, err).
func TestEssbaseAgent_Run_ConnectionClosedImmediately(t *testing.T) {
	port := startAgentLoopback(t, func(conn net.Conn) {
		_ = conn.Close()
	})
	conn, target := dialAgent(t, port)

	plugin := &EssbaseAgentPlugin{}
	service, err := plugin.Run(conn, agentTestTimeout, target)

	assert.Nil(t, service)
	assert.NoError(t, err, "an immediately-closed peer must yield (nil, nil), never (nil, err)")
}

// TestEssbaseAgent_Run_DisabledByEssbaseAgentEnabled is a regression test for
// the essbaseAgentEnabled kill-switch: when it is flipped to false, Run must
// return (nil, nil) immediately, even for a reply that would otherwise be
// classified as the Agent by isEssbaseAgent (a genuinely binary blob). The
// target built by dialAgent has Address.Port() == EssbaseAgentPort, so the
// port gate added in LAB-5054/PR#383 is satisfied and the nil result here is
// attributable to the essbaseAgentEnabled toggle alone, not the port gate.
func TestEssbaseAgent_Run_DisabledByEssbaseAgentEnabled(t *testing.T) {
	original := essbaseAgentEnabled
	essbaseAgentEnabled = func() bool { return false }
	t.Cleanup(func() { essbaseAgentEnabled = original })

	port := startAgentLoopback(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
		time.Sleep(50 * time.Millisecond)
	})
	conn, target := dialAgent(t, port)

	plugin := &EssbaseAgentPlugin{}
	service, err := plugin.Run(conn, agentTestTimeout, target)

	assert.Nil(t, service, "Run must return nil when essbaseAgentEnabled is false, even for an otherwise-detecting reply")
	assert.NoError(t, err)
}

// TestEssbaseAgent_Run_EnabledByDefaultStillDetects confirms the default
// (essbaseAgentEnabled == true) path is unaffected by the kill-switch and
// still detects a genuinely binary reply, given a target on EssbaseAgentPort
// (dialAgent fixes target.Address.Port() at 1423, satisfying the LAB-5054/
// PR#383 port gate). This complements
// TestEssbaseAgent_Run_DisabledByEssbaseAgentEnabled to prove the toggle only
// suppresses detection when explicitly flipped off.
func TestEssbaseAgent_Run_EnabledByDefaultStillDetects(t *testing.T) {
	require.True(t, essbaseAgentEnabled(), "essbaseAgentEnabled must default to true")

	port := startAgentLoopback(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
		time.Sleep(50 * time.Millisecond)
	})
	conn, target := dialAgent(t, port)

	plugin := &EssbaseAgentPlugin{}
	service, err := plugin.Run(conn, agentTestTimeout, target)

	require.NoError(t, err)
	require.NotNil(t, service)
}

// TestEssbaseAgent_Run_PortGate_NonAgentPortSuppressed is a regression test
// for the port-gating fix (LAB-5054, PR #383): EssbaseAgentPlugin.Run must
// return (nil, nil) when target.Address.Port() is anything other than
// EssbaseAgentPort (1423), even for a reply that would otherwise be
// classified as the Agent by isEssbaseAgent (a genuinely binary blob), and
// even though essbaseAgentEnabled defaults to true. This proves the port gate
// closes the false-positive window where slow-lane TCP scans
// (pkg/scan/simple_scan.go) invoke every plugin's Run regardless of
// PortPriority, applying the weak binary-reply heuristic to arbitrary ports.
func TestEssbaseAgent_Run_PortGate_NonAgentPortSuppressed(t *testing.T) {
	require.True(t, essbaseAgentEnabled(), "essbaseAgentEnabled must default to true")

	port := startAgentLoopback(t, func(conn net.Conn) {
		defer conn.Close()
		buf := make([]byte, 64)
		_, _ = conn.Read(buf)
		_, _ = conn.Write([]byte{0xDE, 0xAD, 0xBE, 0xEF})
		time.Sleep(50 * time.Millisecond)
	})
	const nonAgentPort = 8080
	conn, target := dialAgentAtTargetPort(t, port, nonAgentPort)

	plugin := &EssbaseAgentPlugin{}
	service, err := plugin.Run(conn, agentTestTimeout, target)

	assert.Nil(t, service, "Run must suppress detection when target.Address.Port() is not EssbaseAgentPort")
	assert.NoError(t, err)
}

// ---------------------------------------------------------------------------
// 4: Metadata tests (all five plugins)
// ---------------------------------------------------------------------------

func TestPluginMetadata(t *testing.T) {
	t.Run("HyperionPlugin", func(t *testing.T) {
		p := &HyperionPlugin{}
		assert.Equal(t, OracleHyperion, p.Name())
		assert.Equal(t, plugins.TCP, p.Type())
		assert.Equal(t, -1, p.Priority())
		assert.True(t, p.PortPriority(DefaultHyperionPort))
		assert.False(t, p.PortPriority(443))
		assert.False(t, p.PortPriority(80))
		assert.False(t, p.PortPriority(DefaultHyperionSecurePort))
	})

	t.Run("HyperionTLSPlugin", func(t *testing.T) {
		p := &HyperionTLSPlugin{}
		assert.Equal(t, OracleHyperion, p.Name())
		assert.Equal(t, plugins.TCPTLS, p.Type())
		assert.Equal(t, -1, p.Priority())
		assert.True(t, p.PortPriority(443))
		assert.False(t, p.PortPriority(DefaultHyperionPort))
		assert.False(t, p.PortPriority(80))
		assert.True(t, p.PortPriority(DefaultHyperionSecurePort))
	})

	t.Run("EssbasePlugin", func(t *testing.T) {
		p := &EssbasePlugin{}
		assert.Equal(t, OracleEssbase, p.Name())
		assert.Equal(t, plugins.TCP, p.Type())
		assert.Equal(t, -1, p.Priority())
		assert.True(t, p.PortPriority(DefaultEssbaseRESTPort))
		assert.False(t, p.PortPriority(EssbaseRESTPortAlt))
		assert.False(t, p.PortPriority(443))
		assert.False(t, p.PortPriority(80))
	})

	t.Run("EssbaseTLSPlugin", func(t *testing.T) {
		p := &EssbaseTLSPlugin{}
		assert.Equal(t, OracleEssbase, p.Name())
		assert.Equal(t, plugins.TCPTLS, p.Type())
		assert.Equal(t, -1, p.Priority())
		assert.True(t, p.PortPriority(443))
		assert.False(t, p.PortPriority(DefaultEssbaseRESTPort))
		assert.True(t, p.PortPriority(EssbaseRESTPortAlt))
	})

	t.Run("EssbaseAgentPlugin", func(t *testing.T) {
		p := &EssbaseAgentPlugin{}
		// Distinct registry name: the framework keys the plugin registry on
		// {Name, Protocol}, so this TCP plugin cannot share OracleEssbase's
		// name with the TCP EssbasePlugin.
		assert.Equal(t, "oracle_essbase_agent", p.Name())
		assert.Equal(t, OracleEssbaseAgent, p.Name())
		assert.Equal(t, plugins.TCP, p.Type())
		assert.Equal(t, 900, p.Priority())
		assert.True(t, p.PortPriority(EssbaseAgentPort))
		assert.False(t, p.PortPriority(DefaultEssbaseRESTPort))
		assert.False(t, p.PortPriority(443))
	})
}

// ---------------------------------------------------------------------------
// 5: Service struct Type() + JSON round-trip
// ---------------------------------------------------------------------------

func TestServiceTypes(t *testing.T) {
	assert.Equal(t, plugins.ProtoOracleHyperion, plugins.ServiceOracleHyperion{}.Type())
	assert.Equal(t, plugins.ProtoOracleEssbase, plugins.ServiceOracleEssbase{}.Type())
}

func TestServiceRoundTrip(t *testing.T) {
	t.Run("ServiceOracleHyperion", func(t *testing.T) {
		original := plugins.ServiceOracleHyperion{
			SharedServices: true,
			Planning:       true,
			APS:            true,
			CPEs:           []string{"cpe:2.3:a:oracle:hyperion:*:*:*:*:*:*:*:*"},
		}
		b, err := json.Marshal(original)
		require.NoError(t, err)

		var roundTripped plugins.ServiceOracleHyperion
		require.NoError(t, json.Unmarshal(b, &roundTripped))
		assert.Equal(t, original, roundTripped)
	})

	t.Run("ServiceOracleEssbase REST", func(t *testing.T) {
		original := plugins.ServiceOracleEssbase{
			REST: true,
			CPEs: []string{"cpe:2.3:a:oracle:essbase:21.6.0.0.0:*:*:*:*:*:*:*"},
		}
		b, err := json.Marshal(original)
		require.NoError(t, err)

		var roundTripped plugins.ServiceOracleEssbase
		require.NoError(t, json.Unmarshal(b, &roundTripped))
		assert.Equal(t, original, roundTripped)
	})

	t.Run("ServiceOracleEssbase AgentListener", func(t *testing.T) {
		original := plugins.ServiceOracleEssbase{
			AgentListener: true,
			CPEs:          []string{"cpe:2.3:a:oracle:essbase:*:*:*:*:*:*:*:*"},
		}
		b, err := json.Marshal(original)
		require.NoError(t, err)

		var roundTripped plugins.ServiceOracleEssbase
		require.NoError(t, json.Unmarshal(b, &roundTripped))
		assert.Equal(t, original, roundTripped)
	})

	t.Run("zero-value ServiceOracleHyperion omits all fields", func(t *testing.T) {
		b, err := json.Marshal(plugins.ServiceOracleHyperion{})
		require.NoError(t, err)
		output := string(b)
		assert.NotContains(t, output, `"shared_services"`)
		assert.NotContains(t, output, `"planning"`)
		assert.NotContains(t, output, `"aps"`)
		assert.NotContains(t, output, `"cpes"`)
	})
}
