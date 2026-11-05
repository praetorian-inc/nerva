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

func TestIsAnonymousExposure(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		expected bool
	}{
		{name: "200 OK", status: http.StatusOK, expected: true},
		{name: "204 boundary", status: 204, expected: true},
		{name: "299 boundary", status: 299, expected: true},
		{name: "301 moved permanently is not anonymous exposure", status: http.StatusMovedPermanently, expected: false},
		{name: "302 found is not anonymous exposure", status: http.StatusFound, expected: false},
		{name: "303 see other is not anonymous exposure", status: http.StatusSeeOther, expected: false},
		{name: "307 temporary redirect is not anonymous exposure", status: http.StatusTemporaryRedirect, expected: false},
		{name: "308 permanent redirect is not anonymous exposure", status: http.StatusPermanentRedirect, expected: false},
		{name: "401 is not anonymous exposure", status: http.StatusUnauthorized, expected: false},
		{name: "403 is not anonymous exposure", status: http.StatusForbidden, expected: false},
		{name: "404 is not anonymous exposure", status: http.StatusNotFound, expected: false},
		{name: "500 is not anonymous exposure", status: http.StatusInternalServerError, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, isAnonymousExposure(tt.status))
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
			name:         "S3 via redirect Location is detected without anon exposure",
			evs:          []hyperionEvidence{hEv("/interop/", http.StatusFound, "/x?app=Hyperion Shared Services", "", "")},
			wantSS:       true,
			wantDetected: true,
			wantAnon:     false,
		},
		{
			// Regression (LAB-5054 follow-up): evaluateHyperion now URL-decodes
			// ev.location before the Shared Services marker check, so a
			// percent-encoded redirect Location (spaces as %20) still matches
			// even though the raw bytes never contain the literal "Shared
			// Services" substring.
			name:         "S3 via URL-encoded redirect Location (percent-encoded spaces) is detected without anon exposure",
			evs:          []hyperionEvidence{hEv("/interop/", http.StatusFound, "/interop/?app=Hyperion%20Shared%20Services", "", "")},
			wantSS:       true,
			wantDetected: true,
			wantAnon:     false,
		},
		{
			// Negative counterpart: a percent-encoded redirect Location that
			// decodes to nothing but a reflected probe path (no Shared Services
			// marker text) must not be detected merely because it carries '%'
			// escapes.
			name:         "percent-encoded redirect Location with only the reflected probe path is not detected",
			evs:          []hyperionEvidence{hEv("/interop/", http.StatusFound, "/interop/%3Fpath%3Dworkspace", "", "")},
			wantDetected: false,
		},
		{
			// Regression (LAB-5054 follow-up): evaluateHyperion now url.Parse's
			// ev.location and decodes the PATH and QUERY separately. A '+' that
			// falls in the QUERY string (this location's "?app=..." segment) is
			// a query space-encoding convention, so it IS decoded to a space via
			// url.QueryUnescape and the Shared Services marker now matches. This
			// supersedes the previous PathUnescape-only behavior, which wrongly
			// left every '+' - including query-string ones - undecoded.
			name:         "'+' in the QUERY portion of a redirect Location is decoded to a space (detected)",
			evs:          []hyperionEvidence{hEv("/interop/", http.StatusFound, "/interop/?app=Hyperion+Shared+Services", "", "")},
			wantSS:       true,
			wantDetected: true,
			wantAnon:     false,
		},
		{
			// Negative counterpart: a literal '+' in the PATH portion of a
			// redirect Location (no query string at all) must stay literal.
			// Paths do not use '+' as a space-encoding convention (that is a
			// query-string-only rule), so url.Parse's decoded u.Path keeps the
			// '+' verbatim, the marker's required space never appears, and
			// detection must stay false.
			name:         "literal '+' in the PATH portion of a redirect Location is not decoded to a space",
			evs:          []hyperionEvidence{hEv("/interop/", http.StatusFound, "/interop/Hyperion+Shared+Services", "", "")},
			wantDetected: false,
		},
		{
			name:         "S4 EPM cookie on 302 with Location is detected without anon exposure",
			evs:          []hyperionEvidence{hEv("/workspace/index.jsp", http.StatusFound, "/login", "", "EPM_ROOT=a; Path=/")},
			wantDetected: true,
			wantAnon:     false,
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
			// Regression (LAB-5054 follow-up): essbaseVersionShape was widened
			// from a capped `{1,4}` repeat to an unbounded `{1,}` repeat so a
			// 6-component version is no longer dropped.
			name:         "valid JSON name:Essbase with 6-component version (unbounded shape accepts an extra component)",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":"21.6.0.0.0.1"}`},
			wantREST:     true,
			wantVersion:  "21.6.0.0.0.1",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name:         "valid JSON name:Essbase with 5-component version",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":"21.6.0.0.0"}`},
			wantREST:     true,
			wantVersion:  "21.6.0.0.0",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name:         "valid JSON name:Essbase with 4-component version",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":"21.2.3.0"}`},
			wantREST:     true,
			wantVersion:  "21.2.3.0",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name:         "valid JSON name:Essbase with 3-component version",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":"21.2.3"}`},
			wantREST:     true,
			wantVersion:  "21.2.3",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			// 2-component version is the lower bound accepted by
			// essbaseVersionShape (1 initial digit run plus a minimum of 1
			// additional `.digits` group).
			name:         "valid JSON name:Essbase with 2-component version (lower bound)",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":"21.2"}`},
			wantREST:     true,
			wantVersion:  "21.2",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			// Detection is gated ONLY on the name field via json.Unmarshal, not
			// on the version shape. A name-only body is still detected, with
			// version left empty (the CPE builder emits the wildcard version).
			name:         "valid JSON name:Essbase, no version: still detected, version stays empty",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase"}`},
			wantREST:     true,
			wantVersion:  "",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			// A single-component version ("21", no dot) fails
			// essbaseVersionShape (which requires at least one additional
			// `.digits` group) and is dropped; detection still succeeds via the
			// name gate alone.
			name:         "bad version shape (single component) is dropped, detection still succeeds",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":"21"}`},
			wantREST:     true,
			wantVersion:  "",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			// essbaseVersionShape is fully anchored (^...$), so
			// attacker-controlled bytes after the digits (e.g. CPE separators)
			// make the whole shape check miss; version stays empty rather than
			// being truncated.
			name:         "attacker-controlled version with CPE separators fails the version shape",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":"1.2.3.4:*:evil"}`},
			wantREST:     true,
			wantVersion:  "",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			// Regression (LAB-5054 review, Gemini): the decoupled best-effort
			// version field is json.RawMessage, so a server that returns a NUMERIC
			// "version" (rather than a string) no longer fails json.Unmarshal and
			// abort core product detection. Essbase is still detected; the numeric
			// version is dropped (essbaseVersion yields "" for a non-string token).
			name:         "numeric version does not abort detection; version dropped",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":21}`},
			wantREST:     true,
			wantVersion:  "",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			// A non-string JSON version of any shape (here an object) is likewise
			// tolerated: detection succeeds, version is dropped.
			name:         "object version does not abort detection; version dropped",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":{"major":21}}`},
			wantREST:     true,
			wantVersion:  "",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name:         "null version does not abort detection; version dropped",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase","version":null}`},
			wantREST:     true,
			wantVersion:  "",
			wantDetected: true,
			wantAnon:     true,
		},
		{
			name:         "valid JSON but non-Essbase name is not detected",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Something"}`},
			wantREST:     false,
			wantVersion:  "",
			wantDetected: false,
			wantAnon:     false,
		},
		{
			name:         "valid JSON with no name field is not detected",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"product":"Essbase 21c"}`},
			wantREST:     false,
			wantVersion:  "",
			wantDetected: false,
			wantAnon:     false,
		},
		{
			// json.Unmarshal fails on a truncated/malformed body, so the name
			// gate can never be reached.
			name:         "malformed/truncated JSON body is not detected",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `{"name":"Essbase"`},
			wantREST:     false,
			wantVersion:  "",
			wantDetected: false,
			wantAnon:     false,
		},
		{
			name:         "non-JSON body is not detected",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `not json`},
			wantREST:     false,
			wantVersion:  "",
			wantDetected: false,
			wantAnon:     false,
		},
		{
			name:         "empty body is not detected",
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
			name:         "name and version on 302 is detected without anon exposure",
			ev:           essbaseRESTEvidence{statusCode: http.StatusFound, body: `{"name":"Essbase","version":"21.6.0.0.0"}`},
			wantREST:     true,
			wantVersion:  "21.6.0.0.0",
			wantDetected: true,
			wantAnon:     false,
		},
		{
			// Regression: an HTML page whose body merely happens to contain the
			// literal substring "name":"Essbase" (e.g. an error/docs page) must
			// NOT be detected: json.Unmarshal fails on the non-JSON HTML body,
			// so the name gate is never reached.
			name:         "HTML page with embedded name:Essbase substring is not detected",
			ev:           essbaseRESTEvidence{statusCode: http.StatusOK, body: `<html><body>Error: unknown field "name":"Essbase" in request</body></html>`},
			wantREST:     false,
			wantVersion:  "",
			wantDetected: false,
			wantAnon:     false,
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
		{
			// Regression (LAB-5054 follow-up): a 6-component version (now
			// accepted by the unbounded essbaseVersionShape) embeds into the CPE
			// exactly like any other shape-validated version.
			name:     "6-component version embedded exactly",
			version:  "21.6.0.0.0.1",
			expected: []string{"cpe:2.3:a:oracle:essbase:21.6.0.0.0.1:*:*:*:*:*:*:*"},
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

// TestEssbasePlugin_Run_HTMLPageEmbeddedNameSubstring is a regression test
// exercised through the real HTTP path (via detectEssbaseREST, not a
// hand-built essbaseRESTEvidence). An HTML error/docs page whose body happens
// to contain the literal substring "name":"Essbase" must NOT be detected:
// json.Unmarshal fails on the non-JSON HTML body, so the name gate is never
// reached.
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
	require.NotNil(t, service, "the EPM cookie on a 302 still proves detection")
	assert.False(t, service.AnonymousAccess, "a redirect is no longer anonymous access")
	assert.Empty(t, service.SecurityFindings)
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

// tlsDialTarget starts a REAL TLS connection against an httptest.NewTLSServer
// and builds the plugins.Target a scanner would hand to a TLSPlugin. In
// production the scanner completes the TLS handshake itself and invokes
// Run() with an already-established *tls.Conn; the plugin's HTTP client then
// speaks plaintext HTTP framing over that connection (see
// createHTTPClient's DialContext, which always returns the caller-supplied
// conn verbatim, TLS or not). Misconfigs is always true here so that
// CheckTLS(conn) - which type-asserts conn.(*tls.Conn) - actually runs
// against a live tls.Conn instead of hitting its plain-conn nil short-circuit.
func tlsDialTarget(t *testing.T, serverURL string) (*tls.Conn, plugins.Target) {
	t.Helper()
	hostPort := strings.TrimPrefix(serverURL, "https://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	addr := netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))

	tlsConn, err := tls.Dial("tcp", hostPort, &tls.Config{InsecureSkipVerify: true})
	require.NoError(t, err)
	t.Cleanup(func() { _ = tlsConn.Close() })

	target := plugins.Target{
		Host:       addr.Addr().String(),
		Address:    addr,
		Misconfigs: true,
	}
	return tlsConn, target
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

// TestHyperionTLSPlugin_Run_RealTLSConn is regression coverage for the
// reviewer-flagged gap in PR #383/LAB-5054: TestHyperionTLSPlugin_Run_Positive
// and TestHyperionTLSPlugin_Run_Gating above only prove the TLS metadata
// flags (TLS==true, Transport=="tcptls") over a PLAINTEXT httptest.NewServer
// conn, never a real *tls.Conn. This test drives HyperionTLSPlugin.Run
// against an httptest.NewTLSServer over a real tls.Dial connection, so both
// the HTTP-over-TLS transport (createHTTPClient's Transport reusing the
// *tls.Conn across the multiple GETs detectHyperion issues) and the
// CheckTLS(conn) type assertion (conn.(*tls.Conn)) are actually exercised,
// not merely the CreateServiceFrom metadata plumbing.
func TestHyperionTLSPlugin_Run_RealTLSConn(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/workspace/index.jsp":
			fmt.Fprint(w, `<title>Enterprise Performance Management System Workspace</title>`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tlsConn, target := tlsDialTarget(t, server.URL)

	service, err := (&HyperionTLSPlugin{}).Run(tlsConn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service, "detection must succeed over a real *tls.Conn, proving the HTTP-over-TLS transport works")
	assert.True(t, service.TLS)
	assert.Equal(t, "tcptls", service.Transport)

	var payload plugins.ServiceOracleHyperion
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.Len(t, payload.CPEs, 1)

	// Misconfigs=true + a 200 OK anonymous response + a real *tls.Conn means
	// both the anonymous-exposure finding AND CheckTLS(conn)'s findings (if
	// any, given httptest's self-signed cert) are appended. Deliberately not
	// asserting on the exact set/count of CheckTLS findings - only that the
	// call path completed and the exposure finding it appends alongside is
	// still present.
	assert.True(t, service.AnonymousAccess)
	assert.True(t, hasFindingID(service.SecurityFindings, "oracle-hyperion-exposed"),
		"the anonymous-exposure finding must be present alongside whatever CheckTLS(conn) appended")
}

// TestEssbaseTLSPlugin_Run_RealTLSConn mirrors
// TestHyperionTLSPlugin_Run_RealTLSConn for EssbaseTLSPlugin: it drives
// Run() against an httptest.NewTLSServer over a real tls.Dial connection so
// the HTTP-over-TLS transport and CheckTLS(conn)'s conn.(*tls.Conn) type
// assertion are exercised for the Essbase REST detection path too, not just
// the plaintext-conn TLS metadata coverage in
// TestEssbaseTLSPlugin_Run_Positive / TestEssbaseTLSPlugin_Run_Gating above.
func TestEssbaseTLSPlugin_Run_RealTLSConn(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/essbase/rest/v1/about":
			fmt.Fprint(w, `{"name":"Essbase","version":"21.2.3.0.0"}`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tlsConn, target := tlsDialTarget(t, server.URL)

	service, err := (&EssbaseTLSPlugin{}).Run(tlsConn, 5*time.Second, target)
	require.NoError(t, err)
	require.NotNil(t, service, "detection must succeed over a real *tls.Conn, proving the HTTP-over-TLS transport works")
	assert.True(t, service.TLS)
	assert.Equal(t, "tcptls", service.Transport)
	assert.Equal(t, "21.2.3.0.0", service.Version)

	var payload plugins.ServiceOracleEssbase
	require.NoError(t, json.Unmarshal(service.Raw, &payload))
	assert.True(t, payload.REST)

	// Same reasoning as the Hyperion counterpart above: assert the call path
	// through CheckTLS(conn) completed and the exposure finding survives
	// alongside it, without over-asserting CheckTLS's own finding contents.
	assert.True(t, service.AnonymousAccess)
	assert.True(t, hasFindingID(service.SecurityFindings, "oracle-essbase-rest-exposed"),
		"the anonymous-exposure finding must be present alongside whatever CheckTLS(conn) appended")
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
// 4: Metadata tests (all four plugins)
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
