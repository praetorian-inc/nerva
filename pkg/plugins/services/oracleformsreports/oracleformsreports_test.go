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

package oracleformsreports

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// --- Pure helper unit tests ---

func TestHasFormsMarker(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"applet main class", `<applet code="oracle.forms.engine.Main">`, true},
		{"frmall.jar archive", `archive="frmall.jar"`, true},
		{"base HTML provenance comment", `<!-- FILE: webutiljpi.htm (Oracle Forms) -->`, true},
		{"branded Forms Services text", `Oracle Fusion Middleware Forms Services`, true},
		{"FRM-9xxxx error code", `FRM-92050 failed to connect to the Forms server`, true},
		{"FRM code below threshold is not matched", `FRM-401: field must be entered`, false},
		{"bare frmservlet path echo is not a marker", `/forms/frmservlet not found`, false},
		{"generic login page", `<html><body>please log in</body></html>`, false},
		{"empty body", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasFormsMarker(tt.body))
		})
	}
}

func TestHasReportsMarker(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"REP error code", `REP-52251: Cannot get output`, true},
		{"branded Oracle Reports title", `<title>Oracle Reports</title>`, true},
		{"Reports Servlet text", `Reports Servlet Command`, true},
		// Regression (PR #374 round-4): the generic Ora* CSS classes no longer
		// classify Reports on their own — they appear on many Fusion Middleware
		// diagnostic/error pages, so a non-Reports Oracle app would otherwise be
		// misclassified. These cases are kept as negative regression guards.
		{"Oracle diagnostic CSS class OraInstructionText alone is not a marker", `<span class="OraInstructionText">`, false},
		{"Oracle diagnostic CSS class OraDataText alone is not a marker", `<td class="OraDataText">value</td>`, false},
		{"Oracle diagnostic CSS class OraTableCellText alone is not a marker", `<td class="OraTableCellText">value</td>`, false},
		{"bare rwservlet path echo is not a marker", `/reports/rwservlet not found`, false},
		{"echoed sub-path tokens are not markers", `<a href="rwservlet/showenv">showenv</a><a href="rwservlet/getserverinfo">getserverinfo</a>`, false},
		{"unrelated body", "hello world", false},
		{"empty body", "", false},
		// Regression (PR #374 round-4): an Ora*-CSS body that ALSO carries a REP-
		// code or the branded "Oracle Reports" text must still detect — the Ora*
		// classes are simply non-classifying, not disqualifying.
		{"Ora* CSS classes plus REP- code => still detected", `<span class="OraInstructionText">error</span> REP-12345`, true},
		{"Ora* CSS classes plus Oracle Reports text => still detected", `<span class="OraDataText">Oracle Reports</span>`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasReportsMarker(tt.body))
		})
	}
}

func TestParseReportsVersion(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{"XML serverInfo attribute", `<serverInfo name="repserv" version="10.1.2.0.2">`, "10.1.2.0.2"},
		{"HTML version label", `<td>Version: 12.2.1.4.0</td>`, "12.2.1.4.0"},
		{"no version present", `<serverInfo name="repserv">`, ""},
		{"empty body", "", ""},
		// Regression (M1): getserverinfo XML responses begin with an XML
		// declaration ("<?xml version='1.0' ...?>") whose two-segment "1.0" must
		// NOT be mis-extracted as the Reports version; the real three-segment
		// serverInfo version attribute later in the body must win instead.
		{"XML declaration prefix does not shadow the real serverInfo version", `<?xml version='1.0' encoding="UTF-8"?><serverInfo name="repserv" version="10.1.2.0.2">`, "10.1.2.0.2"},
		{"bare two-segment XML declaration version with no serverInfo version => no match", `<?xml version='1.0' encoding="UTF-8"?><serverInfo name="repserv">`, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, parseReportsVersion(tt.body))
		})
	}
}

func TestHasReportsDiagnosticContent(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected bool
	}{
		{"PATH_TRANSLATED env dump", `PATH_TRANSLATED=/u01/oracle/domains/base_domain`, true},
		// Regression (P0): the Ora* CSS classes alone (no PATH_TRANSLATED, no parsed
		// version) merely classify the product (see hasReportsMarker) — they are NOT
		// proof of an actual diagnostic-data leak, so the Medium info-disclosure
		// finding must not fire on them alone.
		{"Oracle diagnostic CSS class alone is not real leaked data", `<span class="OraDataText">env</span>`, false},
		{"parsed version present", `<serverInfo version="10.1.2.0.2">`, true},
		{"bare 200 with no diagnostic content", `OK`, false},
		{"echoed path tokens only (self-referential guard)", `/reports/rwservlet/showenv and /reports/rwservlet/getserverinfo not found`, false},
		{"empty body", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, hasReportsDiagnosticContent(tt.body))
		})
	}
}

func TestEraFromShowenv(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{"OC4J_BI_Forms => 10g", `PATH_TRANSLATED=/ofa/u01/app/oracle/product/10g/j2ee/OC4J_BI_Forms/applications/reports/web/`, "10g"},
		{"DevSuiteHome => 10g", `C:\DevSuiteHome_1\reports\j2ee\reports_ids\web\showenv`, "10g"},
		{"WLS_REPORTS domain layout => 12c", `PATH_TRANSLATED=/u01/oracle/user_projects/domains/base_domain/servers/WLS_REPORTS/`, "12c"},
		{"WLS_FORMS domain layout => 12c", `PATH_TRANSLATED=/u01/oracle/user_projects/domains/base_domain/servers/WLS_FORMS/`, "12c"},
		{"unrelated body => ''", `SOME_ENV=value`, ""},
		{"empty body => ''", ``, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, eraFromShowenv(tt.body))
		})
	}
}

func TestEraFromServerHeader(t *testing.T) {
	assert.Equal(t, "12c", eraFromServerHeader("Oracle-HTTP-Server-12c"))
	assert.Equal(t, "12c", eraFromServerHeader("oracle-http-server-12c/12.2.1.4.0"))
	assert.Equal(t, "", eraFromServerHeader("Oracle-HTTP-Server"))
	assert.Equal(t, "", eraFromServerHeader(""))
}

func TestOhsServerPresent(t *testing.T) {
	assert.True(t, ohsServerPresent("Oracle-HTTP-Server"))
	assert.True(t, ohsServerPresent("oracle-http-server-12c"))
	// Regression: matching is case-insensitive.
	assert.True(t, ohsServerPresent("ORACLE-HTTP-SERVER-12C"))
	assert.False(t, ohsServerPresent(""))
	assert.False(t, ohsServerPresent("nginx"))
}

func TestPortInList(t *testing.T) {
	assert.True(t, portInList(7777))
	assert.True(t, portInList(7778))
	assert.True(t, portInList(8888))
	assert.True(t, portInList(9001))
	assert.False(t, portInList(443))
	assert.False(t, portInList(80))
	assert.False(t, portInList(0))
}

func TestBuildFormsCPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:oracle:forms:*:*:*:*:*:*:*:*", buildFormsCPE())
}

func TestBuildReportsCPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:oracle:reports:*:*:*:*:*:*:*:*", buildReportsCPE(""))
	assert.Equal(t, "cpe:2.3:a:oracle:reports:10.1.2.0.2:*:*:*:*:*:*:*", buildReportsCPE("10.1.2.0.2"))
	// Regression: the current NVD product token for the 12c line is
	// "reports_developer" (e.g. CVE-2024-21133 => oracle:reports_developer:12.2.1.4.0),
	// while the legacy 6i/9i/10g line keeps the "reports" token (case above).
	assert.Equal(t, "cpe:2.3:a:oracle:reports_developer:12.2.1.4.0:*:*:*:*:*:*:*", buildReportsCPE("12.2.1.4.0"))
}

func TestEvaluateForms(t *testing.T) {
	tests := []struct {
		name         string
		ev           formsEvidence
		wantEra      string
		wantFusion   bool
		wantDetected bool
	}{
		{
			name:         "200 + applet class => detected",
			ev:           formsEvidence{statusCode: 200, body: `code="oracle.forms.engine.Main"`},
			wantDetected: true,
		},
		{
			// Updated (PR #374 round-3): the Server: Oracle-HTTP-Server-12c header now
			// also corroborates FusionMiddleware via ohsServerPresent, not just era.
			name:         "200 + marker + Server -12c => era 12c and fusion true",
			ev:           formsEvidence{statusCode: 200, body: `oracle.forms.engine.Main`, server: "Oracle-HTTP-Server-12c"},
			wantEra:      "12c",
			wantFusion:   true,
			wantDetected: true,
		},
		{
			name:         "200 + marker + DMS => fusion true",
			ev:           formsEvidence{statusCode: 200, body: `frmall.jar`, dms: true},
			wantFusion:   true,
			wantDetected: true,
		},
		{
			name:         "200 + marker + Server -12c + DMS => era 12c and fusion true",
			ev:           formsEvidence{statusCode: 200, body: `frmall.jar`, server: "Oracle-HTTP-Server-12c", dms: true},
			wantEra:      "12c",
			wantFusion:   true,
			wantDetected: true,
		},
		{
			name:         "200 generic body => not detected (bare-non-404 guard)",
			ev:           formsEvidence{statusCode: 200, body: "generic page"},
			wantDetected: false,
		},
		{
			name:         "401 with marker still detected (status is not 404)",
			ev:           formsEvidence{statusCode: 401, body: `oracle.forms.engine.Main`},
			wantDetected: true,
		},
		{
			name:         "404 with marker text => not detected",
			ev:           formsEvidence{statusCode: 404, body: `oracle.forms.engine.Main`},
			wantDetected: false,
		},
		{
			name:         "headers alone with no marker => not detected (corroboration-only guard)",
			ev:           formsEvidence{statusCode: 200, body: "generic page", server: "Oracle-HTTP-Server-12c", dms: true},
			wantDetected: false,
		},
		{
			// Regression (PR #374 round-3): Server: Oracle-HTTP-Server corroborates an
			// already-classified Forms service via ohsServerPresent, independent of DMS.
			name:         "200 + marker + Server: Oracle-HTTP-Server (no DMS) => fusion true via ohsServerPresent",
			ev:           formsEvidence{statusCode: 200, body: `oracle.forms.engine.Main`, server: "Oracle-HTTP-Server", dms: false},
			wantFusion:   true,
			wantDetected: true,
		},
		{
			// Case-insensitive / dashed-lowercase 12c variant must also corroborate, and
			// still carries the era via eraFromServerHeader.
			name:         "200 + marker + Server: oracle-http-server-12c (no DMS) => fusion true, era 12c",
			ev:           formsEvidence{statusCode: 200, body: `oracle.forms.engine.Main`, server: "oracle-http-server-12c", dms: false},
			wantEra:      "12c",
			wantFusion:   true,
			wantDetected: true,
		},
		{
			name:         "200 + marker + Server: Apache (no DMS) => fusion false (not Oracle HTTP Server)",
			ev:           formsEvidence{statusCode: 200, body: `oracle.forms.engine.Main`, server: "Apache", dms: false},
			wantFusion:   false,
			wantDetected: true,
		},
		{
			name:         "200 + marker + empty Server (no DMS) => fusion false",
			ev:           formsEvidence{statusCode: 200, body: `oracle.forms.engine.Main`, server: "", dms: false},
			wantFusion:   false,
			wantDetected: true,
		},
		{
			// Regression guard: the Server: Oracle-HTTP-Server corroboration header must
			// NEVER cause detection on its own -- only decorate an already-classified host.
			name:         "Server: Oracle-HTTP-Server with no servlet marker in body => not detected, fusion false",
			ev:           formsEvidence{statusCode: 200, body: "generic page", server: "Oracle-HTTP-Server", dms: false},
			wantFusion:   false,
			wantDetected: false,
		},
		{
			name:         "Server: Oracle-HTTP-Server + marker text but 404 => not detected, fusion false",
			ev:           formsEvidence{statusCode: 404, body: `oracle.forms.engine.Main`, server: "Oracle-HTTP-Server", dms: false},
			wantFusion:   false,
			wantDetected: false,
		},
		{
			// Regression: DMS-based corroboration must keep working (OR-not-replacement)
			// even when the Server header is not an Oracle HTTP Server value.
			name:         "200 + marker + DMS true + non-OHS Server => fusion true (DMS still works)",
			ev:           formsEvidence{statusCode: 200, body: `oracle.forms.engine.Main`, server: "Apache", dms: true},
			wantFusion:   true,
			wantDetected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			era, fusion, detected := evaluateForms(tt.ev)
			assert.Equal(t, tt.wantDetected, detected)
			assert.Equal(t, tt.wantEra, era)
			assert.Equal(t, tt.wantFusion, fusion)
		})
	}
}

func TestEvaluateReports(t *testing.T) {
	tests := []struct {
		name         string
		ev           reportsEvidence
		wantVersion  string
		wantEra      string
		wantFusion   bool
		wantDetected bool
	}{
		{
			name:         "rwservlet 200 + REP code => detected, no version/era",
			ev:           reportsEvidence{statusCode: 200, body: "REP-52251"},
			wantDetected: true,
		},
		{
			name: "getserverinfo version parsed",
			ev: reportsEvidence{
				statusCode:    200,
				body:          "Oracle Reports",
				getServerInfo: diagResponse{statusCode: 200, body: `<serverInfo version="10.1.2.0.2">`},
			},
			wantVersion:  "10.1.2.0.2",
			wantDetected: true,
		},
		{
			name: "getserverinfo gated (non-2xx) => version stays empty",
			ev: reportsEvidence{
				statusCode:    200,
				body:          "Oracle Reports",
				getServerInfo: diagResponse{statusCode: 403, body: `<serverInfo version="10.1.2.0.2">`},
			},
			wantDetected: true,
		},
		{
			name: "showenv OC4J_BI_Forms => era 10g",
			ev: reportsEvidence{
				statusCode: 200,
				body:       "Oracle Reports",
				showenv:    diagResponse{statusCode: 200, body: "PATH_TRANSLATED=.../OC4J_BI_Forms/..."},
			},
			wantEra:      "10g",
			wantDetected: true,
		},
		{
			// Updated (PR #374 round-3): the Server: Oracle-HTTP-Server-12c header now
			// also corroborates FusionMiddleware via ohsServerPresent, not just era.
			name: "Server -12c header + 12c showenv => era 12c (showenv wins over header) and fusion true",
			ev: reportsEvidence{
				statusCode: 200,
				body:       "Oracle Reports",
				server:     "Oracle-HTTP-Server-12c",
				showenv:    diagResponse{statusCode: 200, body: "user_projects/domains/base_domain/servers/WLS_REPORTS"},
			},
			wantEra:      "12c",
			wantFusion:   true,
			wantDetected: true,
		},
		{
			name: "DMS header present => fusion true",
			ev: reportsEvidence{
				statusCode: 200,
				body:       "Oracle Reports",
				dms:        true,
			},
			wantFusion:   true,
			wantDetected: true,
		},
		{
			name:         "rwservlet 200 generic => not detected",
			ev:           reportsEvidence{statusCode: 200, body: "generic page"},
			wantDetected: false,
		},
		{
			name:         "rwservlet 404 => not detected",
			ev:           reportsEvidence{statusCode: 404, body: "Oracle Reports"},
			wantDetected: false,
		},
		{
			name:         "headers alone with no marker => not detected (corroboration-only guard)",
			ev:           reportsEvidence{statusCode: 200, body: "generic page", server: "Oracle-HTTP-Server-12c", dms: true},
			wantDetected: false,
		},
		{
			// Regression (PR #374 round-3): Server: Oracle-HTTP-Server-12c corroborates
			// an already-classified Reports service via ohsServerPresent, independent of
			// DMS. era is also derived from the same header (eraFromServerHeader).
			name:         "rwservlet 200 + REP marker + Server: Oracle-HTTP-Server-12c (no DMS) => fusion true, era 12c",
			ev:           reportsEvidence{statusCode: 200, body: "REP-52251", server: "Oracle-HTTP-Server-12c", dms: false},
			wantEra:      "12c",
			wantFusion:   true,
			wantDetected: true,
		},
		{
			name:         "rwservlet 200 + REP marker + Server: Apache (no DMS) => fusion false (not Oracle HTTP Server)",
			ev:           reportsEvidence{statusCode: 200, body: "REP-52251", server: "Apache", dms: false},
			wantFusion:   false,
			wantDetected: true,
		},
		{
			name:         "rwservlet 200 + REP marker + empty Server (no DMS) => fusion false",
			ev:           reportsEvidence{statusCode: 200, body: "REP-52251", server: "", dms: false},
			wantFusion:   false,
			wantDetected: true,
		},
		{
			// Regression guard: the Server: Oracle-HTTP-Server corroboration header must
			// NEVER cause detection on its own -- only decorate an already-classified host.
			name:         "Server: Oracle-HTTP-Server with no servlet marker in body => not detected, fusion false",
			ev:           reportsEvidence{statusCode: 200, body: "generic page", server: "Oracle-HTTP-Server", dms: false},
			wantFusion:   false,
			wantDetected: false,
		},
		{
			name:         "Server: Oracle-HTTP-Server + marker text but 404 => not detected, fusion false",
			ev:           reportsEvidence{statusCode: 404, body: "REP-52251", server: "Oracle-HTTP-Server", dms: false},
			wantFusion:   false,
			wantDetected: false,
		},
		{
			// Regression: DMS-based corroboration must keep working (OR-not-replacement)
			// even when the Server header is not an Oracle HTTP Server value.
			name:         "rwservlet 200 + REP marker + DMS true + non-OHS Server => fusion true (DMS still works)",
			ev:           reportsEvidence{statusCode: 200, body: "REP-52251", server: "Apache", dms: true},
			wantFusion:   true,
			wantDetected: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, era, fusion, detected := evaluateReports(tt.ev)
			assert.Equal(t, tt.wantDetected, detected)
			assert.Equal(t, tt.wantVersion, version)
			assert.Equal(t, tt.wantEra, era)
			assert.Equal(t, tt.wantFusion, fusion)
		})
	}
}

func TestReportsInfoDisclosed(t *testing.T) {
	tests := []struct {
		name string
		ev   reportsEvidence
		want bool
	}{
		{"getserverinfo 200 + version content", reportsEvidence{getServerInfo: diagResponse{statusCode: 200, body: `version="10.1.2.0.2"`}}, true},
		{"showenv 200 + PATH_TRANSLATED", reportsEvidence{showenv: diagResponse{statusCode: 200, body: "PATH_TRANSLATED=/x"}}, true},
		{"showenv 403 gated => false", reportsEvidence{showenv: diagResponse{statusCode: 403, body: "PATH_TRANSLATED=/x"}}, false},
		{"getserverinfo 404 gated => false", reportsEvidence{getServerInfo: diagResponse{statusCode: 404, body: `version="10.1.2.0.2"`}}, false},
		{"200 but no diagnostic content => false", reportsEvidence{showenv: diagResponse{statusCode: 200, body: "ok"}}, false},
		{"neither diag endpoint populated => false", reportsEvidence{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, reportsInfoDisclosed(tt.ev))
		})
	}
}

// --- httptest end-to-end harness (matches oracleidentity/oraclehttp pattern) ---

// parseTestServerAddr parses an httptest server URL into a netip.AddrPort.
func parseTestServerAddr(t *testing.T, serverURL string) netip.AddrPort {
	t.Helper()
	hostPort := strings.TrimPrefix(serverURL, "http://")
	host, portStr, err := net.SplitHostPort(hostPort)
	require.NoError(t, err)
	port, err := strconv.Atoi(portStr)
	require.NoError(t, err)
	return netip.AddrPortFrom(netip.MustParseAddr(host), uint16(port))
}

// runPluginWithTarget wires an httptest server to a raw TCP dial and invokes
// p.Run with the given Misconfigs/Deep target flags, matching the harness
// pattern used by oracleidentity_test.go / oraclehttp_test.go. TLS plugin
// variants are exercised the same way: Run() only special-cases the conn type
// inside plugins.CheckTLS (a safe no-op for a non-*tls.Conn), so a plain TCP
// dial is sufficient to test TLS-variant detection logic without internals of
// TLS.
func runPluginWithTarget(t *testing.T, p plugins.Plugin, handler http.HandlerFunc, misconfigs, deep bool) *plugins.Service {
	t.Helper()
	server := httptest.NewServer(handler)
	defer server.Close()
	addr := parseTestServerAddr(t, server.URL)
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()
	svc, err := p.Run(conn, 5*time.Second, plugins.Target{Host: addr.Addr().String(), Address: addr, Misconfigs: misconfigs, Deep: deep})
	require.NoError(t, err)
	return svc
}

// runPlugin is the Deep=false convenience wrapper around runPluginWithTarget
// used by the majority of tests that don't need to opt into Deep scanning.
func runPlugin(t *testing.T, p plugins.Plugin, handler http.HandlerFunc, misconfigs bool) *plugins.Service {
	t.Helper()
	return runPluginWithTarget(t, p, handler, misconfigs, false)
}

// --- createHTTPClient single-dial guard (unit) ---

// TestCreateHTTPClient_DialContextGuardRefusesSecondDial is a focused unit test
// for the round-5 concurrency fix: the *http.Transport returned by
// createHTTPClient hands out its single wrapped net.Conn on the first
// DialContext call, then refuses (a clean, non-fatal error) any subsequent
// dial rather than handing the same socket to a second concurrent caller,
// which would otherwise corrupt the connection / race on it.
func TestCreateHTTPClient_DialContextGuardRefusesSecondDial(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer server.Close()
	conn, err := net.DialTimeout("tcp", strings.TrimPrefix(server.URL, "http://"), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	client := createHTTPClient(conn, 5*time.Second)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "createHTTPClient must configure an *http.Transport")

	gotConn, err := transport.DialContext(context.Background(), "tcp", "ignored:0")
	require.NoError(t, err, "the first dial must succeed and hand out the wrapped conn")
	assert.Same(t, conn, gotConn)

	_, err = transport.DialContext(context.Background(), "tcp", "ignored:0")
	require.Error(t, err, "a second dial must be refused rather than handing out the same conn again")
}

// --- Forms plugin: positive detection ---

func TestFormsPlugin_Run_PositiveViaAppletClass(t *testing.T) {
	svc := runPlugin(t, &FormsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forms/frmservlet" {
			fmt.Fprint(w, `<applet code="oracle.forms.engine.Main" archive="frmall.jar"></applet>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, false)
	require.NotNil(t, svc)
	var f plugins.ServiceOracleForms
	require.NoError(t, json.Unmarshal(svc.Raw, &f))
	require.Len(t, f.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:forms:*:*:*:*:*:*:*:*", f.CPEs[0])
	assert.Equal(t, "", svc.Version, "Forms version is never populated (no reliable unauthenticated version surface)")
}

func TestFormsPlugin_Run_PositiveViaFrmErrorCode(t *testing.T) {
	svc := runPlugin(t, &FormsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forms/frmservlet" {
			fmt.Fprint(w, `FRM-92050: unable to connect to the Forms Listener Servlet`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, false)
	require.NotNil(t, svc)
	var f plugins.ServiceOracleForms
	require.NoError(t, json.Unmarshal(svc.Raw, &f))
	require.Len(t, f.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:forms:*:*:*:*:*:*:*:*", f.CPEs[0])
}

func TestFormsPlugin_Run_PositiveViaProvenanceComment(t *testing.T) {
	svc := runPlugin(t, &FormsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forms/frmservlet" {
			fmt.Fprint(w, `<!-- FILE: webutiljpi.htm (Oracle Forms) -->`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, false)
	require.NotNil(t, svc)
}

func TestFormsPlugin_Run_PositiveViaFormsServicesText(t *testing.T) {
	svc := runPlugin(t, &FormsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forms/frmservlet" {
			fmt.Fprint(w, `Oracle Fusion Middleware Forms Services`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, false)
	require.NotNil(t, svc)
}

func TestFormsPlugin_Run_FusionMiddlewareFromDMSHeader(t *testing.T) {
	svc := runPlugin(t, &FormsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forms/frmservlet" {
			w.Header().Set("Server", "Oracle-HTTP-Server-12c")
			w.Header().Set("X-ORACLE-DMS-ECID", "005ABC123.deadbeef")
			fmt.Fprint(w, `code="oracle.forms.engine.Main"`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, false)
	require.NotNil(t, svc)
	var f plugins.ServiceOracleForms
	require.NoError(t, json.Unmarshal(svc.Raw, &f))
	assert.True(t, f.FusionMiddleware, "DMS header on an already-classified Forms service must set FusionMiddleware")
	assert.Equal(t, "12c", f.Era, "Server: Oracle-HTTP-Server-12c corroborates the 12c era on an already-classified service")
}

// --- Forms plugin: negative / false-positive guards ---

func TestFormsPlugin_Run_Negative_Bare200NoMarker(t *testing.T) {
	svc := runPlugin(t, &FormsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "generic /forms/frmservlet landing page")
	}, false)
	assert.Nil(t, svc)
}

func TestFormsPlugin_Run_Negative_Bare404NoMarker(t *testing.T) {
	svc := runPlugin(t, &FormsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "404 not found")
	}, false)
	assert.Nil(t, svc)
}

func TestFormsPlugin_Run_Negative_SelfReferentialPathEcho(t *testing.T) {
	svc := runPlugin(t, &FormsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		// An error/echo page reflecting the requested path is NOT a product marker.
		fmt.Fprintf(w, "The requested resource /forms/frmservlet is not available on this server")
	}, false)
	assert.Nil(t, svc)
}

func TestFormsPlugin_Run_Negative_CorroborationHeadersOnlyNoMarker(t *testing.T) {
	// Server: Oracle-HTTP-Server-12c and the DMS header alone (no servlet marker)
	// must NOT classify the host as Forms.
	svc := runPlugin(t, &FormsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Oracle-HTTP-Server-12c")
		w.Header().Set("X-ORACLE-DMS-ECID", "005ABC123.deadbeef")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "generic welcome page")
	}, false)
	assert.Nil(t, svc)
}

func TestFormsPlugin_Metadata(t *testing.T) {
	p := &FormsPlugin{}
	assert.Equal(t, OracleForms, p.Name())
	assert.Equal(t, plugins.TCP, p.Type())
	assert.Equal(t, -1, p.Priority())
	assert.True(t, p.PortPriority(7777))
	assert.True(t, p.PortPriority(7778))
	assert.True(t, p.PortPriority(8888))
	assert.True(t, p.PortPriority(9001))
	assert.False(t, p.PortPriority(443))
	assert.False(t, p.PortPriority(4443))
}

// --- Forms TLS plugin ---

func TestFormsTLSPlugin_Run_Positive(t *testing.T) {
	svc := runPlugin(t, &FormsTLSPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forms/frmservlet" {
			fmt.Fprint(w, `frmall.jar`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, false)
	require.NotNil(t, svc)
	var f plugins.ServiceOracleForms
	require.NoError(t, json.Unmarshal(svc.Raw, &f))
	require.Len(t, f.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:forms:*:*:*:*:*:*:*:*", f.CPEs[0])
}

func TestFormsTLSPlugin_Run_Negative(t *testing.T) {
	svc := runPlugin(t, &FormsTLSPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "generic landing page")
	}, false)
	assert.Nil(t, svc)
}

func TestFormsTLSPlugin_Run_MisconfigsAppendsFindingAndCheckTLSIsSafeNoop(t *testing.T) {
	// CheckTLS type-asserts the conn to *tls.Conn; a plain TCP conn from httptest
	// makes it a safe no-op, so only the shared exposed finding is expected. Per
	// task instructions we don't assert CheckTLS's internals, only that appending
	// its result doesn't break the plugin.
	svc := runPlugin(t, &FormsTLSPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forms/frmservlet" {
			fmt.Fprint(w, `frmall.jar`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, true)
	require.NotNil(t, svc)
	assert.True(t, svc.AnonymousAccess)
	require.Len(t, svc.SecurityFindings, 1)
	assert.Equal(t, "oracle-forms-reports-exposed", svc.SecurityFindings[0].ID)
}

func TestFormsTLSPlugin_Metadata(t *testing.T) {
	p := &FormsTLSPlugin{}
	assert.Equal(t, OracleForms, p.Name())
	assert.Equal(t, plugins.TCPTLS, p.Type())
	assert.Equal(t, -1, p.Priority())
	assert.True(t, p.PortPriority(443))
	// Regression: 4443 is the Oracle HTTP Server TLS default that commonly fronts
	// Forms, and must be treated as a priority port alongside 443.
	assert.True(t, p.PortPriority(4443))
	assert.False(t, p.PortPriority(7777))
}

// --- Reports plugin: positive detection ---

func TestReportsPlugin_Run_PositiveWithVersionAnd10gEra(t *testing.T) {
	// Misconfigs=true: the admin-only getserverinfo/showenv diagnostics are
	// gated behind Misconfigs||Deep, so opt in to exercise version/era enrichment.
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reports/rwservlet":
			fmt.Fprint(w, `<html><title>Oracle Reports</title>REP-52251</html>`)
		case "/reports/rwservlet/getserverinfo":
			fmt.Fprint(w, `<serverInfo name="repserv" version="10.1.2.0.2">`)
		case "/reports/rwservlet/showenv":
			fmt.Fprint(w, `PATH_TRANSLATED=/ofa/u01/app/oracle/product/10g/j2ee/OC4J_BI_Forms/applications/reports/web/`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}, true)
	require.NotNil(t, svc)
	assert.Equal(t, "10.1.2.0.2", svc.Version)
	var rp plugins.ServiceOracleReports
	require.NoError(t, json.Unmarshal(svc.Raw, &rp))
	assert.Equal(t, "10g", rp.Era)
	require.Len(t, rp.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:reports:10.1.2.0.2:*:*:*:*:*:*:*", rp.CPEs[0])
}

func TestReportsPlugin_Run_XMLDeclarationGetServerInfo_VersionRidesThroughToCPE(t *testing.T) {
	// Regression (M1): getserverinfo answering with a full XML document -- an XML
	// declaration ("<?xml version='1.0' encoding=\"UTF-8\"?>") followed by the real
	// serverInfo version attribute -- must extract the serverInfo version
	// (10.1.2.0.2), not the XML declaration's own two-segment "1.0", and that
	// version must ride through to both svc.Version and the emitted CPE.
	// Misconfigs=true opts into the admin-only getserverinfo diagnostic probe.
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reports/rwservlet":
			fmt.Fprint(w, `<html><title>Oracle Reports</title>REP-52251</html>`)
		case "/reports/rwservlet/getserverinfo":
			fmt.Fprint(w, `<?xml version='1.0' encoding="UTF-8"?><serverInfo name="repserv" version="10.1.2.0.2">`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}, true)
	require.NotNil(t, svc)
	assert.Equal(t, "10.1.2.0.2", svc.Version, "must extract the serverInfo version, not the XML declaration's own version='1.0'")
	var rp plugins.ServiceOracleReports
	require.NoError(t, json.Unmarshal(svc.Raw, &rp))
	require.Len(t, rp.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:reports:10.1.2.0.2:*:*:*:*:*:*:*", rp.CPEs[0])
}

func TestReportsPlugin_Run_PositiveWith12cEra(t *testing.T) {
	// Misconfigs=true opts into the admin-only getserverinfo/showenv diagnostics.
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reports/rwservlet":
			w.Header().Set("Server", "Oracle-HTTP-Server-12c")
			fmt.Fprint(w, `Reports Servlet Command`)
		case "/reports/rwservlet/getserverinfo":
			fmt.Fprint(w, `Version: 12.2.1.4.0`)
		case "/reports/rwservlet/showenv":
			fmt.Fprint(w, `PATH_TRANSLATED=/u01/oracle/user_projects/domains/base_domain/servers/WLS_REPORTS/`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}, true)
	require.NotNil(t, svc)
	assert.Equal(t, "12.2.1.4.0", svc.Version)
	var rp plugins.ServiceOracleReports
	require.NoError(t, json.Unmarshal(svc.Raw, &rp))
	assert.Equal(t, "12c", rp.Era)
	require.Len(t, rp.CPEs, 1)
	// Regression: the current NVD product token for the parsed 12c version is
	// "reports_developer", not the legacy "reports" token.
	assert.Equal(t, "cpe:2.3:a:oracle:reports_developer:12.2.1.4.0:*:*:*:*:*:*:*", rp.CPEs[0])
}

func TestReportsPlugin_Run_FusionMiddlewareFromDMSHeader(t *testing.T) {
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reports/rwservlet":
			w.Header().Set("X-ORACLE-DMS-ECID", "005ABC123.deadbeef")
			fmt.Fprint(w, `Oracle Reports`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}, false)
	require.NotNil(t, svc)
	var rp plugins.ServiceOracleReports
	require.NoError(t, json.Unmarshal(svc.Raw, &rp))
	assert.True(t, rp.FusionMiddleware, "DMS header on an already-classified Reports service must set FusionMiddleware")
}

func TestReportsPlugin_Run_DiagEndpointsGated_VersionAndEraStayUnknown(t *testing.T) {
	// getserverinfo/showenv are frequently DIAGNOSTIC=NO gated (non-2xx); version
	// and era must default to unknown/wildcard rather than erroring. Misconfigs=true
	// so the diagnostics are actually probed (opted in) and observed as gated,
	// rather than simply never being attempted.
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reports/rwservlet":
			fmt.Fprint(w, `Oracle Reports`)
		case "/reports/rwservlet/getserverinfo", "/reports/rwservlet/showenv":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, "Access Forbidden")
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}, true)
	require.NotNil(t, svc)
	assert.Equal(t, "", svc.Version)
	var rp plugins.ServiceOracleReports
	require.NoError(t, json.Unmarshal(svc.Raw, &rp))
	assert.Equal(t, "", rp.Era)
	require.Len(t, rp.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:reports:*:*:*:*:*:*:*:*", rp.CPEs[0])
}

func TestReportsPlugin_Run_BaselineNoOptIn_DiagnosticsNeverProbed(t *testing.T) {
	// Baseline (Misconfigs=false, Deep=false): detection must still succeed via the
	// bare rwservlet classifier marker alone, but the admin-only
	// getserverinfo/showenv diagnostic endpoints must NEVER be probed.
	var diagnosticsProbed atomic.Bool
	svc := runPluginWithTarget(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reports/rwservlet":
			fmt.Fprint(w, `<title>Oracle Reports</title>`)
		case "/reports/rwservlet/getserverinfo", "/reports/rwservlet/showenv":
			diagnosticsProbed.Store(true)
			w.WriteHeader(http.StatusForbidden)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}, false, false)
	require.NotNil(t, svc)
	assert.False(t, diagnosticsProbed.Load(), "baseline scan (Misconfigs=false, Deep=false) must never probe the admin-only getserverinfo/showenv diagnostic endpoints")
	assert.Equal(t, "", svc.Version)
	var rp plugins.ServiceOracleReports
	require.NoError(t, json.Unmarshal(svc.Raw, &rp))
	require.Len(t, rp.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:reports:*:*:*:*:*:*:*:*", rp.CPEs[0])
}

func TestReportsPlugin_Run_DeepTrueProbesDiagnosticsButEmitsNoFindings(t *testing.T) {
	// Deep=true (Misconfigs=false): diagnostics ARE probed (version parsed), but no
	// SecurityFindings are emitted and AnonymousAccess stays false, since finding
	// emission is gated on Misconfigs, not Deep.
	svc := runPluginWithTarget(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reports/rwservlet":
			fmt.Fprint(w, `<title>Oracle Reports</title>`)
		case "/reports/rwservlet/getserverinfo":
			fmt.Fprint(w, `<serverInfo version="10.1.2.0.2">`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}, false, true)
	require.NotNil(t, svc)
	assert.Equal(t, "10.1.2.0.2", svc.Version, "Deep=true opts into the admin-only diagnostic probes")
	assert.False(t, svc.AnonymousAccess)
	assert.Empty(t, svc.SecurityFindings)
}

func TestReportsPlugin_Run_ConnectionCloseForcesRedialGuard_GracefulDegradation(t *testing.T) {
	// Regression (PR #374 round-5): detectReports closes the classifier response
	// BEFORE issuing the getserverinfo/showenv diag probes so the underlying
	// net/http transport can return the single connection to its idle pool and
	// the diag GETs reuse it. But when the server answers the classifier with
	// "Connection: close" (disabling keep-alive for that response), the
	// transport cannot reuse that connection at all and must dial again for the
	// diag probes. The plugin owns exactly one net.Conn, so createHTTPClient's
	// DialContext guard refuses that second dial (a clean, non-fatal error)
	// rather than handing the same socket to a second concurrent request loop,
	// which would otherwise race on / corrupt the connection. The classifier
	// marker was already read into ev.body before the connection closed, so
	// Reports is still detected -- only the admin-only version/era enrichment is
	// gracefully lost. Run with `go test -race` to confirm no data race occurs.
	var diagRequested atomic.Bool
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reports/rwservlet":
			// Disable keep-alive for this response only, forcing the transport to
			// re-dial for any subsequent request on this client.
			w.Header().Set("Connection", "close")
			fmt.Fprint(w, `<html><title>Oracle Reports</title>REP-12345</html>`)
		case "/reports/rwservlet/getserverinfo", "/reports/rwservlet/showenv":
			// Would answer with a real, parseable version/era if ever reached --
			// proves the diag probes are refused by the dial guard before ever
			// reaching the server, not merely gated off elsewhere.
			diagRequested.Store(true)
			fmt.Fprint(w, `<serverInfo version="10.1.2.0.2">`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}, true)

	require.NotNil(t, svc, "the classifier REP- marker was read before the connection closed, so Reports is still detected")
	assert.False(t, diagRequested.Load(), "the diag probes must never reach the server once the classifier connection is non-reusable")
	assert.Equal(t, "", svc.Version, "the re-dial refused by the guard means getserverinfo version enrichment is unavailable")

	var rp plugins.ServiceOracleReports
	require.NoError(t, json.Unmarshal(svc.Raw, &rp))
	assert.Equal(t, "", rp.Era, "showenv era enrichment is unavailable for the same reason")
	require.Len(t, rp.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:reports:*:*:*:*:*:*:*:*", rp.CPEs[0], "CPE stays wildcard since no version was ever enriched")
}

// --- Reports plugin: negative / false-positive guards ---

func TestReportsPlugin_Run_Negative_Bare200NoMarker(t *testing.T) {
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reports/rwservlet" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "generic /reports/rwservlet landing page")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, false)
	assert.Nil(t, svc)
}

func TestReportsPlugin_Run_Negative_Bare404NoMarker(t *testing.T) {
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, "404 not found")
	}, false)
	assert.Nil(t, svc)
}

func TestReportsPlugin_Run_Negative_SelfReferentialPathEcho(t *testing.T) {
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reports/rwservlet" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "proxied /reports/rwservlet not found")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, false)
	assert.Nil(t, svc)
}

func TestReportsPlugin_Run_Negative_CorroborationHeadersOnlyNoMarker(t *testing.T) {
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reports/rwservlet" {
			w.Header().Set("Server", "Oracle-HTTP-Server-12c")
			w.Header().Set("X-ORACLE-DMS-ECID", "005ABC123.deadbeef")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "generic welcome page")
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, false)
	assert.Nil(t, svc)
}

func TestReportsPlugin_Run_Negative_OraCSSClassesAloneAreNotReports(t *testing.T) {
	// Regression (PR #374 round-4): a non-Reports Oracle Fusion Middleware page
	// (e.g. a different FMW product's diagnostic/error page) served at
	// /reports/rwservlet with a non-404 status and ONLY the generic Ora* CSS
	// classes -- no "Oracle Reports"/"Reports Servlet" text, no REP- code -- must
	// NOT be classified as Reports.
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reports/rwservlet" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><span class="OraInstructionText">Enter parameter values</span><td class="OraDataText">value</td><td class="OraTableCellText">value</td></body></html>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, false)
	assert.Nil(t, svc, "Ora* CSS classes alone must not classify a host as Oracle Reports")
}

func TestReportsPlugin_Run_Positive_OraCSSClassesPlusRealMarkerStillDetected(t *testing.T) {
	// Regression (PR #374 round-4): the Ora* CSS classes are simply
	// non-classifying, not disqualifying -- a body carrying them ALONGSIDE a
	// genuine REP- code (or "Oracle Reports"/"Reports Servlet" text) must still
	// be detected as Reports.
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/reports/rwservlet" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, `<html><body><span class="OraInstructionText">Enter parameter values</span>REP-12345: parameter error</body></html>`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, false)
	require.NotNil(t, svc, "a REP- code alongside Ora* CSS classes must still be detected")
}

func TestReportsPlugin_Metadata(t *testing.T) {
	p := &ReportsPlugin{}
	assert.Equal(t, OracleReports, p.Name())
	assert.Equal(t, plugins.TCP, p.Type())
	assert.Equal(t, -1, p.Priority())
	assert.True(t, p.PortPriority(7778))
	assert.False(t, p.PortPriority(443))
	assert.False(t, p.PortPriority(4443))
}

// --- Reports TLS plugin ---

func TestReportsTLSPlugin_Run_Positive(t *testing.T) {
	svc := runPlugin(t, &ReportsTLSPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reports/rwservlet":
			fmt.Fprint(w, `REP-52251`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}, false)
	require.NotNil(t, svc)
	var rp plugins.ServiceOracleReports
	require.NoError(t, json.Unmarshal(svc.Raw, &rp))
	require.Len(t, rp.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:reports:*:*:*:*:*:*:*:*", rp.CPEs[0])
}

func TestReportsTLSPlugin_Run_Negative(t *testing.T) {
	svc := runPlugin(t, &ReportsTLSPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "generic landing page")
	}, false)
	assert.Nil(t, svc)
}

func TestReportsTLSPlugin_Metadata(t *testing.T) {
	p := &ReportsTLSPlugin{}
	assert.Equal(t, OracleReports, p.Name())
	assert.Equal(t, plugins.TCPTLS, p.Type())
	assert.Equal(t, -1, p.Priority())
	assert.True(t, p.PortPriority(443))
	// Regression: 4443 is the Oracle HTTP Server TLS default that commonly fronts
	// Reports, and must be treated as a priority port alongside 443.
	assert.True(t, p.PortPriority(4443))
	assert.False(t, p.PortPriority(7777))
}

// --- Security findings / Misconfigs gating ---

func TestFormsSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forms/frmservlet" {
			fmt.Fprint(w, `code="oracle.forms.engine.Main"`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	})
	t.Run("Misconfigs=true yields AnonymousAccess and Low finding", func(t *testing.T) {
		svc := runPlugin(t, &FormsPlugin{}, handler, true)
		require.NotNil(t, svc)
		assert.True(t, svc.AnonymousAccess)
		require.Len(t, svc.SecurityFindings, 1)
		assert.Equal(t, "oracle-forms-reports-exposed", svc.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityLow, svc.SecurityFindings[0].Severity)
	})
	t.Run("Misconfigs=false yields no findings", func(t *testing.T) {
		svc := runPlugin(t, &FormsPlugin{}, handler, false)
		require.NotNil(t, svc)
		assert.False(t, svc.AnonymousAccess)
		assert.Empty(t, svc.SecurityFindings)
	})
}

func TestFormsSecurityFindings_AbsentOnNon2xxEvenWhenMisconfigsTrue(t *testing.T) {
	// The Forms marker is present but the classifier response itself is a 401 (not
	// a 2xx) — AnonymousAccess/finding must NOT be reported, only the detection.
	svc := runPlugin(t, &FormsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/forms/frmservlet" {
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `code="oracle.forms.engine.Main"`)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}, true)
	require.NotNil(t, svc, "a 401 with a genuine marker is still a detected service")
	assert.False(t, svc.AnonymousAccess)
	assert.Empty(t, svc.SecurityFindings)
}

func TestReportsSecurityFindings(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reports/rwservlet":
			fmt.Fprint(w, `<title>Oracle Reports</title>`)
		case "/reports/rwservlet/getserverinfo":
			fmt.Fprint(w, `<serverInfo version="10.1.2.0.2">`)
		case "/reports/rwservlet/showenv":
			fmt.Fprint(w, `PATH_TRANSLATED=/x/OC4J_BI_Forms/y`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	})
	t.Run("Misconfigs=true yields exposed (Low) + info-disclosure (Medium)", func(t *testing.T) {
		svc := runPlugin(t, &ReportsPlugin{}, handler, true)
		require.NotNil(t, svc)
		assert.True(t, svc.AnonymousAccess)
		require.Len(t, svc.SecurityFindings, 2)
		byID := map[string]plugins.SecurityFinding{}
		for _, f := range svc.SecurityFindings {
			byID[f.ID] = f
		}
		lowFinding, ok := byID["oracle-forms-reports-exposed"]
		require.True(t, ok)
		assert.Equal(t, plugins.SeverityLow, lowFinding.Severity)

		medFinding, ok := byID["oracle-reports-info-disclosure"]
		require.True(t, ok)
		assert.Equal(t, plugins.SeverityMedium, medFinding.Severity)
		// The Medium finding must report protocol facts only — never the actual
		// leaked env/path/version content observed in the diagnostic response body.
		assert.NotContains(t, medFinding.Evidence, "PATH_TRANSLATED")
		assert.NotContains(t, medFinding.Evidence, "OC4J_BI_Forms")
		assert.NotContains(t, medFinding.Evidence, "10.1.2.0.2")
	})
	t.Run("Misconfigs=false yields no findings", func(t *testing.T) {
		svc := runPlugin(t, &ReportsPlugin{}, handler, false)
		require.NotNil(t, svc)
		assert.False(t, svc.AnonymousAccess)
		assert.Empty(t, svc.SecurityFindings)
	})
}

func TestReportsSecurityFindings_AbsentOnNon2xxEvenWhenMisconfigsTrue(t *testing.T) {
	// Main classifier response is 401 (not 2xx) and the diagnostic endpoints are
	// also gated (403) -- neither the exposed nor the info-disclosure finding
	// should be reported, even though the host is still detected as Reports.
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reports/rwservlet":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `Oracle Reports`)
		case "/reports/rwservlet/getserverinfo", "/reports/rwservlet/showenv":
			w.WriteHeader(http.StatusForbidden)
			fmt.Fprint(w, `PATH_TRANSLATED=/x/OC4J_BI_Forms/y`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}, true)
	require.NotNil(t, svc, "a 401 with a genuine marker is still a detected service")
	assert.False(t, svc.AnonymousAccess)
	assert.Empty(t, svc.SecurityFindings)
}

func TestReportsSecurityFindings_InfoDisclosureSetsAnonymousAccessDespiteNon2xxClassifier(t *testing.T) {
	// Regression: Reports.Run must set AnonymousAccess when EITHER the bare
	// rwservlet classifier response is a 2xx OR the diagnostic endpoints leaked
	// real content (reportsInfoDisclosed) -- not only on a 2xx classifier. Here the
	// bare classifier itself is a 401 (non-2xx, but still carries a genuine REP-
	// marker so detection succeeds), while getserverinfo answers 200 with a real
	// parsed version. The Low exposed finding stays gated on the classifier's own
	// 2xx status, so it must be absent; only the Medium info-disclosure finding
	// fires.
	svc := runPlugin(t, &ReportsPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reports/rwservlet":
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `REP-52251: authentication required`)
		case "/reports/rwservlet/getserverinfo":
			fmt.Fprint(w, `<serverInfo name="repserv" version="10.1.2.0.2">`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}, true)
	require.NotNil(t, svc, "a 401 classifier response with a genuine REP- marker is still detected")
	assert.True(t, svc.AnonymousAccess, "info-disclosure alone must set AnonymousAccess even when the classifier itself is non-2xx")
	require.Len(t, svc.SecurityFindings, 1)
	assert.Equal(t, "oracle-reports-info-disclosure", svc.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityMedium, svc.SecurityFindings[0].Severity)

	var ids []string
	for _, f := range svc.SecurityFindings {
		ids = append(ids, f.ID)
	}
	assert.NotContains(t, ids, "oracle-forms-reports-exposed", "the Low finding stays gated on the classifier's own 2xx status")
}

func TestReportsTLSSecurityFindings_CheckTLSAppendedSafely(t *testing.T) {
	// Same as the TCP case, plus plugins.CheckTLS is appended. On a plain TCP
	// httptest conn (not *tls.Conn) CheckTLS is a safe no-op, so the finding count
	// matches the non-TLS variant; we don't assert CheckTLS's internals.
	svc := runPlugin(t, &ReportsTLSPlugin{}, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/reports/rwservlet":
			fmt.Fprint(w, `<title>Oracle Reports</title>`)
		case "/reports/rwservlet/getserverinfo":
			fmt.Fprint(w, `<serverInfo version="10.1.2.0.2">`)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}, true)
	require.NotNil(t, svc)
	assert.True(t, svc.AnonymousAccess)
	require.Len(t, svc.SecurityFindings, 2)
}
