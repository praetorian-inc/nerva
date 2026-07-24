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

/*
Oracle Application Server Forms & Reports Services HTTP Fingerprinting (LAB-5049)

This package detects the two Oracle Fusion Middleware web applications Oracle
Forms Services (dispatched by the Forms Servlet at "/forms/frmservlet") and
Oracle Reports Services (dispatched by the Reports Servlet at
"/reports/rwservlet") over HTTP/HTTPS. Each product ships a TCP and a TLS plugin
variant, for four registered plugins total: FormsPlugin, FormsTLSPlugin,
ReportsPlugin, ReportsTLSPlugin.

Oracle Forms Services (Name "oracle_forms"):

  The plugin issues a single GET to "/forms/frmservlet". A host is classified as
  Forms when that path responds (non-404) AND the body carries a strong,
  Forms-specific, non-reflective marker: the Forms applet main class
  "oracle.forms.engine.Main", the client archive "frmall.jar", the Oracle base
  HTML provenance comment "(Oracle Forms)", the branded "Forms Services" text, or
  an "FRM-9xxxx" runtime/listener error code. A bare non-404 with none of these
  is NOT sufficient.

  CPE Format: cpe:2.3:a:oracle:forms:*:*:*:*:*:*:*:* (version always wildcard —
  no reliable unauthenticated Forms version surface exists).

Oracle Reports Services (Name "oracle_reports"):

  The plugin issues a GET to "/reports/rwservlet". A host is classified as
  Reports when that path responds (non-404) AND the body carries a strong,
  Reports-specific, non-reflective marker: a "REP-" error/status code or the
  branded "Oracle Reports" / "Reports Servlet" text. The generic Oracle
  diagnostic-page CSS classes ("OraInstructionText", "OraDataText",
  "OraTableCellText") are NOT classifiers — they appear on many Fusion Middleware
  diagnostic/error pages, so a non-Reports Oracle app would otherwise be
  misclassified. ONLY after
  detection AND only when the caller opts in (Misconfigs || Deep) does the plugin
  additionally GET the ADMINISTRATOR-ONLY read-only diagnostic actions
  "/reports/rwservlet/getserverinfo" (Reports Server version) and
  "/reports/rwservlet/showenv" (10g/12c era from the deployment path layout). A
  baseline scan (neither flag set) probes only the bare rwservlet path. These are
  best-effort and frequently DIAGNOSTIC=NO gated, so version and era default to
  unknown, and the Medium info-disclosure finding fires only on ACTUAL leaked data
  (a PATH_TRANSLATED env field or a parsed version), never on the Ora* CSS classes
  alone.

  CPE Format: cpe:2.3:a:oracle:reports_developer:<12c-ver>:... for parsed 12c
  versions (the current NVD product token, e.g. CVE-2024-21133 =>
  cpe:2.3:a:oracle:reports_developer:12.2.1.4.0), otherwise
  cpe:2.3:a:oracle:reports:<ver-or-*>:... for the legacy 6i/9i/10g line.

Corroboration-only signals (NEVER standalone classifiers): a
"Server: Oracle-HTTP-Server[-12c]" response header and the "X-ORACLE-DMS-ECID" /
"X-ORACLE-DMS-RID" Dynamic Monitoring Service headers. These are emitted by
Oracle HTTP Server and every Fusion Middleware product fronted by it, so they may
only decorate an already-classified service (set FusionMiddleware=true, infer the
12c era); a host carrying them with no servlet marker is neither Forms nor
Reports.

Self-referential guard: the probe path tokens (frmservlet, rwservlet, showenv,
getserverinfo) echoed back in an error/404 body are NOT markers — only
product-emitted strings count, mirroring oracleidentity's hasOAMMarker exclusion
of the obrareq path token.

Scanning safety: only bare unauthenticated GETs are issued to /forms/frmservlet
and /reports/rwservlet. The admin-only /reports/rwservlet/getserverinfo and
/reports/rwservlet/showenv GETs are issued only when the caller opts in
(Misconfigs || Deep). No query parameter is ever appended to rwservlet (rwservlet
executes reports when given a job request), and no request is ever a POST.

Default Ports: 7777 / 7778 / 8888 / 9001 (TCP variants), 443 / 4443 (TLS variants;
4443 is the Oracle HTTP Server TLS default that commonly fronts Forms/Reports).
*/

package oracleformsreports

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const (
	// OracleForms is the technology name emitted by the Forms plugin variants.
	OracleForms = "oracle_forms"
	// OracleReports is the technology name emitted by the Reports plugin variants.
	OracleReports = "oracle_reports"
	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(10 * 1024 * 1024)
)

// formsReportsTCPPorts are the classic OHS / WebLogic managed-server ports that
// front Oracle Forms/Reports (7777/7778/8888 OHS, 9001 common WLS). PortPriority
// is only a fast-lane ordering hint; the slow lane runs the plugin on any port.
var formsReportsTCPPorts = []uint16{7777, 7778, 8888, 9001}

// frmErrorPattern matches an "FRM-9xxxx" Forms runtime/listener error code
// (e.g. FRM-92050, FRM-92100), distinctive to the Forms servlet/listener.
var frmErrorPattern = regexp.MustCompile(`FRM-9\d{3,}`)

// repErrorPattern matches a "REP-xxxxx" Reports server/servlet code
// (e.g. REP-51002, REP-52251), distinctive to Reports.
var repErrorPattern = regexp.MustCompile(`REP-\d{3,}`)

// reportsVersionPattern extracts a real Oracle Reports version token following a
// "version" label, covering the getserverinfo XML attribute
// (version="10.1.2.0.2") and the HTML key/value form (Version: 12.2.1.4.0). It
// requires at least three dotted numeric segments so the two-segment XML
// declaration value (version='1.0') is rejected rather than mis-extracted as the
// Reports version when getserverinfo answers in the XML statusformat.
var reportsVersionPattern = regexp.MustCompile(`(?i)version\s*[=:>"']{1,3}\s*([0-9]+(?:\.[0-9]+){2,})`)

type FormsPlugin struct{}

// FormsTLSPlugin detects Oracle Forms Services over TLS connections.
type FormsTLSPlugin struct{}

type ReportsPlugin struct{}

// ReportsTLSPlugin detects Oracle Reports Services over TLS connections.
type ReportsTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&FormsPlugin{})
	plugins.RegisterPlugin(&FormsTLSPlugin{})
	plugins.RegisterPlugin(&ReportsPlugin{})
	plugins.RegisterPlugin(&ReportsTLSPlugin{})
}

// createHTTPClient creates an http.Client that wraps the provided net.Conn and
// does not follow redirects (so headers can be inspected directly).
func createHTTPClient(conn net.Conn, timeout time.Duration) *http.Client {
	// The plugin owns a single net.Conn, so the transport may hand it out exactly
	// once. Guard against a re-dial (which would hand the same socket to a second
	// request loop, causing a data race / protocol corruption): return the conn on
	// the first dial and a clean, non-fatal error on any subsequent dial. In correct
	// operation the classifier body is closed before the diag probes, so the diag
	// requests reuse the idle conn and this guard never triggers.
	var dialed atomic.Bool
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if dialed.Swap(true) {
					return nil, fmt.Errorf("oracleformsreports: single-connection transport already dialed")
				}
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
}

// doGet performs a GET request with the nerva User-Agent header. When host is
// non-empty it is set as the HTTP Host header so name-based virtual hosts are
// reached (the connection is still dialed by IP via the client's transport).
func doGet(client *http.Client, url string, host string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nerva/1.0")
	if host != "" {
		req.Host = host
	}
	return client.Do(req)
}

// isSuccessStatus reports whether an HTTP status code is a 2xx success.
func isSuccessStatus(code int) bool {
	return code >= 200 && code < 300
}

// portInList reports whether port is one of the classic Forms/Reports TCP ports.
func portInList(port uint16) bool {
	for _, p := range formsReportsTCPPorts {
		if p == port {
			return true
		}
	}
	return false
}

// dmsPresent reports whether an Oracle Fusion Middleware Dynamic Monitoring
// Service header is set on the response.
func dmsPresent(resp *http.Response) bool {
	return resp.Header.Get("X-ORACLE-DMS-ECID") != "" || resp.Header.Get("X-ORACLE-DMS-RID") != ""
}

// ohsServerPresent reports whether a Server header value identifies Oracle HTTP
// Server (e.g. "Oracle-HTTP-Server" or "Oracle-HTTP-Server-12c"), the Fusion
// Middleware web tier that fronts Forms/Reports. Case-insensitive. Like the DMS
// headers this is a corroboration-only signal: it only decorates a service that a
// servlet marker has already classified, and never classifies a host on its own.
func ohsServerPresent(server string) bool {
	return strings.Contains(strings.ToLower(server), "oracle-http-server")
}

// eraFromServerHeader infers the 12c era from an "Oracle-HTTP-Server-12c" Server
// token. This is a corroboration-only signal: it only decorates a service that a
// servlet marker has already classified. Returns "" when no generation suffix.
func eraFromServerHeader(server string) string {
	if strings.Contains(strings.ToLower(server), "-12c") {
		return "12c"
	}
	return ""
}

// --- Oracle Forms Services ---

// formsEvidence captures the inspectable parts of the single Forms probe.
type formsEvidence struct {
	statusCode int
	body       string
	server     string
	dms        bool
}

// hasFormsMarker reports whether a body carries a strong, non-reflective Oracle
// Forms marker. Case-insensitive product strings plus the FRM-9xxxx code. The
// probe path token "frmservlet" is intentionally NOT a marker: an error/echo page
// reflecting the requested URL would otherwise self-trigger (mirrors
// oracleidentity.hasOAMMarker excluding the obrareq path token).
func hasFormsMarker(body string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "oracle.forms.engine.main") ||
		strings.Contains(lower, "frmall.jar") ||
		strings.Contains(lower, "(oracle forms)") ||
		strings.Contains(lower, "forms services") {
		return true
	}
	return frmErrorPattern.MatchString(body)
}

// evaluateForms decides whether the host is Oracle Forms and, if so, the era and
// FusionMiddleware corroboration. Pure (no I/O); zero values when not detected.
func evaluateForms(ev formsEvidence) (era string, fusion bool, detected bool) {
	detected = ev.statusCode != http.StatusNotFound && hasFormsMarker(ev.body)
	if !detected {
		return "", false, false
	}
	// FusionMiddleware is corroborated by either the DMS monitoring headers or an
	// Oracle-HTTP-Server Server header (both emitted by the OHS/FMW web tier). Only
	// reached once a servlet marker has classified the host, so it enriches — never
	// causes — detection.
	return eraFromServerHeader(ev.server), ev.dms || ohsServerPresent(ev.server), true
}

// detectForms issues the single Forms classifier GET and collects evidence.
func detectForms(client *http.Client, baseURL string, host string) formsEvidence {
	var ev formsEvidence
	resp, err := doGet(client, baseURL+"/forms/frmservlet", host)
	if err != nil {
		return ev
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	ev.statusCode = resp.StatusCode
	ev.body = string(body)
	ev.server = resp.Header.Get("Server")
	ev.dms = dmsPresent(resp)
	return ev
}

// buildFormsCPE returns the CPE for Oracle Forms (version always wildcard, since
// no version is exposed over HTTP).
func buildFormsCPE() string {
	return "cpe:2.3:a:oracle:forms:*:*:*:*:*:*:*:*"
}

// --- Oracle Reports Services ---

// diagResponse captures a Reports diagnostic-endpoint response (getserverinfo /
// showenv).
type diagResponse struct {
	statusCode int
	body       string
}

// reportsEvidence captures the Reports classifier probe plus the (best-effort)
// diagnostic-endpoint responses.
type reportsEvidence struct {
	statusCode    int
	body          string
	server        string
	dms           bool
	getServerInfo diagResponse
	showenv       diagResponse
}

// hasReportsMarker reports whether a body carries a strong, non-reflective Oracle
// Reports marker. The probe path token "rwservlet" is intentionally NOT a marker
// (self-referential echo guard, mirroring hasFormsMarker / hasOAMMarker).
func hasReportsMarker(body string) bool {
	lower := strings.ToLower(body)
	if strings.Contains(lower, "oracle reports") ||
		strings.Contains(lower, "reports servlet") {
		return true
	}
	return repErrorPattern.MatchString(body)
}

// parseReportsVersion extracts the Reports Server version from a getserverinfo
// body (XML version="x" attribute or HTML "Version: x" label). Returns "" when
// absent (e.g. the endpoint is DIAGNOSTIC=NO gated).
func parseReportsVersion(body string) string {
	if m := reportsVersionPattern.FindStringSubmatch(body); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// eraFromShowenv infers the 10g-vs-12c era from a showenv PATH_TRANSLATED / env
// dump: OC4J_BI_Forms / DevSuiteHome => 10g; a WebLogic domain layout => 12c.
func eraFromShowenv(body string) string {
	if strings.Contains(body, "OC4J_BI_Forms") || strings.Contains(body, "DevSuiteHome") {
		return "10g"
	}
	if strings.Contains(body, "user_projects/domains") ||
		strings.Contains(body, "WLS_FORMS") ||
		strings.Contains(body, "WLS_REPORTS") {
		return "12c"
	}
	return ""
}

// hasReportsDiagnosticContent reports whether a getserverinfo/showenv body carries
// ACTUAL leaked Reports diagnostic data (an environment/server-info dump), as
// opposed to a bare 200, a DIAGNOSTIC=NO access-error page, or a generic Oracle
// diagnostic page that merely carries the Ora* CSS classes. The Medium
// info-disclosure finding requires real leaked data: the PATH_TRANSLATED
// environment field, or a parsed Reports version (getserverinfo). The generic
// Ora* CSS classes do NOT by themselves prove a disclosure, so they are
// intentionally excluded here to avoid over-reporting (they also no longer
// classify the product — see hasReportsMarker). Only product-emitted tokens are
// used — never the probe path tokens, so an echoed request URL cannot
// self-trigger.
func hasReportsDiagnosticContent(body string) bool {
	if strings.Contains(body, "PATH_TRANSLATED") {
		return true
	}
	return parseReportsVersion(body) != ""
}

// evaluateReports decides whether the host is Oracle Reports and, if so, the
// best-effort version + era and FusionMiddleware corroboration. Pure (no I/O);
// zero values when not detected.
func evaluateReports(ev reportsEvidence) (version string, era string, fusion bool, detected bool) {
	detected = ev.statusCode != http.StatusNotFound && hasReportsMarker(ev.body)
	if !detected {
		return "", "", false, false
	}
	// FusionMiddleware is corroborated by either the DMS monitoring headers or an
	// Oracle-HTTP-Server Server header (both emitted by the OHS/FMW web tier). Only
	// reached once a servlet marker has classified the host, so it enriches — never
	// causes — detection.
	fusion = ev.dms || ohsServerPresent(ev.server)
	era = eraFromServerHeader(ev.server)
	if isSuccessStatus(ev.getServerInfo.statusCode) {
		if v := parseReportsVersion(ev.getServerInfo.body); v != "" {
			version = v
		}
	}
	if isSuccessStatus(ev.showenv.statusCode) {
		if e := eraFromShowenv(ev.showenv.body); e != "" {
			era = e
		}
	}
	return version, era, fusion, detected
}

// reportsInfoDisclosed reports whether the Reports diagnostic endpoints leaked
// environment/version/topology content on a 2xx response — the trigger for the
// Medium information-disclosure finding. Pure (no I/O).
func reportsInfoDisclosed(ev reportsEvidence) bool {
	if isSuccessStatus(ev.getServerInfo.statusCode) && hasReportsDiagnosticContent(ev.getServerInfo.body) {
		return true
	}
	if isSuccessStatus(ev.showenv.statusCode) && hasReportsDiagnosticContent(ev.showenv.body) {
		return true
	}
	return false
}

// fetchDiag issues one read-only Reports diagnostic GET. Errors are non-fatal
// (returns a zero diagResponse, treated as unavailable).
func fetchDiag(client *http.Client, url string, host string) diagResponse {
	resp, err := doGet(client, url, host)
	if err != nil {
		return diagResponse{}
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	return diagResponse{statusCode: resp.StatusCode, body: string(body)}
}

// detectReports issues the Reports classifier GET and, ONLY when a marker
// classifies the host AND probeDiagnostics is set, the two read-only diagnostic
// GETs (avoids extra requests on non-Reports hosts). getserverinfo and showenv are
// Oracle-documented ADMINISTRATOR-ONLY rwservlet web commands, so they are only
// issued when the caller opts in (Misconfigs || Deep); a baseline scan probes only
// the bare /reports/rwservlet path. Detection via the bare servlet marker still
// works in baseline mode; only version/era enrichment and the info-disclosure
// finding depend on these gated diagnostics. No query parameter is ever appended
// to rwservlet.
func detectReports(client *http.Client, baseURL string, host string, probeDiagnostics bool) reportsEvidence {
	var ev reportsEvidence
	resp, err := doGet(client, baseURL+"/reports/rwservlet", host)
	if err != nil {
		return ev
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	ev.statusCode = resp.StatusCode
	ev.body = string(body)
	ev.server = resp.Header.Get("Server")
	ev.dms = dmsPresent(resp)
	// Close the classifier response BEFORE issuing any diagnostic probe. The plugin
	// holds a single net.Conn, so leaving this body open would prevent the transport
	// from returning the connection to the idle pool and force the diag GET to
	// re-dial the same socket (data race / protocol corruption). Closing here releases
	// the connection so the diag requests reuse it cleanly, one user at a time.
	_ = resp.Body.Close()

	// Enrichment ONLY after the classifier detected Reports, and only when the
	// caller opted into the admin-only diagnostic probes.
	if ev.statusCode == http.StatusNotFound || !hasReportsMarker(ev.body) || !probeDiagnostics {
		return ev
	}
	ev.getServerInfo = fetchDiag(client, baseURL+"/reports/rwservlet/getserverinfo", host)
	ev.showenv = fetchDiag(client, baseURL+"/reports/rwservlet/showenv", host)
	return ev
}

// buildReportsCPE returns the CPE for Oracle Reports, stamping the parsed version
// when available and a wildcard otherwise. The NVD product token is
// version-dependent (verified against the NVD CPE dictionary): the current 12c
// line is published as "reports_developer" (NVD versions 12.2.1.3, 12.2.1.3.0,
// 12.2.1.4.0; e.g. CVE-2024-21133 => cpe:2.3:a:oracle:reports_developer:12.2.1.4.0),
// while the legacy 6i/9i/10g line is published as "reports" (NVD versions 6i, 9i,
// 9.0.2, 10g, ...). Parsed 12c versions therefore map to "reports_developer";
// everything else (legacy or unknown version) keeps the "reports" token.
func buildReportsCPE(version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	product := "reports"
	if strings.HasPrefix(v, "12.") {
		product = "reports_developer"
	}
	return fmt.Sprintf("cpe:2.3:a:oracle:%s:%s:*:*:*:*:*:*:*", product, v)
}

// --- Security findings (shared) ---

// formsReportsExposedFinding is the Low surface-exposure finding shared by both
// products (a reachable frmservlet/rwservlet is an attack-surface fact).
func formsReportsExposedFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-forms-reports-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Forms/Reports Services surface is reachable without authentication; the frmservlet/rwservlet endpoints are exposed to the network",
		Evidence:    "Oracle Forms/Reports servlet endpoints responded without credentials",
	}
}

// reportsInfoDisclosureFinding is the Medium finding for unauthenticated Reports
// diagnostic endpoints. Evidence carries observable protocol facts only — never
// any leaked env/path/version value from the body.
func reportsInfoDisclosureFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-reports-info-disclosure",
		Severity:    plugins.SeverityMedium,
		Description: "Oracle Reports diagnostic endpoints (rwservlet showenv/getserverinfo) are reachable without authentication and disclose server version, environment, and path/topology information useful for targeting",
		Evidence:    "rwservlet showenv/getserverinfo returned diagnostic content on a 2xx response without credentials",
	}
}

// --- Forms plugin variants ---

func (p *FormsPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	ev := detectForms(client, baseURL, target.Host)
	era, fusion, detected := evaluateForms(ev)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleForms{
		Era:              era,
		FusionMiddleware: fusion,
		CPEs:             []string{buildFormsCPE()},
	}
	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
	// A servlet marker on a 401/403 is not anonymous access: only report anonymous
	// access / the finding when the classifier response was a 2xx success.
	if target.Misconfigs && isSuccessStatus(ev.statusCode) {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, formsReportsExposedFinding())
	}
	return service, nil
}

func (p *FormsPlugin) PortPriority(port uint16) bool { return portInList(port) }
func (p *FormsPlugin) Name() string                  { return OracleForms }
func (p *FormsPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *FormsPlugin) Priority() int                 { return -1 } // Runs before generic HTTP so it can claim Forms on shared ports

func (p *FormsTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	ev := detectForms(client, baseURL, target.Host)
	era, fusion, detected := evaluateForms(ev)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleForms{
		Era:              era,
		FusionMiddleware: fusion,
		CPEs:             []string{buildFormsCPE()},
	}
	service := plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS)
	if target.Misconfigs {
		if isSuccessStatus(ev.statusCode) {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, formsReportsExposedFinding())
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *FormsTLSPlugin) PortPriority(port uint16) bool { return port == 443 || port == 4443 } // 4443 is the Oracle HTTP Server TLS default that commonly fronts Forms
func (p *FormsTLSPlugin) Name() string                  { return OracleForms }
func (p *FormsTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *FormsTLSPlugin) Priority() int                 { return -1 } // Runs before generic HTTPS so it can claim Forms on shared ports (e.g. 443)

// --- Reports plugin variants ---

func (p *ReportsPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	ev := detectReports(client, baseURL, target.Host, target.Misconfigs || target.Deep)
	version, era, fusion, detected := evaluateReports(ev)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleReports{
		Era:              era,
		FusionMiddleware: fusion,
		CPEs:             []string{buildReportsCPE(version)},
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	if target.Misconfigs {
		if isSuccessStatus(ev.statusCode) {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, formsReportsExposedFinding())
		}
		if reportsInfoDisclosed(ev) {
			// The surface answered anonymously with real leaked diagnostic data,
			// even if the bare rwservlet classifier response was non-2xx.
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, reportsInfoDisclosureFinding())
		}
	}
	return service, nil
}

func (p *ReportsPlugin) PortPriority(port uint16) bool { return portInList(port) }
func (p *ReportsPlugin) Name() string                  { return OracleReports }
func (p *ReportsPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *ReportsPlugin) Priority() int                 { return -1 } // Runs before generic HTTP so it can claim Reports on shared ports

func (p *ReportsTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	ev := detectReports(client, baseURL, target.Host, target.Misconfigs || target.Deep)
	version, era, fusion, detected := evaluateReports(ev)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleReports{
		Era:              era,
		FusionMiddleware: fusion,
		CPEs:             []string{buildReportsCPE(version)},
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		if isSuccessStatus(ev.statusCode) {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, formsReportsExposedFinding())
		}
		if reportsInfoDisclosed(ev) {
			// The surface answered anonymously with real leaked diagnostic data,
			// even if the bare rwservlet classifier response was non-2xx.
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, reportsInfoDisclosureFinding())
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *ReportsTLSPlugin) PortPriority(port uint16) bool { return port == 443 || port == 4443 } // 4443 is the Oracle HTTP Server TLS default that commonly fronts Reports
func (p *ReportsTLSPlugin) Name() string                  { return OracleReports }
func (p *ReportsTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *ReportsTLSPlugin) Priority() int                 { return -1 } // Runs before generic HTTPS so it can claim Reports on shared ports (e.g. 443)
