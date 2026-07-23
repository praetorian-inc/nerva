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
Oracle Hyperion / Essbase (EPM) Fingerprinting (LAB-5054)

This package detects two Oracle Enterprise Performance Management (EPM)
technologies. Four plugins are registered from a single init():

Oracle Hyperion EPM web tier (Name "oracle_hyperion"): HyperionPlugin (TCP) and
HyperionTLSPlugin (TLS). The plugins issue GET requests to the Workspace landing
page (/workspace/index.jsp), the Shared Services / Foundation console (/interop/),
Hyperion Planning (/HyperionPlanning/) and Analytic Provider Services (/aps/JAPI).

  A host is classified as Hyperion when ANY strong, Oracle-EPM-specific signal is
  present (a bare 200/302/non-404 on a probe path is NEVER sufficient):
    - The branded Workspace <title> ("Enterprise Performance Management System
      Workspace")
    - Workspace bootstrap JS namespaces in the body (BpmMainFrame, bpmui,
      com.hyperion., workspace.taskbar)
    - The Foundation / Shared Services brand pair on /interop/ ("Hyperion" plus
      "Shared Services"/"Foundation Services"), which also sets SharedServices
    - An EPM session cookie NAME (EPM_ROOT, EPMwvSess)
  Corroborating enrichment (never triggers detection on its own): a Planning-branded
  /HyperionPlanning/ response (Planning) and an APS-branded /aps/JAPI response (APS).

Oracle Essbase (Name "oracle_essbase"): three surfaces, any of which asserts the
product.

  EssbasePlugin (TCP) / EssbaseTLSPlugin (TLS) detect the independent Essbase 21c
  REST tier via GET /essbase/rest/v1/about. DETECTION requires only the server-
  generated "name":"Essbase" JSON gate, never a bare 200 or a path echo. The VERSION
  is decoupled and best-effort: when a [0-9.]-shaped "version" is present in the same
  body it feeds the CPE and service.Version; when absent, detection still succeeds and
  the CPE version is wildcard.

  (A best-effort TCP/1423 Essbase Agent detector was intentionally removed: the Agent
  wire protocol is Oracle-proprietary with no published magic byte, so there is no
  confirmed positive signature to assert on. Essbase remains fully detected via the
  21c REST tier above. An agent probe is deferred to a follow-up ticket for when a
  live capture yields a real signature.)

Version:
  The Essbase 21c REST /about surface supplies an exact version WHEN its body carries
  one (best-effort, decoupled from detection); every other surface, and a version-less
  /about, passes version "" and a wildcard CPE version field.
*/

package oraclehyperion

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const (
	OracleHyperion = "oracle_hyperion"
	OracleEssbase  = "oracle_essbase"

	// DefaultHyperionPort is the default EPM Workspace port fronted by Oracle HTTP
	// Server (OHS).
	DefaultHyperionPort = 19000
	// DefaultHyperionSecurePort is the SSL EPM Workspace port (non-SSL is 19000).
	DefaultHyperionSecurePort = 19443
	// DefaultEssbaseRESTPort / EssbaseRESTPortAlt are the Essbase 21c REST web-tier
	// ports. They are split by transport: 9000 serves plaintext (non-SSL) REST and is
	// claimed by the plaintext EssbasePlugin, while 9001 serves secured (HTTPS) REST
	// and is claimed by the TLS EssbaseTLSPlugin.
	DefaultEssbaseRESTPort = 9000
	EssbaseRESTPortAlt     = 9001

	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(1 * 1024 * 1024) // 1 MiB: EPM markers appear early; bounds per-probe memory
)

// titlePattern extracts the contents of an HTML <title> element. The pattern is
// WIDENED from the narrow oracleidentity form: EPM/Workspace titles may carry
// attributes on the <title> tag, so the narrow `<title>` form is a known
// cross-cutting miss. RE2 (linear-time), compiled once at package scope.
var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// essbaseAbout is the narrow projection of the Essbase 21c REST /about document.
// The body is parsed with encoding/json into this fixed struct (never a regex over
// the raw text), so a truncated/malformed JSON body or an HTML page that merely
// contains the "name":"Essbase" substring cannot satisfy the gate.
type essbaseAbout struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// essbaseVersionShape restricts an accepted /about "version" to a digits/dots shape
// (two or more dot-separated numeric components; no upper bound so a future 6-part
// version is not dropped) so attacker-controlled bytes cannot inject CPE separators
// (see buildEssbaseCPE). Version is best-effort and decoupled from detection: a
// version failing this shape is dropped, detection still succeeds, and the CPE
// version stays wildcard.
var essbaseVersionShape = regexp.MustCompile(`^\d+(?:\.\d+){1,}$`)

// HyperionPlugin detects the Oracle Hyperion EPM web tier over plain HTTP.
type HyperionPlugin struct{}

// HyperionTLSPlugin detects the Oracle Hyperion EPM web tier over TLS.
type HyperionTLSPlugin struct{}

// EssbasePlugin detects the Oracle Essbase 21c REST tier over plain HTTP.
type EssbasePlugin struct{}

// EssbaseTLSPlugin detects the Oracle Essbase 21c REST tier over TLS.
type EssbaseTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&HyperionPlugin{})
	plugins.RegisterPlugin(&HyperionTLSPlugin{})
	plugins.RegisterPlugin(&EssbasePlugin{})
	plugins.RegisterPlugin(&EssbaseTLSPlugin{})
}

// --- shared HTTP helpers (mirrors oracleidentity.go) ---

// createHTTPClient creates an http.Client that wraps the provided net.Conn and
// does not follow redirects (so Location headers can be inspected directly, and no
// attacker-chosen redirect target is ever fetched).
//
// The scanner provides a single net.Conn; detectHyperion/detectEssbaseREST reuse
// it across their sequential probes. If the server sends "Connection: close" (or
// closes) after an early probe, later probes fail and are skipped (non-fatal), so
// the highest-signal path (the Workspace title on the first probe) is ordered
// first. Re-dialing per probe is intentionally avoided: the conn may already be
// TLS-wrapped (the TLS variants), and this matches the merged oracleidentity
// precedent.
func createHTTPClient(conn net.Conn, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
}

// doGet performs a GET request with the nerva User-Agent header.
func doGet(client *http.Client, url string, host string) (*http.Response, error) {
	return doGetWithAccept(client, url, host, "")
}

// doGetWithAccept performs a GET request, optionally setting an Accept header. When
// host is non-empty it is set as the HTTP Host header so name-based virtual hosts
// are reached (the connection is still dialed by IP via the client's transport). The
// Host is only ever the caller-supplied target.Host, never synthesized from
// untrusted reverse-DNS.
func doGetWithAccept(client *http.Client, url, host, accept string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nerva/1.0")
	if host != "" {
		req.Host = host
	}
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	return client.Do(req)
}

// extractTitle returns the trimmed contents of the first <title> element, if any.
func extractTitle(body string) string {
	if m := titlePattern.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// isAnonymousExposure reports whether a marker-bearing response shows the product
// reachable WITHOUT authentication. Only a 2xx success qualifies: a redirect (even
// to a login page) means auth is being enforced, and a 4xx/5xx is not access - those
// still identify the product but must not set AnonymousAccess or the exposure finding.
func isAnonymousExposure(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}

// --- Oracle Hyperion EPM web tier ---

// hyperionEvidence captures the inspectable parts of a single Hyperion probe
// response.
type hyperionEvidence struct {
	path       string
	statusCode int
	location   string
	body       string
	setCookies []string
	title      string // extractTitle(body), precomputed
}

// hasWorkspaceTitleMarker reports whether a title is the branded EPM Workspace
// title. This is server-rendered and NOT derived from the requested path, so it is
// a non-reflective marker. The probe-path substrings (workspace, interop,
// HyperionPlanning, aps, JAPI) are intentionally NOT markers: an error/echo page
// that reflects the requested URL must never be a self-referential false positive.
func hasWorkspaceTitleMarker(title string) bool {
	return strings.Contains(strings.ToLower(title),
		"enterprise performance management system workspace")
}

// hasWorkspaceBodyMarker reports whether a body carries a hardcoded Workspace
// bootstrap JS namespace. These are server-emitted app namespaces, not echoes of the
// requested path.
func hasWorkspaceBodyMarker(body string) bool {
	return strings.Contains(body, "BpmMainFrame") ||
		strings.Contains(body, "bpmui") ||
		strings.Contains(body, "com.hyperion.") ||
		strings.Contains(body, "workspace.taskbar")
}

// hasSharedServicesMarker reports whether a string (body+title, or a redirect
// Location) carries the Foundation / Shared Services brand pair. Requires both the
// "Hyperion" brand and a Shared/Foundation Services string, so a bare echo of the
// "/interop/" path never counts.
func hasSharedServicesMarker(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "hyperion") &&
		(strings.Contains(lower, "shared services") ||
			strings.Contains(lower, "foundation services"))
}

// hasEPMCookie reports whether any Set-Cookie header defines an EPM/Workspace
// session cookie by NAME. Each header's real cookie name is isolated (the token
// before the first ';' and before the first '=') and matched exact-equal, so a
// substring like notEPM_ROOT= or x=EPM_ROOT=... can never falsely trigger. Only the
// cookie name is inspected; the cookie value is a live session token and is never
// read, logged, or stored (P0-7).
func hasEPMCookie(setCookies []string) bool {
	for _, sc := range setCookies {
		pair := sc
		if i := strings.IndexByte(pair, ';'); i >= 0 {
			pair = pair[:i]
		}
		name := pair
		if i := strings.IndexByte(name, '='); i >= 0 {
			name = name[:i]
		}
		switch strings.TrimSpace(name) {
		case "EPM_ROOT", "EPMwvSess":
			return true
		}
	}
	return false
}

// evaluateHyperion inspects collected responses and decides whether the host is the
// Oracle Hyperion EPM web tier. Detection asserts on ANY strong non-reflective
// signal (S1-S4); Planning/APS are corroborating enrichment only and never set
// detected. anonExposure reports whether at least one strong signal rode a 2xx
// success response (P0-6); a redirect (even to a login page) means auth is being
// enforced and does not set anonExposure (see isAnonymousExposure).
func evaluateHyperion(evs []hyperionEvidence) (sharedServices, planning, aps, detected, anonExposure bool) {
	for _, ev := range evs {
		strong := false

		// A redirect Location may URL-encode marker text (e.g. spaces as %20), so
		// decode a copy for the location-based marker checks. On decode failure the
		// raw value is kept. The body is NEVER decoded here: a body containing '%'
		// sequences must not be mangled.
		loc := ev.location
		if dec, err := url.QueryUnescape(loc); err == nil {
			loc = dec
		}

		// S1: branded Workspace <title>.
		if hasWorkspaceTitleMarker(ev.title) {
			strong = true
		}
		// S2: Workspace bootstrap JS namespaces.
		if hasWorkspaceBodyMarker(ev.body) {
			strong = true
		}
		// S3: Foundation / Shared Services brand pair (body, title, or redirect
		// Location). Also flags the SharedServices enrichment.
		if hasSharedServicesMarker(ev.body) || hasSharedServicesMarker(ev.title) ||
			hasSharedServicesMarker(loc) {
			strong = true
			sharedServices = true
		}
		// S4: EPM session-cookie name.
		if hasEPMCookie(ev.setCookies) {
			strong = true
		}

		if strong {
			detected = true
			if isAnonymousExposure(ev.statusCode) {
				anonExposure = true
			}
		}

		// C1 (enrichment only): Planning module present.
		if strings.Contains(ev.path, "HyperionPlanning") && ev.statusCode != http.StatusNotFound {
			if strings.Contains(ev.body, "Oracle Hyperion Planning") ||
				strings.Contains(ev.title, "Oracle Hyperion Planning") {
				planning = true
			}
		}
		// C2 (enrichment only): Analytic Provider Services servlet present.
		if strings.Contains(ev.path, "/aps/") && ev.statusCode != http.StatusNotFound {
			if strings.Contains(ev.body, "Analytic Provider Services") {
				aps = true
			}
		}
	}
	return sharedServices, planning, aps, detected, anonExposure
}

// detectHyperion fetches the Hyperion probe paths and evaluates the collected
// evidence. Probe errors are non-fatal (continue with whatever evidence exists); no
// redirect is followed; each body is capped by LimitReader.
func detectHyperion(client *http.Client, baseURL, host string) (sharedServices, planning, aps, detected, anonExposure bool) {
	paths := []string{
		"/workspace/index.jsp",
		"/interop/",
		"/HyperionPlanning/",
		"/aps/JAPI",
	}
	var evs []hyperionEvidence
	for _, p := range paths {
		resp, err := doGet(client, baseURL+p, host)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		bodyStr := string(body)
		evs = append(evs, hyperionEvidence{
			path:       p,
			statusCode: resp.StatusCode,
			location:   resp.Header.Get("Location"),
			body:       bodyStr,
			setCookies: resp.Header.Values("Set-Cookie"),
			title:      extractTitle(bodyStr),
		})
		_ = resp.Body.Close()
	}
	return evaluateHyperion(evs)
}

// buildHyperionCPE returns the CPE list for a detected Hyperion EPM web tier.
//
// NVD verification 2026-07-22 (services.nvd.nist.gov/rest/json/cpes/2.0):
//   - oracle:hyperion                 -> 18 results (9.2.0.3 .. 11.2.13.0.000): VALID umbrella token, emitted generically
//   - oracle:hyperion_planning        ->  2 results: VALID module token, emitted when Planning is detected
//   - oracle:hyperion_bi_plus         ->  0 results: NOT a valid NVD token -> DROPPED (was the plan's proposed generic)
//   - oracle:hyperion_shared_services ->  0 results: NOT a valid NVD token -> NOT emitted (SharedServices stays an enrichment boolean only)
//
// Deviation from architecture.md §2: the plan proposed oracle:hyperion_bi_plus as the
// generic and oracle:hyperion_shared_services as a module token. Neither resolves in
// NVD. The proven umbrella oracle:hyperion is emitted instead; never assert a wrong
// token. Shared Services stays an enrichment boolean on the Service struct and does
// not map to a CPE, so it is not a parameter here.
func buildHyperionCPE(planning bool) []string {
	cpes := []string{"cpe:2.3:a:oracle:hyperion:*:*:*:*:*:*:*:*"}
	if planning {
		cpes = append(cpes, "cpe:2.3:a:oracle:hyperion_planning:*:*:*:*:*:*:*:*")
	}
	return cpes
}

// hyperionFinding is the LOW-severity anonymous-exposure finding for the Hyperion web
// tier. Evidence is a static, hand-written string: no response body, header, or
// cookie value is ever placed in a finding (P0-7).
func hyperionFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-hyperion-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Hyperion EPM (Workspace / Shared Services) web surface is reachable without authentication",
		Evidence:    "Oracle Hyperion EPM web endpoints responded without credentials",
	}
}

// --- Oracle Essbase 21c REST ---

// essbaseRESTEvidence captures the inspectable parts of the /about probe response.
type essbaseRESTEvidence struct {
	statusCode int
	location   string
	body       string
}

// evaluateEssbaseREST decides whether the /about response is a genuine Essbase 21c
// REST document. DETECTION (P0) requires the body to parse as JSON into essbaseAbout
// AND to carry a server-generated "name" that equals "Essbase" case-insensitively. The body is decoded
// with encoding/json (into a fixed narrow struct, over an io.LimitReader-capped
// body), so a truncated/malformed body like `{"name":"Essbase"` or an HTML page that
// merely contains the "name":"Essbase" substring cannot pass. A bare 200 with HTML, a
// 401/403 with no JSON, or a plain echo of the reflectable /essbase/rest/v1/about path
// all fail the parse or the name gate, so none of them assert the product (P0-8, P0-10).
//
// VERSION (P1) is parsed SEPARATELY as best-effort and is deliberately decoupled from
// detection: only a clean digits/dots-shaped about.Version (essbaseVersionShape) is
// returned (feeding the oracle:essbase CPE and service.Version); when it is absent or
// malformed detection STILL succeeds and version stays "" (buildEssbaseCPE emits the
// wildcard cpe:2.3:a:oracle:essbase:*:...). The shape check is the CPE-injection guard.
func evaluateEssbaseREST(ev essbaseRESTEvidence) (rest bool, version string, detected, anonExposure bool) {
	var about essbaseAbout
	if err := json.Unmarshal([]byte(ev.body), &about); err != nil {
		return false, "", false, false
	}
	if !strings.EqualFold(strings.TrimSpace(about.Name), "Essbase") {
		return false, "", false, false
	}
	rest = true
	detected = true
	if essbaseVersionShape.MatchString(about.Version) {
		version = about.Version // best-effort; malformed/absent leaves the CPE wildcard
	}
	anonExposure = isAnonymousExposure(ev.statusCode)
	return rest, version, detected, anonExposure
}

// detectEssbaseREST fetches /essbase/rest/v1/about and evaluates the response. The
// probe error path is non-fatal and the body is capped by LimitReader.
func detectEssbaseREST(client *http.Client, baseURL, host string) (rest bool, version string, detected, anonExposure bool) {
	resp, err := doGetWithAccept(client, baseURL+"/essbase/rest/v1/about", host, "application/json")
	if err != nil {
		return false, "", false, false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	ev := essbaseRESTEvidence{
		statusCode: resp.StatusCode,
		location:   resp.Header.Get("Location"),
		body:       string(body),
	}
	_ = resp.Body.Close()
	return evaluateEssbaseREST(ev)
}

// buildEssbaseCPE returns the CPE for Oracle Essbase. oracle:essbase is a confirmed
// NVD token (verified 2026-07-22: 7 results, e.g. essbase:21.2, essbase:21.7.3.0.0).
// The version is already digits/dots-validated by essbaseVersionShape, or ""
// (wildcard) when the /about body carries no version, so it cannot inject CPE
// separators (P0-5).
func buildEssbaseCPE(version string) []string {
	v := "*"
	if version != "" {
		v = version
	}
	return []string{"cpe:2.3:a:oracle:essbase:" + v + ":*:*:*:*:*:*:*"}
}

// essbaseRestFinding is the LOW-severity anonymous-exposure finding for the Essbase
// 21c REST tier. Evidence is a static string (P0-7).
func essbaseRestFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-essbase-rest-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Essbase 21c REST API (/essbase/rest/v1/about) is reachable without authentication",
		Evidence:    "Oracle Essbase REST /about returned an Essbase-branded JSON document without credentials",
	}
}

// --- HyperionPlugin (TCP) ---

func (p *HyperionPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	ss, planning, aps, detected, anonExposure := detectHyperion(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleHyperion{
		SharedServices: ss,
		Planning:       planning,
		APS:            aps,
		CPEs:           buildHyperionCPE(planning),
	}
	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
	if target.Misconfigs && anonExposure {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, hyperionFinding())
	}
	return service, nil
}

func (p *HyperionPlugin) PortPriority(port uint16) bool { return port == DefaultHyperionPort }
func (p *HyperionPlugin) Name() string                  { return OracleHyperion }
func (p *HyperionPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *HyperionPlugin) Priority() int                 { return -1 } // Runs before generic HTTP so it can claim Hyperion on shared ports

// --- HyperionTLSPlugin (TLS) ---

func (p *HyperionTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	ss, planning, aps, detected, anonExposure := detectHyperion(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleHyperion{
		SharedServices: ss,
		Planning:       planning,
		APS:            aps,
		CPEs:           buildHyperionCPE(planning),
	}
	service := plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS)
	if target.Misconfigs {
		if anonExposure {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, hyperionFinding())
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *HyperionTLSPlugin) PortPriority(port uint16) bool {
	return port == 443 || port == DefaultHyperionSecurePort
}
func (p *HyperionTLSPlugin) Name() string           { return OracleHyperion }
func (p *HyperionTLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }
func (p *HyperionTLSPlugin) Priority() int          { return -1 } // Runs before generic HTTPS so it can claim Hyperion on shared ports (e.g. 443)

// --- EssbasePlugin (TCP, 21c REST) ---

func (p *EssbasePlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	rest, version, detected, anonExposure := detectEssbaseREST(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleEssbase{
		REST: rest,
		CPEs: buildEssbaseCPE(version),
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	if target.Misconfigs && anonExposure {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, essbaseRestFinding())
	}
	return service, nil
}

func (p *EssbasePlugin) PortPriority(port uint16) bool {
	return port == DefaultEssbaseRESTPort
}
func (p *EssbasePlugin) Name() string           { return OracleEssbase }
func (p *EssbasePlugin) Type() plugins.Protocol { return plugins.TCP }
func (p *EssbasePlugin) Priority() int          { return -1 } // Runs before generic HTTP so it can claim Essbase on shared ports

// --- EssbaseTLSPlugin (TLS, 21c REST) ---

func (p *EssbaseTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	rest, version, detected, anonExposure := detectEssbaseREST(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleEssbase{
		REST: rest,
		CPEs: buildEssbaseCPE(version),
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		if anonExposure {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, essbaseRestFinding())
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *EssbaseTLSPlugin) PortPriority(port uint16) bool {
	return port == 443 || port == EssbaseRESTPortAlt
}
func (p *EssbaseTLSPlugin) Name() string           { return OracleEssbase }
func (p *EssbaseTLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }
func (p *EssbaseTLSPlugin) Priority() int          { return -1 } // Runs before generic HTTPS so it can claim Essbase on shared ports (e.g. 443)
