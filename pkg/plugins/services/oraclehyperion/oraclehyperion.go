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
technologies. Five plugins are registered from a single init():

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

  EssbaseAgentPlugin (TCP, port 1423) is a CONSERVATIVE, BEST-EFFORT detector of the
  Essbase Agent (AGENTPORT) listener. The Agent wire protocol is Oracle-proprietary
  with no published magic byte, so there is no positive signature. The plugin sends
  ONE minimal benign probe, performs ONE bounded read, and asserts only on a
  non-empty, non-HTTP, non-printable-ASCII binary reply (negative discriminators).
  It NEVER asserts on a bare open port or on silence (see isEssbaseAgent), claims no
  version, and sets neither AnonymousAccess nor a SecurityFinding.

Version:
  The Essbase 21c REST /about surface supplies an exact version WHEN its body carries
  one (best-effort, decoupled from detection); every other surface, and a version-less
  /about, passes version "" and a wildcard CPE version field.
*/

package oraclehyperion

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	OracleHyperion = "oracle_hyperion"
	OracleEssbase  = "oracle_essbase"
	// OracleEssbaseAgent is the registry NAME for the best-effort TCP/1423 agent
	// plugin. It is deliberately distinct from OracleEssbase: the framework keys the
	// plugin registry on {Name, Protocol} (plugins.CreatePluginID), so two TCP
	// plugins cannot share a Name (a duplicate key panics at init). The DETECTED
	// PRODUCT is still oracle_essbase - that identity comes from the emitted
	// ServiceOracleEssbase.Type() (ProtoOracleEssbase), not from this registry name.
	// See the deviation note in the file header / capability-developer.md.
	OracleEssbaseAgent = "oracle_essbase_agent"

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
	// EssbaseAgentPort is the fixed, well-known Essbase Agent (AGENTPORT) listener.
	EssbaseAgentPort = 1423

	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(1 * 1024 * 1024) // 1 MiB: EPM markers appear early; bounds per-probe memory

	// minAgentResponse is the length floor for a plausible binary Essbase Agent
	// reply. Anything shorter (including an empty read from silence) is not a signal.
	minAgentResponse = 4
	// binaryContentRatio is the minimum fraction of non-printable bytes required for
	// hasBinaryContent to treat a response as genuinely binary (not an ASCII fluke).
	binaryContentRatio = 0.25
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
// so attacker-controlled bytes cannot inject CPE separators (see buildEssbaseCPE).
// Version is best-effort and decoupled from detection: a version failing this shape
// is dropped, detection still succeeds, and the CPE version stays wildcard.
var essbaseVersionShape = regexp.MustCompile(`^\d+(?:\.\d+){1,4}$`)

// HyperionPlugin detects the Oracle Hyperion EPM web tier over plain HTTP.
type HyperionPlugin struct{}

// HyperionTLSPlugin detects the Oracle Hyperion EPM web tier over TLS.
type HyperionTLSPlugin struct{}

// EssbasePlugin detects the Oracle Essbase 21c REST tier over plain HTTP.
type EssbasePlugin struct{}

// EssbaseTLSPlugin detects the Oracle Essbase 21c REST tier over TLS.
type EssbaseTLSPlugin struct{}

// EssbaseAgentPlugin is a best-effort detector of the Essbase Agent (TCP 1423).
type EssbaseAgentPlugin struct{}

func init() {
	plugins.RegisterPlugin(&HyperionPlugin{})
	plugins.RegisterPlugin(&HyperionTLSPlugin{})
	plugins.RegisterPlugin(&EssbasePlugin{})
	plugins.RegisterPlugin(&EssbaseTLSPlugin{})
	plugins.RegisterPlugin(&EssbaseAgentPlugin{})
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
			hasSharedServicesMarker(ev.location) {
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
// The version is already digits/dots-validated by essbaseVersionShape, or "" (wildcard)
// on the agent path, so it cannot inject CPE separators (P0-5).
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

// --- Oracle Essbase Agent (TCP 1423, best-effort) ---

// buildEssbaseAgentProbe returns a minimal, benign probe. Its purpose is a NEGATIVE
// discriminator, not a semantic handshake: an HTTP server answers with an ASCII
// "HTTP/..." status line and a line-oriented banner service greets in ASCII, and
// neither shape qualifies as an Essbase Agent (see isEssbaseAgent). No magic-byte
// Essbase handshake is known (the Agent protocol is proprietary and undocumented), so
// no length-prefixed frame, no credentials, and no ESSLANG negotiation are ever sent
// (P0-9e). One benign write, one bounded read, close.
func buildEssbaseAgentProbe() []byte {
	return []byte("GET / HTTP/1.0\r\n\r\n")
}

// hasHTTPPrefix reports whether a response begins with an HTTP status line.
func hasHTTPPrefix(b []byte) bool {
	return bytes.HasPrefix(b, []byte("HTTP/"))
}

// isPrintableASCII reports whether every byte is printable ASCII or common
// whitespace (tab/CR/LF). A fully-printable response is a text/banner service, not
// the binary Agent.
func isPrintableASCII(b []byte) bool {
	for _, c := range b {
		if c >= 0x20 && c <= 0x7E {
			continue
		}
		if c == 0x09 || c == 0x0A || c == 0x0D {
			continue
		}
		return false
	}
	return true
}

// hasBinaryContent reports whether a meaningful fraction of bytes are outside the
// printable/whitespace set - a conservative "this is genuinely binary" gate rather
// than a single-byte fluke.
func hasBinaryContent(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	nonPrintable := 0
	for _, c := range b {
		if c >= 0x20 && c <= 0x7E {
			continue
		}
		if c == 0x09 || c == 0x0A || c == 0x0D {
			continue
		}
		nonPrintable++
	}
	return float64(nonPrintable)/float64(len(b)) >= binaryContentRatio
}

// isEssbaseAgent is the CONSERVATIVE, BEST-EFFORT, LOW-CONFIDENCE classifier for the
// Essbase Agent listener. There is no published magic byte for the proprietary Agent
// protocol, so this asserts only on negative discriminators plus a length floor.
//
// It returns true ONLY for a non-empty, non-HTTP, non-printable-ASCII binary reply.
// It NEVER asserts on:
//   - an empty response (len 0) - which is exactly what utils.Recv returns for a
//     read timeout or a connection refused (requests.go:77-80). A bare open/held-but-
//     silent port is therefore unrepresentable as a positive here (P0-9a, P0-9b).
//   - a response shorter than minAgentResponse bytes,
//   - a TLS handshake/alert record (0x16/0x15 0x03 ...), the common vector where a
//     TLS-fronted service on 1423 answers the plaintext probe with a binary TLS record,
//   - an SSH banner ("SSH-..."), the common vector where an SSH service on 1423 greets,
//   - an HTTP status line (a web server on 1423),
//   - a fully printable-ASCII response (an FTP/SMTP/SSH/telnet-style banner greeter).
//
// Residual FP risk (P2-3): an unrelated proprietary binary service bound to 1423 that
// answers a stray GET with binary would also match. This is accepted only because
// 1423 is an uncommon, PortPriority-scoped port. If field false positives are
// observed, the sanctioned mitigation is to make this function return false
// unconditionally until a live capture yields a real magic-byte signature.
func isEssbaseAgent(response []byte) bool {
	if len(response) < minAgentResponse {
		return false // empty / silence / RST / too short -> NOT detected
	}
	if len(response) >= 3 && (response[0] == 0x16 || response[0] == 0x15) && response[1] == 0x03 {
		return false // TLS handshake/alert record, not the Agent
	}
	if bytes.HasPrefix(response, []byte("SSH-")) {
		return false // SSH banner, not the Agent
	}
	if hasHTTPPrefix(response) {
		return false // web server, not the Agent
	}
	if isPrintableASCII(response) {
		return false // text/banner service, not the Agent
	}
	if !hasBinaryContent(response) {
		return false // require a real fraction of non-printable bytes
	}
	return true
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

// --- EssbaseAgentPlugin (TCP 1423, best-effort) ---

// EssbaseAgentProbeEnabled is the production configuration switch for the
// best-effort 1423 Essbase Agent probe. DISABLED BY DEFAULT: there is no
// confirmed positive Essbase-agent wire signature, so enabling the binary
// heuristic risks false positives on unrelated binary services. An embedding
// application may set oraclehyperion.EssbaseAgentProbeEnabled = true to opt in
// (e.g. once a live capture yields a real magic-byte signature). Essbase is
// still detected via the HTTP REST tier regardless of this setting.
var EssbaseAgentProbeEnabled = false

// Run performs the best-effort, low-confidence Essbase Agent listener probe. It sends
// ONE benign probe and does ONE bounded read via utils.SendRecv (a fixed 4096-byte
// buffer with a read deadline, a single conn.Read, no goroutine - requests.go:60-87),
// then asserts oracle_essbase ONLY on a non-empty, non-HTTP, non-printable-ASCII
// binary reply. Silence, an empty read, an HTTP/ASCII reply, a bare open port, and any
// probe error (connection refused/closed/RST, write failure, or read timeout) all map
// to (nil, nil) - never (nil, err) - matching the HTTP plugins' "no evidence, swallow"
// convention (P0-9). No version, no AnonymousAccess, and no SecurityFinding are ever
// produced on this path: confidence is too low to make a security claim, and nothing
// was accessed or authenticated.
func (p *EssbaseAgentPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	if !EssbaseAgentProbeEnabled {
		return nil, nil
	}
	// Slow-lane TCP scans (pkg/scan/simple_scan.go) invoke every plugin's Run
	// regardless of PortPriority. The Agent classifier is a weak best-effort
	// binary heuristic, so restrict it to the fixed well-known Agent port (1423)
	// to avoid false-positives on unrelated binary services on other ports.
	if target.Address.Port() != EssbaseAgentPort {
		return nil, nil
	}
	resp, err := utils.SendRecv(conn, buildEssbaseAgentProbe(), timeout)
	if err != nil {
		// Refused / closed / RST / read error -> no evidence, not an error.
		// utils.SendRecv already collapses timeout and connection-refused reads to
		// (empty, nil), but a write failure or a closed-connection read surfaces a
		// WriteError/ReadError here; swallow it to match the HTTP plugins' "empty
		// response is silence, not failure" convention (P0-9). Never (nil, err).
		return nil, nil
	}
	if !isEssbaseAgent(resp) {
		return nil, nil // covers empty/silence/HTTP/ASCII/short
	}
	payload := plugins.ServiceOracleEssbase{
		AgentListener: true,
		CPEs:          buildEssbaseCPE(""),
	}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

func (p *EssbaseAgentPlugin) PortPriority(port uint16) bool { return port == EssbaseAgentPort }

// Name returns the distinct registry name OracleEssbaseAgent (NOT OracleEssbase):
// the registry keys on {Name, Protocol}, and this TCP plugin would otherwise collide
// with the TCP EssbasePlugin. The product this plugin emits is still oracle_essbase
// (via ServiceOracleEssbase.Type()).
func (p *EssbaseAgentPlugin) Name() string           { return OracleEssbaseAgent }
func (p *EssbaseAgentPlugin) Type() plugins.Protocol { return plugins.TCP }
func (p *EssbaseAgentPlugin) Priority() int          { return 900 }
