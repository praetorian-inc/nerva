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
Oracle Enterprise Manager (EM) HTTP Fingerprinting

This plugin fingerprints Oracle Enterprise Manager over a single injected
connection, distinguishing four components:

  - console    : EM Cloud Control console at /em/, which redirects
                 unauthenticated requests to /em/faces/logon/... It is served on
                 7803 (HTTPS) and 7802 (HTTP) (component "console").
  - agent      : the Management Agent, GET /emd/main/ on port 3872, which returns
                 an EM Agent status XML document without authentication and often
                 exposes the agent version (component "agent").
  - express    : EM Database Express (port 5500), whose login page carries the
                 title "Database Express" (component "express").
  - oms-upload : the OMS upload receiver servlet at /empbs/upload, on 4889 (HTTP)
                 and 4903 (HTTPS), which agents post their collected metrics to
                 (component "oms-upload").

Detection Signals (product-specific, no bare-status / generic-title triggers):

  - Management Agent XML at /emd/main/ containing EM markers (e.g. "EMD",
    "AgentState", "Oracle Enterprise Manager"). This surface is genuinely
    anonymous, so on a 2xx it is reported as anonymous access.
  - A /em/ redirect whose parsed Location path contains "/em/faces/logon"
    (Location is parsed with net/url and only the path is compared, never the
    raw header). That parsed path is the sole sufficient console signal. The
    logon path appearing in a response *body* is not sufficient on its own,
    because a server that echoes its redirect target into the body would
    otherwise be misclassified; the body clause therefore requires the logon
    path AND a corroborating EM product marker (see consoleBodyMarkers), and
    neither of those two signals triggers console detection alone.
  - A <title> or body mention of "Database Express" for EM Express, accepted
    only on a non-error (non-4xx/5xx) response, so an error page from fronting
    middleware that happens to name the product is not misclassified.
  - An EM-specific receiver banner ("Http Receiver Servlet active" / "Http XML
    File receiver") in the /empbs/upload body for the OMS upload receiver.

The console and express surfaces are sign-in gates, so they never set
AnonymousAccess. The oms-upload surface is an OMS ingest endpoint rather than a
data-exposure surface, so it does not set it either. Only the anonymously
reachable agent status endpoint does, and only on a 2xx response when
misconfiguration reporting is enabled.

Probe Ordering:
  All probes share the one injected keep-alive connection, so a server that
  closes the connection after the first probe kills the rest. detectEM therefore
  orders its probes by the target port (the surface most likely to answer on that
  port goes first) while still falling through all three, so EM deployments on
  non-default ports are still detected.

Cross-Port Cluster Corroboration:
  The ticket calls for corroborating a Cloud Control install by observing 7803 +
  3872 + 4889/4903 together on one host. That cannot be done inside a Nerva
  plugin: each plugin invocation sees a single injected connection for a single
  port and has no visibility into the other ports of the same host. Cluster
  corroboration therefore belongs to downstream correlation over the per-port
  results this plugin emits.

Default Ports:
  - TCP 3872 (Management Agent), 7802 (Cloud Control HTTP), 4889 (OMS upload)
  - TLS 7803 (Cloud Control HTTPS), 5500 (Database Express), 3872 (Management
    Agent over TLS), 4903 (OMS upload over TLS), 443

CPE Format (version wildcarded unless parseable from the agent response):
  cpe:2.3:a:oracle:enterprise_manager_base_platform:<ver-or-*>:*:*:*:*:*:*:*
*/

package oracleem

import (
	"context"
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
	EM = "oracle_em"

	// maxBody bounds the number of bytes read from any single HTTP response.
	maxBody = int64(512 * 1024)

	// logonPath is the Cloud Control unauthenticated redirect target.
	logonPath = "/em/faces/logon"

	// Default Enterprise Manager ports. Each surface listens on its own port, so
	// these also drive probe ordering in detectEM.
	portAgent        = 3872 // Management Agent status endpoint
	portConsoleHTTP  = 7802 // Cloud Control console over HTTP
	portConsoleHTTPS = 7803 // Cloud Control console over HTTPS
	portExpress      = 5500 // Database Express
	portUploadHTTP   = 4889 // OMS upload receiver over HTTP
	portUploadHTTPS  = 4903 // OMS upload receiver over HTTPS
)

var (
	titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	// agentVersionPattern extracts a version like 13.5.0.0.0 that follows an
	// agent/emd version marker in the Management Agent XML.
	agentVersionPattern = regexp.MustCompile(`(?i)(?:agent[_ ]?version|emd[_ ]?version)["'>:= ]{1,6}v?(\d+(?:\.\d+){2,})`)

	// agentXMLMarkers are structural markers unique to the Management Agent
	// status XML document (the EMResponse/AgentState envelope). At least one MUST
	// be present for a /emd/main/ response to be treated as genuine agent XML.
	// This confines detection to the agent XML context so the generic phrase
	// "Oracle Enterprise Manager" can never trigger as a bare substring on an
	// arbitrary page.
	agentXMLMarkers = []string{
		"<EMResponse",
		"AgentState",
		"emdVersion",
		"EMD_URL",
	}

	// consoleBodyMarkers are EM product markers used ONLY to corroborate a logon
	// path found in a response body. A body match requires the logon path AND one
	// of these markers: neither signal is sufficient alone. The logon path alone
	// would misclassify any page that echoes its redirect target into the body
	// (Go's own http.Redirect writes exactly that shape), and the generic product
	// name alone was already removed as a standalone trigger for the same
	// bare-substring reason.
	consoleBodyMarkers = []string{
		"Oracle Enterprise Manager",
		"oracle.sysman",
	}

	// uploadMarkers are the EM-specific banners the OMS upload receiver servlet
	// serves on a plain GET of /empbs/upload. At least one MUST be present for a
	// /empbs/upload response to count: a bare 200 on that path proves nothing.
	//
	// NOTE: this signature is taken from documented Enterprise Manager behaviour
	// (the receiver servlet's status banner) and has NOT been validated against a
	// live target.
	uploadMarkers = []string{
		"Http Receiver Servlet active",
		"Http XML File receiver",
	}
)

func init() {
	plugins.RegisterPlugin(&Plugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

// createHTTPClient wraps the provided net.Conn so all HTTP requests reuse the
// single injected connection. Redirects are not followed so the Cloud Control
// logon redirect stays observable.
func createHTTPClient(conn net.Conn, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// doGet issues a GET with a User-Agent and, when host is non-empty, a target
// Host header for name-based virtual hosts.
func doGet(client *http.Client, baseURL, path, host string) (*http.Response, error) {
	req, err := http.NewRequest("GET", baseURL+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nerva/1.0")
	if host != "" {
		req.Host = host
	}
	return client.Do(req)
}

// extractTitle returns the trimmed contents of the first <title> element.
func extractTitle(body string) string {
	m := titlePattern.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
}

// containsAny reports whether haystack contains any needle (case-insensitive).
func containsAny(haystack string, needles []string) bool {
	h := strings.ToLower(haystack)
	for _, n := range needles {
		if strings.Contains(h, strings.ToLower(n)) {
			return true
		}
	}
	return false
}

// locationPath returns only the path component of a response's Location header,
// parsed with net/url. This avoids substring matches against the raw header.
func locationPath(resp *http.Response) string {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	return u.Path
}

// extractAgentVersion best-effort parses the Management Agent version from the
// status XML; returns "" when no version marker is present.
func extractAgentVersion(body string) string {
	m := agentVersionPattern.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// detectAgent probes the Management Agent status endpoint. A match reports
// component "agent", the parsed version (may be ""), and anonymous=true when the
// status was served on a 2xx response.
func detectAgent(client *http.Client, baseURL, host string) (version string, anonymous, detected bool) {
	resp, err := doGet(client, baseURL, "/emd/main/", host)
	if err != nil {
		return "", false, false
	}
	is2xx := resp.StatusCode >= 200 && resp.StatusCode < 300
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	_ = resp.Body.Close()
	content := string(body)

	if !containsAny(content, agentXMLMarkers) {
		return "", false, false
	}
	return extractAgentVersion(content), is2xx, true
}

// detectConsoleOrExpress probes /em/ and distinguishes EM Express (title
// "Database Express") from the Cloud Control console (logon redirect or an
// Enterprise Manager title/body). Both are sign-in gates, so anonymous is never
// implied here. Responses carrying a 4xx/5xx status are never classified as
// express; see the gate in the body for why the console clauses need no
// equivalent.
func detectConsoleOrExpress(client *http.Client, baseURL, host string) (component string, detected bool) {
	resp, err := doGet(client, baseURL, "/em/", host)
	if err != nil {
		return "", false
	}
	locPath := locationPath(resp)
	isError := resp.StatusCode >= 400
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	_ = resp.Body.Close()
	content := string(body)
	title := extractTitle(content)

	// "Database Express" is matched as a substring, so without a status gate an
	// error page that merely mentions the product (a WebLogic or OHS 404/500
	// served in front of EM) would be classified as EM Express. A live Express
	// login page answers on a success or redirect status, never on 4xx/5xx, so
	// error responses are excluded from this branch.
	//
	// The console clauses below need no equivalent gate: the parsed Location path
	// is a redirect-only signal, and the body clause already requires two
	// independent signals (the logon path AND an EM product marker).
	if !isError && (containsAny(title, []string{"Database Express"}) ||
		containsAny(content, []string{"Database Express"})) {
		return "express", true
	}
	// The parsed Location path is the one sufficient console signal. A logon path
	// in the body is only accepted when an EM product marker corroborates it, so
	// a page that merely echoes its redirect target is not classified as console.
	if strings.Contains(locPath, logonPath) ||
		(containsAny(content, []string{logonPath}) && containsAny(content, consoleBodyMarkers)) {
		return "console", true
	}
	return "", false
}

// detectUpload probes the OMS upload receiver servlet. A match requires an
// EM-specific receiver banner in the body AND a 2xx response; a bare 200 on
// /empbs/upload is not enough, and neither is a banner on an error page. This
// surface is an OMS ingest endpoint rather than a data-exposure surface, so it
// never implies anonymous access.
//
// The 2xx gate deliberately differs from detectAgent, which matches the agent
// XML markers at any status and gates only the anonymous-access flag on 2xx. An
// agent status document is worth reporting (and yields a version) even when the
// endpoint is protected, whereas the receiver's only signal IS the banner, so a
// banner returned on a non-2xx status is more likely an error page echoing the
// servlet name than a live receiver. The real receiver answers 200.
func detectUpload(client *http.Client, baseURL, host string) (detected bool) {
	resp, err := doGet(client, baseURL, "/empbs/upload", host)
	if err != nil {
		return false
	}
	is2xx := resp.StatusCode >= 200 && resp.StatusCode < 300
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	_ = resp.Body.Close()

	return is2xx && containsAny(string(body), uploadMarkers)
}

// emProbe runs one component probe and reports what it found.
type emProbe func() (component, version string, anonymous, detected bool)

// detectEM runs the EM component probes over the shared client. All probes share
// the single injected keep-alive connection, and a server that closes the
// connection after the first probe kills the rest, so the probe most likely to
// answer on the target port runs first. All three still run in sequence, so EM
// surfaces published on non-default ports are detected regardless of ordering.
func detectEM(client *http.Client, baseURL, host string, port uint16) (component, version string, anonymous, detected bool) {
	probeAgent := func() (string, string, bool, bool) {
		if version, anon, ok := detectAgent(client, baseURL, host); ok {
			return "agent", version, anon, true
		}
		return "", "", false, false
	}
	probeConsoleOrExpress := func() (string, string, bool, bool) {
		if component, ok := detectConsoleOrExpress(client, baseURL, host); ok {
			return component, "", false, true
		}
		return "", "", false, false
	}
	probeUpload := func() (string, string, bool, bool) {
		if detectUpload(client, baseURL, host) {
			return "oms-upload", "", false, true
		}
		return "", "", false, false
	}

	var order []emProbe
	switch port {
	case portAgent:
		order = []emProbe{probeAgent, probeConsoleOrExpress, probeUpload}
	case portUploadHTTP, portUploadHTTPS:
		order = []emProbe{probeUpload, probeAgent, probeConsoleOrExpress}
	default:
		order = []emProbe{probeConsoleOrExpress, probeAgent, probeUpload}
	}

	for _, probe := range order {
		if component, version, anonymous, ok := probe(); ok {
			return component, version, anonymous, true
		}
	}
	return "", "", false, false
}

// buildEMCPE returns the CPEs for the detected Oracle Enterprise Manager
// component. The "express" component is the Database Express console, which is
// a database feature rather than an Enterprise Manager install, so it maps to
// database CPEs (with a wildcard version, since none is exposed). The "console",
// "agent" and "oms-upload" components are all part of an Enterprise Manager
// install, so they map to the Enterprise Manager base platform, wildcarding an
// unknown version.
func buildEMCPE(component, version string) []string {
	if component == "express" {
		return []string{
			"cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*",
			"cpe:2.3:a:oracle:database:*:*:*:*:*:*:*:*",
		}
	}
	if version == "" {
		version = "*"
	}
	return []string{fmt.Sprintf("cpe:2.3:a:oracle:enterprise_manager_base_platform:%s:*:*:*:*:*:*:*", version)}
}

func emAnonymousFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-em-agent-unauthenticated",
		Severity:    plugins.SeverityMedium,
		Description: "Oracle Enterprise Manager Management Agent status endpoint responded without authentication; agent and monitored-target metadata may be exposed",
		Evidence:    "GET /emd/main/ returned an EM Agent status response without credentials",
	}
}

// runEM performs the shared detection and service assembly for both the
// cleartext and TLS plugin variants. tls and transport are the only differences
// between them; TLS-specific findings are appended by the caller.
func runEM(conn net.Conn, timeout time.Duration, target plugins.Target, tls bool, transport plugins.Protocol) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	component, version, anonymous, detected := detectEM(client, baseURL, target.Host, target.Address.Port())
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleEM{
		Component: component,
		CPEs:      buildEMCPE(component, version),
	}
	service := plugins.CreateServiceFrom(target, payload, tls, version, transport)
	if target.Misconfigs && anonymous {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, emAnonymousFinding())
	}
	return service, nil
}

// Plugin detects Oracle Enterprise Manager over cleartext HTTP.
type Plugin struct{}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return runEM(conn, timeout, target, false, plugins.TCP)
}

func (p *Plugin) PortPriority(port uint16) bool {
	// Cleartext EM surfaces: the Management Agent (3872), the HTTP Cloud Control
	// console (7802) and the HTTP OMS upload receiver (4889). The HTTPS console
	// (7803), EM Express (5500) and the HTTPS upload receiver (4903) belong to
	// the TLS variant.
	return port == portAgent || port == portConsoleHTTP || port == portUploadHTTP
}
func (p *Plugin) Name() string           { return EM }
func (p *Plugin) Type() plugins.Protocol { return plugins.TCP }
func (p *Plugin) Priority() int          { return -1 }

// TLSPlugin detects Oracle Enterprise Manager over TLS.
type TLSPlugin struct{}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	service, err := runEM(conn, timeout, target, true, plugins.TCPTLS)
	if err != nil || service == nil {
		return service, err
	}
	if target.Misconfigs {
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *TLSPlugin) PortPriority(port uint16) bool {
	// 7803 (Cloud Control console) and 5500 (EM Express) are HTTPS. Management
	// Agents on 3872 are commonly HTTPS too, so the TLS variant also prioritizes
	// it (the TCP variant keeps 3872 for plaintext agents). 4903 is the HTTPS OMS
	// upload receiver. 443 covers reverse-proxied deployments.
	return port == portConsoleHTTPS || port == portExpress || port == portAgent ||
		port == portUploadHTTPS || port == 443
}
func (p *TLSPlugin) Name() string           { return EM }
func (p *TLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }
func (p *TLSPlugin) Priority() int          { return -1 }
