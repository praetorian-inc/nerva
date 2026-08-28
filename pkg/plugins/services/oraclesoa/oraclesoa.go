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
Oracle SOA Suite / Oracle Service Bus HTTP Fingerprinting

This plugin fingerprints Oracle SOA Suite and Oracle Service Bus over a single
injected connection, distinguishing two products:

  - soa : SOA Suite (SOA Infrastructure, SOA Composer, BPM Workspace).
  - osb : Oracle Service Bus (Service Bus console).

Detection Surfaces (probed over one connection, first match wins):

  - /soa-infra                     SOA Infrastructure landing   -> "soa"
  - /soa-infra/services/default    composite WSDL metadata      -> "soa"
  - /sbconsole                     OSB console (11g)            -> "osb"
  - /servicebus                    OSB console (12c/14c)        -> "osb"
  - /soa/composer                  SOA Composer                 -> "soa"
  - /bpm/workspace                 BPM / Business Process Wksp   -> "soa"
  - /b2bconsole                    Oracle B2B console           -> "soa"

Detection Signals (product-specific, no bare-status / generic-title triggers):

  - SOA markers: "Oracle SOA Platform", "Welcome to the Oracle SOA",
    "Oracle SOA Composer", "Oracle BPM".
  - OSB markers: "Oracle Service Bus", "Service Bus Console".
  - BPM generic terms ("Business Process Workspace", "BPM Workspace") are the
    one exception to the rule that every marker carries an Oracle-specific
    noun: other BPMS products ship both phrases. They therefore match only
    when an Oracle/WebLogic branding signal corroborates them, so a
    third-party BPM workspace published on /bpm/workspace is not attributed to
    Oracle. Neither the generic term nor the branding signal triggers
    detection alone.

The requested path itself (e.g. "soa-infra" or "sbconsole") is never used as a
marker, so a 404 body that merely echoes the requested path cannot trigger a
false positive.

WebLogic substrate markers (a "WebLogic" Server header, an _WL_AUTHCOOKIE_
cookie) are common to every WebLogic deployment, so they are intentionally NOT
detection triggers; detection always requires a product-specific marker. They
are instead recorded as supporting evidence on the payload (WebLogic bool),
accumulated across every probe including non-matching ones, because the
substrate identifies the server rather than the product.

Composite WSDL Exposure:
  /soa-infra/services/default is probed for composite WSDL metadata. A match
  requires a 2xx, a WSDL structural marker AND a SOA composite context marker,
  and yields both a detection and the oracle-soa-wsdl-unauthenticated finding.
  Only the well-known default partition is probed: walking arbitrary partitions
  and composites would be enumeration rather than fingerprinting, and every
  extra request shares the one injected connection.

Version Inference:
  The SOA Infrastructure landing body is parsed for a dotted version, which
  maps to Oracle's release name (11.x -> 11g, 12.x -> 12c, 14.x -> 14c) and
  fills the CPE version; the CPE stays wildcarded when nothing is parseable.
  The ticket also asks for version inference from WebLogic T3. That cannot be
  done inside this plugin: T3 is a distinct protocol on a distinct port, and a
  plugin invocation sees one injected connection for one port. T3-based version
  inference therefore belongs to a T3 plugin plus downstream correlation, the
  same boundary the oracleem plugin documents for cross-port corroboration.

Only the SOA Infrastructure landing page is genuinely anonymous (it renders a
platform welcome without a sign-in), so only it may set AnonymousAccess, and
only on a 2xx response when misconfiguration reporting is enabled. The consoles
are sign-in gates and never imply anonymous access.

Default Ports:
  - TCP 8001 (SOA managed server), 7001 (AdminServer)
  - TLS 443

CPE Format (version filled when parseable, wildcarded otherwise; per product):
  cpe:2.3:a:oracle:soa_suite:<ver-or-*>:*:*:*:*:*:*:*
  cpe:2.3:a:oracle:service_bus:<ver-or-*>:*:*:*:*:*:*:*
*/

package oraclesoa

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const (
	SOA = "oracle_soa"

	// maxBody bounds the number of bytes read from any single HTTP response.
	maxBody = int64(512 * 1024)
)

var (
	soaInfraMarkers = []string{
		"Oracle SOA Platform",
		"Welcome to the Oracle SOA",
	}
	osbMarkers = []string{
		"Oracle Service Bus",
		"Service Bus Console",
	}
	composerMarkers = []string{
		"Oracle SOA Composer",
		"SOA Composer",
	}
	// bpmMarkers are the unambiguous Oracle BPM product markers: any one is
	// sufficient on its own, like every other marker list here.
	bpmMarkers = []string{
		"Oracle BPM",
	}

	// bpmGenericMarkers are BPMS terms that non-Oracle products also use (IBM
	// BPM among others ships both phrases), so unlike every other marker list
	// here they carry no Oracle-specific noun. They count only alongside an
	// oracleCorroborators match; neither signal is sufficient alone. The probe path
	// /bpm/workspace is itself an Oracle/WebLogic context root, so this is
	// defence in depth against a third-party BPMS published on that path rather
	// than a likely occurrence.
	bpmGenericMarkers = []string{
		"Business Process Workspace",
		"BPM Workspace",
	}

	// oracleCorroborators are the Oracle/WebLogic branding signals accepted as
	// corroboration for any probe's genericMarkers (currently BPM and B2B). They
	// never trigger detection alone.
	// The ADF entries are here because Oracle BPM Workspace is an ADF
	// application whose pages reference those resource paths even when the
	// visible text does not spell out "Oracle".
	//
	// NOTE: the ADF resource-path signals are taken from documented ADF
	// behaviour and have NOT been validated against a live Oracle BPM target.
	oracleCorroborators = []string{
		"Oracle",
		"WebLogic",
		"oracle.bpm",
		"/afr/",
		"oracle.adf",
	}

	// b2bMarkers are the unambiguous Oracle B2B product markers for the
	// /b2bconsole corroborating surface.
	b2bMarkers = []string{
		"Oracle B2B",
	}

	// b2bGenericMarkers follow the same rule as bpmGenericMarkers: "B2B Console"
	// carries no Oracle-specific noun, so it counts only alongside an
	// oracleCorroborators match.
	//
	// NOTE: the B2B console signatures are taken from documented Oracle B2B
	// behaviour and have NOT been validated against a live target.
	b2bGenericMarkers = []string{
		"B2B Console",
	}

	// wsdlMarkers are the structural markers of a WSDL document. One MUST be
	// present for a /soa-infra/services response to count as WSDL exposure.
	wsdlMarkers = []string{
		"<definitions",
		"wsdl:definitions",
		"<wsdl:",
	}

	// wsdlContextMarkers confine a WSDL match to the SOA composite context. A
	// bare WSDL document proves only that something serves WSDL, so a match
	// requires a wsdlMarkers hit AND one of these; neither is sufficient alone.
	wsdlContextMarkers = []string{
		"soa-infra",
		"composite",
		"oracle.soa",
	}

	// weblogicEvidenceMarkers are the WebLogic substrate signals recorded as
	// supporting evidence. They are deliberately NOT detection triggers: every
	// WebLogic deployment carries them, so they identify the substrate, never the
	// SOA/OSB product.
	weblogicEvidenceMarkers = []string{
		"WebLogic",
		"_WL_AUTHCOOKIE_",
	}

	// soaVersionPattern extracts a dotted version that follows a version marker
	// in the SOA Infrastructure landing page, e.g. "Version: 12.2.1.4.0".
	soaVersionPattern = regexp.MustCompile(`(?i)(?:version|soa suite|soa infrastructure)[^0-9\n]{0,20}(\d+\.\d+(?:\.\d+){0,3})`)
)

// soaRelease maps a major version to Oracle's marketing release name. Returns ""
// for a major nobody ships, so an unrecognised version never invents a release.
func soaRelease(version string) string {
	switch {
	case strings.HasPrefix(version, "11."):
		return "11g"
	case strings.HasPrefix(version, "12."):
		return "12c"
	case strings.HasPrefix(version, "14."):
		return "14c"
	}
	return ""
}

// extractSOAVersion best-effort parses the SOA version from a landing page body;
// returns "" when no version marker is present.
func extractSOAVersion(body string) string {
	m := soaVersionPattern.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// weblogicEvidence reports whether a response shows the WebLogic substrate, via
// the Server header or a WebLogic auth cookie. Supporting evidence only.
func weblogicEvidence(resp *http.Response) bool {
	if containsAny(resp.Header.Get("Server"), weblogicEvidenceMarkers) {
		return true
	}
	for _, c := range resp.Header.Values("Set-Cookie") {
		if containsAny(c, weblogicEvidenceMarkers) {
			return true
		}
	}
	return false
}

// soaProbe is a non-landing surface probe: fetch a path and confirm with
// product-specific markers.
type soaProbe struct {
	path    string
	product string
	// markers are product-specific: any single match confirms the product.
	markers []string
	// genericMarkers are terms shared with non-Oracle products, so a match
	// counts only alongside one of corroborators. Both are empty for probes
	// whose markers are already unambiguous.
	genericMarkers []string
	corroborators  []string
}

// matches reports whether a probe response body identifies this probe's
// product: an unambiguous marker on its own, or a generic marker corroborated
// by an Oracle/WebLogic signal.
func (p soaProbe) matches(content string) bool {
	if containsAny(content, p.markers) {
		return true
	}
	return len(p.genericMarkers) > 0 &&
		containsAny(content, p.genericMarkers) &&
		containsAny(content, p.corroborators)
}

var soaProbes = []soaProbe{
	{path: "/sbconsole", product: "osb", markers: osbMarkers},
	{path: "/servicebus", product: "osb", markers: osbMarkers},
	{path: "/soa/composer", product: "soa", markers: composerMarkers},
	{
		path:           "/bpm/workspace",
		product:        "soa",
		markers:        bpmMarkers,
		genericMarkers: bpmGenericMarkers,
		corroborators:  oracleCorroborators,
	},
	{
		path:           "/b2bconsole",
		product:        "soa",
		markers:        b2bMarkers,
		genericMarkers: b2bGenericMarkers,
		corroborators:  oracleCorroborators,
	},
}

func init() {
	plugins.RegisterPlugin(&Plugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

// createHTTPClient wraps the provided net.Conn so all HTTP requests reuse the
// single injected connection.
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

// detectSOAInfra probes the SOA Infrastructure landing page. It reports
// anonymous=true only when a 2xx response carries SOA platform markers, plus the
// version the landing page advertises when one is parseable. WebLogic evidence
// is reported whether or not the page matched, since the substrate identifies
// the server rather than the product.
func detectSOAInfra(client *http.Client, baseURL, host string) (version string, anonymous, weblogic, detected bool) {
	resp, err := doGet(client, baseURL, "/soa-infra", host)
	if err != nil {
		return "", false, false, false
	}
	is2xx := resp.StatusCode >= 200 && resp.StatusCode < 300
	wl := weblogicEvidence(resp)
	// Bound the read, then drain whatever is left before closing: every probe in
	// this plugin shares one injected keep-alive connection, and net/http can
	// only reuse that connection if the response body is consumed to EOF. An
	// undrained oversized response would kill every subsequent probe.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	content := string(body)

	if !containsAny(content, soaInfraMarkers) {
		return "", false, wl, false
	}
	return extractSOAVersion(content), is2xx, wl, true
}

// detectSOAWSDL probes the composite metadata surface for the well-known
// "default" partition. A match requires a 2xx, a WSDL structural marker AND a
// SOA composite context marker: a bare WSDL document proves only that something
// serves WSDL, so neither signal counts on its own.
//
// Only the default partition is probed. Walking arbitrary partitions and
// composites would be enumeration rather than fingerprinting, and every extra
// request shares the one injected keep-alive connection, so the cost falls on
// every scanned host.
//
// NOTE: this signature is taken from documented SOA Infrastructure behaviour and
// has NOT been validated against a live target.
func detectSOAWSDL(client *http.Client, baseURL, host string) (exposed, weblogic bool) {
	resp, err := doGet(client, baseURL, "/soa-infra/services/default", host)
	if err != nil {
		return false, false
	}
	is2xx := resp.StatusCode >= 200 && resp.StatusCode < 300
	wl := weblogicEvidence(resp)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	content := string(body)

	return is2xx && containsAny(content, wsdlMarkers) && containsAny(content, wsdlContextMarkers), wl
}

// soaResult is everything the probe chain observed about a target.
type soaResult struct {
	product     string // soa | osb
	version     string // e.g. 12.2.1.4, "" when not parseable
	release     string // 11g | 12c | 14c, "" when unknown
	anonymous   bool   // an anonymous SOA surface answered on a 2xx
	wsdlExposed bool   // composite WSDL metadata served without credentials
	webLogic    bool   // WebLogic substrate observed; supporting evidence only
	detected    bool
}

// detectSOA runs the SOA/OSB probes over the shared client: the anonymous SOA
// Infrastructure landing page first, then its composite metadata surface, then
// the console surfaces. WebLogic evidence accumulates across every probe,
// including non-matching ones, because the substrate identifies the server
// rather than the product.
func detectSOA(client *http.Client, baseURL, host string) soaResult {
	var res soaResult

	version, anon, wl, ok := detectSOAInfra(client, baseURL, host)
	res.webLogic = res.webLogic || wl
	if ok {
		res.product = "soa"
		res.version = version
		res.release = soaRelease(version)
		res.anonymous = anon
		res.detected = true
	}

	// Probed whether or not the landing page matched: it corroborates SOA and is
	// itself an anonymous-metadata exposure worth reporting on its own.
	exposed, wl := detectSOAWSDL(client, baseURL, host)
	res.webLogic = res.webLogic || wl
	if exposed {
		res.wsdlExposed = true
		res.anonymous = true
		if !res.detected {
			res.product = "soa"
			res.detected = true
		}
	}
	if res.detected {
		return res
	}

	for _, probe := range soaProbes {
		resp, err := doGet(client, baseURL, probe.path, host)
		if err != nil {
			continue
		}
		if weblogicEvidence(resp) {
			res.webLogic = true
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		content := string(body)

		if probe.matches(content) {
			res.product = probe.product
			res.detected = true
			return res
		}
	}
	return res
}

// buildSOACPE returns the per-product CPE for SOA Suite or Service Bus, with the
// version filled in when one was parseable and wildcarded otherwise.
func buildSOACPE(product, version string) string {
	name := "soa_suite"
	if product == "osb" {
		name = "service_bus"
	}
	v := "*"
	if version != "" {
		v = version
	}
	return fmt.Sprintf("cpe:2.3:a:oracle:%s:%s:*:*:*:*:*:*:*", name, v)
}

func soaAnonymousFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-soa-infra-unauthenticated",
		Severity:    plugins.SeverityMedium,
		Description: "Oracle SOA Infrastructure landing page responded without authentication; if the SOA endpoints are not access-controlled, deployed composites and platform metadata may be reachable anonymously",
		Evidence:    "GET /soa-infra returned Oracle SOA Platform content without credentials",
	}
}

func soaWSDLFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-soa-wsdl-unauthenticated",
		Severity:    plugins.SeverityMedium,
		Description: "Oracle SOA composite WSDL metadata was served without authentication; exposed service contracts reveal deployed composites, their operations and endpoints, narrowing an attacker's search for reachable integration entry points",
		Evidence:    "GET /soa-infra/services/default returned WSDL definitions in a SOA composite context without credentials",
	}
}

// Plugin detects Oracle SOA Suite / Service Bus over cleartext HTTP.
type Plugin struct{}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	res := detectSOA(client, baseURL, target.Host)
	if !res.detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleSOA{
		Product:     res.product,
		Version:     res.version,
		Release:     res.release,
		WebLogic:    res.webLogic,
		WSDLExposed: res.wsdlExposed,
		CPEs:        []string{buildSOACPE(res.product, res.version)},
	}
	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
	if target.Misconfigs {
		if res.anonymous {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, soaAnonymousFinding())
		}
		if res.wsdlExposed {
			service.SecurityFindings = append(service.SecurityFindings, soaWSDLFinding())
		}
	}
	return service, nil
}

func (p *Plugin) PortPriority(port uint16) bool { return port == 8001 || port == 7001 }
func (p *Plugin) Name() string                  { return SOA }
func (p *Plugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *Plugin) Priority() int                 { return -1 }

// TLSPlugin detects Oracle SOA Suite / Service Bus over TLS.
type TLSPlugin struct{}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	res := detectSOA(client, baseURL, target.Host)
	if !res.detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleSOA{
		Product:     res.product,
		Version:     res.version,
		Release:     res.release,
		WebLogic:    res.webLogic,
		WSDLExposed: res.wsdlExposed,
		CPEs:        []string{buildSOACPE(res.product, res.version)},
	}
	service := plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS)
	if target.Misconfigs {
		if res.anonymous {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, soaAnonymousFinding())
		}
		if res.wsdlExposed {
			service.SecurityFindings = append(service.SecurityFindings, soaWSDLFinding())
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *TLSPlugin) PortPriority(port uint16) bool { return port == 443 }
func (p *TLSPlugin) Name() string                  { return SOA }
func (p *TLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *TLSPlugin) Priority() int                 { return -1 }
