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
Oracle JD Edwards EnterpriseOne + Oracle Siebel CRM HTTP Fingerprinting
(LAB-5053)

This package detects two Oracle enterprise web applications exposed over
HTTP/HTTPS. Each product ships a TCP and a TLS plugin variant, for four
registered plugins total: JDEPlugin, JDETLSPlugin, SiebelPlugin,
SiebelTLSPlugin. It mirrors the merged oracleidentity (OAM+OIM) precedent:
one package, four plugins, two Service structs, two Proto consts, one init().

Detection is P0; version/build extraction is P1 best-effort. Detection never
depends on a version being present — modern Oracle web tiers strip version
headers and gate the login surface, so a missing version is normal.

Oracle JD Edwards EnterpriseOne (Name "oracle_jde"):

  JDE E1 is served by the JAS / HTML Server (WebLogic-hosted Java web app)
  under the /jde context and, increasingly, by the AIS Server (REST) under
  /jderest. The plugin issues GET requests to "/jde/E1Menu.maf", "/jde/owhtml"
  and "/jderest/defaultconfig".

  A host is classified as JDE when ANY strong, non-reflective signal is present:
    - A body or redirect Location carrying a non-reflective JDE marker
      (jdeLoginAction, html4login, companyDislaimerHTML, RENDER_MAFLET,
      "JD Edwards", "EnterpriseOne"). The reflective tokens the plugin itself
      requests (bare "E1Menu", "jde", "/jde/images/") are NOT markers.
    - The /jderest response is a JSON AIS envelope carrying a non-reflective
      AIS token (aisVersion / tokenrequest), which also sets the AIS flag.

  CPE Format: cpe:2.3:a:oracle:jd_edwards_enterpriseone:*:*:*:*:*:*:*:*
  (application, always) plus cpe:2.3:a:oracle:jd_edwards_enterpriseone_tools:
  <toolsRelease>:*:*:*:*:*:*:* when an E1 Tools Release is parsed.
  Default Ports: 80 (TCP variant), 443 (TLS variant)

Oracle Siebel CRM (Name "oracle_siebel"):

  Siebel is fronted by the Siebel Web Server Extension (SWSE); the app is
  reached through the SWE (Siebel Web Engine) entry servlet start.swe. The
  plugin issues GET requests to "/start.swe?SWECmd=Start",
  "/callcenter_enu/start.swe?SWECmd=GetCachedFrame" and
  "/eai_enu/start.swe?SWECmd=Start".

  A host is classified as Siebel when ANY strong, non-reflective signal is
  present:
    - A Set-Cookie defining a Siebel session cookie (_sn= or _sweEntryPoint=) —
      the strongest, lowest-FP signal (a Set-Cookie can't be reflected from a
      GET).
    - A non-reflective SWE body/Location marker (swecommon_top.js,
      SWELogin.swt, SiebWebMainWindow, top._swescript, SWEClearHistoryGotoURL),
      OR start.swe corroborated by a SWE param the plugin did NOT send (SWEHo /
      SWEView / SWEApplet / SWEHtmlID; SWECmd is excluded because it is in the
      probe URL).

  The raw 4-6 digit SWE build folder (e.g. "23021") is recorded opaque in the
  Service payload Build field and is NEVER converted to a CPE version; the
  build-folder → marketing-version mapping is not authoritative. A CPE version
  is emitted only when a clean marketing version string is directly observed.

  CPE Format: cpe:2.3:a:oracle:siebel_crm:<version-or-wildcard>:*:*:*:*:*:*:*
  Default Ports: 80 (TCP variant), 443 (TLS variant)
*/

package oraclejdesiebel

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
	// OracleJDE is the technology name returned by the JDE plugin variants.
	OracleJDE = "oracle_jde"
	// OracleSiebel is the technology name returned by the Siebel plugin variants.
	OracleSiebel = "oracle_siebel"
	// DefaultHTTPPort is the PortPriority port for both TCP variants.
	DefaultHTTPPort = 80
	// DefaultHTTPSPort is the PortPriority port for both TLS variants.
	DefaultHTTPSPort = 443
	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(10 * 1024 * 1024)
)

// --- JDE version regexes (RE2/stdlib, compiled once at package scope) ---

// jdeToolsLabeled matches a labeled "E1 Tools Release" banner. The capture is
// restricted to digits/dots so it cannot inject CPE separators.
var jdeToolsLabeled = regexp.MustCompile(`(?i)(?:E1\s*)?Tools\s*Release[^0-9]{0,10}(\d+\.\d+(?:\.\d+){0,2})`)

// jdeAISVersion matches an AIS JSON version field (dotted quad).
var jdeAISVersion = regexp.MustCompile(`(?i)"?(?:aisVersion|toolsRelease|version)"?\s*[:=]\s*"?(\d+\.\d+\.\d+\.\d+)`)

// jdeQuadFallback matches a bare E1 Tools quad, prefix-validated to a known
// JDE Tools family (9.1.x.x / 9.2.x.x / 8.98.x.x) to cut false positives.
var jdeQuadFallback = regexp.MustCompile(`(?i)\b(9\.[12]\.\d+\.\d+|8\.98\.\d+\.\d+)\b`)

// jdeVersionShape is a defensive allow-list for the captured version before it
// is placed into a CPE (P1-1: prevent CPE injection). Digits and dots only.
var jdeVersionShape = regexp.MustCompile(`^\d+(\.\d+){1,3}$`)

// --- Siebel version/build regexes (RE2/stdlib, compiled once) ---

// siebelBuild matches the numeric SWE build folder in a PUBLIC resource path.
var siebelBuild = regexp.MustCompile(`(?i)/(?:public/)?[a-z]{3}/(\d{4,6})/(?:scripts|files|images|htmltemplates)/`)

// siebelBuildLoose is a looser fallback for a /<build>/scripts/siebel segment.
var siebelBuildLoose = regexp.MustCompile(`(?i)/(\d{5,6})/scripts/siebel`)

// siebelMarketingVer matches a directly-observed clean Siebel marketing version
// (an IP-year line or a legacy dotted version). Capture is [0-9.] plus the
// literal IP prefix, so it cannot inject CPE separators.
var siebelMarketingVer = regexp.MustCompile(`(?i)Siebel[^0-9]{0,15}?(?:version|build)?\s*[:\s]?\s*((?:IP)?20\d{2}|\d{1,2}\.\d{1,2}(?:\.\d+)?)`)

// containsFold reports whether s contains sub, case-insensitively.
func containsFold(s, sub string) bool {
	return strings.Contains(strings.ToLower(s), strings.ToLower(sub))
}

// isAuthChallenge reports whether a status code is an authentication challenge.
// Detection off such a response is product disclosure, not anonymous access
// (P0-4): AnonymousAccess and the "exposed without auth" finding are suppressed
// when the only marker-bearing response was a 401/407 challenge.
func isAuthChallenge(code int) bool {
	return code == http.StatusUnauthorized || code == http.StatusProxyAuthRequired
}

// createHTTPClient creates an http.Client that wraps the provided net.Conn and
// does not follow redirects (so Location headers can be inspected directly).
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

// --- Oracle JD Edwards EnterpriseOne (oracle_jde) ---

// jdeEvidence captures the inspectable parts of a single JDE probe response.
type jdeEvidence struct {
	path       string
	statusCode int
	location   string
	body       string
	ctype      string
}

// hasJDEMarker reports whether a string (body or redirect Location) carries a
// non-reflective JDE marker, case-insensitive. The tokens the plugin itself
// requests (bare "E1Menu", "jde", "/jde/images/") are intentionally excluded:
// a catch-all/error page that echoes the requested URL back would otherwise be
// a self-referential false positive (same caution the OAM plugin documents for
// obrareq.cgi). "companyDislaimerHTML" preserves Oracle's real-world spelling.
func hasJDEMarker(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "jdeloginaction") ||
		strings.Contains(lower, "html4login") ||
		strings.Contains(lower, "companydislaimerhtml") ||
		strings.Contains(lower, "render_maflet") ||
		strings.Contains(lower, "jd edwards") ||
		strings.Contains(lower, "enterpriseone")
}

// isAISEnvelope reports whether a response is a JSON AIS envelope carrying a
// non-reflective AIS token. jderest/defaultconfig are in the request path
// (reflectable), so a JSON body alone is not sufficient — it must also contain
// aisVersion or tokenrequest, which are not part of any request the plugin
// sends. Markers are matched on the raw string (no json.Unmarshal), so an
// attacker-shaped JSON body cannot steer parsing.
func isAISEnvelope(body, ctype string) bool {
	json := containsFold(ctype, "json") || strings.HasPrefix(strings.TrimSpace(body), "{")
	return json && (containsFold(body, "aisVersion") || containsFold(body, "tokenrequest"))
}

// parseJDEToolsRelease tries labeled → AIS-JSON → validated bare-quad, in that
// order, returning "" if none match. The captured value is validated against a
// digits-and-dots allow-list before being returned (P1-1: CPE-injection guard).
func parseJDEToolsRelease(body string) string {
	if m := jdeToolsLabeled.FindStringSubmatch(body); len(m) >= 2 && jdeVersionShape.MatchString(m[1]) {
		return m[1]
	}
	if m := jdeAISVersion.FindStringSubmatch(body); len(m) >= 2 && jdeVersionShape.MatchString(m[1]) {
		return m[1]
	}
	if m := jdeQuadFallback.FindStringSubmatch(body); len(m) >= 2 && jdeVersionShape.MatchString(m[1]) {
		return m[1]
	}
	return ""
}

// evaluateJDE inspects collected responses and decides whether the host is JDE,
// returning whether the AIS REST tier is present, whether the product was
// disclosed without an auth challenge (anonymous), and the best-effort E1 Tools
// Release version (first match wins). anonymous is true only when a detection
// signal came from a non-401/407 response (P0-4).
func evaluateJDE(evs []jdeEvidence) (ais, anonymous bool, version string, detected bool) {
	for _, ev := range evs {
		sig := false
		if hasJDEMarker(ev.body) || hasJDEMarker(ev.location) {
			sig = true
		}
		if strings.Contains(ev.path, "jderest") && isAISEnvelope(ev.body, ev.ctype) {
			ais = true
			sig = true
		}
		if sig {
			detected = true
			if !isAuthChallenge(ev.statusCode) {
				anonymous = true
			}
		}
		if v := parseJDEToolsRelease(ev.body); v != "" && version == "" {
			version = v
		}
	}
	return ais, anonymous, version, detected
}

// detectJDE fetches the JDE probe paths and evaluates the collected evidence.
func detectJDE(client *http.Client, baseURL string, host string) (ais, anonymous bool, version string, detected bool) {
	paths := []string{"/jde/E1Menu.maf", "/jde/owhtml", "/jderest/defaultconfig"}
	var evs []jdeEvidence
	for _, p := range paths {
		resp, err := doGet(client, baseURL+p, host)
		if err != nil {
			// Non-fatal: continue with whatever other evidence we can gather.
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		evs = append(evs, jdeEvidence{
			path:       p,
			statusCode: resp.StatusCode,
			location:   resp.Header.Get("Location"),
			body:       string(body),
			ctype:      resp.Header.Get("Content-Type"),
		})
		_ = resp.Body.Close()
	}
	return evaluateJDE(evs)
}

// buildJDECPEs returns the JDE CPE set: the application CPE (always, version
// wildcard) plus the Tools CPE with the parsed E1 Tools Release when present.
// The Tools Release is a Tools version, so it is never stuffed into the
// application CPE's version field.
func buildJDECPEs(toolsVersion string) []string {
	cpes := []string{"cpe:2.3:a:oracle:jd_edwards_enterpriseone:*:*:*:*:*:*:*:*"}
	if toolsVersion != "" {
		cpes = append(cpes, fmt.Sprintf("cpe:2.3:a:oracle:jd_edwards_enterpriseone_tools:%s:*:*:*:*:*:*:*", toolsVersion))
	}
	return cpes
}

func jdeFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-jde-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle JD Edwards EnterpriseOne web tier (JAS/AIS) is reachable without authentication; the E1 login/menu and REST endpoints are exposed to the network",
		Evidence:    "Oracle JD Edwards EnterpriseOne endpoints responded without credentials",
	}
}

// --- Oracle Siebel CRM (oracle_siebel) ---

// siebelEvidence captures the inspectable parts of a single Siebel probe response.
type siebelEvidence struct {
	path       string
	statusCode int
	location   string
	body       string
	setCookie  string
}

// hasSiebelCookie reports whether the joined Set-Cookie header defines a Siebel
// session cookie. This is the strongest, lowest-FP signal: a Set-Cookie cannot
// be reflected from the plugin's GET.
func hasSiebelCookie(setCookie string) bool {
	return strings.Contains(setCookie, "_sn=") ||
		strings.Contains(setCookie, "_sweEntryPoint=")
}

// hasSiebelStrongMarker reports whether a string (body or Location) carries a
// non-reflective SWE marker, OR start.swe corroborated by a SWE param the
// plugin did NOT send. SWECmd is excluded because it is part of the probe URL
// (reflectable); bare start.swe / SWECmd echoes are therefore not triggers.
func hasSiebelStrongMarker(s string) bool {
	lower := strings.ToLower(s)
	if strings.Contains(lower, "swecommon_top.js") ||
		strings.Contains(lower, "swecommon.js") ||
		strings.Contains(lower, "swelogin.swt") ||
		strings.Contains(lower, "siebwebmainwindow") ||
		strings.Contains(lower, "top._swescript") ||
		strings.Contains(lower, "sweclearhistorygotourl") {
		return true
	}
	if strings.Contains(lower, "start.swe") &&
		(strings.Contains(lower, "sweho") ||
			strings.Contains(lower, "sweview") ||
			strings.Contains(lower, "sweapplet") ||
			strings.Contains(lower, "swehtmlid")) {
		return true
	}
	return false
}

// parseSiebelBuild returns the raw 4-6 digit SWE build folder (opaque), or "".
// This value is NEVER converted to a CPE version.
func parseSiebelBuild(body string) string {
	if m := siebelBuild.FindStringSubmatch(body); len(m) >= 2 {
		return m[1]
	}
	if m := siebelBuildLoose.FindStringSubmatch(body); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// parseSiebelVersion returns a clean marketing version ONLY when directly
// observed, or "". The build folder must never become a version.
func parseSiebelVersion(body string) string {
	if m := siebelMarketingVer.FindStringSubmatch(body); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// evaluateSiebel inspects collected responses and decides whether the host is
// Siebel, returning the best-effort opaque build folder, (rarely) a clean
// marketing version, and whether the product was disclosed without an auth
// challenge (anonymous). anonymous is true only when a detection signal came
// from a non-401/407 response (P0-4).
func evaluateSiebel(evs []siebelEvidence) (build, version string, anonymous, detected bool) {
	for _, ev := range evs {
		sig := false
		if hasSiebelCookie(ev.setCookie) {
			sig = true
		}
		if hasSiebelStrongMarker(ev.body) || hasSiebelStrongMarker(ev.location) {
			sig = true
		}
		if sig {
			detected = true
			if !isAuthChallenge(ev.statusCode) {
				anonymous = true
			}
		}
		if b := parseSiebelBuild(ev.body); b != "" && build == "" {
			build = b
		}
		if v := parseSiebelVersion(ev.body); v != "" && version == "" {
			version = v
		}
	}
	return build, version, anonymous, detected
}

// detectSiebel fetches the Siebel probe paths and evaluates the collected evidence.
func detectSiebel(client *http.Client, baseURL string, host string) (build, version string, anonymous, detected bool) {
	paths := []string{
		"/start.swe?SWECmd=Start",
		"/callcenter_enu/start.swe?SWECmd=GetCachedFrame",
		"/eai_enu/start.swe?SWECmd=Start",
	}
	var evs []siebelEvidence
	for _, p := range paths {
		resp, err := doGet(client, baseURL+p, host)
		if err != nil {
			// Non-fatal: continue with whatever other evidence we can gather.
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		evs = append(evs, siebelEvidence{
			path:       p,
			statusCode: resp.StatusCode,
			location:   resp.Header.Get("Location"),
			body:       string(body),
			setCookie:  strings.Join(resp.Header.Values("Set-Cookie"), "; "),
		})
		_ = resp.Body.Close()
	}
	return evaluateSiebel(evs)
}

// buildSiebelCPE returns the Siebel CPE, with a wildcard version unless a clean
// marketing version was directly observed.
func buildSiebelCPE(version string) []string {
	v := version
	if v == "" {
		v = "*"
	}
	return []string{fmt.Sprintf("cpe:2.3:a:oracle:siebel_crm:%s:*:*:*:*:*:*:*", v)}
}

func siebelFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-siebel-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Siebel CRM web tier (SWSE/SWE) is reachable without authentication; the Siebel Web Engine entry surface is exposed to the network",
		Evidence:    "Oracle Siebel CRM Web Engine endpoints responded without credentials",
	}
}

// --- Plugin structs + registration ---

type JDEPlugin struct{}

// JDETLSPlugin detects Oracle JD Edwards EnterpriseOne over TLS connections.
type JDETLSPlugin struct{}

type SiebelPlugin struct{}

// SiebelTLSPlugin detects Oracle Siebel CRM over TLS connections.
type SiebelTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&JDEPlugin{})
	plugins.RegisterPlugin(&JDETLSPlugin{})
	plugins.RegisterPlugin(&SiebelPlugin{})
	plugins.RegisterPlugin(&SiebelTLSPlugin{})
}

// --- JDE plugin variants ---

func (p *JDEPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	ais, anonymous, version, detected := detectJDE(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleJDE{
		AIS:  ais,
		CPEs: buildJDECPEs(version),
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	if target.Misconfigs && anonymous {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, jdeFinding())
	}
	return service, nil
}

func (p *JDEPlugin) PortPriority(port uint16) bool { return port == DefaultHTTPPort }
func (p *JDEPlugin) Name() string                  { return OracleJDE }
func (p *JDEPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *JDEPlugin) Priority() int                 { return -1 } // Runs before generic HTTP so it can claim JDE on shared ports

func (p *JDETLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	ais, anonymous, version, detected := detectJDE(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleJDE{
		AIS:  ais,
		CPEs: buildJDECPEs(version),
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		if anonymous {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, jdeFinding())
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *JDETLSPlugin) PortPriority(port uint16) bool { return port == DefaultHTTPSPort }
func (p *JDETLSPlugin) Name() string                  { return OracleJDE }
func (p *JDETLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *JDETLSPlugin) Priority() int                 { return -1 } // Runs before generic HTTPS so it can claim JDE on shared ports (e.g. 443)

// --- Siebel plugin variants ---

func (p *SiebelPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	build, version, anonymous, detected := detectSiebel(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleSiebel{
		Build: build,
		CPEs:  buildSiebelCPE(version),
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	if target.Misconfigs && anonymous {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, siebelFinding())
	}
	return service, nil
}

func (p *SiebelPlugin) PortPriority(port uint16) bool { return port == DefaultHTTPPort }
func (p *SiebelPlugin) Name() string                  { return OracleSiebel }
func (p *SiebelPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *SiebelPlugin) Priority() int                 { return -1 } // Runs before generic HTTP so it can claim Siebel on shared ports

func (p *SiebelTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	build, version, anonymous, detected := detectSiebel(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleSiebel{
		Build: build,
		CPEs:  buildSiebelCPE(version),
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		if anonymous {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, siebelFinding())
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *SiebelTLSPlugin) PortPriority(port uint16) bool { return port == DefaultHTTPSPort }
func (p *SiebelTLSPlugin) Name() string                  { return OracleSiebel }
func (p *SiebelTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *SiebelTLSPlugin) Priority() int                 { return -1 } // Runs before generic HTTPS so it can claim Siebel on shared ports (e.g. 443)
