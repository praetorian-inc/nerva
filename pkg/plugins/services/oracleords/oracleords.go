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
Oracle REST Data Services (ORDS) + APEX HTTP Fingerprinting (LAB-5042)

This plugin detects Oracle REST Data Services (ORDS) and Oracle Application
Express (APEX) exposed over HTTP/HTTPS.

ORDS is a Java middle-tier that publishes RESTful services over an Oracle
Database. It is also the HTTP front end for Oracle APEX, and is the common
carrier for AI-oriented database features (Select AI, AI Vector Search results,
OML REST) — so its presence infers AI capability (inferred, not confirmed).

Detection Strategy (best-effort, non-fatal errors):

  The plugin issues GET requests to "/ords/", "/ords/_/landing", and "/".
  The HTTP client does NOT follow redirects; headers and bodies are inspected
  directly.

  A host is classified as ORDS when ANY of these strong signals are present:
    - A response Server header contains "Oracle-REST-Data-Services"
      (this also yields the version via "Oracle-REST-Data-Services/<ver>")
    - A response carries an ORDS/APEX header:
      X-ORDS-STATUS-CODE, X-ORDS-FORWARD, X-APEX-STATUS-CODE, or X-APEX-FORWARD
    - A request under /ords returns a non-404 status AND the Server header
      contains "Jetty(" OR the body contains APEX references
      (the string "apex", "/i/" static refs, or "f?p=")

  A bare "Jetty(" Server header on its own is NOT sufficient (Jetty fronts many
  applications), which avoids false positives against unrelated Jetty deployments.

APEX Flag:
  The markers that identify an ORDS surface are deliberately weaker than the
  ones that identify APEX as an installed product, so the two are kept apart:

    - bodyHasAPEX is the ORDS-detection marker. It accepts "apex", the "/i/"
      static path or an "f?p=" application URL. Modern ORDS emits no Server
      header, so on those instances this is the only thing that identifies the
      service at all --- it matches on the landing page's own "apex" strings
      (the font-apex icon stylesheet and the APEX launcher card), which is
      exactly why it must not double as evidence that APEX is installed.

    - bodyHasAPEXProduct gates the APEX flag, the application_express CPE and
      the APEX version. It is an allowlist of markers only an APEX-rendered
      response produces ("f?p=", "wwv_flow", the APEX library/UI asset paths,
      the APEX CDN prefix). An allowlist is required because that same ORDS
      landing page renders an APEX launcher card --- disabled when APEX is not
      installed --- and so contains fifteen "apex" occurrences on an instance
      with no APEX at all. Without the split, every modern ORDS is reported as
      running APEX, and a body carrying an unrelated versioned asset such as
      "/i/2.0/app.js" would stamp a precise, wrong version onto the
      application_express CPE.

  An X-APEX-* header is authoritative and flags APEX unconditionally. The
  body-based signal is gated to /ords paths so a generic root page does not
  falsely yield an application_express CPE.

Version Detection (LAB-5060):

  ORDS version, in order of preference:

    1. The "Oracle-REST-Data-Services/<ver>" Server token. Older ORDS releases
       (up to and including the 23.x line) emit this; modern standalone ORDS
       does not.

    2. The Database Actions / SQL Developer Web client config at
       "/ords/_sdw/js/config.js", which carries
       "productName":"SQL Developer","productVersion":"<ver>". That resource is
       plain static content shipped in the ORDS distribution and is NOT covered
       by any ORDS privilege pattern (the oracle.dbtools.sdw.user privilege
       guards only "/_sdw/_services/*"), so it is readable anonymously wherever
       a database pool is configured. Its productVersion tracks the ORDS
       release train but pins the patch component at zero (ORDS 26.2.3 ships
       "26.2.0"), so only the <major>.<minor> prefix is reported — claiming a
       patch level we cannot observe would produce false CVE matches. The probe
       runs only when ORDS was already detected and no Server-header version
       was found, so non-ORDS hosts never see the extra request.

  Modern ORDS otherwise leaks no version anonymously. Measured against a live
  ORDS 26.2.3 standalone instance, every unauthenticated surface
  ("/ords/_/landing" and its CSS/JS, "/ords/_/lib/*", "/ords/_/jet/*",
  "/ords/sign-in/", the application/problem+json error bodies) is free of any
  version string, and no Server, X-ORDS-*, X-APEX-* or X-Powered-By header is
  emitted at all. ORDS does return a build-wide ETag on every "/ords/_/" static
  resource (one value per build and locale, not per file), which would identify
  a build exactly, but Oracle publishes only "ords-latest.zip" — prior releases
  are not fetchable without an account — so an ETag-to-version table could
  neither be built nor kept current, and is deliberately not attempted here.
  When no source yields a version the service is still reported, with the
  version left empty.

  APEX version is read from APEX-rendered markup, which carries it in the
  static-asset references: an "?v=<ver>" cache-busting parameter on an "/i/"
  asset, a versioned images directory ("/i/<ver>/"), or the Oracle CDN images
  directory ("static.oracle.com/cdn/apex/<ver>/"). It is only extracted from
  bodies that already qualified as APEX evidence.

CPE Format:
  cpe:2.3:a:oracle:rest_data_services:<ver-or-*>:*:*:*:*:*:*:*
  and, when APEX is detected, also:
  cpe:2.3:a:oracle:application_express:<apex-ver-or-*>:*:*:*:*:*:*:*

Default Ports:
  - 8080 is the ORDS standalone (Jetty) default (PortPriority for the TCP variant)
  - 8443 is the ORDS standalone TLS default (PortPriority for the TLS variant)
*/

package oracleords

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
	OracleORDS = "oracle_ords"
	// DefaultORDSPort is the ORDS standalone (Jetty) default HTTP port.
	DefaultORDSPort = 8080
	// DefaultORDSTLSPort is the ORDS standalone default TLS port.
	DefaultORDSTLSPort = 8443
	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(10 * 1024 * 1024)
	// sdwConfigPath is the Database Actions / SQL Developer Web client config.
	// It is static content and is not covered by an ORDS privilege pattern, so
	// it reads anonymously wherever a database pool is configured.
	sdwConfigPath = "/ords/_sdw/js/config.js"
)

// ordsServerVersionPattern extracts the version from the ORDS Server token:
// "Oracle-REST-Data-Services/22.4.3".
var ordsServerVersionPattern = regexp.MustCompile(`Oracle-REST-Data-Services/([\d.]+)`)

// sdwProductVersionPattern extracts the Database Actions / SQL Developer Web
// productVersion, e.g. `"productVersion":"26.2.0"`. Only the major and minor
// components are captured; see parseSDWProductVersion.
var sdwProductVersionPattern = regexp.MustCompile(`"productVersion"\s*:\s*"(\d+\.\d+)(?:\.\d+)*"`)

// sdwProductNamePattern guards parseSDWProductVersion: "productVersion" is a
// generic key in ORDS client configs (the OAuth admin console reports "1.0.0"
// under it), so the version is only trusted from a config that identifies
// itself as the SQL Developer / Database Actions client.
var sdwProductNamePattern = regexp.MustCompile(`"productName"\s*:\s*"SQL Developer"`)

// apexVersionPatterns match the APEX version as it appears in APEX-rendered
// markup, most specific form first:
//   - cache-busting parameter on an APEX static asset:
//     /i/libraries/apex/minified/desktop.min.js?v=24.1.5
//   - versioned images directory: /i/24.1.5/app_ui/...
//   - Oracle CDN images directory: static.oracle.com/cdn/apex/24.1.5/...
var apexVersionPatterns = []*regexp.Regexp{
	regexp.MustCompile(`/i/[^"'\s>]*\?v=(\d+\.\d+(?:\.\d+){0,3})`),
	regexp.MustCompile(`/i/(\d+\.\d+(?:\.\d+){0,3})/`),
	regexp.MustCompile(`static\.oracle\.com/cdn/apex/(\d+\.\d+(?:\.\d+){0,3})/`),
}

type ORDSPlugin struct{}

// ORDSTLSPlugin detects ORDS/APEX over TLS connections.
type ORDSTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&ORDSPlugin{})
	plugins.RegisterPlugin(&ORDSTLSPlugin{})
}

// createHTTPClient creates an http.Client that wraps the provided net.Conn and
// does not follow redirects (so headers can be inspected directly).
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

// ordsEvidence captures the inspectable parts of a single HTTP response.
type ordsEvidence struct {
	path          string
	statusCode    int
	server        string // Server header
	body          string
	hasORDSHeader bool // X-ORDS-STATUS-CODE or X-ORDS-FORWARD present
	hasAPEXHeader bool // X-APEX-STATUS-CODE or X-APEX-FORWARD present
}

// parseORDSVersion extracts the ORDS version from a Server header value.
// Returns "" when the header does not carry an ORDS version token.
func parseORDSVersion(server string) string {
	if m := ordsServerVersionPattern.FindStringSubmatch(server); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// parseSDWProductVersion extracts the ORDS release train from the Database
// Actions / SQL Developer Web client config body, returning "<major>.<minor>"
// (e.g. "26.2" for a body reporting "26.2.0"). The patch component is dropped
// on purpose: SQL Developer Web pins it at zero for the whole train (ORDS
// 26.2.3 ships "26.2.0"), so reporting it would assert a patch level the
// response does not actually prove. Returns "" when the body is not a SQL
// Developer client config or carries no parseable version.
func parseSDWProductVersion(body string) string {
	if !sdwProductNamePattern.MatchString(body) {
		return ""
	}
	if m := sdwProductVersionPattern.FindStringSubmatch(body); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// parseAPEXVersion extracts the APEX version from APEX-rendered markup. Callers
// must only pass bodies that already qualified as APEX evidence, so that an
// unrelated "/i/<n>.<n>/" path cannot be mistaken for an APEX images directory.
// Returns "" when no version is present.
func parseAPEXVersion(body string) string {
	for _, pattern := range apexVersionPatterns {
		if m := pattern.FindStringSubmatch(body); len(m) >= 2 {
			return m[1]
		}
	}
	return ""
}

// is2xx reports whether an HTTP status code indicates a successful response.
func is2xx(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}

// bodyHasAPEX reports whether a response body carries APEX static/app
// references. This is the ORDS-DETECTION marker and is intentionally broad:
// on modern ORDS, whose responses carry no Server header, the landing page's
// "font-apex" stylesheet reference is the only thing that identifies the
// service. Do not use it to decide that APEX itself is installed --- see
// bodyHasAPEXProduct.
func bodyHasAPEX(body string) bool {
	if strings.Contains(strings.ToLower(body), "apex") {
		return true
	}
	return strings.Contains(body, "/i/") || strings.Contains(body, "f?p=")
}

// apexProductMarkers are references that only an APEX-rendered response
// produces. This is deliberately an allowlist rather than a denylist of the
// weak markers: the ORDS landing page renders an APEX launcher card on every
// instance, disabled when APEX is absent, so on an APEX-free ORDS 26.2.3 its
// markup still contains fifteen occurrences of "apex" --- "font-apex" twice
// plus "cards__apex_card", "card_title_apex", "card_description_apex",
// "apex-submit-form", "apex-card-actions__input-text", "apexhelpbutton" and
// friends. No list of exclusions keeps up with that page across releases.
//
// Matching is case-insensitive; markers are written lowercase.
var apexProductMarkers = []string{
	"f?p=",                        // APEX application URL
	"wwv_flow",                    // APEX PL/SQL gateway procedures
	"/i/libraries/apex/",          // APEX JavaScript/CSS library assets
	"/i/apex_ui/",                 // APEX UI static assets
	"static.oracle.com/cdn/apex/", // APEX images served from the Oracle CDN
	"apex.jquery",                 // APEX client-side global
}

// bodyHasAPEXProduct reports whether a response body carries evidence that APEX
// is actually installed, as opposed to merely identifying an ORDS surface. It
// gates the APEX flag, the application_express CPE and the APEX version, so
// that neither an APEX-free ORDS landing page nor an unrelated versioned asset
// such as "/i/2.0/app.js" can produce a false versioned CVE match.
func bodyHasAPEXProduct(body string) bool {
	lower := strings.ToLower(body)
	for _, marker := range apexProductMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

// ordsResult is the outcome of evaluating the collected ORDS evidence.
type ordsResult struct {
	// version is the ORDS version, empty when no source yielded one.
	version string
	// apex reports whether APEX is fronted by this ORDS instance.
	apex bool
	// apexVersion is the APEX version, empty when it could not be read.
	apexVersion string
	// detected reports whether the host is ORDS at all.
	detected bool
	// anonymous reports whether the ORDS surface answered without credentials.
	anonymous bool
}

// evaluateORDS inspects collected responses and decides whether the host is
// ORDS. anonymous is true only when an ORDS-identifying response actually
// SUCCEEDED (2xx): a service that is identified solely from an auth-challenge
// response (401/403 carrying an ORDS Server header or ORDS headers) is detected
// but is NOT anonymous access.
func evaluateORDS(evs []ordsEvidence) ordsResult {
	var res ordsResult
	for _, ev := range evs {
		// ordsSignal tracks whether THIS response identified ORDS, so that the
		// anonymous-access decision can be gated on its status code.
		ordsSignal := false

		// Strong signal: ORDS Server header (also yields version).
		if strings.Contains(ev.server, "Oracle-REST-Data-Services") {
			res.detected = true
			ordsSignal = true
			if v := parseORDSVersion(ev.server); v != "" && res.version == "" {
				res.version = v
			}
		}

		// Strong signal: ORDS/APEX response headers.
		if ev.hasORDSHeader || ev.hasAPEXHeader {
			res.detected = true
			ordsSignal = true
		}

		// Strong signal: /ords path responds (non-404) and looks like ORDS/APEX.
		// A bare Jetty header alone is NOT sufficient; it must be on an /ords path.
		if strings.HasPrefix(ev.path, "/ords") && ev.statusCode != http.StatusNotFound {
			if strings.Contains(ev.server, "Jetty(") || bodyHasAPEX(ev.body) {
				res.detected = true
				ordsSignal = true
			}
		}

		// Anonymous access requires an ORDS-identifying response that actually
		// succeeded (2xx). An ORDS surface that only answers with an auth
		// challenge (e.g. 401/403) is detected but not anonymously accessible.
		if ordsSignal && is2xx(ev.statusCode) {
			res.anonymous = true
		}

		// APEX flag. The header signal is authoritative and unconditional. The
		// body-based signal requires product-level evidence (bodyHasAPEXProduct,
		// not the broader detection marker) and is gated to /ords-prefixed paths
		// only, so neither an APEX-free ORDS landing page nor a generic root page
		// produces a false application_express CPE.
		//
		// The version is read from that same qualifying body, once, which keeps
		// an unrelated "/i/<n>.<n>/" path out of the version.
		apexBody := strings.HasPrefix(ev.path, "/ords") && bodyHasAPEXProduct(ev.body)
		if ev.hasAPEXHeader || apexBody {
			res.apex = true
			if res.apexVersion == "" {
				if v := parseAPEXVersion(ev.body); v != "" {
					res.apexVersion = v
				}
			}
		}
	}
	return res
}

// fetchEvidence performs a single GET and records the inspectable parts of the
// response. ok is false when the request failed; callers treat that as
// non-fatal and continue with whatever other evidence they can gather.
func fetchEvidence(client *http.Client, baseURL string, path string, host string) (ordsEvidence, bool) {
	resp, err := doGet(client, baseURL+path, host)
	if err != nil {
		return ordsEvidence{}, false
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	return ordsEvidence{
		path:       path,
		statusCode: resp.StatusCode,
		server:     resp.Header.Get("Server"),
		body:       string(body),
		hasORDSHeader: resp.Header.Get("X-ORDS-STATUS-CODE") != "" ||
			resp.Header.Get("X-ORDS-FORWARD") != "",
		hasAPEXHeader: resp.Header.Get("X-APEX-STATUS-CODE") != "" ||
			resp.Header.Get("X-APEX-FORWARD") != "",
	}, true
}

// detectORDS fetches the ORDS probe paths and evaluates the collected evidence.
func detectORDS(client *http.Client, baseURL string, host string) ordsResult {
	paths := []string{"/ords/", "/ords/_/landing", "/"}
	var evs []ordsEvidence
	for _, p := range paths {
		if ev, ok := fetchEvidence(client, baseURL, p, host); ok {
			evs = append(evs, ev)
		}
	}
	res := evaluateORDS(evs)

	// Modern ORDS (24.x/26.x) emits no Server header, so fall back to the
	// Database Actions client config for the release train. The probe is gated
	// on ORDS already being detected without a version, which keeps the extra
	// request off non-ORDS hosts and off hosts that already answered with a
	// Server-header version.
	if res.detected && res.version == "" {
		if ev, ok := fetchEvidence(client, baseURL, sdwConfigPath, host); ok && is2xx(ev.statusCode) {
			res.version = parseSDWProductVersion(ev.body)
		}
	}
	return res
}

// buildORDSCPEs returns the CPE list for ORDS (always) and APEX (when detected).
// An unobtainable version is reported as the CPE "any" wildcard rather than
// guessed.
func buildORDSCPEs(res ordsResult) []string {
	cpes := []string{fmt.Sprintf("cpe:2.3:a:oracle:rest_data_services:%s:*:*:*:*:*:*:*", cpeVersion(res.version))}
	if res.apex {
		cpes = append(cpes, fmt.Sprintf("cpe:2.3:a:oracle:application_express:%s:*:*:*:*:*:*:*", cpeVersion(res.apexVersion)))
	}
	return cpes
}

// cpeVersion renders a version for a CPE, substituting the "any" wildcard for
// an unknown version.
func cpeVersion(version string) string {
	if version == "" {
		return "*"
	}
	return version
}

func ordsFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-ords-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle REST Data Services gateway is reachable without authentication; ORDS commonly fronts APEX applications and database REST endpoints",
		Evidence:    "Oracle REST Data Services endpoints responded without credentials",
	}
}

func (p *ORDSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	res := detectORDS(client, baseURL, target.Host)
	if !res.detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleORDS{
		APEX:        res.apex,
		APEXVersion: res.apexVersion,
		// AICapable is inferred: ORDS is the common gateway for Select AI /
		// AI Vector Search results / OML REST. Capability is inferred, not confirmed.
		AICapable: true,
		CPEs:      buildORDSCPEs(res),
	}
	service := plugins.CreateServiceFrom(target, payload, false, res.version, plugins.TCP)
	// Only flag anonymous access / the exposure finding when ORDS actually served
	// a successful (2xx) response; an auth-challenge-only surface is detected but
	// is not anonymously accessible.
	if target.Misconfigs && res.anonymous {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, ordsFinding())
	}
	return service, nil
}

func (p *ORDSPlugin) PortPriority(port uint16) bool { return port == DefaultORDSPort }
func (p *ORDSPlugin) Name() string                  { return OracleORDS }
func (p *ORDSPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *ORDSPlugin) Priority() int                 { return -1 } // Runs before generic HTTP so it can claim ORDS on shared ports (e.g. 8080)

func (p *ORDSTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	res := detectORDS(client, baseURL, target.Host)
	if !res.detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleORDS{
		APEX:        res.apex,
		APEXVersion: res.apexVersion,
		AICapable:   true,
		CPEs:        buildORDSCPEs(res),
	}
	service := plugins.CreateServiceFrom(target, payload, true, res.version, plugins.TCPTLS)
	if target.Misconfigs {
		// Only flag anonymous access / the exposure finding on a successful (2xx)
		// ORDS response; an auth-challenge-only surface is detected but not
		// anonymously accessible. TLS findings are unrelated and always collected.
		if res.anonymous {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, ordsFinding())
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *ORDSTLSPlugin) PortPriority(port uint16) bool { return port == DefaultORDSTLSPort }
func (p *ORDSTLSPlugin) Name() string                  { return OracleORDS }
func (p *ORDSTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *ORDSTLSPlugin) Priority() int                 { return -1 } // Runs before generic HTTPS so it can claim ORDS on shared ports (e.g. 8443)
