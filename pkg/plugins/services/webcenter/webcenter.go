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
Oracle WebCenter (Content / Portal / Sites) HTTP Fingerprinting (LAB-5047)

This package detects the Oracle WebCenter family exposed over HTTP/HTTPS. It
ships a TCP and a TLS plugin variant (WebCenterPlugin, WebCenterTLSPlugin) that
emit a single technology, "oracle_webcenter". The discriminated sub-product is
carried in the Component field ("Content", "Portal", or "Sites") for enrichment
only; the emitted technology name is always the constant oracle_webcenter.

Detection Strategy (best-effort, non-fatal errors):

  The plugin issues read-only GET requests to a fixed set of probe paths and
  classifies the host only when a strong, non-reflective, branded WebCenter
  signal is present:

    Strong standalone (any ONE -> detected, Component=Content):
      - The idcplg PING_SERVER response body is a valid Idc/HDA structure
        (contains the "<?hda" processing-instruction marker). The reflected query
        tokens (idcplg, PING_SERVER,
        IdcService) are deliberately NOT markers -- an echo of the requested URL
        would otherwise be a self-referential false positive (mirrors the
        obrareq guard in oracleidentity.hasOAMMarker).
      - A Set-Cookie header defining IdcLocale= or IntradocAuth= (Content Server
        session cookies).
      - A <title> containing "Oracle WebCenter Content", "Content Server", or
        "Stellent".

    Corroboration-only (a bare non-404/200 is NEVER sufficient):
      - "/webcenter/" contributes Portal only alongside an "Oracle WebCenter
        Portal" title.
      - "/sites/" or "/cs/Satellite" contribute Sites only alongside an "Oracle
        WebCenter Sites" title (or a WebCenter-family title seen with the
        Satellite servlet).
      - "/cs" and "/_dav/" are supporting reads only.

  Component precedence when multiple signals match: Content -> Sites -> Portal.

Version:
  Parsed from the PING_SERVER HDA prefix (version="12.2.1.2.0-...-rNNNNNN") ->
  "12.2.1.2.0". Content only; Portal, Sites, and a disabled anonymous ping all
  default to "" (wildcard CPE version).

CPE (one per detected component, NVD-verified):
  Content -> cpe:2.3:a:oracle:webcenter_content:<ver-or-*>:*:*:*:*:*:*:*
  Portal  -> cpe:2.3:a:oracle:webcenter_portal:*:*:*:*:*:*:*:*
  Sites   -> cpe:2.3:a:oracle:webcenter_sites:*:*:*:*:*:*:*:*

Scanning safety:
  All probes are pure unauthenticated GETs. The only IdcService issued is the
  read-only PING_SERVER; the plugin never POSTs and never places a
  state-changing IdcService in a URL.

Default Ports:
  - 16200 is the Content (UCM) managed-server HTTP port (PortPriority for the TCP
    variant).
  - 443 is the PortPriority for the TLS variant.
*/

package webcenter

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
	OracleWebCenter = "oracle_webcenter"
	// DefaultWebCenterPort is the Content (UCM) managed-server HTTP port.
	DefaultWebCenterPort = 16200
	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(10 * 1024 * 1024)

	// Discriminated sub-products (enrichment only; the technology is always
	// oracle_webcenter).
	componentContent = "Content"
	componentPortal  = "Portal"
	componentSites   = "Sites"
)

// Probe paths issued in a single ordered pass. The idcplg PING_SERVER probe is
// the sole IdcService issued and is read-only.
const (
	pathPing      = "/cs/idcplg?IdcService=PING_SERVER&IsJava=1&IsAllowAnonymous=1"
	pathCS        = "/cs"
	pathDav       = "/_dav/"
	pathSatellite = "/cs/Satellite"
	pathSites     = "/sites/"
	pathWebCenter = "/webcenter/"
)

// PortPriority port sets, from Oracle's documented WebCenter port table. Detection
// stays marker-gated, so broadening these only affects --fast reachability across
// the Content, Portal, and Sites default ports (a broadened priority never causes
// a detection on its own).
var (
	// webCenterTCPPorts are the cleartext HTTP default ports.
	webCenterTCPPorts = []uint16{
		DefaultWebCenterPort, // 16200 Content (UCM) managed server
		8888, 8889,           // Portal
		7103, 7105, 7107, 7109, // Sites
	}
	// webCenterTLSPorts are the TLS default ports.
	webCenterTLSPorts = []uint16{
		443,                 // Content / general HTTPS
		16201, 16301, 16251, // Content SSL
		8788, 8789, // Portal SSL
		7104, 7106, 7108, 7110, // Sites SSL
	}
)

// portInList reports whether port is a member of list.
func portInList(port uint16, list []uint16) bool {
	for _, p := range list {
		if port == p {
			return true
		}
	}
	return false
}

// titlePattern extracts the contents of an HTML <title> element, tolerating any
// attributes on the opening tag (e.g. `<title id="pageTitle">`).
var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// hdaVersionPattern extracts the leading dotted-numeric product version from the
// PING_SERVER HDA prefix, e.g.
// `<?hda version="12.2.1.2.0-2017-07-05 09:25:44Z-r155055" ...?>` -> "12.2.1.2.0".
// The trailing date/-rNNNNNN build stamp is dropped. Returns "" when the
// attribute is absent or non-numeric.
var hdaVersionPattern = regexp.MustCompile(`(?i)<\?hda[^>]*\bversion="([\d]+(?:\.[\d]+)+)`)

type WebCenterPlugin struct{}

// WebCenterTLSPlugin detects Oracle WebCenter over TLS connections.
type WebCenterTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&WebCenterPlugin{})
	plugins.RegisterPlugin(&WebCenterTLSPlugin{})
}

// createHTTPClient creates an http.Client that wraps the provided net.Conn and
// does not follow redirects (so Location headers and non-2xx statuses can be
// inspected directly -- a redirect to a login/SSO surface is not anonymous
// access).
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

// extractTitle returns the trimmed contents of the first <title> element, if any.
func extractTitle(body string) string {
	if m := titlePattern.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// isSuccessStatus reports whether an HTTP status code is a 2xx success.
func isSuccessStatus(code int) bool {
	return code >= 200 && code < 300
}

// wcEvidence captures the inspectable parts of a single WebCenter probe response.
type wcEvidence struct {
	path       string
	statusCode int
	body       string
	setCookie  string
}

// isIdcplgPath reports whether a probe path is the Content Server idcplg
// dispatcher path. This matches the path this plugin requested (not response
// content), so it carries no reflection risk.
func isIdcplgPath(path string) bool {
	return strings.Contains(path, "idcplg")
}

// hasHDAMarker reports whether a body is a genuine Idc/HDA response, identified
// by whether it contains the "<?hda" processing-instruction marker. The reflected
// probe tokens
// idcplg, PING_SERVER, and IdcService are intentionally NOT markers: an
// error/echo page that reflects the requested query string back would otherwise
// be a self-referential false positive. This mirrors the obrareq guard in
// oracleidentity.hasOAMMarker.
func hasHDAMarker(body string) bool {
	return strings.Contains(body, "<?hda")
}

// hasContentServerCookie reports whether the joined Set-Cookie header defines a
// Content Server / UCM session cookie.
func hasContentServerCookie(setCookie string) bool {
	return strings.Contains(setCookie, "IdcLocale=") ||
		strings.Contains(setCookie, "IntradocAuth=")
}

// titleIsWebCenterContent reports whether an HTML title is a branded WebCenter
// Content / Content Server / Stellent title (strong standalone signal).
func titleIsWebCenterContent(title string) bool {
	return strings.Contains(title, "Oracle WebCenter Content") ||
		strings.Contains(title, "Content Server") ||
		strings.Contains(title, "Stellent")
}

// titleIsWebCenterPortal reports whether an HTML title is a branded WebCenter
// Portal title.
func titleIsWebCenterPortal(title string) bool {
	return strings.Contains(title, "Oracle WebCenter Portal")
}

// titleIsWebCenterSites reports whether an HTML title is a branded WebCenter
// Sites title.
func titleIsWebCenterSites(title string) bool {
	return strings.Contains(title, "Oracle WebCenter Sites")
}

// titleIsWebCenterFamily reports whether an HTML title carries the WebCenter
// family brand (used to corroborate the Sites Satellite servlet).
func titleIsWebCenterFamily(title string) bool {
	return strings.Contains(title, "Oracle WebCenter")
}

// parseHDAVersion extracts the dotted-numeric product version from an HDA prefix.
// Returns "" when absent or non-numeric.
func parseHDAVersion(body string) string {
	if m := hdaVersionPattern.FindStringSubmatch(body); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// verOrStar returns the version, or "*" when the version is unknown.
func verOrStar(version string) string {
	if version == "" {
		return "*"
	}
	return version
}

// buildWebCenterCPE returns the single, component-accurate CPE. The version is
// stamped only for Content (from the HDA prefix); Portal and Sites always use a
// wildcard version.
func buildWebCenterCPE(component, version string) string {
	switch component {
	case componentContent:
		return fmt.Sprintf("cpe:2.3:a:oracle:webcenter_content:%s:*:*:*:*:*:*:*", verOrStar(version))
	case componentSites:
		return "cpe:2.3:a:oracle:webcenter_sites:*:*:*:*:*:*:*:*"
	case componentPortal:
		return "cpe:2.3:a:oracle:webcenter_portal:*:*:*:*:*:*:*:*"
	default:
		// Unreachable in Run: only called when detected => component != "".
		return ""
	}
}

// evaluateWebCenter inspects collected probe evidence and classifies the host as
// a WebCenter component, returning the discriminated component, the extracted
// version (Content only), and whether the host was detected.
//
// Guards: the HDA marker is counted only from the idcplg probe path; the generic
// paths (/webcenter/, /sites/, /cs, /_dav/, /cs/Satellite) never classify on a
// bare non-404 -- a branded title (or the Satellite servlet alongside a WebCenter
// family title) is required. Precedence is Content -> Sites -> Portal.
func evaluateWebCenter(evs []wcEvidence) (component string, version string, detected bool) {
	var (
		hasHDA           bool
		hasIdcCookie     bool
		contentTitle     bool
		portalTitle      bool
		sitesTitle       bool
		satelliteBranded bool
		idcBody          string
	)

	for _, ev := range evs {
		if isIdcplgPath(ev.path) && hasHDAMarker(ev.body) {
			hasHDA = true
			idcBody = ev.body
		}
		if hasContentServerCookie(ev.setCookie) {
			hasIdcCookie = true
		}

		title := extractTitle(ev.body)
		if titleIsWebCenterContent(title) {
			contentTitle = true
		}
		if titleIsWebCenterPortal(title) {
			portalTitle = true
		}
		if titleIsWebCenterSites(title) {
			sitesTitle = true
		}
		// Correlate the Satellite/Sites signal to THIS response only: a bare
		// non-404 on /cs/Satellite is never enough -- the same response must also
		// carry a Sites-specific title, or a generic WebCenter-family title that is
		// NOT a Portal title. A generic family title (e.g. the bare "Oracle
		// WebCenter" brand) still corroborates Sites, but a Portal deployment whose
		// Portal page appears at /cs/Satellite must not be misclassified as Sites.
		if strings.Contains(ev.path, pathSatellite) && ev.statusCode != http.StatusNotFound &&
			(titleIsWebCenterSites(title) || (titleIsWebCenterFamily(title) && !titleIsWebCenterPortal(title))) {
			satelliteBranded = true
		}
	}

	if hasHDA {
		version = parseHDAVersion(idcBody)
	}

	switch {
	case hasHDA || hasIdcCookie || contentTitle:
		component = componentContent
	case sitesTitle || satelliteBranded:
		component = componentSites
	case portalTitle:
		component = componentPortal
	}

	detected = component != ""
	return component, version, detected
}

// evaluateFindings computes the two security-finding gates from probe evidence.
// surfaceReachable is true when the host would still be classified as WebCenter
// using only its 2xx responses -- i.e. a branded or corroborated signal (ANY
// detection path, including Sites via the Satellite servlet corroborated by a
// WebCenter-family title) was actually served without authentication. Deriving
// this from evaluateWebCenter keeps Finding A in lock-step with detection instead
// of re-enumerating a branded subset that can drift from the classifier. It is
// fail-safe: the 2xx subset is a subset of all evidence and detection is
// monotonic, so surfaceReachable can never fire on an undetected host.
//
// idcAnonymous is narrower: the read-only idcplg PING_SERVER probe itself returned
// a valid, non-reflective Idc/HDA response on a 2xx -- a redirect to a login/SSO
// surface is not a 2xx and does not count.
func evaluateFindings(evs []wcEvidence) (surfaceReachable bool, idcAnonymous bool) {
	var success []wcEvidence
	for _, ev := range evs {
		if isSuccessStatus(ev.statusCode) {
			success = append(success, ev)
		}
	}

	if _, _, detected := evaluateWebCenter(success); detected {
		surfaceReachable = true
	}

	for _, ev := range success {
		if isIdcplgPath(ev.path) && hasHDAMarker(ev.body) {
			idcAnonymous = true
			break
		}
	}
	return surfaceReachable, idcAnonymous
}

// detectWebCenter fetches the WebCenter probe paths, builds the evidence set, and
// evaluates both classification and the security-finding gates.
func detectWebCenter(client *http.Client, baseURL string, host string) (component, version string, detected, surfaceReachable, idcAnonymous bool) {
	paths := []string{pathPing, pathCS, pathDav, pathSatellite, pathSites, pathWebCenter}
	var evs []wcEvidence
	for _, p := range paths {
		resp, err := doGet(client, baseURL+p, host)
		if err != nil {
			// Non-fatal: continue with whatever other evidence we can gather.
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		evs = append(evs, wcEvidence{
			path:       p,
			statusCode: resp.StatusCode,
			body:       string(body),
			setCookie:  strings.Join(resp.Header.Values("Set-Cookie"), "; "),
		})
		_ = resp.Body.Close()
	}

	component, version, detected = evaluateWebCenter(evs)
	surfaceReachable, idcAnonymous = evaluateFindings(evs)
	return component, version, detected, surfaceReachable, idcAnonymous
}

// webcenterExposedFinding reports a reachable, unauthenticated WebCenter surface.
func webcenterExposedFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-webcenter-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle WebCenter (Content/Portal/Sites) surface is reachable without authentication; the unauthenticated WebCenter application endpoints are exposed to the network",
		Evidence:    "Oracle WebCenter endpoints responded without credentials",
	}
}

// webcenterIdcAnonymousFinding reports that the Content Server Idc service
// dispatcher answered the anonymous PING_SERVER request -- an unauthenticated
// management/status interface. It never claims data access, admin, or compromise.
func webcenterIdcAnonymousFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-webcenter-content-idc-anonymous",
		Severity:    plugins.SeverityMedium,
		Description: "Oracle WebCenter Content Server Idc service interface responds to anonymous requests; the PING_SERVER status service is reachable without authentication, indicating the anonymous role can reach the Content Server service layer",
		Evidence:    "idcplg IdcService=PING_SERVER returned a Content Server status response without credentials",
	}
}

func (p *WebCenterPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	component, version, detected, surfaceReachable, idcAnonymous := detectWebCenter(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleWebCenter{
		Component: component,
		CPEs:      []string{buildWebCenterCPE(component, version)},
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	if target.Misconfigs {
		if surfaceReachable {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, webcenterExposedFinding())
		}
		if idcAnonymous {
			service.SecurityFindings = append(service.SecurityFindings, webcenterIdcAnonymousFinding())
		}
	}
	return service, nil
}

func (p *WebCenterPlugin) PortPriority(port uint16) bool { return portInList(port, webCenterTCPPorts) }
func (p *WebCenterPlugin) Name() string                  { return OracleWebCenter }
func (p *WebCenterPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *WebCenterPlugin) Priority() int                 { return -1 } // Runs before generic HTTP so it can claim WebCenter on shared ports

func (p *WebCenterTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	component, version, detected, surfaceReachable, idcAnonymous := detectWebCenter(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleWebCenter{
		Component: component,
		CPEs:      []string{buildWebCenterCPE(component, version)},
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		if surfaceReachable {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, webcenterExposedFinding())
		}
		if idcAnonymous {
			service.SecurityFindings = append(service.SecurityFindings, webcenterIdcAnonymousFinding())
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *WebCenterTLSPlugin) PortPriority(port uint16) bool {
	return portInList(port, webCenterTLSPorts)
}
func (p *WebCenterTLSPlugin) Name() string           { return OracleWebCenter }
func (p *WebCenterTLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }
func (p *WebCenterTLSPlugin) Priority() int          { return -1 } // Runs before generic HTTPS so it can claim WebCenter on shared ports (e.g. 443)
