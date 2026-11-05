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
Oracle Communications Session Border Controller (SBC) + Enterprise
Communications Broker (ECB) — Acme Packet HTTP Fingerprinting (LAB-5074)

This package detects the Acme Packet SBC/ECB management and REST surface
exposed over HTTP/HTTPS. Two plugin variants are registered: SBCPlugin (TCP)
and SBCTLSPlugin (TCPTLS).

Shared codebase — single plugin covers both products:

  Oracle Communications SBC and ECB share the same Acme Packet web-GUI and
  REST API codebase. The two products are NOT distinguishable unauthenticated;
  a single plugin covers both and emits CPEs for both.

Detection surface:

  The plugin probes two paths:
    1. /rest/v1.1/auth/token — the Acme Packet SBC/ESBC REST API endpoint.
       Unauthenticated, it returns a 401 challenge. This is the PRIMARY signal.
    2. / — the web-GUI login page (for branded text, cookies, version).

Non-reflective guard:

  The probe path /rest/v1.1/auth/token contains the tokens "rest", "auth",
  "token". These tokens MUST NOT be used as standalone body markers, because an
  error page that echoes the requested URL back in its body would be a
  self-referential false positive. Only the branded strings, cookies, and the
  <acmeWebReq XML tag are valid body markers.

CPE formats (all three emitted on detection):

  cpe:2.3:a:oracle:communications_session_border_controller:{ver}:*:*:*:*:*:*:*
  cpe:2.3:a:oracle:enterprise_session_border_controller:{ver}:*:*:*:*:*:*:*
  cpe:2.3:a:oracle:enterprise_communications_broker:{ver}:*:*:*:*:*:*:*

Version (best-effort):

  Acme Packet version strings look like SCZ8.4.0, ECZ9.1.0, etc.
  Version extraction matches Acme-style tokens only; no generic fallback
  is used to avoid false matches on unrelated numbers. Version "" (unknown)
  is expected and acceptable.
*/

package oraclesbc

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
	OracleSBC       = "oracle_sbc"
	maxResponseSize = int64(10 * 1024 * 1024)
)

// sbcVersionAcme matches Acme Packet version tokens such as SCZ8.4.0, ECZ9.1.0,
// nnSCZ740, SCZ740, etc. The leading optional digits handle older numeric-prefix
// formats.
var sbcVersionAcme = regexp.MustCompile(`(?i)([SE]C[XZ]?\d+\.\d+\.\d+[A-Za-z0-9.]*)`)

// acmePrefixPattern matches the alphabetic prefix on an Acme version token
// (e.g. "SCZ", "ECZ") for stripping during CPE normalization.
var acmePrefixPattern = regexp.MustCompile(`(?i)^[A-Za-z]+`)

// sbcEvidence captures the inspectable parts of a single probe response.
type sbcEvidence struct {
	path       string
	statusCode int
	body       string
	setCookie  string
}

// hasSBCCookie reports whether the joined Set-Cookie header value carries an
// Acme Packet session cookie.
func hasSBCCookie(setCookie string) bool {
	return strings.Contains(setCookie, "usersessionid") ||
		strings.Contains(setCookie, "activeTabs")
}

// hasAcmeWebReqMarker reports whether a body contains the Acme Packet web
// request XML wrapper tag. This is a non-reflective marker: it is a concrete
// XML element name that does not appear in the probe URL.
func hasAcmeWebReqMarker(body string) bool {
	return strings.Contains(body, "<acmeWebReq")
}

// hasAcmeGuiParams reports whether a body carries the distinctive Acme Packet
// web-GUI request parameters. Requires at least three of the five params so the
// combination is distinctive (individually these words are too generic). These
// are non-reflective: none appear in the probe paths.
func hasAcmeGuiParams(body string) bool {
	params := []string{"parentKey", "clientfilename", "category", "object", "type"}
	count := 0
	for _, p := range params {
		if strings.Contains(body, p) {
			count++
		}
	}
	return count >= 3
}

// hasAcmePacketMarker reports whether a string (body or title) carries an
// Acme Packet / Oracle Communications branding string. All matches are
// case-insensitive. These strings are non-reflective: none of them appear in
// the probe paths.
//
// Non-reflective guard note: the probe path /rest/v1.1/auth/token contains the
// tokens "rest", "auth", "token". Those tokens are intentionally NOT used as
// body markers because an error page echoing the requested URL back in its body
// would be a self-referential false positive.
func hasAcmePacketMarker(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "acme packet") ||
		strings.Contains(lower, "session border controller") ||
		strings.Contains(lower, "enterprise communications broker") ||
		strings.Contains(lower, "oracle communications")
}

// extractSBCVersion attempts best-effort version extraction from an HTML body.
// It matches Acme-style tokens only (e.g. SCZ8.4.0, ECZ9.1.0). Returns ""
// when no version is found; this is expected and acceptable.
func extractSBCVersion(body string) string {
	if m := sbcVersionAcme.FindString(body); m != "" {
		return m
	}
	return ""
}

// normalizeSBCVersion strips the Acme prefix (SCZ, ECZ, etc.) from a version
// token so it can be used in CPEs. E.g. "SCZ8.4.0" -> "8.4.0", "ECZ9.1.0" -> "9.1.0".
// Returns the input unchanged if no prefix is found.
func normalizeSBCVersion(version string) string {
	return acmePrefixPattern.ReplaceAllString(version, "")
}

// evaluateSBC inspects evidence collected from the REST and root probes and
// decides whether this host is an Acme Packet SBC/ECB. It returns the detected
// version string (may be ""), whether the REST 401 challenge fired, and whether
// the host was detected.
//
// Detection rules:
//   - restChallenge = (rest path contains "auth/token") && rest.statusCode == 401
//   - cookie = hasSBCCookie on rest or root Set-Cookie
//   - xml = hasAcmeWebReqMarker on rest or root body
//   - guiParams = hasAcmeGuiParams on rest or root body (≥3 of 5 web-GUI params)
//   - structural = xml || guiParams  (structural web-GUI signal)
//   - branding = hasAcmePacketMarker on rest or root body
//
// detected is true when ANY of:
//   - restChallenge && (cookie || structural || branding)  — REST 401 corroborated by marker
//   - cookie && (structural || branding)                   — web-GUI cookies + second marker
//   - structural && branding                               — structural marker + branding
//
// A bare 401 alone does NOT trigger (too many APIs return 401).
// A bare branding-only or cookie-only response does NOT trigger.
func evaluateSBC(rest, root sbcEvidence) (version string, restAPI bool, detected bool) {
	restChallenge := strings.Contains(rest.path, "auth/token") && rest.statusCode == http.StatusUnauthorized
	cookie := hasSBCCookie(rest.setCookie) || hasSBCCookie(root.setCookie)
	xml := hasAcmeWebReqMarker(rest.body) || hasAcmeWebReqMarker(root.body)
	guiParams := hasAcmeGuiParams(rest.body) || hasAcmeGuiParams(root.body)
	structural := xml || guiParams
	branding := hasAcmePacketMarker(rest.body) || hasAcmePacketMarker(root.body)

	detected = (restChallenge && (cookie || structural || branding)) ||
		(cookie && (structural || branding)) ||
		(structural && branding)

	restAPI = restChallenge

	// Version: try root body first, then rest body.
	version = extractSBCVersion(root.body)
	if version == "" {
		version = extractSBCVersion(rest.body)
	}

	return version, restAPI, detected
}

// createHTTPClient creates an http.Client that wraps the provided net.Conn and
// does not follow redirects (so Location headers can be inspected directly).
func createHTTPClient(conn net.Conn, timeout time.Duration) *http.Client {
	var dialed atomic.Bool
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if dialed.Swap(true) {
					return nil, fmt.Errorf("oraclesbc: single-connection transport already dialed")
				}
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
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

// detectSBC probes multiple Acme Packet REST API version paths and the web-GUI
// root, then returns the detected version, whether the REST 401 challenge fired,
// and whether the host was detected as SBC/ECB.
//
// Different SBC firmware releases expose different REST API versions. We probe
// v1.0, v1.1, and v1.2 in order and stop at the first that returns HTTP 401
// (that is the REST challenge evidence). If none returns 401 we keep the last
// REST response so its body can still contribute markers. The evaluator is
// version-agnostic: all probed paths contain "auth/token", so the
// strings.Contains(rest.path, "auth/token") check in evaluateSBC remains correct
// for whichever path is selected.
func detectSBC(client *http.Client, baseURL string, host string) (version string, restAPI bool, detected bool, rootAccessible bool) {
	restVersionPaths := []string{
		"/rest/v1.0/auth/token",
		"/rest/v1.1/auth/token",
		"/rest/v1.2/auth/token",
	}

	// Probe REST API version paths; stop at first 401, else keep last response.
	var rest sbcEvidence
	for _, path := range restVersionPaths {
		resp, err := doGet(client, baseURL+path, host)
		if err != nil {
			// Non-fatal: continue with next version.
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		ev := sbcEvidence{
			path:       path,
			statusCode: resp.StatusCode,
			body:       string(body),
			setCookie:  strings.Join(resp.Header.Values("Set-Cookie"), "; "),
		}
		_ = resp.Body.Close()
		rest = ev
		if resp.StatusCode == http.StatusUnauthorized {
			// REST challenge found; no need to probe further versions.
			break
		}
	}

	// Probe the web-GUI root for branding, cookies, and version.
	var root sbcEvidence
	if resp, err := doGet(client, baseURL+"/", host); err == nil {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		root = sbcEvidence{
			path:       "/",
			statusCode: resp.StatusCode,
			body:       string(body),
			setCookie:  strings.Join(resp.Header.Values("Set-Cookie"), "; "),
		}
		_ = resp.Body.Close()
	}

	version, restAPI, detected = evaluateSBC(rest, root)
	rootAccessible = root.statusCode >= 200 && root.statusCode < 300
	return
}

// buildSBCCPEs returns all three Oracle SBC/E-SBC/ECB CPEs. When version is "",
// the version field is the wildcard "*". Acme-prefixed tokens (e.g. "SCZ8.4.0")
// are normalized to plain dotted versions (e.g. "8.4.0") to match NVD CPE entries.
func buildSBCCPEs(version string) []string {
	ver := normalizeSBCVersion(version)
	if ver == "" {
		ver = "*"
	}
	return []string{
		fmt.Sprintf("cpe:2.3:a:oracle:communications_session_border_controller:%s:*:*:*:*:*:*:*", ver),
		fmt.Sprintf("cpe:2.3:a:oracle:enterprise_session_border_controller:%s:*:*:*:*:*:*:*", ver),
		fmt.Sprintf("cpe:2.3:a:oracle:enterprise_communications_broker:%s:*:*:*:*:*:*:*", ver),
	}
}

// sbcFinding returns the security finding for an exposed Acme Packet SBC/ECB
// management and REST surface.
func sbcFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-sbc-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Communications SBC/ECB (Acme Packet) management and REST surface is reachable without authentication; the web-GUI login page and REST API are exposed to the network",
		Evidence:    "Acme Packet SBC/ECB web-GUI or REST endpoint responded without credentials",
	}
}

// SBCPlugin detects Oracle Communications SBC/ECB over plain TCP connections.
type SBCPlugin struct{}

// SBCTLSPlugin detects Oracle Communications SBC/ECB over TLS connections.
type SBCTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&SBCPlugin{})
	plugins.RegisterPlugin(&SBCTLSPlugin{})
}

func (p *SBCPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	version, restAPI, detected, rootAccessible := detectSBC(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleSBC{
		Product: "sbc",
		RestAPI: restAPI,
		CPEs:    buildSBCCPEs(version),
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	if target.Misconfigs {
		service.AnonymousAccess = rootAccessible
		service.SecurityFindings = append(service.SecurityFindings, sbcFinding())
	}
	return service, nil
}

func (p *SBCPlugin) PortPriority(port uint16) bool { return false } // Management is HTTPS
func (p *SBCPlugin) Name() string                  { return OracleSBC }
func (p *SBCPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *SBCPlugin) Priority() int                 { return -1 } // Runs before generic HTTP so it can claim the port

func (p *SBCTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	version, restAPI, detected, rootAccessible := detectSBC(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleSBC{
		Product: "sbc",
		RestAPI: restAPI,
		CPEs:    buildSBCCPEs(version),
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		service.AnonymousAccess = rootAccessible
		service.SecurityFindings = append(service.SecurityFindings, sbcFinding())
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *SBCTLSPlugin) PortPriority(port uint16) bool { return port == 443 || port == 8443 }
func (p *SBCTLSPlugin) Name() string                  { return OracleSBC }
func (p *SBCTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *SBCTLSPlugin) Priority() int                 { return -1 } // Runs before generic HTTPS so it can claim the port
