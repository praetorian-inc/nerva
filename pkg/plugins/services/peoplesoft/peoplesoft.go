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
Oracle PeopleSoft HTTP Fingerprinting (LAB-5039)

This plugin detects Oracle PeopleSoft (PeopleSoft Enterprise / PeopleTools)
exposed over HTTP/HTTPS.

PeopleSoft is a large enterprise application suite (HCM/FSCM/CRM) fronted by the
PeopleSoft Internet Architecture (PIA). The PIA exposes a distinctive portal
surface under /psp/ (portal servlet) and /psc/ (content servlet) and issues the
signature PS_TOKEN authentication cookie.

Detection Strategy (best-effort, non-fatal errors):

  The plugin issues GET requests to "/", "/psp/ps/?cmd=login", and "/psc/ps/".
  The HTTP client does NOT follow redirects; headers and bodies are inspected
  directly.

  A host is classified as PeopleSoft when ANY strong signal is present:
    - A Set-Cookie header contains the PS_TOKEN cookie (definitive)
    - A <title> contains "Oracle PeopleSoft Sign-in"
    - Both /psp/ AND /psc/ respond (non-404) with PeopleSoft body markers

  The cookies PS_TOKENEXPIRE / PS_LOGINLIST corroborate but are not treated as
  definitive on their own (PS_TOKENEXPIRE deliberately does not match the
  PS_TOKEN cookie check, which requires the "PS_TOKEN=" name token).

  ServicePeopleSoft.PSToken is set true when the definitive PS_TOKEN cookie was
  observed.

Version (best-effort):
  The plugin issues GET "/PSEMHUB/hub" (the PeopleSoft Environment Management
  Hub). When the response carries a "Registered Hosts Summary", a PeopleTools
  version is parsed from the body via regex. Otherwise the version is "".

CPE Format:
  The version parsed from /PSEMHUB/hub is a PeopleTools version, not a
  PeopleSoft Enterprise application version, so it is not stamped onto the
  application CPE. The plugin always emits:
    cpe:2.3:a:oracle:peoplesoft_enterprise:*:*:*:*:*:*:*:*
  and, when a PeopleTools version is found, additionally:
    cpe:2.3:a:oracle:peoplesoft_enterprise_peopletools:<ver>:*:*:*:*:*:*:*
  (the product NVD uses for PeopleTools CVEs).

Default Ports:
  - 8000 is the classic PeopleSoft PIA HTTP port (PortPriority for the TCP variant)
  - 443 for the TLS variant
*/

package peoplesoft

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
	PeopleSoft = "oracle_peoplesoft"
	// DefaultPeopleSoftPort is the classic PeopleSoft PIA HTTP port.
	DefaultPeopleSoftPort = 8000
	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(10 * 1024 * 1024)
)

// titlePattern extracts the contents of an HTML <title> element.
var titlePattern = regexp.MustCompile(`(?is)<title>(.*?)</title>`)

// peopleToolsVersionPattern extracts a PeopleTools version, e.g.
// "PeopleTools 8.59.07".
var peopleToolsVersionPattern = regexp.MustCompile(`(?i)PeopleTools[^0-9]*([0-9]+\.[0-9]+(?:\.[0-9]+)?)`)

type PeopleSoftPlugin struct{}

// PeopleSoftTLSPlugin detects Oracle PeopleSoft over TLS connections.
type PeopleSoftTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&PeopleSoftPlugin{})
	plugins.RegisterPlugin(&PeopleSoftTLSPlugin{})
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

// psEvidence captures the inspectable parts of a single HTTP response.
type psEvidence struct {
	path       string
	statusCode int
	body       string
	setCookie  string
}

// extractTitle returns the trimmed contents of the first <title> element, if any.
func extractTitle(body string) string {
	if m := titlePattern.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// cookieContains reports whether the joined Set-Cookie header defines a cookie
// with the given name. The name must appear at a cookie boundary — either at the
// start of the Set-Cookie value or immediately after a cookie delimiter (';' or
// ',', with optional surrounding whitespace) — and be followed by '='. Matching
// "<name>=" at a boundary (rather than as a bare substring) means a differently
// named cookie does NOT satisfy the check: PS_TOKENEXPIRE (different name) and
// APP_PS_TOKEN (name embedded mid-token) do not match the PS_TOKEN check, while
// "PS_TOKEN=abc" and "PS_LASTSITE=x; PS_TOKEN=abc" do.
func cookieContains(setCookie, name string) bool {
	re := regexp.MustCompile(`(?i)(^|[;,])\s*` + regexp.QuoteMeta(name) + `=`)
	return re.MatchString(setCookie)
}

// bodyHasPeopleSoftMarker reports whether a response body carries a genuine
// PeopleSoft-specific marker. The bare "/psp/" and "/psc/" path tokens are
// deliberately NOT treated as markers: they are exactly the servlet paths this
// plugin probes, so a catch-all app that reflects the requested URL back in its
// body would otherwise be misidentified as PeopleSoft. Only PeopleSoft-specific
// content ("PeopleSoft"/"PeopleTools" strings or a PS_TOKEN reference) — which a
// path-reflecting responder does not emit — counts as a real marker.
func bodyHasPeopleSoftMarker(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "peoplesoft") ||
		strings.Contains(lower, "peopletools") ||
		strings.Contains(body, "PS_TOKEN")
}

// parsePeopleToolsVersion extracts a PeopleTools version from the PSEMHUB hub
// page. It only attempts extraction when a "Registered Hosts Summary" marker is
// present, returning "" otherwise.
func parsePeopleToolsVersion(body string) string {
	if !strings.Contains(body, "Registered Hosts Summary") {
		return ""
	}
	if m := peopleToolsVersionPattern.FindStringSubmatch(body); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// evaluatePeopleSoft inspects collected responses and decides whether the host
// is PeopleSoft, returning the detected title and whether the PS_TOKEN cookie
// was observed.
func evaluatePeopleSoft(evs []psEvidence) (title string, psToken bool, detected bool) {
	pspOK := false
	pscOK := false
	for _, ev := range evs {
		respTitle := extractTitle(ev.body)
		if title == "" && respTitle != "" {
			title = respTitle
		}

		// Definitive signal: PS_TOKEN authentication cookie.
		if cookieContains(ev.setCookie, "PS_TOKEN") {
			psToken = true
			detected = true
		}

		// Strong signal: PeopleSoft sign-in page title.
		if strings.Contains(respTitle, "Oracle PeopleSoft Sign-in") {
			detected = true
		}

		// Track /psp/ (portal) and /psc/ (content) servlets responding as PeopleSoft.
		if ev.statusCode != http.StatusNotFound && bodyHasPeopleSoftMarker(ev.body) {
			if strings.Contains(ev.path, "/psp/") {
				pspOK = true
			}
			if strings.Contains(ev.path, "/psc/") {
				pscOK = true
			}
		}
	}

	// Strong signal: both the portal and content servlets respond as PeopleSoft.
	if pspOK && pscOK {
		detected = true
	}
	return title, psToken, detected
}

// fetchPeopleToolsVersion issues a best-effort request to the PSEMHUB hub and
// parses a PeopleTools version, returning "" when unavailable.
func fetchPeopleToolsVersion(client *http.Client, baseURL string, host string) string {
	resp, err := doGet(client, baseURL+"/PSEMHUB/hub", host)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	return parsePeopleToolsVersion(string(body))
}

// detectPeopleSoft fetches the PeopleSoft probe paths and evaluates the
// collected evidence, then best-effort resolves the PeopleTools version.
func detectPeopleSoft(client *http.Client, baseURL string, host string) (title string, psToken bool, version string, detected bool) {
	paths := []string{"/", "/psp/ps/?cmd=login", "/psc/ps/"}
	var evs []psEvidence
	for _, p := range paths {
		resp, err := doGet(client, baseURL+p, host)
		if err != nil {
			// Non-fatal: continue with whatever other evidence we can gather.
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		evs = append(evs, psEvidence{
			path:       p,
			statusCode: resp.StatusCode,
			body:       string(body),
			setCookie:  strings.Join(resp.Header.Values("Set-Cookie"), "; "),
		})
		_ = resp.Body.Close()
	}

	title, psToken, detected = evaluatePeopleSoft(evs)
	if detected {
		version = fetchPeopleToolsVersion(client, baseURL, host)
	}
	return title, psToken, version, detected
}

// buildPeopleSoftCPEs returns the CPE list for a detected PeopleSoft host.
//
// The version parsed from /PSEMHUB/hub is a PeopleTools version, NOT a
// PeopleSoft Enterprise application version, so it must not be stamped onto the
// peoplesoft_enterprise CPE. We therefore always emit the application CPE with a
// wildcard version, and when a PeopleTools version is known we additionally emit
// the peoplesoft_enterprise_peopletools CPE (the product NVD uses for
// PeopleTools CVEs) carrying that version.
func buildPeopleSoftCPEs(version string) []string {
	cpes := []string{"cpe:2.3:a:oracle:peoplesoft_enterprise:*:*:*:*:*:*:*:*"}
	if version != "" {
		cpes = append(cpes, fmt.Sprintf("cpe:2.3:a:oracle:peoplesoft_enterprise_peopletools:%s:*:*:*:*:*:*:*", version))
	}
	return cpes
}

func peopleSoftFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-peoplesoft-login-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle PeopleSoft sign-in surface is reachable without authentication; the PeopleSoft Internet Architecture portal endpoints are exposed to the network",
		Evidence:    "Oracle PeopleSoft portal endpoints responded without credentials",
	}
}

func (p *PeopleSoftPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	_, psToken, version, detected := detectPeopleSoft(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServicePeopleSoft{
		PSToken: psToken,
		CPEs:    buildPeopleSoftCPEs(version),
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	if target.Misconfigs {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, peopleSoftFinding())
	}
	return service, nil
}

func (p *PeopleSoftPlugin) PortPriority(port uint16) bool { return port == DefaultPeopleSoftPort }
func (p *PeopleSoftPlugin) Name() string                  { return PeopleSoft }
func (p *PeopleSoftPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *PeopleSoftPlugin) Priority() int                 { return -1 } // Runs before generic HTTP so it can claim PeopleSoft on shared ports (e.g. 8000)

func (p *PeopleSoftTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	_, psToken, version, detected := detectPeopleSoft(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServicePeopleSoft{
		PSToken: psToken,
		CPEs:    buildPeopleSoftCPEs(version),
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, peopleSoftFinding())
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *PeopleSoftTLSPlugin) PortPriority(port uint16) bool { return port == 443 }
func (p *PeopleSoftTLSPlugin) Name() string                  { return PeopleSoft }
func (p *PeopleSoftTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *PeopleSoftTLSPlugin) Priority() int                 { return -1 } // Runs before generic HTTPS so it can claim PeopleSoft on shared ports (e.g. 443)
