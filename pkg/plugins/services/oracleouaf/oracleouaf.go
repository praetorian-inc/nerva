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
Oracle Utilities Application Framework (OUAF) + Testing Accelerator (UTA) HTTP Fingerprinting (LAB-5080)

This plugin detects Oracle Utilities Application Framework (OUAF) and Oracle
Utilities Testing Accelerator (UTA) exposed over HTTP/HTTPS.

OUAF is the shared platform underneath Oracle Utilities products (Customer
Care & Billing, Meter Data Management, etc.). It exposes a distinctive login
surface under /ouaf/. UTA is a separate product with its own context at /uta/.

Detection Strategy (best-effort, non-fatal errors):

  The plugin issues GET requests to "/ouaf/loginPage.jsp", "/ouaf/cis.jsp",
  "/ouaf/rest", and "/uta/login.html". The HTTP client does NOT follow
  redirects, so each response's status code, headers, and body are inspected
  directly.

  OUAF detection — a host is classified as OUAF when ANY of these signals
  are present:
    - A response under /ouaf/ contains "Oracle Utilities", "loginPage",
      "j_security_check", or "cis.jsp" (case-insensitive body check)
    - A redirect (301/302/303/307) Location header points to a /ouaf/ path
    - The /ouaf/rest endpoint returns a non-404 response containing
      "application" (JSON REST API surface)

  UTA detection — a host is classified as UTA when:
    - /uta/login.html returns a non-404 response containing
      "Testing Accelerator" or "Oracle Utilities" (body or title)
    - A redirect Location header points to a /uta/ path

  Per-product differentiation (CCB vs MDM) is NOT resolvable unauthenticated;
  the plugin reports "OUAF" generically.

Version:
  Not reliably available unauthenticated (post-login only); best-effort only.
  The version string passed to CreateServiceFrom is "" (known product, unknown
  version).

CPE Format:
  cpe:2.3:a:oracle:utilities_application_framework:*:*:*:*:*:*:*:*
  cpe:2.3:a:oracle:utilities_testing_accelerator:*:*:*:*:*:*:*:*

Default Ports:
  - 6501 is the OUAF native HTTP port (PortPriority for the TCP variant)
  - 6500 is the alternate OUAF port (PortPriority for the TCP variant)
  - 443 for the TLS variant
*/

package oracleouaf

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
	// OracleOUAF is the protocol name for Oracle Utilities Application Framework.
	OracleOUAF = "oracle_ouaf"
	// OracleUTA is the protocol name for Oracle Utilities Testing Accelerator.
	OracleUTA = "oracle_uta"
	// DefaultOUAFPort is the OUAF native HTTP port.
	DefaultOUAFPort = 6501
	// DefaultOUAFAltPort is the alternate OUAF HTTP port.
	DefaultOUAFAltPort = 6500
	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(10 * 1024 * 1024)
)

// titlePattern extracts the contents of an HTML <title> element.
var titlePattern = regexp.MustCompile(`(?is)<title>(.*?)</title>`)

// OUAFPlugin detects Oracle OUAF and UTA over plain TCP connections.
type OUAFPlugin struct{}

// OUAFTLSPlugin detects Oracle OUAF and UTA over TLS connections.
type OUAFTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&OUAFPlugin{})
	plugins.RegisterPlugin(&OUAFTLSPlugin{})
}

// createHTTPClient creates an http.Client that wraps the provided net.Conn.
// This enables multiple HTTP requests over the same connection via HTTP/1.1
// keep-alive. The client does not follow redirects, so Location headers can
// be inspected directly.
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

// ouafEvidence captures the inspectable parts of a single HTTP response.
type ouafEvidence struct {
	path       string
	statusCode int
	location   string
	body       string
}

// extractTitle returns the trimmed contents of the first <title> element, if any.
func extractTitle(body string) string {
	if m := titlePattern.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// locationPointsToOUAF reports whether a redirect Location header points at
// the OUAF context root. It parses the Location and compares only the path
// component; if parsing fails, it returns false.
func locationPointsToOUAF(location string) bool {
	u, err := url.Parse(location)
	if err != nil {
		return false
	}
	return strings.HasPrefix(u.Path, "/ouaf/")
}

// locationPointsToUTA reports whether a redirect Location header points at
// the UTA context root.
func locationPointsToUTA(location string) bool {
	u, err := url.Parse(location)
	if err != nil {
		return false
	}
	return strings.HasPrefix(u.Path, "/uta/")
}

// isRedirect reports whether an HTTP status code is a redirect.
func isRedirect(statusCode int) bool {
	return statusCode == http.StatusMovedPermanently ||
		statusCode == http.StatusFound ||
		statusCode == http.StatusSeeOther ||
		statusCode == http.StatusTemporaryRedirect
}

// evaluateOUAF inspects collected responses and decides whether the host
// exposes OUAF, UTA, or both, returning the detected title.
func evaluateOUAF(evs []ouafEvidence) (title string, ouafDetected bool, utaDetected bool) {
	for _, ev := range evs {
		respTitle := extractTitle(ev.body)
		if title == "" && respTitle != "" {
			title = respTitle
		}

		bodyLower := strings.ToLower(ev.body)

		// OUAF signals: product-specific body markers on /ouaf/ paths.
		if strings.HasPrefix(ev.path, "/ouaf/") && ev.statusCode != http.StatusNotFound {
			if strings.Contains(bodyLower, "oracle utilities") ||
				strings.Contains(bodyLower, "loginpage") ||
				strings.Contains(ev.body, "j_security_check") ||
				strings.Contains(bodyLower, "cis.jsp") {
				ouafDetected = true
			}
		}

		// OUAF signal: redirect to /ouaf/ context root.
		if isRedirect(ev.statusCode) && locationPointsToOUAF(ev.location) {
			ouafDetected = true
		}

		// UTA signals: product-specific body markers on /uta/ paths.
		if strings.HasPrefix(ev.path, "/uta/") && ev.statusCode != http.StatusNotFound {
			if strings.Contains(bodyLower, "testing accelerator") ||
				strings.Contains(bodyLower, "oracle utilities") {
				utaDetected = true
			}
		}

		// UTA signal: redirect to /uta/ context root.
		if isRedirect(ev.statusCode) && locationPointsToUTA(ev.location) {
			utaDetected = true
		}
	}

	return title, ouafDetected, utaDetected
}

// detectOUAF fetches the OUAF/UTA probe paths and evaluates the collected
// evidence.
func detectOUAF(client *http.Client, baseURL string, host string) (title string, ouafDetected bool, utaDetected bool) {
	paths := []string{
		"/ouaf/loginPage.jsp",
		"/ouaf/cis.jsp",
		"/ouaf/rest",
		"/uta/login.html",
	}
	var evs []ouafEvidence
	for _, p := range paths {
		resp, err := doGet(client, baseURL+p, host)
		if err != nil {
			// Non-fatal: continue with whatever other evidence we can gather.
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		evs = append(evs, ouafEvidence{
			path:       p,
			statusCode: resp.StatusCode,
			location:   resp.Header.Get("Location"),
			body:       string(body),
		})
		_ = resp.Body.Close()
	}
	return evaluateOUAF(evs)
}

// buildOUAFCPEs returns the CPE list for OUAF (when detected) and UTA (when
// detected). Version is always wildcard since the exact version is not exposed
// unauthenticated.
func buildOUAFCPEs(ouaf bool, uta bool) []string {
	var cpes []string
	if ouaf {
		cpes = append(cpes, "cpe:2.3:a:oracle:utilities_application_framework:*:*:*:*:*:*:*:*")
	}
	if uta {
		cpes = append(cpes, "cpe:2.3:a:oracle:utilities_testing_accelerator:*:*:*:*:*:*:*:*")
	}
	return cpes
}

// ouafFinding returns the security finding for an exposed OUAF login surface.
func ouafFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-ouaf-login-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Utilities Application Framework login surface (/ouaf/) is exposed to the network; the login page itself does not grant access but broadens the attack surface for credential and CVE-based attacks",
		Evidence:    "Oracle Utilities Application Framework login endpoints are reachable",
	}
}

// utaFinding returns the security finding for an exposed UTA login surface.
func utaFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-uta-login-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Utilities Testing Accelerator login surface (/uta/) is exposed to the network; the login page itself does not grant access but broadens the attack surface for credential and CVE-based attacks",
		Evidence:    "Oracle Utilities Testing Accelerator login endpoints are reachable",
	}
}

func (p *OUAFPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	title, ouaf, uta := detectOUAF(client, baseURL, target.Host)
	if !ouaf && !uta {
		return nil, nil
	}

	payload := plugins.ServiceOracleOUAF{
		OUAF:  ouaf,
		UTA:   uta,
		Title: title,
		CPEs:  buildOUAFCPEs(ouaf, uta),
	}
	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
	if target.Misconfigs {
		// A reachable login page is not anonymous access; only flag the
		// exposed login surface (same treatment as Oracle E-Business Suite).
		if ouaf {
			service.SecurityFindings = append(service.SecurityFindings, ouafFinding())
		}
		if uta {
			service.SecurityFindings = append(service.SecurityFindings, utaFinding())
		}
	}
	return service, nil
}

func (p *OUAFPlugin) PortPriority(port uint16) bool { return port == DefaultOUAFPort || port == DefaultOUAFAltPort }
func (p *OUAFPlugin) Name() string                  { return OracleOUAF }
func (p *OUAFPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *OUAFPlugin) Priority() int                 { return -1 } // Runs before generic HTTP so it can claim OUAF on shared ports

func (p *OUAFTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	title, ouaf, uta := detectOUAF(client, baseURL, target.Host)
	if !ouaf && !uta {
		return nil, nil
	}

	payload := plugins.ServiceOracleOUAF{
		OUAF:  ouaf,
		UTA:   uta,
		Title: title,
		CPEs:  buildOUAFCPEs(ouaf, uta),
	}
	service := plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS)
	if target.Misconfigs {
		if ouaf {
			service.SecurityFindings = append(service.SecurityFindings, ouafFinding())
		}
		if uta {
			service.SecurityFindings = append(service.SecurityFindings, utaFinding())
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *OUAFTLSPlugin) PortPriority(port uint16) bool { return port == 443 }
func (p *OUAFTLSPlugin) Name() string                  { return OracleOUAF }
func (p *OUAFTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *OUAFTLSPlugin) Priority() int                 { return -1 } // Runs before generic HTTPS so it can claim OUAF on shared ports (e.g. 443)
