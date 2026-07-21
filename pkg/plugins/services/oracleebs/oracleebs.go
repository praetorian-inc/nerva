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
Oracle E-Business Suite HTTP Fingerprinting (LAB-5044)

This plugin detects Oracle E-Business Suite (EBS) exposed over HTTP/HTTPS.

Oracle E-Business Suite is a large enterprise application suite (ERP/CRM/SCM)
fronted by an HTTP server that exposes a distinctive login surface under /OA_HTML/.

Detection Strategy (best-effort, non-fatal errors):

  The plugin issues GET requests to "/" and "/OA_HTML/AppsLogin". The HTTP client
  does NOT follow redirects, so each response's status code, Location header, and
  body are inspected directly.

  A host is classified as Oracle E-Business Suite when ANY of these EBS-specific
  signals are present:
    - The page <title> contains "E-Business Suite Home Page Redirect"
    - The body contains "Oracle E-Business Suite" (the generic "Oracle
      Applications" substring is deliberately not used: too FP-prone)
    - A redirect (301/302/307) Location header points to
      "/OA_HTML/AppsLogin" or "/OA_HTML/AppsLocalLogin.jsp"
    - The body or a Location header references "AppsLocalLogin"
    - A Set-Cookie header contains an "APPS_SSO_" cookie

  The generic "Oracle-HTTP-Server" Server header is treated only as corroboration
  and is NOT sufficient on its own, to avoid false positives against non-EBS sites
  hosted on Oracle HTTP Server.

Release Extraction:
  - If AppsLocalLogin.jsp is referenced, the deployment is Release 12 ("R12").
  - Otherwise the release is left empty; 11i is only claimed with a clear marker
    (this plugin does not overclaim 11i from legacy AppsLogin static content).

Version:
  - The product is identified but the exact version is not exposed, so the version
    string passed to CreateServiceFrom is "" (known product, unknown version).

CPE Format:
  cpe:2.3:a:oracle:e-business_suite:*:*:*:*:*:*:*:*  (version "*" when unknown)

Default Ports:
  - 8000 is the classic Oracle EBS HTTP port (PortPriority for the TCP variant)
  - 443 for the TLS variant
*/

package oracleebs

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
	OracleEBS = "oracle_ebs"
	// DefaultEBSPort is the classic Oracle E-Business Suite HTTP port.
	DefaultEBSPort = 8000
	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(10 * 1024 * 1024)
)

// titlePattern extracts the contents of an HTML <title> element.
var titlePattern = regexp.MustCompile(`(?is)<title>(.*?)</title>`)

type EBSPlugin struct{}

// EBSTLSPlugin detects Oracle E-Business Suite over TLS connections.
type EBSTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&EBSPlugin{})
	plugins.RegisterPlugin(&EBSTLSPlugin{})
}

// createHTTPClient creates an http.Client that wraps the provided net.Conn.
// This enables multiple HTTP requests over the same connection via HTTP/1.1
// keep-alive. Multi-path probing is therefore best-effort: if the server closes
// the connection after the first response, later probes fail on the dead conn
// (this mirrors the single-injected-connection convention used by the other
// HTTP fingerprinters, e.g. librechat and sonarqube). The client does not
// follow redirects, so Location headers can be inspected directly.
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

// ebsEvidence captures the inspectable parts of a single HTTP response.
type ebsEvidence struct {
	statusCode int
	location   string
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

// evaluateEBS inspects collected responses and decides whether the host is
// Oracle E-Business Suite, returning the detected title and release.
func evaluateEBS(evs []ebsEvidence) (title string, release string, detected bool) {
	for _, ev := range evs {
		respTitle := extractTitle(ev.body)
		if title == "" && respTitle != "" {
			title = respTitle
		}

		// Signal: EBS home page redirect title.
		if strings.Contains(respTitle, "E-Business Suite Home Page Redirect") {
			detected = true
		}

		// Signal: EBS-specific body marker. The bare "Oracle Applications"
		// substring is intentionally NOT a trigger; it is too generic and
		// false-positive prone.
		if strings.Contains(ev.body, "Oracle E-Business Suite") {
			detected = true
		}

		// Signal: redirect to the EBS login surface.
		if ev.statusCode == http.StatusMovedPermanently ||
			ev.statusCode == http.StatusFound ||
			ev.statusCode == http.StatusTemporaryRedirect {
			if strings.Contains(ev.location, "/OA_HTML/AppsLogin") ||
				strings.Contains(ev.location, "/OA_HTML/AppsLocalLogin.jsp") {
				detected = true
			}
		}

		// Signal: AppsLocalLogin evidence implies Release 12.
		if strings.Contains(ev.body, "AppsLocalLogin") ||
			strings.Contains(ev.location, "AppsLocalLogin") {
			detected = true
			release = "R12"
		}

		// Signal: EBS single sign-on cookie.
		if strings.Contains(ev.setCookie, "APPS_SSO_") {
			detected = true
		}
	}
	return title, release, detected
}

// detectEBS fetches the EBS probe paths and evaluates the collected evidence.
func detectEBS(client *http.Client, baseURL string, host string) (title string, release string, detected bool) {
	paths := []string{"/", "/OA_HTML/AppsLogin"}
	var evs []ebsEvidence
	for _, p := range paths {
		resp, err := doGet(client, baseURL+p, host)
		if err != nil {
			// Non-fatal: continue with whatever other evidence we can gather.
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		evs = append(evs, ebsEvidence{
			statusCode: resp.StatusCode,
			location:   resp.Header.Get("Location"),
			body:       string(body),
			setCookie:  strings.Join(resp.Header.Values("Set-Cookie"), "; "),
		})
		_ = resp.Body.Close()
	}
	return evaluateEBS(evs)
}

// buildEBSCPE returns the CPE for Oracle E-Business Suite (version always
// wildcard, since the exact version is not exposed over HTTP).
func buildEBSCPE() string {
	return "cpe:2.3:a:oracle:e-business_suite:*:*:*:*:*:*:*:*"
}

func ebsFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-ebs-login-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle E-Business Suite login surface (/OA_HTML/) is exposed to the network; the login page itself does not grant access but broadens the attack surface for credential and CVE-based attacks",
		Evidence:    "Oracle E-Business Suite login endpoints are reachable",
	}
}

func (p *EBSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	title, release, detected := detectEBS(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleEBS{
		Title:   title,
		Release: release,
		CPEs:    []string{buildEBSCPE()},
	}
	// Version unknown (product known): pass "" like librechat's fallback.
	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
	if target.Misconfigs {
		// A reachable login page is not anonymous access, so do not set
		// AnonymousAccess; only flag the exposed login surface.
		service.SecurityFindings = append(service.SecurityFindings, ebsFinding())
	}
	return service, nil
}

func (p *EBSPlugin) PortPriority(port uint16) bool { return port == DefaultEBSPort }
func (p *EBSPlugin) Name() string                  { return OracleEBS }
func (p *EBSPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *EBSPlugin) Priority() int                 { return -1 } // Runs before generic HTTP so it can claim EBS on shared ports (e.g. 8000)

func (p *EBSTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	title, release, detected := detectEBS(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleEBS{
		Title:   title,
		Release: release,
		CPEs:    []string{buildEBSCPE()},
	}
	service := plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS)
	if target.Misconfigs {
		// A reachable login page is not anonymous access, so do not set
		// AnonymousAccess; only flag the exposed login surface.
		service.SecurityFindings = append(service.SecurityFindings, ebsFinding())
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *EBSTLSPlugin) PortPriority(port uint16) bool { return port == 443 }
func (p *EBSTLSPlugin) Name() string                  { return OracleEBS }
func (p *EBSTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *EBSTLSPlugin) Priority() int                 { return -1 } // Runs before generic HTTPS so it can claim EBS on shared ports (e.g. 443)
