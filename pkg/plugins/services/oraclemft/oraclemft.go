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
Oracle Managed File Transfer (MFT) HTTP Fingerprinting (LAB-5087)

This plugin detects Oracle Managed File Transfer (MFT) exposed over
HTTP/HTTPS.

MFT is a Fusion Middleware product that provides secure file exchange
capabilities. It deploys as a web application on Oracle WebLogic Server,
exposing a JSF-based console at /mftconsole and a REST API at /mftapp/rest/.

Detection Strategy (best-effort, non-fatal errors):

  The plugin issues GET requests to "/mftconsole", "/mftconsole/faces/login",
  and "/mftapp/rest/v1/". The HTTP client does NOT follow redirects, so each
  response's status code, headers, and body are inspected directly.

  A host is classified as MFT when ANY of these signals are present:
    - A response body under /mftconsole contains "Managed File Transfer"
      (product name in the login page)
    - A response body under /mftconsole contains "LoginSubmit.do" or
      "j_security_check" (MFT/WebLogic login form actions)
    - The /mftapp/rest/v1/ endpoint returns a non-404 response containing
      "mft" (REST API surface)
    - A redirect (301/302/303/307/308) Location header points to a
      /mftconsole/ subpath (JSF login redirect); a redirect to the exact
      probed path /mftconsole is NOT counted, because generic HTTPS
      redirects preserve the path

  The bare substring "mftconsole" echoed back in a soft-404 or
  access-denied page is NOT sufficient on its own; the plugin requires
  product-specific body markers. Similarly, the REST API check requires
  product-specific content (not just "mft" which appears in the probed
  URL and could be echoed by generic error pages).

Version:
  Not reliably available unauthenticated. The REST API may expose version
  information but typically requires authentication. Best-effort only.

CPE Format:
  cpe:2.3:a:oracle:managed_file_transfer:*:*:*:*:*:*:*:*

Default Ports:
  MFT deploys on a WebLogic managed server; no single well-known port
  exists. Common ports include 7001, 7003, 7011, 8001. The plugin does
  not claim PortPriority for the TCP variant. The TLS variant claims 443.
*/

package oraclemft

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const (
	// OracleMFT is the protocol name for Oracle Managed File Transfer.
	OracleMFT = "oracle_mft"
	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(10 * 1024 * 1024)
)

// titlePattern extracts the contents of an HTML <title> element.
var titlePattern = regexp.MustCompile(`(?is)<title>(.*?)</title>`)

// MFTPlugin detects Oracle MFT over plain TCP connections.
type MFTPlugin struct{}

// MFTTLSPlugin detects Oracle MFT over TLS connections.
type MFTTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&MFTPlugin{})
	plugins.RegisterPlugin(&MFTTLSPlugin{})
}

// createHTTPClient creates an http.Client that wraps the provided net.Conn.
// An atomic guard prevents a re-dial after the server sends Connection: close.
// The client does not follow redirects, so Location headers can be inspected
// directly.
func createHTTPClient(conn net.Conn, timeout time.Duration) *http.Client {
	var dialed atomic.Bool
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				if dialed.Swap(true) {
					return nil, fmt.Errorf("oraclemft: single-connection transport already dialed")
				}
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// doGet performs a GET request with the nerva User-Agent header.
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

// mftEvidence captures the inspectable parts of a single HTTP response.
type mftEvidence struct {
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

// locationPointsToMFTConsole reports whether a redirect Location header
// points at the /mftconsole/ context root.
func locationPointsToMFTConsole(location string) bool {
	u, err := url.Parse(location)
	if err != nil {
		return false
	}
	// Require a subpath under /mftconsole/ — the exact path /mftconsole is
	// indistinguishable from a generic path-preserving HTTPS redirect.
	return strings.HasPrefix(u.Path, "/mftconsole/")
}

// isRedirect reports whether an HTTP status code is a redirect.
func isRedirect(statusCode int) bool {
	return statusCode == http.StatusMovedPermanently ||
		statusCode == http.StatusFound ||
		statusCode == http.StatusSeeOther ||
		statusCode == http.StatusTemporaryRedirect ||
		statusCode == http.StatusPermanentRedirect
}

// evaluateMFT inspects collected responses and decides whether the host
// exposes Oracle MFT. The title is only captured from responses that
// contributed to detection.
func evaluateMFT(evs []mftEvidence) (title string, detected bool) {
	for _, ev := range evs {
		bodyLower := strings.ToLower(ev.body)
		matched := false

		// MFT signals: product-specific body markers on /mftconsole paths.
		if strings.HasPrefix(ev.path, "/mftconsole") && ev.statusCode != http.StatusNotFound {
			if strings.Contains(bodyLower, "managed file transfer") {
				detected = true
				matched = true
			}
			if strings.Contains(ev.body, "LoginSubmit.do") ||
				strings.Contains(ev.body, "j_security_check") {
				detected = true
				matched = true
			}
		}

		// MFT signal: /mftapp/rest/v1/ returns an MFT-specific REST API response.
		// Bare "mft" is FP-prone because it appears in the probed URL and
		// generic error pages echo it back. Require product-specific content.
		if ev.path == "/mftapp/rest/v1/" && ev.statusCode != http.StatusNotFound {
			if strings.Contains(bodyLower, "managed file transfer") ||
				(strings.Contains(bodyLower, `"application"`) && strings.Contains(bodyLower, `"mft"`)) {
				detected = true
				matched = true
			}
		}

		// MFT signal: redirect to /mftconsole/ context root.
		if isRedirect(ev.statusCode) && locationPointsToMFTConsole(ev.location) {
			detected = true
			matched = true
		}

		if matched && title == "" {
			if respTitle := extractTitle(ev.body); respTitle != "" {
				title = respTitle
			}
		}
	}

	return title, detected
}

// detectMFT fetches probe paths and evaluates the collected evidence.
func detectMFT(client *http.Client, baseURL string, host string) (title string, detected bool) {
	paths := []string{
		"/mftconsole",
		"/mftconsole/faces/login",
		"/mftapp/rest/v1/",
	}
	var evs []mftEvidence
	for _, p := range paths {
		resp, err := doGet(client, baseURL+p, host)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		evs = append(evs, mftEvidence{
			path:       p,
			statusCode: resp.StatusCode,
			location:   resp.Header.Get("Location"),
			body:       string(body),
		})
		_ = resp.Body.Close()
	}
	return evaluateMFT(evs)
}

// mftFinding returns the security finding for an exposed MFT console.
func mftFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-mft-console-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Managed File Transfer console (/mftconsole) is exposed to the network; the login page itself does not grant access but broadens the attack surface for credential and CVE-based attacks",
		Evidence:    "Oracle Managed File Transfer console endpoints are reachable",
	}
}

func (p *MFTPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	title, detected := detectMFT(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceMFT{
		Title: title,
		CPEs:  []string{"cpe:2.3:a:oracle:managed_file_transfer:*:*:*:*:*:*:*:*"},
	}
	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
	if target.Misconfigs {
		service.SecurityFindings = append(service.SecurityFindings, mftFinding())
	}
	return service, nil
}

func (p *MFTPlugin) PortPriority(port uint16) bool { return false }
func (p *MFTPlugin) Name() string                  { return OracleMFT }
func (p *MFTPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *MFTPlugin) Priority() int                 { return -1 }

func (p *MFTTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	title, detected := detectMFT(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceMFT{
		Title: title,
		CPEs:  []string{"cpe:2.3:a:oracle:managed_file_transfer:*:*:*:*:*:*:*:*"},
	}
	service := plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS)
	if target.Misconfigs {
		service.SecurityFindings = append(service.SecurityFindings, mftFinding())
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *MFTTLSPlugin) PortPriority(port uint16) bool { return port == 443 }
func (p *MFTTLSPlugin) Name() string                  { return OracleMFT }
func (p *MFTTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *MFTTLSPlugin) Priority() int                 { return -1 }
