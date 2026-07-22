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
Oracle Agile PLM HTTP Fingerprinting (LAB-5073)

This package detects Oracle Agile Product Lifecycle Management (PLM) exposed
over HTTP/HTTPS. Each variant ships a TCP and a TLS plugin: AgilePLMPlugin and
AgilePLMTLSPlugin.

Detection Strategy:

  The plugin issues a GET request to "/Agile/default/login-cms.jsp", the
  unauthenticated login page. A host is classified as Oracle Agile PLM when
  the response is non-404 AND contains at least one non-reflective body marker:

    - "Agile Product Lifecycle Management" (branded product name)
    - "PLMServlet"  (the PLM entry servlet reference in the login form; NOT the
                     probe path, so not self-referential)
    - "/Agile/static/" (Agile-specific static asset path)

  Tokens that appear in the probe path itself ("login-cms.jsp", "default",
  "Agile") are intentionally excluded as standalone markers: an error page that
  reflects the requested URL would otherwise produce false positives. A bare
  non-404 response without any of the above markers is NOT sufficient.

Version Extraction:

  The login page footer contains version strings of the form:
    "9.3.6 (Build 47)" or "9.3.1.2 (Build 09)"

  Regex: (\d+\.\d+(?:\.\d+){0,2})\s*\(Build\s+(\d+)\)

  The dotted-numeric part (e.g. "9.3.6") is used for the CPE version field.
  The build number is stored in ServiceOracleAgilePLM.Build. Version is
  validated as 2-4 dot-separated numeric segments before use; a malformed
  match falls back to the wildcard CPE.

CPE Format:

  cpe:2.3:a:oracle:agile_plm:{version}:*:*:*:*:*:*:*

  Verified against CVE-2024-21287 (unauthenticated file disclosure). When
  version is unknown the version field is the wildcard "*".

Scanning Safety:

  The probe path is the public login page (read-only, unauthenticated). No
  credentials are submitted and no state-changing requests are issued.

Default Ports:

  Oracle Agile PLM runs on Oracle WebLogic which may listen on any port. No
  default port is assigned; PortPriority returns false for the TCP variant.
  The TLS variant fast-lanes port 443.
*/

package oracleagile

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
	OracleAgilePLM  = "oracle_agile_plm"
	maxResponseSize = int64(10 * 1024 * 1024)
)

// versionPattern matches Agile PLM version strings in the login page footer,
// e.g. "9.3.6 (Build 47)" or "9.3.1.2 (Build 09)".
var versionPattern = regexp.MustCompile(`(\d+\.\d+(?:\.\d+){0,2})\s*\(Build\s+(\d+)\)`)

// validVersionPattern validates that a dotted-numeric version has 2-4 segments.
var validVersionPattern = regexp.MustCompile(`^\d+\.\d+(?:\.\d+){0,2}$`)

// titlePattern extracts the contents of an HTML <title> element.
var titlePattern = regexp.MustCompile(`(?is)<title>(.*?)</title>`)

// AgilePLMPlugin detects Oracle Agile PLM over plain TCP connections.
type AgilePLMPlugin struct{}

// AgilePLMTLSPlugin detects Oracle Agile PLM over TLS connections.
type AgilePLMTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&AgilePLMPlugin{})
	plugins.RegisterPlugin(&AgilePLMTLSPlugin{})
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
			return http.ErrUseLastResponse
		},
	}
}

// doGet performs a GET request with the nerva User-Agent header. When host is
// non-empty it is set as the HTTP Host header so name-based virtual hosts are
// reached.
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

// agileEvidence captures the inspectable parts of the Agile PLM probe response.
type agileEvidence struct {
	statusCode int
	body       string
	server     string
}

// hasAgileMarker reports whether a body carries a non-reflective Oracle Agile
// PLM marker. Tokens that are part of the probe path ("/Agile/default/login-cms.jsp")
// are deliberately excluded to prevent self-referential false positives on error pages
// that echo the requested URL.
func hasAgileMarker(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "agile product lifecycle management") ||
		strings.Contains(body, "PLMServlet") ||
		strings.Contains(body, "PCMServlet") ||
		strings.Contains(body, "ExternalServlet") ||
		strings.Contains(body, "/Agile/static/")
}

// extractAgileVersion parses the login page body for a version/build string.
// Returns the dotted-numeric version and build number, both empty if not found.
func extractAgileVersion(body string) (version string, build string) {
	m := versionPattern.FindStringSubmatch(body)
	if len(m) < 3 {
		return "", ""
	}
	v := m[1]
	if !validVersionPattern.MatchString(v) {
		return "", ""
	}
	return v, m[2]
}

// evaluateAgile inspects collected evidence and decides whether the host is
// Oracle Agile PLM. Returns the version, build, and whether detection succeeded.
func evaluateAgile(ev agileEvidence) (version string, build string, detected bool) {
	if ev.statusCode == http.StatusNotFound || ev.statusCode == 0 {
		return "", "", false
	}
	if !hasAgileMarker(ev.body) {
		return "", "", false
	}
	version, build = extractAgileVersion(ev.body)
	return version, build, true
}

// detectAgile fetches the Agile PLM probe path and returns the evidence struct.
func detectAgile(client *http.Client, baseURL string, host string) agileEvidence {
	resp, err := doGet(client, baseURL+"/Agile/default/login-cms.jsp", host)
	if err != nil {
		return agileEvidence{}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	ev := agileEvidence{
		statusCode: resp.StatusCode,
		body:       string(body),
		server:     resp.Header.Get("Server"),
	}
	_ = resp.Body.Close()
	return ev
}

// buildAgilePLMCPE returns the CPE for Oracle Agile PLM. When version is empty
// or does not validate, the version field is the wildcard "*".
func buildAgilePLMCPE(version string) string {
	v := "*"
	if validVersionPattern.MatchString(version) {
		v = version
	}
	return fmt.Sprintf("cpe:2.3:a:oracle:agile_plm:%s:*:*:*:*:*:*:*", v)
}

func agileFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:       "oracle-agile-plm-exposed",
		Severity: plugins.SeverityLow,
		Description: "Oracle Agile PLM login surface (/Agile/default/login-cms.jsp) is exposed to the network; " +
			"the login page discloses the product version and broadens the attack surface for credential and " +
			"CVE-based attacks including CVE-2024-21287 (unauthenticated file disclosure)",
		Evidence: "Oracle Agile PLM login page responded without credentials",
	}
}

// --- TCP plugin ---

func (p *AgilePLMPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	ev := detectAgile(client, baseURL, target.Host)
	version, build, detected := evaluateAgile(ev)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleAgilePLM{
		Build: build,
		CPEs:  []string{buildAgilePLMCPE(version)},
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	if target.Misconfigs {
		service.AnonymousAccess = ev.statusCode >= 200 && ev.statusCode < 300
		service.SecurityFindings = append(service.SecurityFindings, agileFinding())
	}
	return service, nil
}

func (p *AgilePLMPlugin) PortPriority(_ uint16) bool { return false }
func (p *AgilePLMPlugin) Name() string               { return OracleAgilePLM }
func (p *AgilePLMPlugin) Type() plugins.Protocol     { return plugins.TCP }
func (p *AgilePLMPlugin) Priority() int              { return -1 } // Runs before generic HTTP to claim the port

// --- TLS plugin ---

func (p *AgilePLMTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	ev := detectAgile(client, baseURL, target.Host)
	version, build, detected := evaluateAgile(ev)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleAgilePLM{
		Build: build,
		CPEs:  []string{buildAgilePLMCPE(version)},
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		service.AnonymousAccess = ev.statusCode >= 200 && ev.statusCode < 300
		service.SecurityFindings = append(service.SecurityFindings, agileFinding())
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *AgilePLMTLSPlugin) PortPriority(port uint16) bool { return port == 443 }
func (p *AgilePLMTLSPlugin) Name() string                  { return OracleAgilePLM }
func (p *AgilePLMTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *AgilePLMTLSPlugin) Priority() int                 { return -1 } // Runs before generic HTTPS to claim port 443
