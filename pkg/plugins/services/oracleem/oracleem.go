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
Oracle Enterprise Manager (EM) HTTP Fingerprinting

This plugin fingerprints Oracle Enterprise Manager over a single injected
connection, distinguishing three components:

  - console : EM Cloud Control console at /em/, which redirects unauthenticated
              requests to /em/faces/logon/... (component "console").
  - agent   : the Management Agent, GET /emd/main/ on port 3872, which returns an
              EM Agent status XML document without authentication and often
              exposes the agent version (component "agent").
  - express : EM Database Express (port 5500), whose login page carries the title
              "Database Express" (component "express").

Detection Signals (product-specific, no bare-status / generic-title triggers):

  - Management Agent XML at /emd/main/ containing EM markers (e.g. "EMD",
    "AgentState", "Oracle Enterprise Manager"). This surface is genuinely
    anonymous, so on a 2xx it is reported as anonymous access.
  - A /em/ redirect whose parsed Location path contains "/em/faces/logon"
    (Location is parsed with net/url and only the path is compared, never the
    raw header), or a body/title naming Enterprise Manager.
  - A <title> containing "Database Express" for EM Express.

The console and express surfaces are sign-in gates, so they never set
AnonymousAccess. Only the anonymously reachable agent status endpoint does, and
only on a 2xx response when misconfiguration reporting is enabled.

Default Ports:
  - TCP 7803 (Cloud Control), 3872 (Management Agent), 5500 (Database Express)
  - TLS 7803 / 443

CPE Format (version wildcarded unless parseable from the agent response):
  cpe:2.3:a:oracle:enterprise_manager_base_platform:<ver-or-*>:*:*:*:*:*:*:*
*/

package oracleem

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
	EM = "oracle_em"

	// maxBody bounds the number of bytes read from any single HTTP response.
	maxBody = int64(512 * 1024)

	// logonPath is the Cloud Control unauthenticated redirect target.
	logonPath = "/em/faces/logon"
)

var (
	titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)
	// agentVersionPattern extracts a version like 13.5.0.0.0 that follows an
	// agent/emd version marker in the Management Agent XML.
	agentVersionPattern = regexp.MustCompile(`(?i)(?:agent[_ ]?version|emd[_ ]?version)["'>:= ]{1,6}v?(\d+(?:\.\d+){2,})`)

	// agentXMLMarkers are structural markers unique to the Management Agent
	// status XML document (the EMResponse/AgentState envelope). At least one MUST
	// be present for a /emd/main/ response to be treated as genuine agent XML.
	// This confines detection to the agent XML context so the generic phrase
	// "Oracle Enterprise Manager" can never trigger as a bare substring on an
	// arbitrary page.
	agentXMLMarkers = []string{
		"<EMResponse",
		"AgentState",
		"emdVersion",
		"EMD_URL",
	}
)

func init() {
	plugins.RegisterPlugin(&Plugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

// createHTTPClient wraps the provided net.Conn so all HTTP requests reuse the
// single injected connection. Redirects are not followed so the Cloud Control
// logon redirect stays observable.
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

// extractTitle returns the trimmed contents of the first <title> element.
func extractTitle(body string) string {
	m := titlePattern.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(m[1])
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

// locationPath returns only the path component of a response's Location header,
// parsed with net/url. This avoids substring matches against the raw header.
func locationPath(resp *http.Response) string {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return ""
	}
	u, err := url.Parse(loc)
	if err != nil {
		return ""
	}
	return u.Path
}

// extractAgentVersion best-effort parses the Management Agent version from the
// status XML; returns "" when no version marker is present.
func extractAgentVersion(body string) string {
	m := agentVersionPattern.FindStringSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// detectAgent probes the Management Agent status endpoint. A match reports
// component "agent", the parsed version (may be ""), and anonymous=true when the
// status was served on a 2xx response.
func detectAgent(client *http.Client, baseURL, host string) (version string, anonymous, detected bool) {
	resp, err := doGet(client, baseURL, "/emd/main/", host)
	if err != nil {
		return "", false, false
	}
	is2xx := resp.StatusCode >= 200 && resp.StatusCode < 300
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	_ = resp.Body.Close()
	content := string(body)

	if !containsAny(content, agentXMLMarkers) {
		return "", false, false
	}
	return extractAgentVersion(content), is2xx, true
}

// detectConsoleOrExpress probes /em/ and distinguishes EM Express (title
// "Database Express") from the Cloud Control console (logon redirect or an
// Enterprise Manager title/body). Both are sign-in gates, so anonymous is never
// implied here.
func detectConsoleOrExpress(client *http.Client, baseURL, host string) (component string, detected bool) {
	resp, err := doGet(client, baseURL, "/em/", host)
	if err != nil {
		return "", false
	}
	locPath := locationPath(resp)
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	_ = resp.Body.Close()
	content := string(body)
	title := extractTitle(content)

	if containsAny(title, []string{"Database Express"}) ||
		containsAny(content, []string{"Database Express"}) {
		return "express", true
	}
	if strings.Contains(locPath, logonPath) ||
		containsAny(content, []string{"/em/faces/logon"}) {
		return "console", true
	}
	return "", false
}

// detectEM runs the EM component probes over the shared client, agent first.
func detectEM(client *http.Client, baseURL, host string) (component, version string, anonymous, detected bool) {
	if version, anon, ok := detectAgent(client, baseURL, host); ok {
		return "agent", version, anon, true
	}
	if component, ok := detectConsoleOrExpress(client, baseURL, host); ok {
		return component, "", false, true
	}
	return "", "", false, false
}

// buildEMCPE returns the CPEs for the detected Oracle Enterprise Manager
// component. The "express" component is the Database Express console, which is
// a database feature rather than an Enterprise Manager install, so it maps to
// database CPEs (with a wildcard version, since none is exposed). The "console"
// and "agent" components map to the Enterprise Manager base platform,
// wildcarding an unknown version.
func buildEMCPE(component, version string) []string {
	if component == "express" {
		return []string{
			"cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*",
			"cpe:2.3:a:oracle:database:*:*:*:*:*:*:*:*",
		}
	}
	if version == "" {
		version = "*"
	}
	return []string{fmt.Sprintf("cpe:2.3:a:oracle:enterprise_manager_base_platform:%s:*:*:*:*:*:*:*", version)}
}

func emAnonymousFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-em-agent-unauthenticated",
		Severity:    plugins.SeverityMedium,
		Description: "Oracle Enterprise Manager Management Agent status endpoint responded without authentication; agent and monitored-target metadata may be exposed",
		Evidence:    "GET /emd/main/ returned an EM Agent status response without credentials",
	}
}

// Plugin detects Oracle Enterprise Manager over cleartext HTTP.
type Plugin struct{}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	component, version, anonymous, detected := detectEM(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleEM{
		Component: component,
		CPEs:      buildEMCPE(component, version),
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	if target.Misconfigs && anonymous {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, emAnonymousFinding())
	}
	return service, nil
}

func (p *Plugin) PortPriority(port uint16) bool {
	// 3872 is the plaintext Management Agent port. The HTTPS console (7803)
	// and EM Express (5500) ports belong to the TLS variant.
	return port == 3872
}
func (p *Plugin) Name() string           { return EM }
func (p *Plugin) Type() plugins.Protocol { return plugins.TCP }
func (p *Plugin) Priority() int          { return -1 }

// TLSPlugin detects Oracle Enterprise Manager over TLS.
type TLSPlugin struct{}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	component, version, anonymous, detected := detectEM(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleEM{
		Component: component,
		CPEs:      buildEMCPE(component, version),
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		if anonymous {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, emAnonymousFinding())
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *TLSPlugin) PortPriority(port uint16) bool {
	// 7803 (Cloud Control console) and 5500 (EM Express) are HTTPS. Management
	// Agents on 3872 are commonly HTTPS too, so the TLS variant also prioritizes
	// it (the TCP variant keeps 3872 for plaintext agents). 443 covers
	// reverse-proxied deployments.
	return port == 7803 || port == 5500 || port == 3872 || port == 443
}
func (p *TLSPlugin) Name() string           { return EM }
func (p *TLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }
func (p *TLSPlugin) Priority() int          { return -1 }
