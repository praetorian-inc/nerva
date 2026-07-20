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
Oracle Access Manager (OAM) + Oracle Identity Manager (OIM/OIG) HTTP
Fingerprinting (LAB-5040)

This package detects two Oracle Identity and Access Management products exposed
over HTTP/HTTPS. Each product ships a TCP and a TLS plugin variant, for four
registered plugins total: OAMPlugin, OAMTLSPlugin, OIMPlugin, OIMTLSPlugin.

Oracle Access Manager (Name "oracle_oam"):

  OAM fronts protected applications with a WebGate agent. The plugin issues GET
  requests to "/oam/server/obrareq.cgi" (the OBRAR request handler, which
  redirects unauthenticated requests to the OAM login surface) and
  "/oam/server/logout".

  A host is classified as OAM when ANY strong, Oracle-specific signal is present:
    - The obrareq.cgi WebGate handler responds (non-404) with an OAM marker in
      the redirect Location or body (a bare 200/redirect is NOT sufficient)
    - A Set-Cookie header defines an OAM cookie: OAM_ID, OAMAuthnCookie_, or
      OAM_REQ

  The plugin also probes "/oam/server/opensso/sessionservice"; if it responds
  (non-404) ServiceOracleOAM.OpenSSO is set true, indicating the legacy 11g
  OpenSSO proxy endpoint (associated with CVE-2021-35587 exposure).

  CPE Format: cpe:2.3:a:oracle:access_manager:*:*:*:*:*:*:*:*
  Default Ports: 14100 (TCP variant), 443 (TLS variant)

Oracle Identity Manager / Governance (Name "oracle_oim"):

  OIM/OIG exposes ADF-based self-service and administration consoles. The plugin
  issues GET requests to "/identity", "/sysadmin", "/iam/governance/", and
  "/xlWebApp".

  A host is classified as OIM when ANY strong, Oracle-specific signal is present:
    - A <title> containing "Oracle Identity Self Service" or
      "System Administration"
    - An ADF static reference ("/afr/") in the body
    - The Oracle-specific "/iam/governance" path responding (non-404)

  The plugin also probes "/xlWebApp"; if it responds (non-404)
  ServiceOracleOIM.Legacy is set true, indicating the legacy 11g xlWebApp
  console.

  CPE Format: cpe:2.3:a:oracle:identity_manager:*:*:*:*:*:*:*:*
  Default Ports: 14000 (TCP variant), 443 (TLS variant)

Version:
  Neither product exposes an exact version over these HTTP surfaces, so the
  version passed to CreateServiceFrom is "" (known product, unknown version) and
  the CPE version field is a wildcard.
*/

package oracleidentity

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
	OracleOAM = "oracle_oam"
	OracleOIM = "oracle_oim"
	// DefaultOAMPort is the classic Oracle Access Manager managed-server HTTP port.
	DefaultOAMPort = 14100
	// DefaultOIMPort is the classic Oracle Identity Manager managed-server HTTP port.
	DefaultOIMPort = 14000
	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(10 * 1024 * 1024)
)

// titlePattern extracts the contents of an HTML <title> element.
var titlePattern = regexp.MustCompile(`(?is)<title>(.*?)</title>`)

type OAMPlugin struct{}

// OAMTLSPlugin detects Oracle Access Manager over TLS connections.
type OAMTLSPlugin struct{}

type OIMPlugin struct{}

// OIMTLSPlugin detects Oracle Identity Manager over TLS connections.
type OIMTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&OAMPlugin{})
	plugins.RegisterPlugin(&OAMTLSPlugin{})
	plugins.RegisterPlugin(&OIMPlugin{})
	plugins.RegisterPlugin(&OIMTLSPlugin{})
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

// doGet performs a GET request with the nerva User-Agent header.
func doGet(client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nerva/1.0")
	return client.Do(req)
}

// extractTitle returns the trimmed contents of the first <title> element, if any.
func extractTitle(body string) string {
	if m := titlePattern.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// isRedirect reports whether an HTTP status code is a redirect the plugin cares
// about.
func isRedirect(code int) bool {
	return code == http.StatusMovedPermanently ||
		code == http.StatusFound ||
		code == http.StatusSeeOther ||
		code == http.StatusTemporaryRedirect
}

// --- Oracle Access Manager (OAM) ---

// oamEvidence captures the inspectable parts of a single OAM probe response.
type oamEvidence struct {
	path       string
	statusCode int
	location   string
	body       string
	setCookie  string
}

// hasOAMCookie reports whether the joined Set-Cookie header defines an OAM
// authentication cookie.
func hasOAMCookie(setCookie string) bool {
	return strings.Contains(setCookie, "OAM_ID=") ||
		strings.Contains(setCookie, "OAM_REQ=") ||
		strings.Contains(setCookie, "OAMAuthnCookie_")
}

// hasOAMMarker reports whether a string (redirect Location or body) carries an
// Oracle Access Manager marker.
func hasOAMMarker(s string) bool {
	lower := strings.ToLower(s)
	return strings.Contains(lower, "oracle access manager") ||
		strings.Contains(lower, "/oam/") ||
		strings.Contains(lower, "obrareq")
}

// evaluateOAM inspects collected responses and decides whether the host is
// Oracle Access Manager, returning whether the legacy OpenSSO endpoint is
// present.
func evaluateOAM(evs []oamEvidence) (openSSO bool, detected bool) {
	for _, ev := range evs {
		// Strong signal: OAM authentication cookies (any probed path).
		if hasOAMCookie(ev.setCookie) {
			detected = true
		}

		// Strong signal: the obrareq.cgi WebGate handler responds with an
		// Oracle-specific marker (not a bare 200/redirect).
		if strings.Contains(ev.path, "obrareq.cgi") && ev.statusCode != http.StatusNotFound {
			if isRedirect(ev.statusCode) && hasOAMMarker(ev.location) {
				detected = true
			}
			if hasOAMMarker(ev.body) {
				detected = true
			}
		}

		// Enrichment: legacy 11g OpenSSO proxy endpoint present.
		if strings.Contains(ev.path, "opensso/sessionservice") && ev.statusCode != http.StatusNotFound {
			openSSO = true
		}
	}
	return openSSO, detected
}

// detectOAM fetches the OAM probe paths and evaluates the collected evidence.
func detectOAM(client *http.Client, baseURL string) (openSSO bool, detected bool) {
	paths := []string{
		"/oam/server/obrareq.cgi",
		"/oam/server/logout",
		"/oam/server/opensso/sessionservice",
	}
	var evs []oamEvidence
	for _, p := range paths {
		resp, err := doGet(client, baseURL+p)
		if err != nil {
			// Non-fatal: continue with whatever other evidence we can gather.
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		evs = append(evs, oamEvidence{
			path:       p,
			statusCode: resp.StatusCode,
			location:   resp.Header.Get("Location"),
			body:       string(body),
			setCookie:  strings.Join(resp.Header.Values("Set-Cookie"), "; "),
		})
		_ = resp.Body.Close()
	}
	return evaluateOAM(evs)
}

// buildOAMCPE returns the CPE for Oracle Access Manager (version always
// wildcard, since the exact version is not exposed over HTTP).
func buildOAMCPE() string {
	return "cpe:2.3:a:oracle:access_manager:*:*:*:*:*:*:*:*"
}

func oamFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-oam-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Access Manager authentication surface is reachable without authentication; the OAM WebGate endpoints are exposed to the network",
		Evidence:    "Oracle Access Manager server endpoints responded without credentials",
	}
}

// --- Oracle Identity Manager (OIM/OIG) ---

// oimEvidence captures the inspectable parts of a single OIM probe response.
type oimEvidence struct {
	path       string
	statusCode int
	body       string
}

// titleIsOracleIdentity reports whether an HTML title identifies an Oracle
// Identity console.
func titleIsOracleIdentity(title string) bool {
	return strings.Contains(title, "Oracle Identity Self Service") ||
		strings.Contains(title, "System Administration")
}

// bodyHasADFRef reports whether a body carries an ADF (Application Development
// Framework) static reference, distinctive to OIM/OIG consoles.
func bodyHasADFRef(body string) bool {
	return strings.Contains(body, "/afr/")
}

// evaluateOIM inspects collected responses and decides whether the host is
// Oracle Identity Manager, returning whether the legacy 11g xlWebApp console is
// present.
func evaluateOIM(evs []oimEvidence) (legacy bool, detected bool) {
	for _, ev := range evs {
		// Strong signal: Oracle Identity console title.
		if titleIsOracleIdentity(extractTitle(ev.body)) {
			detected = true
		}

		// Strong signal: ADF static references.
		if bodyHasADFRef(ev.body) {
			detected = true
		}

		// Strong signal: the Oracle-specific governance path responds.
		if strings.Contains(ev.path, "/iam/governance") && ev.statusCode != http.StatusNotFound {
			detected = true
		}

		// Enrichment: legacy 11g xlWebApp console present.
		if strings.Contains(ev.path, "xlWebApp") && ev.statusCode != http.StatusNotFound {
			legacy = true
		}
	}
	return legacy, detected
}

// detectOIM fetches the OIM probe paths and evaluates the collected evidence.
func detectOIM(client *http.Client, baseURL string) (legacy bool, detected bool) {
	paths := []string{"/identity", "/sysadmin", "/iam/governance/", "/xlWebApp"}
	var evs []oimEvidence
	for _, p := range paths {
		resp, err := doGet(client, baseURL+p)
		if err != nil {
			// Non-fatal: continue with whatever other evidence we can gather.
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		evs = append(evs, oimEvidence{
			path:       p,
			statusCode: resp.StatusCode,
			body:       string(body),
		})
		_ = resp.Body.Close()
	}
	return evaluateOIM(evs)
}

// buildOIMCPE returns the CPE for Oracle Identity Manager (version always
// wildcard, since the exact version is not exposed over HTTP).
func buildOIMCPE() string {
	return "cpe:2.3:a:oracle:identity_manager:*:*:*:*:*:*:*:*"
}

func oimFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-oim-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Identity Manager console surface is reachable without authentication; the OIM/OIG self-service and administration endpoints are exposed to the network",
		Evidence:    "Oracle Identity Manager console endpoints responded without credentials",
	}
}

// --- OAM plugin variants ---

func (p *OAMPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	openSSO, detected := detectOAM(client, baseURL)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleOAM{
		OpenSSO: openSSO,
		CPEs:    []string{buildOAMCPE()},
	}
	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
	if target.Misconfigs {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, oamFinding())
	}
	return service, nil
}

func (p *OAMPlugin) PortPriority(port uint16) bool { return port == DefaultOAMPort }
func (p *OAMPlugin) Name() string                  { return OracleOAM }
func (p *OAMPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *OAMPlugin) Priority() int                 { return 100 }

func (p *OAMTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	openSSO, detected := detectOAM(client, baseURL)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleOAM{
		OpenSSO: openSSO,
		CPEs:    []string{buildOAMCPE()},
	}
	service := plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS)
	if target.Misconfigs {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, oamFinding())
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *OAMTLSPlugin) PortPriority(port uint16) bool { return port == 443 }
func (p *OAMTLSPlugin) Name() string                  { return OracleOAM }
func (p *OAMTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *OAMTLSPlugin) Priority() int                 { return 100 }

// --- OIM plugin variants ---

func (p *OIMPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	legacy, detected := detectOIM(client, baseURL)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleOIM{
		Legacy: legacy,
		CPEs:   []string{buildOIMCPE()},
	}
	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
	if target.Misconfigs {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, oimFinding())
	}
	return service, nil
}

func (p *OIMPlugin) PortPriority(port uint16) bool { return port == DefaultOIMPort }
func (p *OIMPlugin) Name() string                  { return OracleOIM }
func (p *OIMPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *OIMPlugin) Priority() int                 { return 100 }

func (p *OIMTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	legacy, detected := detectOIM(client, baseURL)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleOIM{
		Legacy: legacy,
		CPEs:   []string{buildOIMCPE()},
	}
	service := plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS)
	if target.Misconfigs {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, oimFinding())
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *OIMTLSPlugin) PortPriority(port uint16) bool { return port == 443 }
func (p *OIMTLSPlugin) Name() string                  { return OracleOIM }
func (p *OIMTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *OIMTLSPlugin) Priority() int                 { return 100 }
