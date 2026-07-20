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
  APEX is reported when APEX evidence is present: an X-APEX-* header (always),
  or a body referencing "apex", the "/i/" static path, or an "f?p=" application
  URL when that body was served under an /ords-prefixed path. The body-based
  signal is gated to /ords paths so a generic root page does not falsely yield
  an application_express CPE.

Version:
  Parsed from the "Oracle-REST-Data-Services/<ver>" Server token when present,
  otherwise left empty.

CPE Format:
  cpe:2.3:a:oracle:rest_data_services:<ver-or-*>:*:*:*:*:*:*:*
  and, when APEX is detected, also:
  cpe:2.3:a:oracle:application_express:*:*:*:*:*:*:*:*

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
)

// ordsServerVersionPattern extracts the version from the ORDS Server token:
// "Oracle-REST-Data-Services/22.4.3".
var ordsServerVersionPattern = regexp.MustCompile(`Oracle-REST-Data-Services/([\d.]+)`)

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

// is2xx reports whether an HTTP status code indicates a successful response.
func is2xx(statusCode int) bool {
	return statusCode >= 200 && statusCode < 300
}

// bodyHasAPEX reports whether a response body carries APEX static/app references.
func bodyHasAPEX(body string) bool {
	if strings.Contains(strings.ToLower(body), "apex") {
		return true
	}
	return strings.Contains(body, "/i/") || strings.Contains(body, "f?p=")
}

// evaluateORDS inspects collected responses and decides whether the host is
// ORDS, returning the parsed version, whether APEX is present, whether ORDS was
// detected, and whether the ORDS surface is anonymously accessible. anonymous is
// true only when an ORDS-identifying response actually SUCCEEDED (2xx): a service
// that is identified solely from an auth-challenge response (401/403 carrying an
// ORDS Server header or ORDS headers) is detected but is NOT anonymous access.
func evaluateORDS(evs []ordsEvidence) (version string, apex bool, detected bool, anonymous bool) {
	for _, ev := range evs {
		// ordsSignal tracks whether THIS response identified ORDS, so that the
		// anonymous-access decision can be gated on its status code.
		ordsSignal := false

		// Strong signal: ORDS Server header (also yields version).
		if strings.Contains(ev.server, "Oracle-REST-Data-Services") {
			detected = true
			ordsSignal = true
			if v := parseORDSVersion(ev.server); v != "" && version == "" {
				version = v
			}
		}

		// Strong signal: ORDS/APEX response headers.
		if ev.hasORDSHeader || ev.hasAPEXHeader {
			detected = true
			ordsSignal = true
		}

		// Strong signal: /ords path responds (non-404) and looks like ORDS/APEX.
		// A bare Jetty header alone is NOT sufficient; it must be on an /ords path.
		if strings.HasPrefix(ev.path, "/ords") && ev.statusCode != http.StatusNotFound {
			if strings.Contains(ev.server, "Jetty(") || bodyHasAPEX(ev.body) {
				detected = true
				ordsSignal = true
			}
		}

		// Anonymous access requires an ORDS-identifying response that actually
		// succeeded (2xx). An ORDS surface that only answers with an auth
		// challenge (e.g. 401/403) is detected but not anonymously accessible.
		if ordsSignal && is2xx(ev.statusCode) {
			anonymous = true
		}

		// APEX flag. The header signal is authoritative and unconditional.
		// The body-based signal is gated to /ords-prefixed paths only, so a
		// generic root page that happens to contain "apex" or "/i/" does not
		// produce a false application_express CPE.
		if ev.hasAPEXHeader {
			apex = true
		}
		if strings.HasPrefix(ev.path, "/ords") && bodyHasAPEX(ev.body) {
			apex = true
		}
	}
	return version, apex, detected, anonymous
}

// detectORDS fetches the ORDS probe paths and evaluates the collected evidence.
func detectORDS(client *http.Client, baseURL string, host string) (version string, apex bool, detected bool, anonymous bool) {
	paths := []string{"/ords/", "/ords/_/landing", "/"}
	var evs []ordsEvidence
	for _, p := range paths {
		resp, err := doGet(client, baseURL+p, host)
		if err != nil {
			// Non-fatal: continue with whatever other evidence we can gather.
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		evs = append(evs, ordsEvidence{
			path:       p,
			statusCode: resp.StatusCode,
			server:     resp.Header.Get("Server"),
			body:       string(body),
			hasORDSHeader: resp.Header.Get("X-ORDS-STATUS-CODE") != "" ||
				resp.Header.Get("X-ORDS-FORWARD") != "",
			hasAPEXHeader: resp.Header.Get("X-APEX-STATUS-CODE") != "" ||
				resp.Header.Get("X-APEX-FORWARD") != "",
		})
		_ = resp.Body.Close()
	}
	return evaluateORDS(evs)
}

// buildORDSCPEs returns the CPE list for ORDS (always) and APEX (when detected).
func buildORDSCPEs(version string, apex bool) []string {
	v := version
	if v == "" {
		v = "*"
	}
	cpes := []string{fmt.Sprintf("cpe:2.3:a:oracle:rest_data_services:%s:*:*:*:*:*:*:*", v)}
	if apex {
		cpes = append(cpes, "cpe:2.3:a:oracle:application_express:*:*:*:*:*:*:*:*")
	}
	return cpes
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

	version, apex, detected, anonymous := detectORDS(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleORDS{
		APEX: apex,
		// AICapable is inferred: ORDS is the common gateway for Select AI /
		// AI Vector Search results / OML REST. Capability is inferred, not confirmed.
		AICapable: true,
		CPEs:      buildORDSCPEs(version, apex),
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	// Only flag anonymous access / the exposure finding when ORDS actually served
	// a successful (2xx) response; an auth-challenge-only surface is detected but
	// is not anonymously accessible.
	if target.Misconfigs && anonymous {
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

	version, apex, detected, anonymous := detectORDS(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleORDS{
		APEX:      apex,
		AICapable: true,
		CPEs:      buildORDSCPEs(version, apex),
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		// Only flag anonymous access / the exposure finding on a successful (2xx)
		// ORDS response; an auth-challenge-only surface is detected but not
		// anonymously accessible. TLS findings are unrelated and always collected.
		if anonymous {
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
