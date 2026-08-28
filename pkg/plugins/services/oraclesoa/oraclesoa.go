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
Oracle SOA Suite / Oracle Service Bus HTTP Fingerprinting

This plugin fingerprints Oracle SOA Suite and Oracle Service Bus over a single
injected connection, distinguishing two products:

  - soa : SOA Suite (SOA Infrastructure, SOA Composer, BPM Workspace).
  - osb : Oracle Service Bus (Service Bus console).

Detection Surfaces (probed over one connection, first match wins):

  - /soa-infra       SOA Infrastructure landing               -> product "soa"
  - /sbconsole       Oracle Service Bus console (11g)          -> product "osb"
  - /servicebus      Oracle Service Bus console (12c/14c)      -> product "osb"
  - /soa/composer    SOA Composer                             -> product "soa"
  - /bpm/workspace   BPM / Business Process Workspace         -> product "soa"

Detection Signals (product-specific, no bare-status / generic-title triggers):

  - SOA markers: "Oracle SOA Platform", "Welcome to the Oracle SOA",
    "Oracle SOA Composer", "Oracle BPM".
  - OSB markers: "Oracle Service Bus", "Service Bus Console".
  - BPM generic terms ("Business Process Workspace", "BPM Workspace") are the
    one exception to the rule that every marker carries an Oracle-specific
    noun: other BPMS products ship both phrases. They therefore match only
    when an Oracle/WebLogic branding signal corroborates them, so a
    third-party BPM workspace published on /bpm/workspace is not attributed to
    Oracle. Neither the generic term nor the branding signal triggers
    detection alone.

The requested path itself (e.g. "soa-infra" or "sbconsole") is never used as a
marker, so a 404 body that merely echoes the requested path cannot trigger a
false positive.

WebLogic auth cookies (e.g. _WL_AUTHCOOKIE_) are common to every WebLogic
deployment, so they are intentionally NOT used as a detection trigger here;
detection requires a product-specific marker, which inherently prevents a
WebLogic cookie from triggering on its own.

Only the SOA Infrastructure landing page is genuinely anonymous (it renders a
platform welcome without a sign-in), so only it may set AnonymousAccess, and
only on a 2xx response when misconfiguration reporting is enabled. The consoles
are sign-in gates and never imply anonymous access.

Default Ports:
  - TCP 8001 (SOA managed server), 7001 (AdminServer)
  - TLS 443

CPE Format (version wildcarded; per product):
  cpe:2.3:a:oracle:soa_suite:*:*:*:*:*:*:*:*
  cpe:2.3:a:oracle:service_bus:*:*:*:*:*:*:*:*
*/

package oraclesoa

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const (
	SOA = "oracle_soa"

	// maxBody bounds the number of bytes read from any single HTTP response.
	maxBody = int64(512 * 1024)
)

var (
	soaInfraMarkers = []string{
		"Oracle SOA Platform",
		"Welcome to the Oracle SOA",
	}
	osbMarkers = []string{
		"Oracle Service Bus",
		"Service Bus Console",
	}
	composerMarkers = []string{
		"Oracle SOA Composer",
		"SOA Composer",
	}
	// bpmMarkers are the unambiguous Oracle BPM product markers: any one is
	// sufficient on its own, like every other marker list here.
	bpmMarkers = []string{
		"Oracle BPM",
	}

	// bpmGenericMarkers are BPMS terms that non-Oracle products also use (IBM
	// BPM among others ships both phrases), so unlike every other marker list
	// here they carry no Oracle-specific noun. They count only alongside a
	// bpmCorroborators match; neither signal is sufficient alone. The probe path
	// /bpm/workspace is itself an Oracle/WebLogic context root, so this is
	// defence in depth against a third-party BPMS published on that path rather
	// than a likely occurrence.
	bpmGenericMarkers = []string{
		"Business Process Workspace",
		"BPM Workspace",
	}

	// bpmCorroborators are the Oracle/WebLogic branding signals accepted as
	// corroboration for bpmGenericMarkers. They never trigger detection alone.
	// The ADF entries are here because Oracle BPM Workspace is an ADF
	// application whose pages reference those resource paths even when the
	// visible text does not spell out "Oracle".
	//
	// NOTE: the ADF resource-path signals are taken from documented ADF
	// behaviour and have NOT been validated against a live Oracle BPM target.
	bpmCorroborators = []string{
		"Oracle",
		"WebLogic",
		"oracle.bpm",
		"/afr/",
		"oracle.adf",
	}
)

// soaProbe is a non-landing surface probe: fetch a path and confirm with
// product-specific markers.
type soaProbe struct {
	path    string
	product string
	// markers are product-specific: any single match confirms the product.
	markers []string
	// genericMarkers are terms shared with non-Oracle products, so a match
	// counts only alongside one of corroborators. Both are empty for probes
	// whose markers are already unambiguous.
	genericMarkers []string
	corroborators  []string
}

// matches reports whether a probe response body identifies this probe's
// product: an unambiguous marker on its own, or a generic marker corroborated
// by an Oracle/WebLogic signal.
func (p soaProbe) matches(content string) bool {
	if containsAny(content, p.markers) {
		return true
	}
	return len(p.genericMarkers) > 0 &&
		containsAny(content, p.genericMarkers) &&
		containsAny(content, p.corroborators)
}

var soaProbes = []soaProbe{
	{path: "/sbconsole", product: "osb", markers: osbMarkers},
	{path: "/servicebus", product: "osb", markers: osbMarkers},
	{path: "/soa/composer", product: "soa", markers: composerMarkers},
	{
		path:           "/bpm/workspace",
		product:        "soa",
		markers:        bpmMarkers,
		genericMarkers: bpmGenericMarkers,
		corroborators:  bpmCorroborators,
	},
}

func init() {
	plugins.RegisterPlugin(&Plugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

// createHTTPClient wraps the provided net.Conn so all HTTP requests reuse the
// single injected connection.
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

// detectSOAInfra probes the SOA Infrastructure landing page. It reports
// anonymous=true only when a 2xx response carries SOA platform markers.
func detectSOAInfra(client *http.Client, baseURL, host string) (anonymous, detected bool) {
	resp, err := doGet(client, baseURL, "/soa-infra", host)
	if err != nil {
		return false, false
	}
	is2xx := resp.StatusCode >= 200 && resp.StatusCode < 300
	// Bound the read, then drain whatever is left before closing: every probe in
	// this plugin shares one injected keep-alive connection, and net/http can
	// only reuse that connection if the response body is consumed to EOF. An
	// undrained oversized response would kill every subsequent probe.
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	content := string(body)

	if !containsAny(content, soaInfraMarkers) {
		return false, false
	}
	return is2xx, true
}

// detectSOA runs the SOA/OSB probes over the shared client, the anonymous SOA
// Infrastructure landing page first.
func detectSOA(client *http.Client, baseURL, host string) (product string, anonymous, detected bool) {
	if anon, ok := detectSOAInfra(client, baseURL, host); ok {
		return "soa", anon, true
	}

	for _, probe := range soaProbes {
		resp, err := doGet(client, baseURL, probe.path, host)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
		content := string(body)

		if probe.matches(content) {
			return probe.product, false, true
		}
	}
	return "", false, false
}

// buildSOACPE returns the per-product CPE for SOA Suite or Service Bus.
func buildSOACPE(product string) string {
	name := "soa_suite"
	if product == "osb" {
		name = "service_bus"
	}
	return fmt.Sprintf("cpe:2.3:a:oracle:%s:*:*:*:*:*:*:*:*", name)
}

func soaAnonymousFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-soa-infra-unauthenticated",
		Severity:    plugins.SeverityMedium,
		Description: "Oracle SOA Infrastructure landing page responded without authentication; if the SOA endpoints are not access-controlled, deployed composites and platform metadata may be reachable anonymously",
		Evidence:    "GET /soa-infra returned Oracle SOA Platform content without credentials",
	}
}

// Plugin detects Oracle SOA Suite / Service Bus over cleartext HTTP.
type Plugin struct{}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	product, anonymous, detected := detectSOA(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleSOA{
		Product: product,
		CPEs:    []string{buildSOACPE(product)},
	}
	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
	if target.Misconfigs && anonymous {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, soaAnonymousFinding())
	}
	return service, nil
}

func (p *Plugin) PortPriority(port uint16) bool { return port == 8001 || port == 7001 }
func (p *Plugin) Name() string                  { return SOA }
func (p *Plugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *Plugin) Priority() int                 { return -1 }

// TLSPlugin detects Oracle SOA Suite / Service Bus over TLS.
type TLSPlugin struct{}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	product, anonymous, detected := detectSOA(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleSOA{
		Product: product,
		CPEs:    []string{buildSOACPE(product)},
	}
	service := plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS)
	if target.Misconfigs {
		if anonymous {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, soaAnonymousFinding())
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *TLSPlugin) PortPriority(port uint16) bool { return port == 443 }
func (p *TLSPlugin) Name() string                  { return SOA }
func (p *TLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *TLSPlugin) Priority() int                 { return -1 }
