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
Oracle Analytics / Oracle Business Intelligence (OBIEE) HTTP Fingerprinting

This plugin fingerprints Oracle Analytics Server / Oracle Business Intelligence
Enterprise Edition (OBIEE), including BI Publisher and the Data Visualization /
augmented-analytics surfaces, over a single injected connection.

Detection Surfaces (probed over one connection, first match wins):

  - /analytics/saw.dll     Oracle BI Presentation Services (SAW)  -> surface "analytics"
  - /analytics-ws/saw.dll  Presentation Services web-services      -> surface "analytics"
  - /xmlpserver            Oracle BI Publisher                     -> surface "bi-publisher"
  - /dv                    Oracle Data Visualization               -> surface "dv"
  - /va                    Oracle Analytics (visual analyzer)      -> surface "dv"

Detection Signals (product-specific, no bare-status / generic-title triggers):

  - A Set-Cookie whose name begins with "ORA_BIPS_" (e.g. ORA_BIPS_NQID). This is
    matched on the parsed cookie NAME (boundary-safe, case-sensitive), never as a
    substring of the raw header.
  - A <title> containing "Oracle Business Intelligence" / "Oracle Business
    Intelligence Sign In" / "Oracle Analytics" / "Oracle Data Visualization".
  - Body markers unique to a surface (e.g. "Oracle BI Presentation",
    "sawServerVersion", "Oracle BI Publisher").

The Presentation Services entry points typically redirect to a sign-in page and
set the ORA_BIPS_* cookie there; because a sign-in page is NOT anonymous access,
this plugin never sets AnonymousAccess.

Default Ports:
  - TCP 9704 (Managed Server, 11g), 9502 (12c)
  - TLS 443

CPE Format (version wildcarded; a precise version is not reliably parseable):
  cpe:2.3:a:oracle:business_intelligence:*:*:*:*:*:*:*:*
*/

package oracleobiee

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
	OBIEE = "oracle_obiee"

	// maxBody bounds the number of bytes read from any single HTTP response.
	maxBody = int64(512 * 1024)

	// oraBIPSCookiePrefix is the distinctive Presentation Services cookie prefix.
	oraBIPSCookiePrefix = "ORA_BIPS_"
)

var titlePattern = regexp.MustCompile(`(?is)<title[^>]*>(.*?)</title>`)

// obieeProbe describes one surface probe and the product-specific markers that
// confirm it. Cookie detection (ORA_BIPS_*) applies to every probe.
type obieeProbe struct {
	path         string
	surface      string
	titleMarkers []string
	bodyMarkers  []string
}

var obieeProbes = []obieeProbe{
	{
		path:    "/analytics/saw.dll",
		surface: "analytics",
		titleMarkers: []string{
			"Oracle Business Intelligence",
			"Oracle Analytics",
		},
		bodyMarkers: []string{
			"Oracle BI Presentation",
			"sawServerVersion",
			"Oracle BI Enterprise Edition",
		},
	},
	{
		path:    "/analytics-ws/saw.dll",
		surface: "analytics",
		titleMarkers: []string{
			"Oracle Business Intelligence",
			"Oracle Analytics",
		},
		bodyMarkers: []string{
			"Oracle BI Presentation",
			"sawServerVersion",
		},
	},
	{
		path:    "/xmlpserver",
		surface: "bi-publisher",
		titleMarkers: []string{
			"Oracle BI Publisher",
			"BI Publisher",
		},
		bodyMarkers: []string{
			"Oracle BI Publisher",
			"xmlpserver",
		},
	},
	{
		path:    "/dv",
		surface: "dv",
		titleMarkers: []string{
			"Oracle Analytics",
			"Oracle Data Visualization",
		},
		bodyMarkers: []string{
			"Oracle Data Visualization",
			"Oracle Analytics",
		},
	},
	{
		path:    "/va",
		surface: "dv",
		titleMarkers: []string{
			"Oracle Analytics",
			"Oracle Data Visualization",
		},
		bodyMarkers: []string{
			"Oracle Data Visualization",
			"Oracle Analytics",
		},
	},
}

func init() {
	plugins.RegisterPlugin(&Plugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

// createHTTPClient wraps the provided net.Conn so all HTTP requests reuse the
// single injected connection (HTTP/1.1 keep-alive). Redirects are not followed
// so Location/Set-Cookie on a 3xx sign-in redirect remain observable.
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

// hasCookieWithPrefix reports whether any Set-Cookie name begins with prefix.
// Matching uses the parsed cookie name, so it is boundary-safe and
// case-sensitive (never a substring match on the raw header).
func hasCookieWithPrefix(resp *http.Response, prefix string) bool {
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, prefix) {
			return true
		}
	}
	return false
}

// detectOBIEE probes each OBIEE surface over the shared client and returns the
// matched surface. It returns detected=false when no product-specific marker is
// found.
func detectOBIEE(client *http.Client, baseURL, host string) (surface string, detected bool) {
	for _, probe := range obieeProbes {
		resp, err := doGet(client, baseURL, probe.path, host)
		if err != nil {
			continue
		}

		cookieHit := hasCookieWithPrefix(resp, oraBIPSCookiePrefix)

		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
		_ = resp.Body.Close()
		content := string(body)
		title := extractTitle(content)

		if cookieHit ||
			containsAny(title, probe.titleMarkers) ||
			containsAny(content, probe.bodyMarkers) {
			return probe.surface, true
		}
	}
	return "", false
}

// buildOBIEECPE returns the wildcard-version CPE for Oracle Business Intelligence.
func buildOBIEECPE() string {
	return "cpe:2.3:a:oracle:business_intelligence:*:*:*:*:*:*:*:*"
}

// Plugin detects OBIEE over cleartext HTTP.
type Plugin struct{}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	surface, detected := detectOBIEE(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleOBIEE{
		Surface: surface,
		CPEs:    []string{buildOBIEECPE()},
	}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

func (p *Plugin) PortPriority(port uint16) bool { return port == 9704 || port == 9502 }
func (p *Plugin) Name() string                  { return OBIEE }
func (p *Plugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *Plugin) Priority() int                 { return -1 }

// TLSPlugin detects OBIEE over TLS.
type TLSPlugin struct{}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	surface, detected := detectOBIEE(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleOBIEE{
		Surface: surface,
		CPEs:    []string{buildOBIEECPE()},
	}
	service := plugins.CreateServiceFrom(target, payload, true, "", plugins.TCPTLS)
	if target.Misconfigs {
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *TLSPlugin) PortPriority(port uint16) bool { return port == 443 }
func (p *TLSPlugin) Name() string                  { return OBIEE }
func (p *TLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *TLSPlugin) Priority() int                 { return -1 }
