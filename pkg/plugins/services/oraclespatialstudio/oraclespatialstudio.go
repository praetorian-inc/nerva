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
Oracle Spatial Studio HTTP Fingerprinting (LAB-5079)

This plugin detects Oracle Spatial Studio exposed over HTTP/HTTPS.

Spatial Studio is a free, self-hostable web application built on Oracle JET
that runs on an embedded Jetty server. It provides a no-code interface for
spatial analysis over Oracle Database spatial data.

Detection Strategy (best-effort, non-fatal errors):

  The plugin issues GET requests to "/spatialstudio",
  "/spatialstudio/api/v1/", and "/spatialstudio/oauth/v1/". The HTTP client
  does NOT follow redirects, so each response's status code, headers, and
  body are inspected directly.

  A host is classified as Spatial Studio when ANY of these signals are
  present:
    - A response body under /spatialstudio contains "Spatial Studio"
      (product-specific marker in the Oracle JET login SPA)
    - A response body under /spatialstudio contains Oracle JET markers:
      "oraclejet" or "oj-module" (JET web component tags)
    - The /spatialstudio/api/v1/ endpoint returns a non-404 response
      containing "spatialstudio" (REST API surface)
    - A redirect (301/302/303/307/308) Location header points to a
      /spatialstudio/ path

  The bare substring "spatialstudio" echoed back in a soft-404 or
  access-denied page is NOT sufficient on its own; the plugin requires
  product-specific body markers or a structured API response.

Version:
  Best-effort extraction from the /spatialstudio/api/v1/ JSON response
  (a "version" field when present). Not reliably available unauthenticated;
  the version string passed to CreateServiceFrom is "" unless extracted.

CPE Format:
  cpe:2.3:a:oracle:spatial_studio:<ver-or-*>:*:*:*:*:*:*:*

Default Ports:
  - 4040 is the Spatial Studio embedded Jetty HTTPS default (PortPriority
    for the TCP variant)
  - 443 for the TLS variant
*/

package oraclespatialstudio

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
	// OracleSpatialStudio is the protocol name for Oracle Spatial Studio.
	OracleSpatialStudio = "oracle_spatial_studio"
	// DefaultSpatialStudioPort is the embedded Jetty HTTPS default port.
	DefaultSpatialStudioPort = 4040
	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(10 * 1024 * 1024)
)

// titlePattern extracts the contents of an HTML <title> element.
var titlePattern = regexp.MustCompile(`(?is)<title>(.*?)</title>`)

// versionPattern extracts a version string from a JSON "version" field.
var versionPattern = regexp.MustCompile(`"version"\s*:\s*"([\d.]+)"`)

// SpatialStudioPlugin detects Oracle Spatial Studio over plain TCP connections.
type SpatialStudioPlugin struct{}

// SpatialStudioTLSPlugin detects Oracle Spatial Studio over TLS connections.
type SpatialStudioTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&SpatialStudioPlugin{})
	plugins.RegisterPlugin(&SpatialStudioTLSPlugin{})
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
					return nil, fmt.Errorf("oraclespatialstudio: single-connection transport already dialed")
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

// spatialEvidence captures the inspectable parts of a single HTTP response.
type spatialEvidence struct {
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

// extractVersion extracts a version string from a JSON response body.
func extractVersion(body string) string {
	if m := versionPattern.FindStringSubmatch(body); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// locationPointsToSpatialStudio reports whether a redirect Location header
// points at the /spatialstudio/ context root.
func locationPointsToSpatialStudio(location string) bool {
	u, err := url.Parse(location)
	if err != nil {
		return false
	}
	return strings.HasPrefix(u.Path, "/spatialstudio/") || u.Path == "/spatialstudio"
}

// isRedirect reports whether an HTTP status code is a redirect.
func isRedirect(statusCode int) bool {
	return statusCode == http.StatusMovedPermanently ||
		statusCode == http.StatusFound ||
		statusCode == http.StatusSeeOther ||
		statusCode == http.StatusTemporaryRedirect ||
		statusCode == http.StatusPermanentRedirect
}

// evaluateSpatialStudio inspects collected responses and decides whether the
// host exposes Oracle Spatial Studio. The title and version are only captured
// from responses that contributed to detection.
func evaluateSpatialStudio(evs []spatialEvidence) (title string, version string, detected bool) {
	for _, ev := range evs {
		bodyLower := strings.ToLower(ev.body)
		matched := false

		// Spatial Studio signals: product-specific body markers on
		// /spatialstudio paths. "Spatial Studio" is the product name;
		// "oraclejet" and "oj-module" are Oracle JET SPA framework markers
		// that confirm this is a JET application (not just any page echoing
		// the context path).
		if strings.HasPrefix(ev.path, "/spatialstudio") && ev.statusCode != http.StatusNotFound {
			if strings.Contains(bodyLower, "spatial studio") {
				detected = true
				matched = true
			}
			if strings.Contains(bodyLower, "oraclejet") || strings.Contains(bodyLower, "oj-module") {
				detected = true
				matched = true
			}
		}

		// Spatial Studio signal: /spatialstudio/api/v1/ returns a REST API surface.
		if ev.path == "/spatialstudio/api/v1/" && ev.statusCode != http.StatusNotFound {
			if strings.Contains(bodyLower, "spatialstudio") {
				detected = true
				matched = true
			}
		}

		// Spatial Studio signal: redirect to /spatialstudio/ context root.
		if isRedirect(ev.statusCode) && locationPointsToSpatialStudio(ev.location) {
			detected = true
			matched = true
		}

		if matched {
			if title == "" {
				if respTitle := extractTitle(ev.body); respTitle != "" {
					title = respTitle
				}
			}
			if version == "" {
				if v := extractVersion(ev.body); v != "" {
					version = v
				}
			}
		}
	}

	return title, version, detected
}

// detectSpatialStudio fetches probe paths and evaluates the collected evidence.
func detectSpatialStudio(client *http.Client, baseURL string, host string) (title string, version string, detected bool) {
	paths := []string{
		"/spatialstudio",
		"/spatialstudio/api/v1/",
		"/spatialstudio/oauth/v1/",
	}
	var evs []spatialEvidence
	for _, p := range paths {
		resp, err := doGet(client, baseURL+p, host)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		evs = append(evs, spatialEvidence{
			path:       p,
			statusCode: resp.StatusCode,
			location:   resp.Header.Get("Location"),
			body:       string(body),
		})
		_ = resp.Body.Close()
	}
	return evaluateSpatialStudio(evs)
}

// buildSpatialStudioCPE returns the CPE for Oracle Spatial Studio.
func buildSpatialStudioCPE(version string) string {
	v := "*"
	if version != "" {
		v = version
	}
	return fmt.Sprintf("cpe:2.3:a:oracle:spatial_studio:%s:*:*:*:*:*:*:*", v)
}

// spatialStudioFinding returns the security finding for an exposed Spatial
// Studio login surface.
func spatialStudioFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-spatial-studio-login-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Spatial Studio login surface (/spatialstudio) is exposed to the network; the login page itself does not grant access but broadens the attack surface for credential and CVE-based attacks",
		Evidence:    "Oracle Spatial Studio login endpoints are reachable",
	}
}

func (p *SpatialStudioPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	title, version, detected := detectSpatialStudio(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceSpatialStudio{
		Title:   title,
		Version: version,
		CPEs:    []string{buildSpatialStudioCPE(version)},
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	if target.Misconfigs {
		service.SecurityFindings = append(service.SecurityFindings, spatialStudioFinding())
	}
	return service, nil
}

func (p *SpatialStudioPlugin) PortPriority(port uint16) bool { return port == DefaultSpatialStudioPort }
func (p *SpatialStudioPlugin) Name() string                  { return OracleSpatialStudio }
func (p *SpatialStudioPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *SpatialStudioPlugin) Priority() int                 { return -1 }

func (p *SpatialStudioTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	title, version, detected := detectSpatialStudio(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceSpatialStudio{
		Title:   title,
		Version: version,
		CPEs:    []string{buildSpatialStudioCPE(version)},
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		service.SecurityFindings = append(service.SecurityFindings, spatialStudioFinding())
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *SpatialStudioTLSPlugin) PortPriority(port uint16) bool { return port == 443 }
func (p *SpatialStudioTLSPlugin) Name() string                  { return OracleSpatialStudio }
func (p *SpatialStudioTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *SpatialStudioTLSPlugin) Priority() int                 { return -1 }
