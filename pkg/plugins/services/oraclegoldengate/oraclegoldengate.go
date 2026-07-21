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
Oracle GoldenGate Fingerprinting

This plugin fingerprints Oracle GoldenGate over a single injected connection,
distinguishing two editions:

  - microservices : GoldenGate Microservices Architecture (MA), an HTTP/HTTPS
                    control plane (Service Manager, adminsrvr, distsrvr, etc.)
                    that exposes a REST/JSON API and a single-page-application
                    (SPA) login UI.
  - classic       : Classic Architecture, whose Manager listens on TCP 7809 and
                    speaks the proprietary binary GGSNET protocol (not HTTP).

Microservices Detection Surfaces (probed over one connection, first match wins):

  - /services/v2/deployments   MA REST deployments endpoint (REST/JSON)
  - /                          GoldenGate SPA login UI (title/branding)
  - /services/                 MA health JSON (version enrichment)

Detection Signals (product-specific, no bare-status / generic-title triggers):

  - REST/JSON or SPA content containing the Oracle-specific string
    "Oracle GoldenGate". The bare word "GoldenGate" is intentionally NOT used as
    a marker because it also occurs in unrelated documentation and marketing
    content; requiring the full product string avoids those false positives.
  - A version is best-effort parsed from the /services/ health JSON when present;
    otherwise the version is wildcarded.

Classic Manager (TCP 7809):

  The Classic Manager speaks GGSNET, a proprietary binary protocol that sends no
  unsolicited banner and has no publicly documented, reliable plaintext probe
  signature. To avoid false positives, the classic variant performs only a
  conservative passive read: it reports edition "classic" solely when the peer
  volunteers a distinguishing GoldenGate marker, and otherwise returns nil.

Default Ports:
  - TCP 9011, 9100 (Microservices control plane)
  - TLS 443
  - TCP 7809 (Classic Manager, GGSNET)

CPE Format (version wildcarded unless parseable):
  cpe:2.3:a:oracle:goldengate:<ver-or-*>:*:*:*:*:*:*:*
*/

package oraclegoldengate

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
	"github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	GOLDENGATE = "oracle_goldengate"

	// GOLDENGATE_MANAGER is the distinct registration name for the Classic
	// Architecture Manager detector. It differs from GOLDENGATE so the
	// microservices Plugin and the ClassicPlugin, which both register as
	// plugins.TCP, produce distinct PluginIDs (name+protocol) and do not
	// collide during init() registration. It affects only plugin registration;
	// the emitted service Protocol remains plugins.ProtoOracleGoldenGate.
	GOLDENGATE_MANAGER = "oracle_goldengate_manager"

	// maxBody bounds the number of bytes read from any single HTTP response.
	maxBody = int64(512 * 1024)
)

var (
	// ggVersionPattern extracts a version like 21.3.0.0.0 from a JSON "version"
	// field in the MA health response.
	ggVersionPattern = regexp.MustCompile(`(?i)"version"\s*:\s*"v?(\d+(?:\.\d+){2,})`)

	// goldenGateMarkers requires the full, Oracle-specific product string. The
	// bare word "GoldenGate" is avoided because it also appears in unrelated
	// documentation and marketing content, which would cause false positives.
	goldenGateMarkers = []string{
		"Oracle GoldenGate",
	}
)

func init() {
	plugins.RegisterPlugin(&Plugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
	plugins.RegisterPlugin(&ClassicPlugin{})
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

// bodyOf fetches path over the shared client and returns the (bounded) body.
func bodyOf(client *http.Client, baseURL, path, host string) (string, bool) {
	resp, err := doGet(client, baseURL, path, host)
	if err != nil {
		return "", false
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	_ = resp.Body.Close()
	return string(body), true
}

// extractVersion best-effort parses the GoldenGate version from the MA health
// JSON at /services/; returns "" when no version marker is present.
func extractVersion(client *http.Client, baseURL, host string) string {
	content, ok := bodyOf(client, baseURL, "/services/", host)
	if !ok {
		return ""
	}
	if m := ggVersionPattern.FindStringSubmatch(content); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// detectMicroservices probes the MA REST endpoint and the SPA login UI over the
// shared client, confirming with GoldenGate-specific markers, and enriches the
// version from the /services/ health JSON.
func detectMicroservices(client *http.Client, baseURL, host string) (version string, detected bool) {
	for _, path := range []string{"/services/v2/deployments", "/"} {
		content, ok := bodyOf(client, baseURL, path, host)
		if !ok {
			continue
		}
		if containsAny(content, goldenGateMarkers) {
			return extractVersion(client, baseURL, host), true
		}
	}
	return "", false
}

// buildGoldenGateCPE returns the CPE for Oracle GoldenGate, wildcarding an
// unknown version.
func buildGoldenGateCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:oracle:goldengate:%s:*:*:*:*:*:*:*", version)
}

// Plugin detects Oracle GoldenGate Microservices over cleartext HTTP.
type Plugin struct{}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	version, detected := detectMicroservices(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleGoldenGate{
		Edition: "microservices",
		CPEs:    []string{buildGoldenGateCPE(version)},
	}
	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *Plugin) PortPriority(port uint16) bool { return port == 9011 || port == 9100 }
func (p *Plugin) Name() string                  { return GOLDENGATE }
func (p *Plugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *Plugin) Priority() int                 { return -1 }

// TLSPlugin detects Oracle GoldenGate Microservices over TLS.
type TLSPlugin struct{}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	version, detected := detectMicroservices(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleGoldenGate{
		Edition: "microservices",
		CPEs:    []string{buildGoldenGateCPE(version)},
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *TLSPlugin) PortPriority(port uint16) bool { return port == 443 }
func (p *TLSPlugin) Name() string                  { return GOLDENGATE }
func (p *TLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *TLSPlugin) Priority() int                 { return -1 }

// ClassicPlugin detects the Classic Architecture Manager (GGSNET) on TCP 7809.
//
// GGSNET is a proprietary binary protocol that sends no unsolicited banner and
// has no publicly documented, reliable plaintext probe signature. This variant
// therefore performs only a conservative passive read and reports edition
// "classic" solely when the peer volunteers a distinguishing GoldenGate marker.
// Absent such a marker it returns nil, avoiding false positives.
type ClassicPlugin struct{}

func (p *ClassicPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	banner, err := pluginutils.Recv(conn, timeout)
	if err != nil || len(banner) == 0 {
		return nil, nil
	}
	if !containsAny(string(banner), goldenGateMarkers) {
		return nil, nil
	}

	payload := plugins.ServiceOracleGoldenGate{
		Edition: "classic",
		CPEs:    []string{buildGoldenGateCPE("")},
	}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

func (p *ClassicPlugin) PortPriority(port uint16) bool { return port == 7809 }
func (p *ClassicPlugin) Name() string                  { return GOLDENGATE_MANAGER }
func (p *ClassicPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *ClassicPlugin) Priority() int                 { return -1 }
