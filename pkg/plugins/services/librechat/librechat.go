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
LibreChat HTTP Fingerprinting

This plugin implements LibreChat fingerprinting through multi-phase detection of
version information from HTML, JavaScript bundles, and API endpoints.

LibreChat is an open-source AI chat platform (Vite-built SPA) that exposes version
information through JavaScript bundles and API endpoints.

Detection Strategy (3-Phase):

  Phase 1: PRIMARY DETECTION (GET / → Parse HTML → Download JS bundle → Extract VERSION)
    - Send GET / HTTP request
    - Parse HTML response to find Vite-hashed JS bundle URL in <script> tags
    - Download the identified JS bundle file
    - Extract VERSION using regex: e\.VERSION="(v[\d.]+)" or similar patterns
    - Also extract CONFIG_VERSION: e\.CONFIG_VERSION="([\d.]+)"
    - VERSION format: "v0.8.2" (with leading v)
    - Distinguishes LibreChat from other chat platforms

  Phase 2: FALLBACK/ENRICHMENT (GET /api/config)
    - Used when Phase 1 fails or for additional metadata
    - Returns JSON with feature flags: {"registration":false,"socialLoginEnabled":true,...}
    - If returns valid JSON with LibreChat-specific fields, confirms LibreChat
    - Feature flags can map to version ranges for rough version estimation
    - Does not provide exact version but confirms product identity

  Phase 3: ANONYMOUS ACCESS CHECK (GET /health)
    - Tests if /health endpoint exists (available in >= v0.7.6)
    - HTTP 200 = endpoint exists, adds confidence to detection
    - HTTP 404 = older version or different product
    - Best-effort enrichment (does not block detection)

Expected Response Structures:

GET /:
  HTTP/1.1 200 OK
  Content-Type: text/html
  <script type="module" crossorigin src="/assets/index-abc123def.js"></script>

GET /assets/index-abc123def.js:
  HTTP/1.1 200 OK
  Content-Type: application/javascript
  ...e.VERSION="v0.8.2"...e.CONFIG_VERSION="1.0.5"...

GET /api/config:
  HTTP/1.1 200 OK
  Content-Type: application/json
  {"registration":false,"socialLoginEnabled":true,"emailLoginEnabled":true,...}

GET /health:
  HTTP/1.1 200 OK
  OK

Version Format:
  - LibreChat versions: "v0.8.2" (leading v, MAJOR.MINOR.PATCH)
  - For CPE generation, strip leading v: "v0.8.2" → "0.8.2"
  - CONFIG_VERSION is separate metadata (e.g., "1.0.5"), not the app version

Version Compatibility:
  - LibreChat >= v0.7.6: /health endpoint available
  - All versions: VERSION in JavaScript bundle (primary detection method)
  - /api/config: Available on all modern versions

False Positive Mitigation:
  - Require VERSION pattern match in JS bundle (unique to LibreChat)
  - Validate /api/config returns JSON with LibreChat-specific fields
  - JS bundle extraction prevents matching generic React/Vite apps
  - Version validation ensures extracted string matches expected format

Default Ports:
  - 3080 (default LibreChat development port)
  - 80 and 443 are common when deployed behind reverse proxies but are NOT PortPriority

CPE Format:
  cpe:2.3:a:librechat:librechat:{version}:*:*:*:*:*:*:*
  Example: cpe:2.3:a:librechat:librechat:0.8.2:*:*:*:*:*:*:*
*/

package librechat

import (
	"context"
	"encoding/json"
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
	LIBRECHAT            = "librechat"
	DefaultLibreChatPort = 3080
)

var (
	// versionPattern extracts VERSION from JS bundle: e.VERSION="v0.8.2"
	versionPattern = regexp.MustCompile(`VERSION="(v[\d.]+)"`)
	// configVersionPattern extracts CONFIG_VERSION from JS bundle
	configVersionPattern = regexp.MustCompile(`CONFIG_VERSION="([\d.]+)"`)
	// scriptPattern finds JS bundle URLs in HTML: /assets/index-{hash}.js
	scriptPattern = regexp.MustCompile(`<script[^>]+src="(/assets/[^"]+\.js)"`)
)

type LibreChatPlugin struct{}

func init() {
	plugins.RegisterPlugin(&LibreChatPlugin{})
	plugins.RegisterPlugin(&LibreChatTLSPlugin{})
}

// createHTTPClient creates an http.Client that wraps the provided net.Conn
// This enables multiple HTTP requests over the same connection via HTTP/1.1 keep-alive
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

// doGet performs a GET request with User-Agent header
func doGet(client *http.Client, url string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nerva/1.0")
	return client.Do(req)
}

// detectViaJSBundle performs Phase 1 detection: GET / → parse HTML → download JS → extract VERSION
// Returns: (version, configVersion, detected, error)
func detectViaJSBundle(client *http.Client, baseURL string) (string, string, bool, error) {
	// Step 1: Fetch root HTML page
	resp, err := doGet(client, baseURL+"/")
	if err != nil {
		return "", "", false, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Require HTTP 200
	if resp.StatusCode != 200 {
		return "", "", false, nil
	}

	// Read HTML response
	maxResponseSize := int64(10 * 1024 * 1024) // 10MB limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return "", "", false, err
	}

	htmlContent := string(body)

	// Step 2: Parse HTML to find JS bundle URL
	scriptMatches := scriptPattern.FindStringSubmatch(htmlContent)
	if len(scriptMatches) < 2 {
		// No script tag found, not LibreChat or different structure
		return "", "", false, nil
	}

	scriptURL := scriptMatches[1]

	// Step 3: Download JS bundle
	resp2, err := doGet(client, baseURL+scriptURL)
	if err != nil {
		return "", "", false, err
	}
	defer func() { _ = resp2.Body.Close() }()

	if resp2.StatusCode != 200 {
		return "", "", false, nil
	}

	// Read JS bundle
	jsBody, err := io.ReadAll(io.LimitReader(resp2.Body, maxResponseSize))
	if err != nil {
		return "", "", false, err
	}

	jsContent := string(jsBody)

	// Step 4: Extract VERSION from JS bundle
	versionMatches := versionPattern.FindStringSubmatch(jsContent)
	if len(versionMatches) < 2 {
		// No VERSION found, not LibreChat
		return "", "", false, nil
	}

	version := versionMatches[1]

	// Extract CONFIG_VERSION (optional)
	configVersion := ""
	configMatches := configVersionPattern.FindStringSubmatch(jsContent)
	if len(configMatches) >= 2 {
		configVersion = configMatches[1]
	}

	// LibreChat detected! Clean version for CPE (strip leading v)
	cleanedVersion := strings.TrimPrefix(version, "v")

	return cleanedVersion, configVersion, true, nil
}

// detectViaAPIConfig performs Phase 2 detection/enrichment using /api/config endpoint
// Returns: (detected, error)
func detectViaAPIConfig(client *http.Client, baseURL string) (bool, error) {
	resp, err := doGet(client, baseURL+"/api/config")
	if err != nil {
		return false, err
	}
	defer func() { _ = resp.Body.Close() }()

	// Require HTTP 200
	if resp.StatusCode != 200 {
		return false, nil
	}

	// Read JSON response
	maxResponseSize := int64(10 * 1024 * 1024) // 10MB limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return false, err
	}

	// Parse JSON
	var config map[string]interface{}
	err = json.Unmarshal(body, &config)
	if err != nil {
		// Not valid JSON
		return false, nil
	}

	// Check for LibreChat-specific fields in /api/config response.
	// Generic fields like "registration" or "socialLoginEnabled" appear in many apps,
	// so we require fields that are distinctive to LibreChat's config schema.
	libreChatFields := []string{
		"endpoints",
		"modelSpecs",
		"checkBalance",
		"interfaceConfig",
	}

	matchCount := 0
	for _, field := range libreChatFields {
		if _, ok := config[field]; ok {
			matchCount++
		}
	}

	// Require at least 2 LibreChat-specific fields to reduce false positives
	return matchCount >= 2, nil
}

// checkHealthEndpoint performs Phase 3 check using /health endpoint
// Returns: true if endpoint exists (HTTP 200), false otherwise
func checkHealthEndpoint(client *http.Client, baseURL string) bool {
	resp, err := doGet(client, baseURL+"/health")
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()

	// Drain response body so connection can be reused
	_, _ = io.Copy(io.Discard, resp.Body)

	// HTTP 200 = /health endpoint exists
	return resp.StatusCode == 200
}

// buildLibreChatCPE generates a CPE (Common Platform Enumeration) string for LibreChat
// CPE format: cpe:2.3:a:librechat:librechat:{version}:*:*:*:*:*:*:*
func buildLibreChatCPE(version string) string {
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:librechat:librechat:%s:*:*:*:*:*:*:*", version)
}

func (p *LibreChatPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	// Phase 1: Primary detection via JS bundle VERSION extraction
	// Errors here (e.g. connection reset) are non-fatal; fall through to Phase 2
	version, configVersion, detected, err := detectViaJSBundle(client, baseURL)
	if err != nil {
		detected = false
	}

	// Phase 2: Fallback/enrichment via /api/config
	if !detected {
		if apiConfigDetected, _ := detectViaAPIConfig(client, baseURL); apiConfigDetected {
			detected = true
			// No exact version from /api/config, but product confirmed
			version = ""
			configVersion = ""
		}
	}

	if !detected {
		return nil, nil
	}

	// Phase 3: Check /health endpoint (best-effort enrichment)
	hasHealth := checkHealthEndpoint(client, baseURL)

	cpe := buildLibreChatCPE(version)
	payload := plugins.ServiceLibreChat{
		ConfigVersion: configVersion,
		HasHealth:     hasHealth,
		CPEs:          []string{cpe},
	}
	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *LibreChatPlugin) PortPriority(port uint16) bool {
	return port == DefaultLibreChatPort
}

func (p *LibreChatPlugin) Name() string {
	return LIBRECHAT
}

func (p *LibreChatPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *LibreChatPlugin) Priority() int {
	return 100
}

// LibreChatTLSPlugin detects LibreChat over TLS connections
type LibreChatTLSPlugin struct{}

func (p *LibreChatTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
    client := createHTTPClient(conn, timeout)
    baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

    // Phase 1: Primary detection via JS bundle VERSION extraction
    // Errors here (e.g. connection reset) are non-fatal; fall through to Phase 2
    version, configVersion, detected, err := detectViaJSBundle(client, baseURL)
    if err != nil {
            detected = false
    }

    // Phase 2: Fallback/enrichment via /api/config
    if !detected {
            if apiConfigDetected, _ := detectViaAPIConfig(client, baseURL); apiConfigDetected {
                    detected = true
                    // No exact version from /api/config, but product confirmed
                    version = ""
                    configVersion = ""
            }
    }

    if !detected {
            return nil, nil
    }

    hasHealth := checkHealthEndpoint(client, baseURL)

    cpe := buildLibreChatCPE(version)
    payload := plugins.ServiceLibreChat{
            ConfigVersion: configVersion,
            HasHealth:     hasHealth,
            CPEs:          []string{cpe},
    }
    return plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS), nil
}

func (p *LibreChatTLSPlugin) PortPriority(port uint16) bool { return port == 443 }
func (p *LibreChatTLSPlugin) Name() string                  { return LIBRECHAT }
func (p *LibreChatTLSPlugin) Type() plugins.Protocol         { return plugins.TCPTLS }
func (p *LibreChatTLSPlugin) Priority() int                  { return 100 }