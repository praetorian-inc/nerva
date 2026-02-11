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
SonarQube HTTP API Fingerprinting

This plugin implements SonarQube fingerprinting using the HTTP REST API endpoints.
SonarQube is a code quality and security analysis platform that exposes version information
and configuration details through dedicated system status endpoints.

Detection Strategy (3-Phase):
  Phase 1: PRIMARY DETECTION (GET /api/system/status)
    - Send GET /api/system/status HTTP request
    - Validate HTTP 200 OK response
    - Parse JSON response: {"id":"...","version":"10.3.0.82913","status":"UP"}
    - Validate required fields: id (non-empty) and status (one of valid status values)
    - NOTE: version field may be empty in newer versions (>9.9.1 removed from unauthenticated responses)
    - Distinguishes SonarQube from other code quality platforms

  Phase 2: FALLBACK/ENRICHMENT (GET /api/server/version)
    - Used when version is missing from Phase 1, or as fallback if Phase 1 fails
    - Returns plain text version string (NOT JSON): "10.3.0.82913"
    - Content-Type: text/html;charset=utf-8
    - Validates format with regex: digits and dots only

  Phase 3: ANONYMOUS ACCESS CHECK (GET /api/components/search)
    - Tests if anonymous access is enabled
    - HTTP 200 = anonymous access enabled
    - HTTP 401/403 = authentication required
    - Best-effort enrichment (does not block detection)

Expected Response Structures:

/api/system/status:
  HTTP/1.1 200 OK
  Content-Type: application/json
  {"id":"unique-server-id","version":"10.3.0.82913","status":"UP"}
  (version may be empty string in newer SonarQube versions)

/api/server/version:
  HTTP/1.1 200 OK
  Content-Type: text/html;charset=utf-8
  10.3.0.82913

/api/components/search:
  HTTP/1.1 200 OK = anonymous access enabled
  HTTP/1.1 401/403 = authentication required

Version Format:
  - SonarQube versions: MAJOR.MINOR.PATCH.BUILD (e.g., "10.3.0.82913")
  - For CPE generation, strip build number: "10.3.0.82913" → "10.3.0"
  - Some versions may be 3-part only: "9.9.0" (no build number)

Version Compatibility:
  - SonarQube 8.x+: /api/system/status endpoint available
  - SonarQube >9.9.1: version removed from unauthenticated /api/system/status responses
  - /api/server/version: Available on all modern versions

False Positive Mitigation:
  - Require id field (non-empty) in /api/system/status response
  - Validate status is one of the known SonarQube status values
  - Distinguish from Grafana, Jenkins, and other platforms with /api endpoints
  - JSON structure validation prevents matching generic HTTP servers
  - Version validation ensures plain text response contains only digits and dots
*/

package sonarqube

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
	SONARQUBE            = "sonarqube"
	DefaultSonarQubePort = 9000
)

var (
	// validStatuses contains all known SonarQube status values
	validStatuses = map[string]bool{
		"UP":                   true,
		"DOWN":                 true,
		"STARTING":             true,
		"RESTARTING":           true,
		"DB_MIGRATION_NEEDED":  true,
		"DB_MIGRATION_RUNNING": true,
	}

	// versionPattern validates version strings (digits and dots only)
	versionPattern = regexp.MustCompile(`^\d+\.\d+(\.\d+)*$`)
)

type SonarQubePlugin struct{}

func init() {
	plugins.RegisterPlugin(&SonarQubePlugin{})
}

// sonarQubeStatusResponse represents the JSON structure returned by GET /api/system/status
type sonarQubeStatusResponse struct {
	ID      string `json:"id"`
	Version string `json:"version"` // May be empty in newer versions
	Status  string `json:"status"`
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

// detectViaSystemStatus performs Phase 1 detection using /api/system/status endpoint
// Returns: (version, status, detected, error)
// NOTE: version may be empty string if newer SonarQube version (>9.9.1)
func detectViaSystemStatus(client *http.Client, baseURL string) (string, string, bool, error) {
	resp, err := doGet(client, baseURL+"/api/system/status")
	if err != nil {
		return "", "", false, err
	}
	defer resp.Body.Close()

	// Require HTTP 200
	if resp.StatusCode != 200 {
		return "", "", false, nil
	}

	// Parse JSON response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", false, err
	}

	var statusResponse sonarQubeStatusResponse
	err = json.Unmarshal(body, &statusResponse)
	if err != nil {
		// Not valid JSON or not SonarQube format
		return "", "", false, nil
	}

	// Validate SonarQube-specific JSON structure
	// id and status must be non-empty (version can be empty in newer versions)
	if statusResponse.ID == "" || statusResponse.Status == "" {
		// Missing required fields
		return "", "", false, nil
	}

	// Validate status is one of the known SonarQube status values
	if !validStatuses[statusResponse.Status] {
		// Invalid status value
		return "", "", false, nil
	}

	// SonarQube detected! Clean version for CPE (may be empty string)
	cleanedVersion := ""
	if statusResponse.Version != "" {
		cleanedVersion = cleanSonarQubeVersion(statusResponse.Version)
	}

	return cleanedVersion, statusResponse.Status, true, nil
}

// detectViaServerVersion performs Phase 2 detection/enrichment using /api/server/version endpoint
// Returns: (version, detected, error)
func detectViaServerVersion(client *http.Client, baseURL string) (string, bool, error) {
	resp, err := doGet(client, baseURL+"/api/server/version")
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	// Require HTTP 200
	if resp.StatusCode != 200 {
		return "", false, nil
	}

	// Read plain text response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", false, err
	}

	versionStr := strings.TrimSpace(string(body))

	// Validate version format (digits and dots only)
	if !versionPattern.MatchString(versionStr) {
		return "", false, nil
	}

	// Clean version for CPE
	cleanedVersion := cleanSonarQubeVersion(versionStr)
	return cleanedVersion, true, nil
}

// checkAnonymousAccess performs Phase 3 check using /api/components/search endpoint
// Returns: true if anonymous access enabled, false otherwise
func checkAnonymousAccess(client *http.Client, baseURL string) bool {
	resp, err := doGet(client, baseURL+"/api/components/search")
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	// Drain response body so connection can be reused
	io.Copy(io.Discard, resp.Body)

	// HTTP 200 = anonymous access enabled
	// HTTP 401/403 = authentication required
	return resp.StatusCode == 200
}

// cleanSonarQubeVersion removes build number from version string for CPE generation
// Examples: "10.3.0.82913" → "10.3.0", "9.9.0" → "9.9.0"
func cleanSonarQubeVersion(version string) string {
	parts := strings.Split(version, ".")
	// If 4+ parts, take first 3 (strip build number)
	if len(parts) >= 4 {
		return strings.Join(parts[:3], ".")
	}
	// Otherwise return as-is (already 3 or fewer parts)
	return version
}

// buildSonarQubeCPE generates a CPE (Common Platform Enumeration) string for SonarQube
// CPE format: cpe:2.3:a:sonarsource:sonarqube:{version}:*:*:*:*:*:*:*
func buildSonarQubeCPE(version string) string {
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:sonarsource:sonarqube:%s:*:*:*:*:*:*:*", version)
}

func (p *SonarQubePlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	// Phase 1: Primary detection via /api/system/status
	version, status, detected, err := detectViaSystemStatus(client, baseURL)
	if err != nil {
		return nil, err
	}

	// Phase 2: Fallback/enrichment via /api/server/version
	if !detected || version == "" {
		if v, ok, _ := detectViaServerVersion(client, baseURL); ok {
			if !detected {
				detected = true
				// If system/status didn't work, assume status is UP
				status = "UP"
			}
			if version == "" {
				version = v
			}
		}
	}

	if !detected {
		return nil, nil
	}

	// Phase 3: Check anonymous access (best-effort enrichment)
	anonAccess := checkAnonymousAccess(client, baseURL)

	cpe := buildSonarQubeCPE(version)
	payload := plugins.ServiceSonarQube{
		Status:          status,
		AnonymousAccess: anonAccess,
		CPEs:            []string{cpe},
	}
	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *SonarQubePlugin) PortPriority(port uint16) bool {
	return port == DefaultSonarQubePort
}

func (p *SonarQubePlugin) Name() string {
	return SONARQUBE
}

func (p *SonarQubePlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *SonarQubePlugin) Priority() int {
	return 100
}
