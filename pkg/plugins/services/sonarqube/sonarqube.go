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

This plugin implements SonarQube fingerprinting using the HTTP REST API status endpoint.
SonarQube is a code quality and security analysis platform that exposes version information
through dedicated system status endpoints.

Detection Strategy:
  DETECTION (determines if the service is SonarQube):
    PRIMARY METHOD (GET /api/system/status): Works on all modern SonarQube versions
      - Send GET /api/system/status HTTP request
      - Validate HTTP 200 OK response
      - Parse JSON response: {"id":"...","version":"10.3.0.82913","status":"UP"}
      - Validate required fields: id, version, status (all non-empty)
      - Validate status is one of: UP, DOWN, STARTING, RESTARTING,
        DB_MIGRATION_NEEDED, DB_MIGRATION_RUNNING
      - Distinguishes SonarQube from other code quality platforms

Expected /api/system/status Response Structure:
  HTTP/1.1 200 OK
  Content-Type: application/json

  {
    "id": "unique-server-id",
    "version": "10.3.0.82913",
    "status": "UP"
  }

Version Format:
  - SonarQube versions: MAJOR.MINOR.PATCH.BUILD (e.g., "10.3.0.82913")
  - For CPE generation, strip build number: "10.3.0.82913" → "10.3.0"
  - Some versions may be 3-part only: "9.9.0" (no build number)

Version Compatibility:
  - SonarQube 8.x+: /api/system/status endpoint available
  - Earlier versions may not have this endpoint

False Positive Mitigation:
  - Require all three fields (id, version, status) to be non-empty
  - Validate status is one of the known SonarQube status values
  - Distinguish from Grafana, Jenkins, and other platforms with /api endpoints
  - JSON structure validation prevents matching generic HTTP servers
*/

package sonarqube

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	SONARQUBE           = "sonarqube"
	DefaultSonarQubePort = 9000
)

type SonarQubePlugin struct{}

func init() {
	plugins.RegisterPlugin(&SonarQubePlugin{})
}

// sonarQubeStatusResponse represents the JSON structure returned by GET /api/system/status
type sonarQubeStatusResponse struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	Status  string `json:"status"`
}

// buildSonarQubeHTTPRequest constructs an HTTP/1.1 GET request for the specified path
func buildSonarQubeHTTPRequest(path, host string) string {
	return fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: nerva/1.0\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		path, host)
}

// extractHTTPHeaders parses HTTP response and extracts headers into a map
func extractHTTPHeaders(response []byte) map[string]string {
	headers := make(map[string]string)

	// Convert to string for easier parsing
	responseStr := string(response)

	// Split into lines
	lines := strings.Split(responseStr, "\r\n")
	if len(lines) == 0 {
		return headers
	}

	// Skip status line, parse headers until blank line
	for i := 1; i < len(lines); i++ {
		line := lines[i]
		if line == "" {
			// End of headers
			break
		}

		// Parse "Key: Value" format
		parts := strings.SplitN(line, ": ", 2)
		if len(parts) == 2 {
			// Normalize header name to lowercase for case-insensitive lookup
			headerName := strings.ToLower(strings.TrimSpace(parts[0]))
			headerValue := strings.TrimSpace(parts[1])
			headers[headerName] = headerValue
		}
	}

	return headers
}

// extractHTTPBody extracts the body from an HTTP response (after \r\n\r\n separator)
func extractHTTPBody(response []byte) []byte {
	// Find the header/body separator
	bodyStart := 0
	for i := 0; i < len(response)-3; i++ {
		if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
			bodyStart = i + 4
			break
		}
	}

	// If separator found and body exists, return body
	if bodyStart > 0 && bodyStart < len(response) {
		return response[bodyStart:]
	}

	return nil
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

// detectSonarQube performs SonarQube detection using the /api/system/status endpoint
// Returns: (version, status, detected, error)
func detectSonarQube(conn net.Conn, target plugins.Target, timeout time.Duration) (string, string, bool, error) {
	// Build HTTP GET /api/system/status request
	host := fmt.Sprintf("%s:%d", target.Host, target.Address.Port())
	request := buildSonarQubeHTTPRequest("/api/system/status", host)

	// Send request and receive response
	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return "", "", false, err
	}
	if len(response) == 0 {
		return "", "", false, nil
	}

	// Parse HTTP response
	responseStr := string(response)

	// Check for HTTP 200 OK
	hasOKStatus := strings.Contains(responseStr, "HTTP/1.1 200") ||
		strings.Contains(responseStr, "HTTP/1.0 200")

	if !hasOKStatus {
		// Not a successful response
		return "", "", false, nil
	}

	// Extract JSON body
	body := extractHTTPBody(response)
	if body == nil || len(body) == 0 {
		return "", "", false, nil
	}

	// Parse JSON response
	var statusResponse sonarQubeStatusResponse
	err = json.Unmarshal(body, &statusResponse)
	if err != nil {
		// Not valid JSON or not SonarQube format
		return "", "", false, nil
	}

	// Validate SonarQube-specific JSON structure
	// All three fields must be non-empty
	if statusResponse.ID == "" || statusResponse.Version == "" || statusResponse.Status == "" {
		// Missing required fields
		return "", "", false, nil
	}

	// Validate status is one of the known SonarQube status values
	validStatuses := map[string]bool{
		"UP":                     true,
		"DOWN":                   true,
		"STARTING":               true,
		"RESTARTING":             true,
		"DB_MIGRATION_NEEDED":    true,
		"DB_MIGRATION_RUNNING":   true,
	}

	if !validStatuses[statusResponse.Status] {
		// Invalid status value
		return "", "", false, nil
	}

	// SonarQube detected! Clean version for CPE
	cleanedVersion := cleanSonarQubeVersion(statusResponse.Version)
	return cleanedVersion, statusResponse.Status, true, nil
}

func (p *SonarQubePlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Detection via /api/system/status
	version, status, detected, err := detectSonarQube(conn, target, timeout)
	if err != nil {
		return nil, err
	}
	if detected {
		// SonarQube detected
		cpe := buildSonarQubeCPE(version)
		payload := plugins.ServiceSonarQube{
			Status: status,
			CPEs:   []string{cpe},
		}
		return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
	}

	// Not detected
	return nil, nil
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
