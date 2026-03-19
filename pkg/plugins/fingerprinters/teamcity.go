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
Package fingerprinters provides HTTP fingerprinting for JetBrains TeamCity.

# Detection Strategy

JetBrains TeamCity is a CI/CD build management server. Exposed instances
represent a security concern due to:
  - Build configuration access with potentially sensitive environment variables
  - Source code repository connection credentials
  - Deployment pipeline secrets and API tokens
  - Build agent access allowing code execution

Detection uses a two-pronged approach:
 1. Passive: Check for TeamCity-specific response headers (TeamCity-Node-Id, X-TC-CSRF-Token)
 2. Active: Query /app/rest/server endpoint (may require authentication)

# API Response Format

The /app/rest/server endpoint returns JSON (with Accept: application/json):

	{
	  "version": "2023.11.4 (build 147571)",
	  "versionMajor": 2023,
	  "versionMinor": 11,
	  "buildNumber": "147571",
	  "buildDate": "20240301T000000+0000",
	  "internalId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
	  "webUrl": "https://teamcity.example.com"
	}

Or XML (default format):

	<server version="2023.11.4 (build 147571)" buildNumber="147571"
	        internalId="a1b2c3d4-e5f6-7890-abcd-ef1234567890"
	        webUrl="https://teamcity.example.com"/>

# Port Configuration

TeamCity typically runs on:
  - 8111: Default TeamCity HTTP port
  - 443:  HTTPS in production
  - 8443: Alternative HTTPS port

# Example Usage

	fp := &TeamCityFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s\n", result.Technology, result.Version)
		}
	}
*/
package fingerprinters

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// TeamCityFingerprinter detects JetBrains TeamCity instances via /app/rest/server endpoint
type TeamCityFingerprinter struct{}

// teamcityServerResponse represents the JSON structure from /app/rest/server
type teamcityServerResponse struct {
	Version      string `json:"version"`
	VersionMajor int    `json:"versionMajor"`
	VersionMinor int    `json:"versionMinor"`
	BuildNumber  string `json:"buildNumber"`
	BuildDate    string `json:"buildDate"`
	InternalID   string `json:"internalId"`
	WebURL       string `json:"webUrl"`
}

// teamcityServerXML represents the XML structure from /app/rest/server
// Used as fallback when JSON parsing fails (e.g., Accept header mismatch)
type teamcityServerXML struct {
	XMLName     xml.Name `xml:"server"`
	Version     string   `xml:"version,attr"`
	BuildNumber string   `xml:"buildNumber,attr"`
	InternalID  string   `xml:"internalId,attr"`
	WebURL      string   `xml:"webUrl,attr"`
}

// teamcityVersionRegex validates TeamCity version format
// Accepts: 2023.11.4, 2023.11, 2024.1 (year.minor or year.minor.patch)
var teamcityVersionRegex = regexp.MustCompile(`^\d{4}\.\d{1,2}(\.\d+)?$`)

func init() {
	Register(&TeamCityFingerprinter{})
}

func (f *TeamCityFingerprinter) Name() string {
	return "teamcity"
}

func (f *TeamCityFingerprinter) ProbeEndpoint() string {
	return "/app/rest/server"
}

func (f *TeamCityFingerprinter) Match(resp *http.Response) bool {
	// TeamCity-Node-Id header is present on ALL TeamCity HTTP responses
	if resp.Header.Get("TeamCity-Node-Id") != "" {
		return true
	}
	// X-TC-CSRF-Token header is present when CSRF protection is enabled
	return resp.Header.Get("X-TC-CSRF-Token") != ""
}

func (f *TeamCityFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	metadata := make(map[string]any)
	detected := false

	// Extract nodeId from response header (present on all TeamCity responses)
	if nodeId := resp.Header.Get("TeamCity-Node-Id"); nodeId != "" {
		metadata["node_id"] = nodeId
		detected = true
	}

	// Phase 1: Try JSON parsing (primary)
	version, buildNumber, internalID := parseTeamCityJSON(body)

	// Phase 2: Fall back to XML parsing if JSON failed
	if version == "" {
		version, buildNumber, internalID = parseTeamCityXML(body)
	}

	// Clean and validate version if extracted
	if version != "" {
		version = cleanTeamCityVersion(version)
		if !teamcityVersionRegex.MatchString(version) {
			version = "" // Invalid format, discard but don't abort detection
		}
	}

	// Must have header-based detection or a valid version
	if !detected && version == "" {
		return nil, nil
	}

	// Enrich metadata
	if buildNumber != "" {
		metadata["build_number"] = buildNumber
	}
	if internalID != "" {
		metadata["internal_id"] = internalID
	}

	return &FingerprintResult{
		Technology: "teamcity",
		Version:    version,
		CPEs:       []string{buildTeamCityCPE(version)},
		Metadata:   metadata,
	}, nil
}

// cleanTeamCityVersion strips the " (build XXXXX)" suffix from TeamCity version strings
func cleanTeamCityVersion(version string) string {
	if idx := strings.Index(version, " (build "); idx > 0 {
		return version[:idx]
	}
	return version
}

// parseTeamCityJSON attempts to parse body as TeamCity JSON server response
func parseTeamCityJSON(body []byte) (version, buildNumber, internalID string) {
	var server teamcityServerResponse
	if err := json.Unmarshal(body, &server); err != nil {
		return "", "", ""
	}
	if server.Version == "" {
		return "", "", ""
	}
	return server.Version, server.BuildNumber, server.InternalID
}

// parseTeamCityXML attempts to parse body as TeamCity XML server response
func parseTeamCityXML(body []byte) (version, buildNumber, internalID string) {
	var server teamcityServerXML
	if err := xml.Unmarshal(body, &server); err != nil {
		return "", "", ""
	}
	if server.Version == "" {
		return "", "", ""
	}
	return server.Version, server.BuildNumber, server.InternalID
}

func buildTeamCityCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:jetbrains:teamcity:%s:*:*:*:*:*:*:*", version)
}
