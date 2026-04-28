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
Package fingerprinters provides HTTP fingerprinting for GitLab DevOps Platform.

# Detection Strategy

GitLab is an open-source DevOps platform with ~49K+ instances exposed on Shodan.
Exposed instances represent a significant security concern due to:
  - CVE-2024-45409: SAML authentication bypass (critical)
  - CVE-2021-22205: Unauthenticated remote code execution via image parsing
  - Source code and intellectual property exposure
  - CI/CD pipeline compromise allowing supply chain attacks

Detection uses a two-pronged approach:
 1. Passive (root response): HTML meta tag og:site_name="GitLab" and X-GitLab-* response headers
 2. Active (probe /api/v4/version): JSON endpoint returning version/revision (may require auth)

# HTML Detection

GitLab injects identifying markers in the root HTML response:

	<meta content="GitLab" property="og:site_name">
	<meta name="generator" content="GitLab Community Edition 17.0.0">

The generator meta tag provides edition (CE/EE) and version information.

# API Response Format

The /api/v4/version endpoint returns JSON (requires authentication on most instances):

	{
	  "version": "17.0.0-ee",
	  "revision": "abc123def456"
	}

Version suffix "-ee" indicates Enterprise Edition, "-ce" indicates Community Edition.

# Port Configuration

GitLab typically runs on:
  - 80:   HTTP
  - 443:  HTTPS in production
  - 8080: Alternative HTTP port
  - 8443: Alternative HTTPS port

# Example Usage

	fp := &GitLabFingerprinter{}
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
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// GitLabFingerprinter detects GitLab instances via HTML meta tags, X-GitLab-* headers,
// and the /api/v4/version JSON endpoint.
type GitLabFingerprinter struct{}

func init() {
	Register(&GitLabFingerprinter{})
}

// gitlabVersionResponse represents the JSON response from /api/v4/version
type gitlabVersionResponse struct {
	Version  string `json:"version"`
	Revision string `json:"revision"`
}

// gitlabVersionRegex validates GitLab version format and extracts semver + optional edition suffix.
// Valid formats: "17.0.0", "17.0.0-ee", "16.8.1-ce", "17.0.0-pre"
var gitlabVersionRegex = regexp.MustCompile(`^(\d+\.\d+\.\d+)(?:-(ee|ce|pre))?$`)

// gitlabSafeVersionRegex validates that the entire version string only contains safe characters.
// Prevents CPE injection via colons, semicolons, parentheses, etc.
var gitlabSafeVersionRegex = regexp.MustCompile(`^[0-9a-zA-Z.\-]+$`)

func (f *GitLabFingerprinter) Name() string {
	return "gitlab"
}

// ProbeEndpoint returns the endpoint used for active GitLab detection.
// The /api/v4/version endpoint returns version info (may require authentication).
func (f *GitLabFingerprinter) ProbeEndpoint() string {
	return "/api/v4/version"
}

// Match returns true if the response might be from GitLab.
// Accepts HTML, JSON, and responses with X-GitLab-* headers.
func (f *GitLabFingerprinter) Match(resp *http.Response) bool {
	// Check for X-GitLab-* headers (case-insensitive header key matching)
	for key := range resp.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-gitlab") {
			return true
		}
	}
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/json")
}

// Fingerprint performs GitLab detection by inspecting headers, HTML meta tags,
// and parsing the /api/v4/version JSON response.
func (f *GitLabFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	detected := false
	version := ""
	edition := ""
	revision := ""
	metadata := make(map[string]any)

	// Check for X-GitLab-* headers
	for key := range resp.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-gitlab") {
			detected = true
			break
		}
	}

	bodyStr := string(body)

	// Check HTML body for og:site_name="GitLab" meta tag
	if strings.Contains(bodyStr, `<meta content="GitLab"`) {
		detected = true
	}

	// Try extracting version and edition from HTML generator meta tag.
	// Format: <meta name="generator" content="GitLab Community Edition 17.0.0">
	//      or <meta name="generator" content="GitLab Enterprise Edition 17.0.0">
	if strings.Contains(bodyStr, `name="generator"`) || strings.Contains(bodyStr, `name='generator'`) {
		version, edition = extractGitLabMetaGenerator(bodyStr)
	}

	// Try parsing body as /api/v4/version JSON response
	var apiVersion, apiEdition, apiRevision string
	apiVersion, apiEdition, apiRevision = parseGitLabAPIVersion(body)
	if apiVersion != "" {
		detected = true
		// API response takes precedence over HTML meta for version
		version = apiVersion
		if apiEdition != "" {
			edition = apiEdition
		}
		if apiRevision != "" {
			revision = apiRevision
		}
	}

	if !detected {
		return nil, nil
	}

	// Populate metadata
	if edition != "" {
		metadata["edition"] = edition
	}
	if revision != "" {
		metadata["revision"] = revision
	}
	if version != "" {
		metadata["raw_version"] = version
	}

	return &FingerprintResult{
		Technology: "gitlab",
		Version:    version,
		CPEs:       []string{buildGitLabCPE(version, edition)},
		Metadata:   metadata,
		Severity:   plugins.SeverityHigh,
	}, nil
}

// extractGitLabMetaGenerator parses the HTML generator meta tag to extract version and edition.
// Handles both double-quoted and single-quoted attribute values.
func extractGitLabMetaGenerator(body string) (version, edition string) {
	// Match both double-quote and single-quote variants
	// Pattern: content="GitLab Community Edition 17.0.0" or content='GitLab Community Edition 17.0.0'
	generatorRegex := regexp.MustCompile(`(?i)<meta\s[^>]*name=["']generator["'][^>]*content=["']GitLab\s+(Community|Enterprise)\s+Edition\s+([0-9]+\.[0-9]+\.[0-9]+)["']`)
	matches := generatorRegex.FindStringSubmatch(body)
	if len(matches) >= 3 {
		editionWord := strings.ToLower(matches[1])
		rawVersion := matches[2]
		switch editionWord {
		case "community":
			edition = "ce"
		case "enterprise":
			edition = "ee"
		}
		// Validate version characters
		if gitlabSafeVersionRegex.MatchString(rawVersion) {
			version = rawVersion
		}
		return version, edition
	}

	// Also try reversed attribute order: content=... name=...
	generatorRegexAlt := regexp.MustCompile(`(?i)<meta\s[^>]*content=["']GitLab\s+(Community|Enterprise)\s+Edition\s+([0-9]+\.[0-9]+\.[0-9]+)["'][^>]*name=["']generator["']`)
	matches = generatorRegexAlt.FindStringSubmatch(body)
	if len(matches) >= 3 {
		editionWord := strings.ToLower(matches[1])
		rawVersion := matches[2]
		switch editionWord {
		case "community":
			edition = "ce"
		case "enterprise":
			edition = "ee"
		}
		if gitlabSafeVersionRegex.MatchString(rawVersion) {
			version = rawVersion
		}
	}
	return version, edition
}

// parseGitLabAPIVersion attempts to parse body as a /api/v4/version JSON response.
// Returns version, edition, and revision if successful.
func parseGitLabAPIVersion(body []byte) (version, edition, revision string) {
	var data gitlabVersionResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return "", "", ""
	}
	if data.Version == "" {
		return "", "", ""
	}

	raw := data.Version

	// Validate safe characters first
	if !gitlabSafeVersionRegex.MatchString(raw) {
		return "", "", ""
	}

	// Extract X.Y.Z and optional edition suffix
	matches := gitlabVersionRegex.FindStringSubmatch(raw)
	if len(matches) < 2 {
		return "", "", ""
	}

	version = matches[1]
	if len(matches) >= 3 && matches[2] != "" {
		edition = matches[2]
	}

	revision = data.Revision
	return version, edition, revision
}

// buildGitLabCPE generates a CPE 2.3 string for GitLab.
// Format: cpe:2.3:a:gitlab:gitlab:{version}:*:*:*:{edition}:*:*:*
// edition is "ce", "ee", or "*" when unknown.
func buildGitLabCPE(version, edition string) string {
	if version == "" {
		version = "*"
	}
	if edition == "" {
		edition = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:gitlab:gitlab:%s:*:*:*:%s:*:*:*", version, edition)
}
