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

// gitlabVersionRegex validates GitLab version format and extracts semver, optional qualifier, and edition.
// Valid formats: "17.0.0", "17.0.0-ee", "16.8.1-ce", "17.0.0-pre", "17.0.0-rc1-ee"
var gitlabVersionRegex = regexp.MustCompile(`^(\d+\.\d+\.\d+)(?:-(pre|rc\d+))?(?:-(ee|ce))?$`)

// gitlabSafeVersionRegex validates that the entire version string only contains safe characters.
// Prevents CPE injection via colons, semicolons, parentheses, etc.
var gitlabSafeVersionRegex = regexp.MustCompile(`^[0-9a-zA-Z.\-]+$`)

// gitlabGeneratorRegex extracts edition and version from generator meta tag with name before content.
// Format: <meta name="generator" content="GitLab Community Edition 17.0.0">
var gitlabGeneratorRegex = regexp.MustCompile(`(?i)<meta\s[^>]*name=["']generator["'][^>]*content=["']GitLab\s+(Community|Enterprise)\s+Edition\s+([0-9]+\.[0-9]+\.[0-9]+)["']`)

// gitlabGeneratorRegexAlt extracts edition and version from generator meta tag with content before name.
// Format: <meta content="GitLab Community Edition 17.0.0" name="generator">
var gitlabGeneratorRegexAlt = regexp.MustCompile(`(?i)<meta\s[^>]*content=["']GitLab\s+(Community|Enterprise)\s+Edition\s+([0-9]+\.[0-9]+\.[0-9]+)["'][^>]*name=["']generator["']`)

// gitlabOGSiteNameRegex matches <meta> with og:site_name property and "GitLab" content value.
// Handles both attribute orders and anchors content value to prevent partial matches.
var gitlabOGSiteNameRegex = regexp.MustCompile(`(?i)<meta\s+[^>]*?(?:content=["']GitLab["'][^>]*?property=["']og:site_name["']|property=["']og:site_name["'][^>]*?content=["']GitLab["'])`)

func (f *GitLabFingerprinter) Name() string {
	return "gitlab"
}

// ProbeEndpoint returns the endpoint used for active GitLab detection.
// The /api/v4/version endpoint returns version info (may require authentication).
func (f *GitLabFingerprinter) ProbeEndpoint() string {
	return "/api/v4/version"
}

// Match returns true if the response might be from GitLab.
// This is deliberately broad: HTML is needed because passive detection parses
// meta tags from the root page body, and JSON is needed because the active
// /api/v4/version probe returns JSON. Fingerprint() performs the actual
// GitLab-specific checks and returns nil for non-GitLab responses.
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

	// Check HTML body for og:site_name="GitLab" meta tag (both attribute orders)
	if gitlabOGSiteNameRegex.MatchString(bodyStr) {
		detected = true
	}

	// Try extracting version and edition from HTML generator meta tag.
	// Format: <meta name="generator" content="GitLab Community Edition 17.0.0">
	//      or <meta name="generator" content="GitLab Enterprise Edition 17.0.0">
	if strings.Contains(bodyStr, `name="generator"`) || strings.Contains(bodyStr, `name='generator'`) {
		version, edition = extractGitLabMetaGenerator(bodyStr)
		if version != "" || edition != "" {
			detected = true
		}
	}

	// Try parsing body as /api/v4/version JSON response.
	// Require both version and revision — GitLab always returns both fields,
	// and this prevents false positives from generic JSON APIs with a "version" field.
	apiVersion, apiEdition, apiRevision, apiQualifier := parseGitLabAPIVersion(body)
	if apiVersion != "" && apiRevision != "" {
		detected = true
		// API response takes precedence over HTML meta for version
		version = apiVersion
		if apiEdition != "" {
			edition = apiEdition
		}
		revision = apiRevision
		if apiQualifier != "" {
			metadata["qualifier"] = apiQualifier
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
// Handles both double-quoted and single-quoted attribute values, and both attribute orderings.
func extractGitLabMetaGenerator(body string) (version, edition string) {
	matches := gitlabGeneratorRegex.FindStringSubmatch(body)
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
	matches = gitlabGeneratorRegexAlt.FindStringSubmatch(body)
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
// Returns version, edition, revision, and qualifier if successful.
func parseGitLabAPIVersion(body []byte) (version, edition, revision, qualifier string) {
	var data gitlabVersionResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return "", "", "", ""
	}
	if data.Version == "" {
		return "", "", "", ""
	}

	raw := data.Version

	// Validate safe characters first
	if !gitlabSafeVersionRegex.MatchString(raw) {
		return "", "", "", ""
	}

	// Extract X.Y.Z, optional qualifier (pre/rcN), and optional edition (ee/ce)
	matches := gitlabVersionRegex.FindStringSubmatch(raw)
	if len(matches) < 2 {
		return "", "", "", ""
	}

	version = matches[1]
	if len(matches) >= 3 && matches[2] != "" {
		qualifier = matches[2]
	}
	if len(matches) >= 4 && matches[3] != "" {
		edition = matches[3]
	}

	// Validate revision against safe-character set to prevent injection
	if data.Revision != "" && gitlabSafeVersionRegex.MatchString(data.Revision) {
		revision = data.Revision
	}
	return version, edition, revision, qualifier
}

// buildGitLabCPE generates a CPE 2.3 string for GitLab.
// Format: cpe:2.3:a:gitlab:gitlab:{version}:*:*:*:{edition}:*:*:*
// edition is "ce", "ee", or "*" when unknown. Qualifiers (pre, rcN) are excluded from CPE.
func buildGitLabCPE(version, edition string) string {
	if version == "" {
		version = "*"
	}
	if edition == "" {
		edition = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:gitlab:gitlab:%s:*:*:*:%s:*:*:*", version, edition)
}
