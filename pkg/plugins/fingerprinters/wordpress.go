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
Package fingerprinters provides HTTP fingerprinting for WordPress.

# Detection Strategy

WordPress is the world's most popular CMS. Exposed instances represent a security
concern due to plugin vulnerabilities, outdated core versions, and exposed admin
interfaces.

Detection uses a multi-signal approach:

Signal 1 - Link header (most reliable passive signal):
  - WordPress injects a Link header containing "api.w.org" on every page
  - Example: Link: <https://example.com/wp-json/>; rel="https://api.w.org/"
  - Very distinctive — specific to WordPress REST API

Signal 2 - Body markers (active probe and general pages):
  - Any page may contain /wp-content/ or /wp-includes/ paths
  - These are standard WordPress directory structures

Signal 3 - REST API JSON response:
  - /wp-json/wp/v2/ returns JSON with namespaces array
  - Namespace "wp/v2" indicates WordPress REST API

Match():
  - If Link header contains "api.w.org" → return true (definitive WordPress signal)
  - Otherwise, accept any 200-499 status (body will be checked in Fingerprint())

Fingerprint():
  1. Check Link header for api.w.org
  2. Check body for wp-content/ or wp-includes/ strings
  3. Try JSON parse for probe response (namespaces containing "wp/v2")
  4. If none match → return nil, nil
  5. Extract version from meta generator regex
  6. Extract plugin slugs (deduplicated)
  7. Extract theme slugs (deduplicated)
  8. Try JSON parse for siteName from probe response
  9. Build metadata with plugins, themes, siteName (omit empty fields)
  10. Validate version before including in CPE

ProbeEndpoint(): /wp-json/wp/v2/ — the WordPress REST API namespace endpoint

Version extraction:
  - From meta generator tag: <meta name="generator" content="WordPress 6.4.2">
  - Version regex: ^\d+\.\d+(\.\d+)?$ for CPE injection prevention

CPE: cpe:2.3:a:wordpress:wordpress:${version}:*:*:*:*:*:*:*

Metadata:
  - plugins: deduplicated slice of plugin slugs found in body
  - themes: deduplicated slice of theme slugs found in body
  - siteName: site name from REST API response (if available)

# Example Usage

	fp := &WordPressFingerprinter{}
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
)

// WordPressFingerprinter detects WordPress instances via Link header, body markers,
// and REST API probe.
type WordPressFingerprinter struct{}

// wpVersionRegex validates WordPress version format to prevent CPE injection.
// Accepts: 6.4.2, 6.4, 5.0
var wpVersionRegex = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)

// wpMetaGeneratorRegex extracts WordPress version from meta generator tag.
// Example: <meta name="generator" content="WordPress 6.4.2">
var wpMetaGeneratorRegex = regexp.MustCompile(`(?i)<meta\s+name=["']generator["']\s+content=["']WordPress\s+([\d.]+)["']`)

// wpPluginRegex extracts plugin slugs from wp-content/plugins/ paths.
var wpPluginRegex = regexp.MustCompile(`/wp-content/plugins/([a-zA-Z0-9_-]+)/`)

// wpThemeRegex extracts theme slugs from wp-content/themes/ paths.
var wpThemeRegex = regexp.MustCompile(`/wp-content/themes/([a-zA-Z0-9_-]+)/`)

// wpRestResponse represents the JSON structure from /wp-json/wp/v2/
type wpRestResponse struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Namespaces  []string `json:"namespaces"`
}

func init() {
	Register(&WordPressFingerprinter{})
}

func (f *WordPressFingerprinter) Name() string {
	return "wordpress"
}

func (f *WordPressFingerprinter) ProbeEndpoint() string {
	return "/wp-json/wp/v2/"
}

func (f *WordPressFingerprinter) Match(resp *http.Response) bool {
	// Definitive WordPress signal: Link header containing api.w.org
	if strings.Contains(resp.Header.Get("Link"), "api.w.org") {
		return true
	}

	// Accept 200-499 for body-based detection (reject 5xx server errors)
	return resp.StatusCode >= 200 && resp.StatusCode < 500
}

func (f *WordPressFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	bodyStr := string(body)

	// Determine if any WordPress signal is present
	hasLinkHeader := strings.Contains(resp.Header.Get("Link"), "api.w.org")
	hasBodyMarkers := strings.Contains(bodyStr, "wp-content/") || strings.Contains(bodyStr, "wp-includes/")

	// Try JSON parse for REST API namespace confirmation
	hasRestAPI := false
	var restResp wpRestResponse
	if err := json.Unmarshal(body, &restResp); err == nil {
		for _, ns := range restResp.Namespaces {
			if ns == "wp/v2" {
				hasRestAPI = true
				break
			}
		}
	}

	if !hasLinkHeader && !hasBodyMarkers && !hasRestAPI {
		return nil, nil
	}

	// Extract version from meta generator tag
	version := ""
	if matches := wpMetaGeneratorRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
		candidate := matches[1]
		if wpVersionRegex.MatchString(candidate) {
			version = candidate
		}
	}

	// Extract plugin slugs (deduplicated)
	plugins := deduplicateMatches(wpPluginRegex.FindAllStringSubmatch(bodyStr, -1))

	// Extract theme slugs (deduplicated)
	themes := deduplicateMatches(wpThemeRegex.FindAllStringSubmatch(bodyStr, -1))

	// Try to extract site name from REST API response
	siteName := ""
	if hasRestAPI && restResp.Name != "" {
		siteName = restResp.Name
	}

	// Build metadata (omit empty fields)
	metadata := map[string]any{}
	if len(plugins) > 0 {
		metadata["plugins"] = plugins
	}
	if len(themes) > 0 {
		metadata["themes"] = themes
	}
	if siteName != "" {
		metadata["site_name"] = siteName
	}

	return &FingerprintResult{
		Technology: "wordpress",
		Version:    version,
		CPEs:       []string{buildWordPressCPE(version)},
		Metadata:   metadata,
	}, nil
}

// deduplicateMatches returns unique capture group values (index 1) from regex matches.
func deduplicateMatches(matches [][]string) []string {
	seen := make(map[string]struct{})
	var result []string
	for _, m := range matches {
		if len(m) > 1 {
			slug := m[1]
			if _, exists := seen[slug]; !exists {
				seen[slug] = struct{}{}
				result = append(result, slug)
			}
		}
	}
	return result
}

func buildWordPressCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:wordpress:wordpress:%s:*:*:*:*:*:*:*", version)
}
