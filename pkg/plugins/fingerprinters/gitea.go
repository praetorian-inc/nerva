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

package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// GiteaFingerprinter detects Gitea self-hosted Git service via /api/v1/version endpoint.
// Detection is based on parsing the version field in the JSON response.
type GiteaFingerprinter struct{}

func init() {
	Register(&GiteaFingerprinter{})
}

// giteaVersionResponse represents the JSON response from /api/v1/version endpoint
type giteaVersionResponse struct {
	Version string `json:"version"`
}

// versionRegex validates Gitea version format and extracts semver prefix.
// Valid formats: "1.21.0", "v1.21.0", "1.26.0+dev-489-gc9a038bc4e", "14.0.0-103-5e0b41b3+gitea-1.22.0"
// Handles optional 'v' prefix and extracts: X.Y.Z from the beginning
var giteaVersionRegex = regexp.MustCompile(`^v?(\d+\.\d+\.\d+)`)

// forkGiteaVersionRegex extracts the actual Gitea version from fork version strings.
// Fork formats: "14.0.0-103-5e0b41b3+gitea-1.22.0" (Codeberg), "7.0.0+gitea-1.21.0" (Forgejo)
// Extracts: X.Y.Z after "+gitea-"
var forkGiteaVersionRegex = regexp.MustCompile(`\+gitea-v?(\d+\.\d+\.\d+)`)

// safeVersionRegex validates that the entire version string only contains safe characters.
// Allows: digits, dots, hyphens, plus signs, and letters (for git hashes)
// Prevents: CPE injection characters like colons, semicolons, parentheses, etc.
var giteaSafeVersionRegex = regexp.MustCompile(`^[0-9a-zA-Z.\-+]+$`)

// cssGiteaVersionRegex extracts Gitea version from CSS query params in HTML responses.
// Fork CSS paths contain patterns like "~gitea-1.22.0" or "gitea-1.21.0"
var cssGiteaVersionRegex = regexp.MustCompile(`gitea-v?(\d+\.\d+\.\d+)`)

func (f *GiteaFingerprinter) Name() string {
	return "gitea"
}

// ProbeEndpoint returns the endpoint needed for Gitea detection.
// Gitea exposes version info at /api/v1/version endpoint.
func (f *GiteaFingerprinter) ProbeEndpoint() string {
	return "/api/v1/version"
}

// Match returns true if the response might be from Gitea (JSON content type).
func (f *GiteaFingerprinter) Match(resp *http.Response) bool {
	// Check for Gitea-specific headers (passive path against / HTML response)
	if hasGiteaCookie(resp) || resp.Header.Get("X-Gitea-Version") != "" {
		return true
	}
	// Active path: probe endpoint /api/v1/version returns JSON
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

// Fingerprint performs Gitea detection by parsing the /api/v1/version JSON response.
func (f *GiteaFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Check for X-Gitea-Version header (definitive, works on any response type)
	if headerVersion := resp.Header.Get("X-Gitea-Version"); headerVersion != "" {
		if !giteaSafeVersionRegex.MatchString(headerVersion) {
			return nil, nil
		}
		matches := giteaVersionRegex.FindStringSubmatch(headerVersion)
		if len(matches) < 2 {
			return nil, nil
		}
		return &FingerprintResult{
			Technology: "gitea",
			Version:    matches[1],
			CPEs:       []string{buildGiteaCPE(matches[1])},
			Metadata: map[string]any{
				"raw_version":    headerVersion,
				"detection_path": "header",
			},
		}, nil
	}

	// Check for i_like_gitea cookie (passive path, HTML response)
	if hasGiteaCookie(resp) {
		metadata := map[string]any{
			"detection_path": "cookie",
		}
		version := ""

		// Try to extract version from CSS paths in HTML body
		bodyStr := string(body)
		if cssMatches := cssGiteaVersionRegex.FindStringSubmatch(bodyStr); len(cssMatches) >= 2 {
			if giteaSafeVersionRegex.MatchString(cssMatches[1]) {
				version = cssMatches[1]
				metadata["raw_version"] = cssMatches[0]
			}
		}

		return &FingerprintResult{
			Technology: "gitea",
			Version:    version,
			CPEs:       []string{buildGiteaCPE(version)},
			Metadata:   metadata,
		}, nil
	}

	// Active path: JSON response from /api/v1/version
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "application/json") {
		return nil, nil
	}

	var data giteaVersionResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, nil
	}

	if data.Version == "" {
		return nil, nil
	}

	// Gitea's /api/v1/version returns exactly {"version":"X.Y.Z"} with no other fields.
	// Reject JSON objects with additional fields to prevent false positives
	// from generic APIs that happen to include a "version" field.
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err != nil || len(raw) != 1 {
		return nil, nil
	}

	if !giteaSafeVersionRegex.MatchString(data.Version) {
		return nil, nil
	}

	matches := giteaVersionRegex.FindStringSubmatch(data.Version)
	if len(matches) < 2 {
		return nil, nil
	}

	version := matches[1]

	metadata := map[string]any{
		"raw_version": data.Version,
	}

	forkMatches := forkGiteaVersionRegex.FindStringSubmatch(data.Version)
	if len(forkMatches) >= 2 {
		giteaVersion := forkMatches[1]
		metadata["is_fork"] = true
		metadata["fork_version"] = version
		version = giteaVersion
	}

	return &FingerprintResult{
		Technology: "gitea",
		Version:    version,
		CPEs:       []string{buildGiteaCPE(version)},
		Metadata:   metadata,
	}, nil
}

// hasGiteaCookie checks if the response contains the i_like_gitea cookie.
func hasGiteaCookie(resp *http.Response) bool {
	for _, cookie := range resp.Header["Set-Cookie"] {
		if strings.Contains(cookie, "i_like_gitea") {
			return true
		}
	}
	return false
}

// buildGiteaCPE generates CPE string for Gitea.
// Format: cpe:2.3:a:gitea:gitea:{version}:*:*:*:*:*:*:*
func buildGiteaCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:gitea:gitea:%s:*:*:*:*:*:*:*", version)
}
