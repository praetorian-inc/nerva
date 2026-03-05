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
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

// Fingerprint performs Gitea detection by parsing the /api/v1/version JSON response.
func (f *GiteaFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Parse JSON response
	var data giteaVersionResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, nil // Not valid JSON
	}

	// Gitea detection: version field must be non-empty
	if data.Version == "" {
		return nil, nil
	}

	// Validate that version string only contains safe characters (prevents injection)
	if !giteaSafeVersionRegex.MatchString(data.Version) {
		return nil, nil
	}

	// Extract and validate version format (X.Y.Z)
	matches := giteaVersionRegex.FindStringSubmatch(data.Version)
	if len(matches) < 2 {
		return nil, nil // Version doesn't match expected format
	}

	// Extract semver (first capture group)
	version := matches[1]

	// Build metadata with raw version string
	metadata := map[string]any{
		"raw_version": data.Version,
	}

	// Check if this is a fork (Codeberg, Forgejo, etc.) with "+gitea-X.Y.Z" pattern
	// For forks, we want the actual Gitea version for CPE matching, not the fork version
	forkMatches := forkGiteaVersionRegex.FindStringSubmatch(data.Version)
	if len(forkMatches) >= 2 {
		// This is a fork - extract the actual Gitea version
		giteaVersion := forkMatches[1]
		metadata["is_fork"] = true
		metadata["fork_version"] = version // Store the fork's version (e.g., "14.0.0")
		version = giteaVersion             // Use Gitea version for CPE (e.g., "1.22.0")
	}

	return &FingerprintResult{
		Technology: "gitea",
		Version:    version,
		CPEs:       []string{buildGiteaCPE(version)},
		Metadata:   metadata,
	}, nil
}

// buildGiteaCPE generates CPE string for Gitea.
// Format: cpe:2.3:a:gitea:gitea:{version}:*:*:*:*:*:*:*
func buildGiteaCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:gitea:gitea:%s:*:*:*:*:*:*:*", version)
}
