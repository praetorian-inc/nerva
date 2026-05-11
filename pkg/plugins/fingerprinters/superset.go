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
Package fingerprinters provides HTTP fingerprinting for Apache Superset.

# Detection Strategy

SupersetFingerprinter uses a two-pronged detection strategy:

 1. Passive (HTML body): Count signals from the root page response, requiring
    at least 2 of 3 signals to match:
    - HTML <title> tag containing "Superset" (case-insensitive)
    - Body containing /static/appbuilder/ or /superset/ asset paths
    - Body containing Superset-specific data-bootstrap markers
      (SUPERSET_WEBSERVER_TIMEOUT, superset-logo, or data-bootstrap= keys
      unique to Apache Superset's React SPA bootstrap JSON blob)

 2. Active (probe /api/v1/info): Parse the JSON response to extract version
    information when the endpoint is accessible:

    {"status_code": 200, "result": {"version": "4.0.1"}}

# Why Active Probing

Apache Superset's /api/v1/info endpoint is publicly accessible and returns
version information without authentication. This enables precise CPE generation
for vulnerability matching against known Superset CVEs.

# Signal Gate (>=2 of 3)

Requiring at least two independent signals prevents false positives from:
  - Generic Flask-AppBuilder apps that share CSS class names
  - Pages that reference Superset in prose without being a Superset instance
  - Other Apache projects using appbuilder patterns
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

var (
	supersetTitlePattern      = regexp.MustCompile(`(?i)<title[^>]{0,200}>[^<]{0,200}superset[^<]{0,200}</title>`)
	supersetAssetPathPattern  = regexp.MustCompile(`(?i)(?:/static/appbuilder/|/superset/)`)
	supersetFABMarkerPattern  = regexp.MustCompile(`(?i)(?:SUPERSET_WEBSERVER_TIMEOUT|superset-logo|data-bootstrap=)`)
	supersetVersionCharset    = regexp.MustCompile(`^[0-9a-zA-Z.\-]+$`)
	supersetVersionSemver     = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

// SupersetFingerprinter detects Apache Superset instances via HTML body signals
// and the /api/v1/info JSON endpoint.
type SupersetFingerprinter struct{}

func init() {
	Register(&SupersetFingerprinter{})
}

// supersetInfoResponse represents the JSON response from /api/v1/info
type supersetInfoResponse struct {
	StatusCode int `json:"status_code"`
	Result     struct {
		Version string `json:"version"`
	} `json:"result"`
}

// Name returns the fingerprinter identifier.
func (f *SupersetFingerprinter) Name() string { return "superset" }

// ProbeEndpoint returns the endpoint used for active Superset detection.
func (f *SupersetFingerprinter) ProbeEndpoint() string {
	return "/api/v1/info"
}

// Match returns true for HTML, JSON, or empty Content-Type responses that may be Superset.
// Returns false immediately if resp is nil.
func (f *SupersetFingerprinter) Match(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return ct == "" ||
		strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "application/xhtml+xml")
}

// Fingerprint detects Apache Superset by counting HTML body signals or parsing
// the /api/v1/info JSON response. Returns nil if resp is nil, body is empty,
// or insufficient signals are present.
func (f *SupersetFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil || len(body) == 0 {
		return nil, nil
	}

	// Try active JSON probe only when response is JSON
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "application/json") {
		var info supersetInfoResponse
		if err := json.Unmarshal(body, &info); err == nil && info.StatusCode == 200 && info.Result.Version != "" {
			version := sanitizeSupersetVersion(info.Result.Version)
			return &FingerprintResult{
				Technology: "superset",
				Version:    version,
				CPEs:       []string{buildSupersetCPE(version)},
				Metadata: map[string]any{
					"login_path": "/login/",
				},
				Severity: plugins.SeverityHigh,
			}, nil
		}
	}

	// Passive HTML signal counting
	signals := 0
	if supersetTitlePattern.Match(body) {
		signals++
	}
	if supersetAssetPathPattern.Match(body) {
		signals++
	}
	if supersetFABMarkerPattern.Match(body) {
		signals++
	}

	if signals < 2 {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "superset",
		Version:    "",
		CPEs:       []string{buildSupersetCPE("")},
		Metadata: map[string]any{
			"login_path": "/login/",
		},
		Severity: plugins.SeverityHigh,
	}, nil
}

// sanitizeSupersetVersion validates and sanitizes a version string.
// Returns empty string on any violation.
func sanitizeSupersetVersion(v string) string {
	if len(v) > 16 {
		return ""
	}
	if !supersetVersionCharset.MatchString(v) {
		return ""
	}
	if !supersetVersionSemver.MatchString(v) {
		return ""
	}
	return v
}

// buildSupersetCPE generates a CPE 2.3 string for Apache Superset.
// Uses "*" for empty version.
func buildSupersetCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:apache:superset:%s:*:*:*:*:*:*:*", version)
}
