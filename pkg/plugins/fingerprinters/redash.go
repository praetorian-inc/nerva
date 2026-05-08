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
Package fingerprinters provides HTTP fingerprinting for Redash.

# Detection Strategy

RedashFingerprinter detects Redash data visualization instances using two complementary
approaches:

 1. Passive (HTML body): Count signals in the root HTML response, require >= 2 of 3:
    - HTML <title> tag containing "Redash" (case-insensitive)
    - Body containing Redash-specific asset paths (/static/images/redash_icon or
      /static/images/favicon)
    - Body containing Angular app markers (ng-app="redash"), data attributes (data-redash),
      or client-config with Redash-specific markers

 2. Active (/api/session probe): Parse the JSON response for Redash-specific field
    combinations (org_slug, client_config, csrf_token) to confirm identity.
    This distinguishes Redash from MLflow, which also runs on port 5000.

# False Positive Prevention (MLflow Disambiguation)

Both Redash and MLflow commonly run on port 5000. The active probe validates that the
JSON response contains Redash-unique fields (org_slug, client_config, csrf_token) that
do not appear in MLflow responses.

# Version Extraction

Version may appear in client_config.version in the /api/session response. Version strings
are validated with a strict sanitizer (semver only, <=16 chars, safe charset) before use.
Wildcard ("*") is used in CPEs when version is unavailable.

# CPE Format

NVD vendor is "redash" (not "getredash"):
cpe:2.3:a:redash:redash:{version}:*:*:*:*:*:*:*
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
	redashTitlePattern      = regexp.MustCompile(`(?i)<title[^>]{0,200}>[^<]{0,200}redash[^<]{0,200}</title>`)
	redashAssetPathPattern  = regexp.MustCompile(`/static/images/(?:redash_icon|favicon)`)
	redashAppMarkerPattern  = regexp.MustCompile(`(?:ng-app=["']redash["']|data-redash|client-config.*redash|redash.*client-config)`)
	redashVersionSafeRegex  = regexp.MustCompile(`^[0-9a-zA-Z.\-]+$`)
	redashVersionSemverRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
)

// RedashFingerprinter detects Redash data visualization instances via HTML body signals
// and the /api/session JSON endpoint.
type RedashFingerprinter struct{}

func init() {
	Register(&RedashFingerprinter{})
}

// redashSessionResponse represents relevant fields from the /api/session JSON response.
type redashSessionResponse struct {
	OrgSlug      string                 `json:"org_slug"`
	CSRFToken    string                 `json:"csrf_token"`
	ClientConfig map[string]interface{} `json:"client_config"`
}

// Name returns the fingerprinter identifier.
func (f *RedashFingerprinter) Name() string { return "redash" }

// ProbeEndpoint returns the endpoint path used for active Redash detection.
func (f *RedashFingerprinter) ProbeEndpoint() string { return "/api/session" }

// Match returns true for HTML or JSON responses that may be Redash.
// Returns false immediately if resp is nil.
func (f *RedashFingerprinter) Match(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return ct == "" ||
		strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "application/xhtml+xml")
}

// Fingerprint performs Redash detection.
// For HTML responses it counts passive signals (>=2 required).
// For JSON responses it validates Redash-specific field combinations.
// Returns nil, nil on non-detection, parse errors, or nil resp.
func (f *RedashFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil || len(body) == 0 {
		return nil, nil
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))

	// Active probe: try JSON parsing first when content type is JSON or body looks like JSON.
	if strings.Contains(ct, "application/json") || (len(body) > 0 && body[0] == '{') {
		return f.fingerprintJSON(body)
	}

	// Passive: HTML signal counting.
	return f.fingerprintHTML(body)
}

// fingerprintHTML counts passive HTML signals and returns a result if >=2 match.
func (f *RedashFingerprinter) fingerprintHTML(body []byte) (*FingerprintResult, error) {
	signals := 0
	if redashTitlePattern.Match(body) {
		signals++
	}
	if redashAssetPathPattern.Match(body) {
		signals++
	}
	if redashAppMarkerPattern.Match(body) {
		signals++
	}

	if signals < 2 {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "redash",
		Version:    "",
		CPEs:       []string{buildRedashCPE("")},
		Metadata:   map[string]any{"login_path": "/login"},
		Severity:   plugins.SeverityHigh,
	}, nil
}

// fingerprintJSON parses a /api/session JSON response and validates Redash-specific fields.
func (f *RedashFingerprinter) fingerprintJSON(body []byte) (*FingerprintResult, error) {
	var data redashSessionResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, nil
	}

	// Require Redash-unique field combinations to avoid false positives (e.g., MLflow).
	// At least two of the three Redash-specific fields must be present.
	redashFieldCount := 0
	if data.OrgSlug != "" {
		redashFieldCount++
	}
	if data.CSRFToken != "" {
		redashFieldCount++
	}
	if data.ClientConfig != nil {
		redashFieldCount++
	}

	if redashFieldCount < 2 {
		return nil, nil
	}

	// Attempt to extract version from client_config.version.
	version := ""
	if data.ClientConfig != nil {
		if v, ok := data.ClientConfig["version"]; ok {
			if vStr, ok := v.(string); ok {
				version = sanitizeRedashVersion(vStr)
			}
		}
	}

	return &FingerprintResult{
		Technology: "redash",
		Version:    version,
		CPEs:       []string{buildRedashCPE(version)},
		Metadata:   map[string]any{"login_path": "/login"},
		Severity:   plugins.SeverityHigh,
	}, nil
}

// sanitizeRedashVersion validates and returns a safe Redash version string.
// Returns "" if the version fails any validation check.
func sanitizeRedashVersion(v string) string {
	if len(v) > 16 {
		return ""
	}
	if !redashVersionSafeRegex.MatchString(v) {
		return ""
	}
	if !redashVersionSemverRegex.MatchString(v) {
		return ""
	}
	return v
}

// buildRedashCPE generates a CPE 2.3 string for Redash.
// NVD vendor is "redash", not "getredash".
// Uses "*" for empty version.
func buildRedashCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:redash:redash:%s:*:*:*:*:*:*:*", version)
}
