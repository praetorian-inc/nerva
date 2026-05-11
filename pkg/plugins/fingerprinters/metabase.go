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
Package fingerprinters provides HTTP fingerprinting for Metabase.

# Detection Strategy

MetabaseFingerprinter uses a dual-mode detection approach:

 1. Passive (HTML response): Counts signals from the root page body.
    Detection fires when at least 2 of 3 signals match:
    a. HTML <title> tag containing "Metabase" (case-insensitive)
    b. Meta tag with og:site_name containing "Metabase"
    c. Body containing Metabase-specific JS bundle references (/app/dist/ or metabase. JS files)

 2. Active (probe /api/session/properties): Parses the JSON response from
    Metabase's session properties endpoint. Detection requires BOTH the
    "engines" AND "version" fields to be present to prevent false positives
    against Grafana (which also commonly runs on port 3000). Version is
    extracted from version.tag, stripping the leading "v" prefix.

# Security Critical: Setup Token Detection

When setup-token is present and non-empty in the /api/session/properties
response, metadata["setup_token_present"] is set to true. The actual token
value is NEVER stored. An exposed setup token allows unauthenticated
administrative access to configure the Metabase instance.

# False Positive Prevention

Both Metabase and Grafana commonly run on port 3000. The active probe
requires both "engines" (Metabase database engine configs) AND "version"
(Metabase version info) fields to be present. Grafana's API responses do
not contain "engines", preventing false positive matches.
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
	metabaseTitlePattern   = regexp.MustCompile(`(?i)<title[^>]{0,200}>[^<]{0,200}metabase[^<]{0,200}</title>`)
	metabaseOGSiteNameRegex = regexp.MustCompile(`(?i)<meta\s[^>]*?(?:content=["']Metabase["'][^>]*?property=["']og:site_name["']|property=["']og:site_name["'][^>]*?content=["']Metabase["'])`)
	metabaseJSBundlePattern = regexp.MustCompile(`(?i)(?:/?app/dist/|metabase\.[a-zA-Z0-9_\-]+\.js)`)
	metabaseVersionRegex    = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	metabaseSafeVersionRegex = regexp.MustCompile(`^[0-9a-zA-Z.\-]+$`)
)

// MetabaseFingerprinter detects Metabase instances via HTML body signals
// and the /api/session/properties JSON endpoint.
type MetabaseFingerprinter struct{}

func init() {
	Register(&MetabaseFingerprinter{})
}

// metabaseSessionProperties represents the JSON response from /api/session/properties.
// Only the fields relevant for fingerprinting and security detection are captured.
type metabaseSessionProperties struct {
	Version    *metabaseVersion       `json:"version"`
	Engines    map[string]interface{} `json:"engines"`
	SetupToken string                 `json:"setup-token"`
}

type metabaseVersion struct {
	Tag  string `json:"tag"`
	Date string `json:"date"`
	Hash string `json:"hash"`
}

// Name returns the fingerprinter identifier.
func (f *MetabaseFingerprinter) Name() string { return "metabase" }

// ProbeEndpoint returns the endpoint used for active Metabase detection.
func (f *MetabaseFingerprinter) ProbeEndpoint() string {
	return "/api/session/properties"
}

// Match returns true for HTML or JSON responses (or empty Content-Type) that may be Metabase.
// Returns false immediately if resp is nil.
func (f *MetabaseFingerprinter) Match(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return ct == "" ||
		strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "application/xhtml+xml")
}

// Fingerprint detects Metabase by inspecting the response body.
// For HTML responses, it counts signals (requires >= 2 of 3).
// For JSON responses, it parses /api/session/properties and requires
// both "engines" and "version" fields to prevent false positives.
// Returns nil if resp is nil, or if insufficient signals/fields are present.
func (f *MetabaseFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil {
		return nil, nil
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))

	// Active probe: JSON response from /api/session/properties
	if strings.Contains(ct, "application/json") {
		if result, err := f.fingerprintJSON(body); result != nil || err != nil {
			return result, err
		}
		// JSON probe failed — fall back to HTML signal counting
	}

	// Passive: HTML detection
	if len(body) == 0 {
		return nil, nil
	}
	return f.fingerprintHTML(body)
}

// fingerprintHTML counts HTML body signals and returns a result if >= 2 match.
func (f *MetabaseFingerprinter) fingerprintHTML(body []byte) (*FingerprintResult, error) {
	signals := 0
	if metabaseTitlePattern.Match(body) {
		signals++
	}
	if metabaseOGSiteNameRegex.Match(body) {
		signals++
	}
	if metabaseJSBundlePattern.Match(body) {
		signals++
	}

	if signals < 2 {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "metabase",
		Version:    "",
		CPEs:       []string{buildMetabaseCPE("")},
		Metadata: map[string]any{
			"login_path": "/auth/login",
		},
		Severity: plugins.SeverityHigh,
	}, nil
}

// fingerprintJSON parses /api/session/properties JSON to detect and fingerprint Metabase.
// Requires both "engines" and "version" fields to prevent false positives against Grafana.
func (f *MetabaseFingerprinter) fingerprintJSON(body []byte) (*FingerprintResult, error) {
	if len(body) == 0 {
		return nil, nil
	}

	var props metabaseSessionProperties
	if err := json.Unmarshal(body, &props); err != nil {
		return nil, nil
	}

	// MUST have both "engines" AND "version" to prevent Grafana false positives
	if props.Engines == nil || props.Version == nil {
		return nil, nil
	}

	version := ""
	if props.Version.Tag != "" {
		rawTag := props.Version.Tag
		// Strip leading "v" prefix
		rawTag = strings.TrimPrefix(rawTag, "v")
		version = sanitizeMetabaseVersion(rawTag)
	}

	setupTokenPresent := props.SetupToken != ""

	return &FingerprintResult{
		Technology: "metabase",
		Version:    version,
		CPEs:       []string{buildMetabaseCPE(version)},
		Metadata: map[string]any{
			"login_path":          "/auth/login",
			"setup_token_present": setupTokenPresent,
		},
		Severity: plugins.SeverityHigh,
	}, nil
}

// sanitizeMetabaseVersion validates a Metabase version string and returns it if safe,
// or empty string on any violation.
// Rules:
//   - Length cap: 16 chars
//   - Charset allowlist: ^[0-9a-zA-Z.\-]+$
//   - Semver structure: ^\d+\.\d+\.\d+$
func sanitizeMetabaseVersion(v string) string {
	if len(v) > 16 {
		return ""
	}
	if !metabaseSafeVersionRegex.MatchString(v) {
		return ""
	}
	if !metabaseVersionRegex.MatchString(v) {
		return ""
	}
	return v
}

// buildMetabaseCPE generates a CPE 2.3 string for Metabase.
// Uses "*" for empty version.
func buildMetabaseCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:metabase:metabase:%s:*:*:*:*:*:*:*", version)
}
