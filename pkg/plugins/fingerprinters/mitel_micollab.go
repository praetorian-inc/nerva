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

const mitelMaxBodySize = 1 << 20

// MitelMicollabFingerprinter detects Mitel MiCollab unified communications servers.
//
// Detection Strategy:
//
//  1. Standalone (from active probe): The JSON response from /ucs/micollab/version.json
//     contains a "version" key with a numeric version value (e.g., "9.8.1.201").
//     This endpoint is unique to MiCollab and sufficient alone.
//  2. Corroborated (passive): Body contains "MiCollab End User Portal" or
//     "AWC User Portal" — both are product-specific phrases.
//  3. Corroborated (passive): Body contains "/awc/" path AND "Mitel" brand
//     (case-insensitive) — both required together.
//
// "Mitel" brand alone is NOT sufficient — it appears on comparison pages,
// news sites, and documentation.
//
// Active Probe: GET /ucs/micollab/version.json
//
// Version Detection:
// Extracted from the JSON "version" field. Format: "9.8.1.201".
// Validated with `^\d+\.\d+(?:\.\d+(?:\.\d+)?)?$`.
// Full 4-segment version is stored in CPE (NVD MiCollab CPEs use full 4-segment).
//
// CPE: cpe:2.3:a:mitel:micollab:<version>:*:*:*:*:*:*:*
type MitelMicollabFingerprinter struct{}

func init() {
	Register(&MitelMicollabFingerprinter{})
}

// mitelBrandPattern matches "Mitel" brand case-insensitively.
// Precompiled to avoid per-call allocation in Fingerprint().
var mitelBrandPattern = regexp.MustCompile(`(?i)mitel`)

// mitelVersionValidRegex validates extracted version strings before CPE use.
// Accepts: "9.8.1.201", "9.8.1", "9.8" — full 4-segment or shorter.
var mitelVersionValidRegex = regexp.MustCompile(`^\d+\.\d+(?:\.\d+(?:\.\d+)?)?$`)

func (f *MitelMicollabFingerprinter) Name() string {
	return "mitel-micollab"
}

func (f *MitelMicollabFingerprinter) ProbeEndpoint() string {
	return "/ucs/micollab/version.json"
}

// Match accepts application/json and text/html content types.
// Also accepts 3xx redirects to known MiCollab paths (/portal/, /awc/).
// Rejects 5xx.
func (f *MitelMicollabFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode >= 500 {
		return false
	}

	// Accept redirects to known MiCollab paths.
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "/portal/") || strings.Contains(location, "/awc/") {
			return true
		}
		return false
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "application/json") || strings.Contains(ct, "text/html")
}

// Fingerprint performs full detection and returns a result if this is a Mitel MiCollab server.
// Returns nil, nil for non-matching responses.
func (f *MitelMicollabFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > mitelMaxBodySize {
		body = body[:mitelMaxBodySize]
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))

	// Signal 1 (standalone): JSON probe response with "version" key.
	if strings.Contains(ct, "application/json") {
		var payload map[string]any
		if err := json.Unmarshal(body, &payload); err == nil {
			if v, ok := payload["version"]; ok {
				version := extractMitelVersion(v)
				if version != "" {
					return buildMitelResult(version), nil
				}
				// "version" key present but not a valid version string —
				// still a detection signal if it's a string at all.
				if _, isStr := v.(string); isStr {
					return buildMitelResult(""), nil
				}
			}
		}
	}

	bodyStr := string(body)

	// Signal 2 (corroborated): product-specific portal phrases.
	if strings.Contains(bodyStr, "MiCollab End User Portal") || strings.Contains(bodyStr, "AWC User Portal") {
		return buildMitelResult(""), nil
	}

	// Signal 3 (corroborated): /awc/ path + Mitel brand.
	hasAWCPath := strings.Contains(bodyStr, "/awc/")
	hasMitelBrand := mitelBrandPattern.MatchString(bodyStr)
	if hasAWCPath && hasMitelBrand {
		return buildMitelResult(""), nil
	}

	// Accept redirects to MiCollab paths (already filtered in Match).
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		location := resp.Header.Get("Location")
		if strings.Contains(location, "/portal/") || strings.Contains(location, "/awc/") {
			return buildMitelResult(""), nil
		}
	}

	return nil, nil
}

// extractMitelVersion extracts and validates a version from a JSON "version" field value.
// The value from json.Unmarshal is any; we expect a string like "9.8.1.201".
func extractMitelVersion(v any) string {
	str, ok := v.(string)
	if !ok {
		return ""
	}
	if !mitelVersionValidRegex.MatchString(str) {
		return ""
	}
	return str
}

func buildMitelResult(version string) *FingerprintResult {
	v := version
	if v == "" {
		v = "*"
	}
	return &FingerprintResult{
		Technology: "mitel-micollab",
		Version:    version,
		CPEs:       []string{fmt.Sprintf("cpe:2.3:a:mitel:micollab:%s:*:*:*:*:*:*:*", v)},
		Metadata: map[string]any{
			"vendor":  "Mitel",
			"product": "MiCollab",
		},
	}
}
