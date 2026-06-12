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
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

const simplehelpMaxBodySize = 1 << 20

// SimplehelpFingerprinter detects SimpleHelp remote access and support instances.
//
// Detection Strategy:
//
// SimpleHelp is a remote access and support platform. Detection uses two signals:
//
//  1. Standalone: Server response header contains "SimpleHelp" (case-insensitive).
//     The Server header is set by the SimpleHelp application server and is a reliable
//     standalone indicator.
//  2. Corroborated: Body contains "SimpleHelp" brand AND either the distinctive asset
//     "simplehelp-text.svg" (standalone sufficient) OR at least 2 of the 3 portal paths
//     ("/customer", "/technician", "/access") — both required together.
//
// "SimpleHelp" in the body alone without a corroborating asset or path is NOT
// sufficient — the name can appear in documentation, comparison pages, or other
// unrelated content.
//
// Version Detection:
// Extracted from the Server header when present. SimpleHelp emits headers like:
//   - "SimpleHelp/5.5.16"
//   - "SimpleHelp 5.5.16"
//
// Validated with `^\d+\.\d+(?:\.\d+)?$`. Empty string if not found or invalid.
//
// CPE: cpe:2.3:a:simple-help:simplehelp:<version>:*:*:*:*:*:*:*
type SimplehelpFingerprinter struct{}

func init() {
	Register(&SimplehelpFingerprinter{})
}

// simplehelpServerPattern matches SimpleHelp in a Server header value,
// case-insensitively. Precompiled to avoid per-call allocation.
var simplehelpServerPattern = regexp.MustCompile(`(?i)simplehelp`)


// simplehelpVersionPattern extracts the version from a Server header value.
// Matches "SimpleHelp/5.5.16" or "SimpleHelp 5.5.16".
// Requires end-of-string or whitespace after the version to prevent partial
// matches from garbled strings like "5.5.16abc" (which would otherwise match "5.5").
var simplehelpVersionPattern = regexp.MustCompile(`(?i)simplehelp[/\s](\d+\.\d+(?:\.\d+)?)(?:\s|$)`)

// simplehelpVersionValidRegex validates extracted version strings before CPE use.
// Accepts: "5.5.16", "5.5" — rejects anything with non-numeric, injection chars.
var simplehelpVersionValidRegex = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)

func (f *SimplehelpFingerprinter) Name() string {
	return "simplehelp"
}

// Match accepts any response with a Server header containing "SimpleHelp" OR
// text/html content type. Rejects 5xx.
func (f *SimplehelpFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode >= 500 {
		return false
	}

	// Server header containing SimpleHelp is a standalone match signal.
	if simplehelpServerPattern.MatchString(resp.Header.Get("Server")) {
		return true
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full detection and returns a result if this is a SimpleHelp instance.
// Returns nil, nil for non-matching responses.
func (f *SimplehelpFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > simplehelpMaxBodySize {
		body = body[:simplehelpMaxBodySize]
	}

	serverHeader := resp.Header.Get("Server")

	// Signal 1 (standalone): Server header contains SimpleHelp.
	if simplehelpServerPattern.MatchString(serverHeader) {
		version := extractSimplehelpVersion(serverHeader)
		return buildSimplehelpResult(version), nil
	}

	bodyStr := string(body)

	// Signal 2 (corroborated): SimpleHelp brand in body + distinctive asset or multiple portal paths.
	// simplehelpBrandInBody checks for "simplehelp" (case-insensitive) not immediately followed
	// by a hyphen, so the SVG filename "simplehelp-text.svg" does not satisfy the brand check.
	hasBrand := simplehelpBrandInBody(strings.ToLower(bodyStr))
	hasDistinctiveAsset := strings.Contains(bodyStr, "simplehelp-text.svg")

	portalPathCount := 0
	for _, path := range []string{"/customer", "/technician", "/access"} {
		if strings.Contains(bodyStr, path) {
			portalPathCount++
		}
	}

	if hasBrand && (hasDistinctiveAsset || portalPathCount >= 2) {
		return buildSimplehelpResult(""), nil
	}

	return nil, nil
}

// simplehelpBrandInBody reports whether the lowercased body string contains "simplehelp"
// as a brand word — that is, not immediately followed by a hyphen (which would indicate
// a compound filename like "simplehelp-text.svg").
func simplehelpBrandInBody(lowered string) bool {
	const needle = "simplehelp"
	idx := 0
	for {
		pos := strings.Index(lowered[idx:], needle)
		if pos < 0 {
			return false
		}
		abs := idx + pos
		after := abs + len(needle)
		if after >= len(lowered) || lowered[after] != '-' {
			return true
		}
		idx = abs + 1
	}
}

// extractSimplehelpVersion extracts a version string from the Server header.
// Returns empty string if no valid version is found.
func extractSimplehelpVersion(serverHeader string) string {
	m := simplehelpVersionPattern.FindStringSubmatch(serverHeader)
	if len(m) < 2 {
		return ""
	}
	v := m[1]
	if !simplehelpVersionValidRegex.MatchString(v) {
		return ""
	}
	return v
}

func buildSimplehelpResult(version string) *FingerprintResult {
	v := version
	if v == "" {
		v = "*"
	}
	return &FingerprintResult{
		Technology: "simplehelp",
		Version:    version,
		CPEs:       []string{fmt.Sprintf("cpe:2.3:a:simple-help:simplehelp:%s:*:*:*:*:*:*:*", v)},
		Metadata: map[string]any{
			"vendor":  "SimpleHelp",
			"product": "SimpleHelp",
		},
	}
}
