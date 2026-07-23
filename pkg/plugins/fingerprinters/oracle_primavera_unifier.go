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
Package fingerprinters provides HTTP fingerprinting for Oracle Primavera Unifier.

Oracle Primavera Unifier is a project controls and cost management platform used
in capital-intensive industries (construction, engineering, energy). Detection
relies on the unauthenticated login page served under the /bluedoor context root.

# Detection Strategy

Detection probes GET /bluedoor and matches any of these signals in the response:

  - hasUnifierTitle: case-insensitive <title> containing "Primavera Unifier Login"
  - hasUnifierBranding: body contains the product name "Primavera Unifier"
  - hasCodeVersion: body contains the JSON config field "codeVersion"

# Reflection Safety

The probe path /bluedoor is intentionally NOT used as a detection signal; an
attacker-controlled 404 page could reflect the path back, producing false positives.
All three signals above are reflection-safe against /bluedoor.

# Version Extraction

Two formats are present on the login page:

  - HTML format: Version25.12.1 b-12242025-15
    Captured by: unifierVersionRegex (group 1 = version, group 2 = build string)

  - JSON format: "codeVersion":"25.12.1-b-12242025-15"
    Captured by: unifierCodeVersionRegex (group 1 = version, group 2 = build string)

The HTML format is tried first; the JSON format is the fallback.

# CPE

cpe:2.3:a:oracle:primavera_unifier:*:*:*:*:*:*:*:*
NVD-verified product token: primavera_unifier
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// unifierVersionRegex matches the HTML login-page version string.
// Handles both "Version 25.12.1 b-12242025-15" and "Version25.12.1 b-12242025-15".
var unifierVersionRegex = regexp.MustCompile(`Version\s*(\d+(?:\.\d+)+)\s*b-([^\s"<,]+)`)

// unifierCodeVersionRegex matches the JSON codeVersion field.
// Example: "codeVersion":"25.12.1-b-12242025-15"
var unifierCodeVersionRegex = regexp.MustCompile(`"codeVersion"\s*:\s*"(\d+(?:\.\d+)+)-b-([^"]+)"`)

// unifierTitleRegex matches the Primavera Unifier login page title, tolerating
// arbitrary attributes and surrounding whitespace.
var unifierTitleRegex = regexp.MustCompile(`(?i)<title[^>]*>\s*Primavera Unifier Login\s*</title>`)

// OraclePrimaveraUnifierFingerprinter detects Oracle Primavera Unifier instances
// via their unauthenticated login page at /bluedoor.
type OraclePrimaveraUnifierFingerprinter struct{}

func init() {
	Register(&OraclePrimaveraUnifierFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *OraclePrimaveraUnifierFingerprinter) Name() string {
	return "oracle_primavera_unifier"
}

// ProbeEndpoint returns the active probe path. The Unifier login page is served
// under the /bluedoor context root.
func (f *OraclePrimaveraUnifierFingerprinter) ProbeEndpoint() string {
	return "/bluedoor"
}

// ProbeAccept returns the Accept header for the active probe. Unifier serves
// an HTML login page at /bluedoor.
func (f *OraclePrimaveraUnifierFingerprinter) ProbeAccept() string {
	return "text/html"
}

// Match returns true when the response is worth inspecting for Unifier signals.
// Rejects status < 200 or >= 500; accepts text/html responses.
func (f *OraclePrimaveraUnifierFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full Oracle Primavera Unifier detection and metadata extraction.
// Returns nil when no Unifier signal is found. Body is capped at 2 MiB internally.
func (f *OraclePrimaveraUnifierFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// 2 MiB body cap; a legitimate Unifier login page is well under this limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	bodyStr := string(body)

	// Signal 1 (highest confidence): page title "Primavera Unifier Login".
	hasUnifierTitle := unifierTitleRegex.MatchString(bodyStr)

	// Signal 2: product name in body.
	hasUnifierBranding := strings.Contains(bodyStr, "Primavera Unifier")

	// Signal 3: JSON codeVersion config field unique to the Unifier login page.
	hasCodeVersion := strings.Contains(bodyStr, `"codeVersion":`)

	if !hasUnifierTitle && !hasUnifierBranding && !hasCodeVersion {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":           "Oracle",
		"product":          "Oracle Primavera Unifier",
		"detection_method": unifierDetectionMethod(hasUnifierTitle, hasUnifierBranding, hasCodeVersion),
	}

	// Version extraction: try HTML format first, then JSON codeVersion.
	var version string
	if m := unifierVersionRegex.FindStringSubmatch(bodyStr); m != nil {
		v := m[1]
		if !strings.ContainsAny(v, ":*?") {
			version = v
			metadata["build"] = m[2]
			metadata["version_note"] = "extracted from login page"
		}
	}
	if version == "" {
		if m := unifierCodeVersionRegex.FindStringSubmatch(bodyStr); m != nil {
			v := m[1]
			if !strings.ContainsAny(v, ":*?") {
				version = v
				metadata["build"] = m[2]
				metadata["version_note"] = "extracted from login page"
			}
		}
	}

	return &FingerprintResult{
		Technology: "oracle_primavera_unifier",
		Version:    version,
		CPEs:       []string{buildPrimaveraUnifierCPE(version)},
		Metadata:   metadata,
	}, nil
}

// unifierDetectionMethod returns the highest-priority detection method name.
func unifierDetectionMethod(hasUnifierTitle, hasUnifierBranding, hasCodeVersion bool) string {
	switch {
	case hasUnifierTitle:
		return "unifier_title"
	case hasUnifierBranding:
		return "unifier_branding"
	default:
		return "code_version"
	}
}

// buildPrimaveraUnifierCPE constructs a CPE 2.3 string for Oracle Primavera Unifier.
// Wildcards are used when version is empty or contains CPE metacharacters.
func buildPrimaveraUnifierCPE(version string) string {
	if version == "" || strings.ContainsAny(version, ":*?") {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:oracle:primavera_unifier:%s:*:*:*:*:*:*:*", version)
}
