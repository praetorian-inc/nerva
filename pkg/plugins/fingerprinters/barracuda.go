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
	"unicode/utf8"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// BarracudaESGFingerprinter detects Barracuda Email Security Gateway appliances.
//
// Detection Strategy:
// Barracuda ESG appliances expose X-Barracuda-* headers on responses and may
// identify themselves via the Server header. Detection is entirely passive
// (header- and body-based; no probe endpoint required):
//
//  1. X-Barracuda-* headers — any response header key starting with
//     "X-Barracuda" is definitive; Barracuda ESG is the only device family
//     that injects these headers.
//  2. Server header containing "barracuda" (case-insensitive).
//  3. Body brand text: body contains "barracuda" AND at least one of
//     "email security", "spam firewall", or "barracuda networks".
//
// CVE Context:
//   - CVE-2023-2868 (CVSS 9.8): Incomplete input validation of .tar file names
//     in Barracuda ESG. Exploited by UNC4841 (China-nexus APT). Listed on the
//     CISA KEV catalog and the Five Eyes AA24-317A advisory Top 15. The FBI
//     issued an unprecedented recommendation for physical device replacement.
//
// Default Port:
//   - 443: HTTPS management/gateway interface
//
// Version Detection:
// Barracuda ESG rarely exposes version in HTTP responses. When available,
// version is found in the X-Barracuda-Version header or body text.
//
// CPE (NVD, CVE-2023-2868):
//
//	cpe:2.3:o:barracuda:email_security_gateway_firmware:{version}:*:*:*:*:*:*:*
//
// Security Risks:
//   - CVE-2023-2868 (CVSS 9.8): RCE via malformed .tar filename; FBI advised
//     physical replacement of all affected appliances.
type BarracudaESGFingerprinter struct{}

func init() {
	Register(&BarracudaESGFingerprinter{})
}

// barracudaVersionValidRegex validates extracted version strings before CPE use.
// Accepts: "9.2", "9.2.0", "9.2.0.001", "12.0.1.123", "12.0.1.123.4"
// Rejects anything with injection characters, letters, or CPE metacharacters.
var barracudaVersionValidRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,4}$`)

// barracudaBodyVersionPattern extracts a version number from body text.
// Requires a "version" or "ver" keyword in context to avoid matching
// unrelated numeric sequences.
var barracudaBodyVersionPattern = regexp.MustCompile(
	`(?i)(?:version|ver)[:\s=]*([0-9]+(?:\.[0-9]+){1,4})`,
)

// barracudaMaxBodySize is the maximum number of bytes read from the body.
// Bodies larger than this are truncated before text searches.
const barracudaMaxBodySize = 2 * 1024 * 1024 // 2 MiB

// barracudaMaxVersionLen caps version string length to guard against
// pathologically long strings before the regex runs.
const barracudaMaxVersionLen = 32

func (f *BarracudaESGFingerprinter) Name() string {
	return "barracuda-esg"
}

// Match is a fast pre-filter. Returns true when the response warrants a full
// Fingerprint() call. Accepts responses that have X-Barracuda-* headers, a
// Barracuda Server header, or a text/html body. Rejects 5xx server errors.
func (f *BarracudaESGFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// X-Barracuda-* headers are definitive — accept immediately.
	if hasBarracudaHeaders(resp) {
		return true
	}

	// Server header containing "barracuda"
	if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "barracuda") {
		return true
	}

	// text/html — accept for body-driven detection
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full detection and returns a result if this is a
// Barracuda ESG appliance. Returns nil, nil for non-matching responses.
func (f *BarracudaESGFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status 200-499
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: body cap
	if len(body) > barracudaMaxBodySize {
		body = body[:barracudaMaxBodySize]
	}

	bodyLower := strings.ToLower(string(body))

	// Gate 3: CPE injection defence — reject bodies containing ":*:" which
	// could indicate an adversarially crafted response attempting to inject
	// into CPE strings.
	if strings.Contains(bodyLower, ":*:") {
		return nil, nil
	}

	// Detection signals
	headerSignal := hasBarracudaHeaders(resp)
	serverSignal := strings.Contains(strings.ToLower(resp.Header.Get("Server")), "barracuda")

	// Body brand signal: "barracuda" AND ("email security" OR "spam firewall" OR "barracuda networks")
	bodyHasBrand := strings.Contains(bodyLower, "barracuda")
	bodyHasProduct := strings.Contains(bodyLower, "email security") ||
		strings.Contains(bodyLower, "spam firewall") ||
		strings.Contains(bodyLower, "barracuda networks")
	bodySignal := bodyHasBrand && bodyHasProduct

	if !headerSignal && !serverSignal && !bodySignal {
		return nil, nil
	}

	// Determine detection method
	detectionMethod := "body"
	if headerSignal || serverSignal {
		detectionMethod = "header"
	}

	// Version extraction
	version := extractBarracudaVersion(resp, bodyLower)

	// Collect sanitized X-Barracuda-* headers
	barracudaHeaders := collectBarracudaHeaders(resp)

	// Build metadata
	metadata := map[string]any{
		"vendor":           "Barracuda Networks",
		"product":          "Email Security Gateway",
		"detection_method": detectionMethod,
	}
	if len(barracudaHeaders) > 0 {
		metadata["barracuda_headers"] = barracudaHeaders
	}

	return &FingerprintResult{
		Technology: "barracuda-esg",
		Version:    version,
		CPEs:       []string{buildBarracudaCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityCritical,
	}, nil
}

// hasBarracudaHeaders returns true if any response header key starts with
// "X-Barracuda" (case-insensitive).
func hasBarracudaHeaders(resp *http.Response) bool {
	for key := range resp.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-barracuda") {
			return true
		}
	}
	return false
}

// collectBarracudaHeaders returns a map of all X-Barracuda-* header keys to
// their sanitized first values.
func collectBarracudaHeaders(resp *http.Response) map[string]string {
	result := make(map[string]string)
	for key, vals := range resp.Header {
		if strings.HasPrefix(strings.ToLower(key), "x-barracuda") {
			if len(vals) > 0 {
				result[key] = sanitizeBarracudaHeaderValue(vals[0])
			}
		}
	}
	return result
}

// sanitizeBarracudaHeaderValue strips control characters and non-printable
// bytes from a header value before storing it in Metadata. Keeps only runes
// in the range 0x20–0x7E (printable ASCII). Caps output at 512 bytes.
func sanitizeBarracudaHeaderValue(s string) string {
	if len(s) > 512 {
		s = s[:512]
	}
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r >= 0x20 && r <= 0x7E {
			b = utf8.AppendRune(b, r)
		}
	}
	return string(b)
}

// extractBarracudaVersion attempts to extract a version string from the
// X-Barracuda-Version header first, then falls back to body text patterns.
// Returns "" if no valid version is found.
func extractBarracudaVersion(resp *http.Response, bodyLower string) string {
	// Primary: X-Barracuda-Version header
	if v := resp.Header.Get("X-Barracuda-Version"); v != "" {
		if candidate := validateBarracudaVersion(v); candidate != "" {
			return candidate
		}
	}

	// Fallback: body version pattern
	if matches := barracudaBodyVersionPattern.FindStringSubmatch(bodyLower); len(matches) >= 2 {
		if candidate := validateBarracudaVersion(matches[1]); candidate != "" {
			return candidate
		}
	}

	return ""
}

// validateBarracudaVersion trims, length-caps, and regex-validates a candidate
// version string. Returns the version on success or "" on failure.
func validateBarracudaVersion(v string) string {
	v = strings.TrimSpace(v)
	if len(v) > barracudaMaxVersionLen {
		return ""
	}
	if !barracudaVersionValidRegex.MatchString(v) {
		return ""
	}
	return v
}

// buildBarracudaCPE constructs the CPE 2.3 string for Barracuda ESG firmware.
// Uses type "o" (operating system/firmware) per NVD CPE for CVE-2023-2868.
// When version is empty, uses "*" per CPE 2.3 spec.
func buildBarracudaCPE(version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:o:barracuda:email_security_gateway_firmware:%s:*:*:*:*:*:*:*", v)
}
