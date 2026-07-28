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

const nakivoMaxBodySize = 1 << 20

// NAKIVOFingerprinter detects NAKIVO Backup & Replication instances.
//
// Detection Strategy:
//
//  1. Standalone: HTML <title> contains "NAKIVO Backup" (case-insensitive).
//  2. Corroborated: body contains both "/c/router" AND "AuthenticationManagement"
//     — the Ext Direct RPC endpoint/action pattern unique to NAKIVO — both
//     required together.
//
// Active Probe: GET /c/login
//
// Version Detection:
// Extracted from the HTML body via a dotted three-part version pattern
// ("10.11.3"). Validated with `^\d+\.\d+\.\d+$`. Empty string if not found
// or invalid.
//
// CPE: cpe:2.3:a:nakivo:backup_\&_replication_director:<version>:*:*:*:*:*:*:*
type NAKIVOFingerprinter struct{}

func init() {
	Register(&NAKIVOFingerprinter{})
}

// nakivoTitleRegex matches the NAKIVO Backup title tag. Structural match —
// the <title> tag is a definitive page identity marker.
var nakivoTitleRegex = regexp.MustCompile(`(?i)<title[^>]*>[^<]*nakivo\s+backup[^<]*</title>`)

// nakivoVersionStrictPattern extracts a dotted three-part version that
// appears near NAKIVO-specific text, within the same HTML element.
// [^<]{0,200}? prevents crossing HTML tag boundaries, avoiding unrelated
// version-like strings (JS library versions, etc.) in neighboring tags.
// The leading [^\d.] (rather than \b) requires the character immediately
// preceding the version not be a digit or dot — this rejects mid-number
// matches against IP address fragments (e.g. "68.1.10" inside
// "192.168.1.100") while still permitting a letter prefix (e.g. "v10.11.3").
// The trailing \b rejects partial matches against longer alphanumeric
// tokens (e.g. "5.38abc").
var nakivoVersionStrictPattern = regexp.MustCompile(`(?i)nakivo[^<]{0,200}?[^\d.](\d{1,2}\.\d{1,2}\.\d{1,2})\b`)

// nakivoVersionLoosePattern is the same as nakivoVersionStrictPattern but
// allows crossing HTML tag boundaries. Used only as a fallback when the
// strict pattern finds no match, to support version text that legitimately
// appears in a different tag than the nearest NAKIVO mention (e.g. version
// in <body> following a <title> mention).
var nakivoVersionLoosePattern = regexp.MustCompile(`(?is)nakivo.{0,200}?[^\d.](\d{1,2}\.\d{1,2}\.\d{1,2})\b`)

// nakivoVersionValidRegex validates extracted version strings before CPE use.
var nakivoVersionValidRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func (f *NAKIVOFingerprinter) Name() string {
	return "nakivo"
}

func (f *NAKIVOFingerprinter) ProbeEndpoint() string {
	return "/c/login"
}

// Match is a fast pre-filter. Accepts responses in the 200-499 range with
// text/html content type.
func (f *NAKIVOFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode > 499 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full detection and returns a result if this is a
// NAKIVO instance. Returns nil, nil for non-matching responses.
func (f *NAKIVOFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 499 {
		return nil, nil
	}

	if len(body) > nakivoMaxBodySize {
		body = body[:nakivoMaxBodySize]
	}
	bodyStr := string(body)

	// Signal 1 (standalone): title contains "NAKIVO Backup".
	hasStandalone := nakivoTitleRegex.MatchString(bodyStr)

	// Signal 2 (corroborated): Ext Direct RPC endpoint + action, both required.
	hasCorroborated := strings.Contains(bodyStr, "/c/router") && strings.Contains(bodyStr, "AuthenticationManagement")

	if !hasStandalone && !hasCorroborated {
		return nil, nil
	}

	version := extractNAKIVOVersion(bodyStr)

	return &FingerprintResult{
		Technology: "nakivo",
		Version:    version,
		CPEs:       []string{buildNAKIVOCPE(version)},
		Metadata: map[string]any{
			"vendor":  "NAKIVO",
			"product": "Backup & Replication",
		},
	}, nil
}

// extractNAKIVOVersion extracts a version anchored to NAKIVO-specific
// context. Tries the strict (same-element) pattern first; falls back to the
// tag-crossing pattern only if the strict pattern finds nothing. Returns
// empty string if no valid version is found or it contains CPE
// metacharacters.
func extractNAKIVOVersion(bodyStr string) string {
	m := nakivoVersionStrictPattern.FindStringSubmatch(bodyStr)
	if m == nil {
		m = nakivoVersionLoosePattern.FindStringSubmatch(bodyStr)
	}
	if m == nil {
		return ""
	}
	v := m[1]
	if !nakivoVersionValidRegex.MatchString(v) {
		return ""
	}
	if strings.ContainsAny(v, ":*?") {
		return ""
	}
	return v
}

// buildNAKIVOCPE constructs a CPE 2.3 string for NAKIVO Backup & Replication.
// The product name escapes the ampersand per NVD's CPE format (CVE-2024-48248).
// When version is empty, uses "*" per CPE 2.3 spec.
func buildNAKIVOCPE(version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:nakivo:backup_\\&_replication_director:%s:*:*:*:*:*:*:*", v)
}
