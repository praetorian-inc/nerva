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
Package fingerprinters provides HTTP fingerprinting for Boa embedded web server.

# Detection Strategy

Boa is a single-tasking HTTP server abandoned since 2005, still found on
~200-400K devices including IP cameras, DVRs, routers, and IoT devices
via RealTek SDK bundling. Being permanently unmaintained makes any Boa
instance a high-risk finding.

Detection uses Server header:
  - Standard: "Boa/0.94.14rc21", "Boa/0.94.13"
  - Early versions: "Boa/0.92o", "Boa/0.93.15"
  - Vendor-modified: "Boa/0.94.101wk"

# Detection Method

 1. Check Server header for "Boa/" (case-insensitive, slash required to avoid false positives)
 2. Accept status codes 200-499 (reject 5xx server errors)
 3. Extract version if present
 4. Validate version format to prevent CPE injection
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// BoaFingerprinter detects Boa embedded web server via Server header
type BoaFingerprinter struct{}

// boaVersionRegex extracts version from Server header
// Matches: Boa/0.94.14rc21, Boa/0.94.13, Boa/0.92o, Boa/0.94.101wk
var boaVersionRegex = regexp.MustCompile(`(?i)Boa/([\d]+[\d.]*\w*)`)

// boaVersionValidationRegex validates extracted version format
// Prevents CPE injection by ensuring version contains only digits, dots, and alphanumeric suffixes
var boaVersionValidationRegex = regexp.MustCompile(`(?i)^[\d]+[\d.]*\w*$`)

func init() {
	Register(&BoaFingerprinter{})
}

func (f *BoaFingerprinter) Name() string {
	return "boa"
}

func (f *BoaFingerprinter) Match(resp *http.Response) bool {
	// Only accept 2xx-4xx responses (reject 5xx server errors)
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Check Server header for "boa/" (case-insensitive, slash required to avoid false positives
	// with words like "aboard") or bare "boa" (no version)
	server := strings.ToLower(resp.Header.Get("Server"))
	return strings.Contains(server, "boa/") || server == "boa"
}

func (f *BoaFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Only accept 2xx-4xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Extract Server header
	serverHeader := resp.Header.Get("Server")
	if serverHeader == "" {
		return nil, nil
	}

	// Verify it contains "boa/" (case-insensitive) or is exactly "boa" (no version)
	serverLower := strings.ToLower(serverHeader)
	if !strings.Contains(serverLower, "boa/") && serverLower != "boa" {
		return nil, nil
	}

	// Additional check: Ensure Server header doesn't contain CPE-like patterns
	// that could indicate injection attempts (e.g., "Boa/1.0.0:*:*:*:*:*:*:*")
	if strings.Contains(serverHeader, ":*:") {
		return nil, nil
	}

	// Extract version from Server header if present
	version := ""
	matches := boaVersionRegex.FindStringSubmatch(serverHeader)
	if len(matches) >= 2 {
		version = matches[1]

		// Validate version format to prevent CPE injection
		if !boaVersionValidationRegex.MatchString(version) {
			return nil, nil
		}
	}

	// Build metadata
	metadata := map[string]any{
		"vendor":        "Boa",
		"product":       "Boa",
		"server_header": serverHeader,
	}

	return &FingerprintResult{
		Technology: "boa",
		Version:    version,
		CPEs:       []string{buildBoaCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildBoaCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:boa:boa:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:boa:boa:%s:*:*:*:*:*:*:*", version)
}
