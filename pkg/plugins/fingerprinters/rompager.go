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
Package fingerprinters provides HTTP fingerprinting for Allegro RomPager embedded web server.

# Detection Strategy

RomPager is an embedded HTTP server developed by Allegro Software, widely deployed
in home routers and DSL modems from vendors including D-Link, ZyXEL, Huawei, and
Billion. Versions prior to 4.34 are affected by the "Misfortune Cookie" vulnerability
(CVE-2014-9222), which allows unauthenticated remote code execution.

Detection uses Server header:
  - Standard: "RomPager/4.07 UPnP/1.0", "RomPager/4.51 UPnP/1.0"
  - Vendor-modified: "Allegro-Software-RomPager/4.34"
  - Bare (no version): "RomPager"

# Detection Method

 1. Check Server header for "rompager/" (case-insensitive, slash required to avoid
    false positives like "notRomPager"), or exact match "rompager" (no version)
 2. Accept status codes 200-499 (reject 5xx server errors)
 3. Extract version and optional UPnP version if present
 4. Validate version format to prevent CPE injection
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// RomPagerFingerprinter detects Allegro RomPager embedded web server via Server header
type RomPagerFingerprinter struct{}

// romPagerVersionRegex extracts version from Server header
// Matches: RomPager/4.07, RomPager/4.34, RomPager/4.51, Allegro-Software-RomPager/4.34
var romPagerVersionRegex = regexp.MustCompile(`(?i)RomPager/(\S+)`)

// romPagerVersionValidationRegex validates extracted version format
// Prevents CPE injection by ensuring version contains only digits, dots, and alphanumeric suffixes
var romPagerVersionValidationRegex = regexp.MustCompile(`^[\d]+[\d.]*[a-zA-Z0-9]*$`)

// romPagerUPnPVersionRegex extracts UPnP version from Server header
// Matches: UPnP/1.0, UPnP/1.1
var romPagerUPnPVersionRegex = regexp.MustCompile(`(?i)UPnP/([\d]+[\d.]*)`)

// romPagerUPnPVersionValidationRegex validates extracted UPnP version format
// Only allows digits and dots to prevent CPE injection
var romPagerUPnPVersionValidationRegex = regexp.MustCompile(`^[\d]+[\d.]*$`)

func init() {
	Register(&RomPagerFingerprinter{})
}

func (f *RomPagerFingerprinter) Name() string {
	return "rompager"
}

func (f *RomPagerFingerprinter) Match(resp *http.Response) bool {
	// Only accept 2xx-4xx responses (reject 5xx server errors)
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Check Server header for "rompager/" (case-insensitive, slash required to avoid
	// false positives with words like "notrompager") or bare "rompager" (no version)
	server := strings.ToLower(resp.Header.Get("Server"))
	return strings.Contains(server, "rompager/") || server == "rompager"
}

func (f *RomPagerFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Only accept 2xx-4xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Extract Server header
	serverHeader := resp.Header.Get("Server")
	if serverHeader == "" {
		return nil, nil
	}

	// Verify it contains "rompager/" (case-insensitive) or is exactly "rompager" (no version)
	serverLower := strings.ToLower(serverHeader)
	if !strings.Contains(serverLower, "rompager/") && serverLower != "rompager" {
		return nil, nil
	}

	// Additional check: Ensure Server header doesn't contain CPE-like patterns
	// that could indicate injection attempts (e.g., "RomPager/1.0:*:*:*:*:*:*:*")
	if strings.Contains(serverHeader, ":*:") {
		return nil, nil
	}

	// Extract version from Server header if present
	version := ""
	matches := romPagerVersionRegex.FindStringSubmatch(serverHeader)
	if len(matches) >= 2 {
		version = matches[1]

		// Validate version format to prevent CPE injection
		if !romPagerVersionValidationRegex.MatchString(version) {
			return nil, nil
		}
	}

	// Build metadata
	metadata := map[string]any{
		"vendor":        "Allegro",
		"product":       "RomPager",
		"server_header": sanitizeHTTPHeaderValue(serverHeader),
	}

	// Extract UPnP version if present
	upnpMatches := romPagerUPnPVersionRegex.FindStringSubmatch(serverHeader)
	if len(upnpMatches) >= 2 && romPagerUPnPVersionValidationRegex.MatchString(upnpMatches[1]) {
		metadata["upnp_version"] = upnpMatches[1]
	}

	return &FingerprintResult{
		Technology: "rompager",
		Version:    version,
		CPEs:       []string{buildRomPagerCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildRomPagerCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:allegrosoft:rompager:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:allegrosoft:rompager:%s:*:*:*:*:*:*:*", version)
}
