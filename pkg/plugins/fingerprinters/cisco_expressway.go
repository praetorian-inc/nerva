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

// CiscoExpresswayFingerprinter detects Cisco Expressway/VCS (Video Communication Server).
//
// Detection Strategy:
// Cisco Expressway (formerly TelePresence VCS) is a collaboration gateway for video
// conferencing. It typically runs on port 8443 with XMPP on 5222.
//
// Observed behavior from PALIG hunt:
// - Root "/" on port 8443 returns: `<html><head><title>Bad Request</title></head><body></body></html>`
// - Server header: CE_E (Expressway-E, edge/external) or CE_C (Expressway-C, core/internal)
// - This "Bad Request" response is characteristic but not unique enough alone
//
// Detection approach - use ProbeEndpoint for a more distinctive page:
// - ProbeEndpoint: /login - the Expressway web admin login page contains distinctive markers
//
// Match():
// - Accept status 200-499
// - Check body for "Expressway" or "TelePresence" or "TANDBERG" (legacy brand name)
// - OR check Server header for "Cisco" or "Expressway" or "CE_E" or "CE_C"
//
// Fingerprint():
// 1. Check body for "Expressway" (product name in login page title/text)
// 2. Check body for "TelePresence" (legacy product name, still appears in some versions)
// 3. Check body for "TANDBERG" (original manufacturer before Cisco acquisition)
// 4. Check Server header for CE_E or CE_C (distinctive Expressway identifiers)
// 5. Extract version if present: pattern `(?:Expressway|VCS|TelePresence)[\s-]*(?:version\s*)?[:\s]*(X?\d+\.\d+(?:\.\d+)?)`
// 6. If only the generic "Bad Request" page is found with no distinctive indicators, return nil (too generic)
//
// Version format: Cisco Expressway uses "X" prefix versions like X14.3.2, X15.0.1
// Version regex: `^X?\d+\.\d+(\.\d+)?$`
//
// CPE: cpe:2.3:a:cisco:expressway:${version}:*:*:*:*:*:*:*
//
// Metadata:
// - vendor: "Cisco", product: "Expressway"
// - legacyName: "TelePresence VCS" if TANDBERG/TelePresence detected
type CiscoExpresswayFingerprinter struct{}

func init() {
	Register(&CiscoExpresswayFingerprinter{})
}

// expresswayServerHeaders are Server header values specific to Cisco Expressway.
// CE_E = Collaboration Edge - Expressway-E (edge/external)
// CE_C = Collaboration Edge - Expressway-C (core/internal)
var expresswayServerHeaders = []string{"ce_e", "ce_c"}

// Expressway detection patterns in response body
var expresswayPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)expressway`),
	regexp.MustCompile(`(?i)telepresence`),
	regexp.MustCompile(`(?i)tandberg`),
}

// Expressway version extraction pattern
// Accepts: X14.3.2, X15.0.1, 14.3.2 (with or without X prefix)
var expresswayVersionPattern = regexp.MustCompile(`(?i)(?:version|expressway|vcs|telepresence)[\s-]*(?:version\s*)?[:\s]+(X?\d+\.\d+(?:\.\d+)?)`)

// Expressway version validation regex
var expresswayVersionRegex = regexp.MustCompile(`^X?\d+\.\d+(\.\d+)?$`)

func isExpresswayServerHeader(serverHeader string) bool {
	serverLower := strings.ToLower(strings.TrimSpace(serverHeader))
	for _, h := range expresswayServerHeaders {
		if serverLower == h {
			return true
		}
	}
	return false
}

func (f *CiscoExpresswayFingerprinter) Name() string {
	return "cisco-expressway"
}

func (f *CiscoExpresswayFingerprinter) ProbeEndpoint() string {
	return "/login"
}

func (f *CiscoExpresswayFingerprinter) Match(resp *http.Response) bool {
	// Accept 2xx-4xx responses (reject 5xx server errors)
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Check Server header for Cisco, Expressway, or CE_E/CE_C
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverHeader, "cisco") || strings.Contains(serverHeader, "expressway") || isExpresswayServerHeader(resp.Header.Get("Server")) {
		return true
	}

	// Always match for body-based detection in Fingerprint()
	// This allows us to check body patterns during fingerprinting
	return true
}

func (f *CiscoExpresswayFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Accept 2xx-4xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Check response body for Expressway markers
	bodyStr := string(body)
	bodyMatch := false
	legacyDetected := false

	for _, pattern := range expresswayPatterns {
		if pattern.MatchString(bodyStr) {
			bodyMatch = true
			// Detect legacy naming
			if strings.Contains(strings.ToLower(bodyStr), "telepresence") || strings.Contains(strings.ToLower(bodyStr), "tandberg") {
				legacyDetected = true
			}
			break
		}
	}

	// Check if Server header is a known Expressway-specific header
	serverHeaderMatch := isExpresswayServerHeader(resp.Header.Get("Server"))

	// Require either body match OR distinctive server header
	if !bodyMatch && !serverHeaderMatch {
		return nil, nil
	}

	// Extract version
	version := extractExpresswayVersion(bodyStr)

	// Build metadata
	metadata := map[string]any{
		"vendor":  "Cisco",
		"product": "Expressway",
	}

	if legacyDetected {
		metadata["legacyName"] = "TelePresence VCS"
	}

	return &FingerprintResult{
		Technology: "cisco-expressway",
		Version:    version,
		CPEs:       []string{buildCiscoExpresswayCPE(version)},
		Metadata:   metadata,
	}, nil
}

func extractExpresswayVersion(body string) string {
	// Extract version from body using pattern
	matches := expresswayVersionPattern.FindStringSubmatch(body)
	if len(matches) > 1 {
		version := matches[1]
		// Validate version format to prevent CPE injection
		if expresswayVersionRegex.MatchString(version) {
			return version
		}
	}

	return ""
}

func buildCiscoExpresswayCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:cisco:expressway:%s:*:*:*:*:*:*:*", version)
}
