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

// SophosFirewallFingerprinter detects Sophos XG/XGS Firewall appliances.
//
// Detection Strategy:
// Sophos XG/XGS Firewall exposes web admin and user portal interfaces.
// Detection uses multiple signals:
//
//  1. Server Header: "xxxx" (exactly 4 x's, case-insensitive) — Sophos-specific
//     obfuscated server header. NOTE: FortiGate uses "xxxxxxxx-xxxxx" (8x-dash-5x),
//     which is a different string. "xxxx" (4 chars exactly) is safe to use for Sophos.
//  2. HTML Title: <title>Sophos</title> in login page body
//  3. Body Marker: uiLangToHTMLLangAttributeValueMapping (unique Sophos JS string)
//  4. Path Markers: /webconsole/ or /userportal/ in body or Location header
//
// Active Probe:
//   - GET /webconsole/webpages/login.jsp returns admin login page
//
// Default Ports:
//   - 4444: Default admin web console (HTTPS)
//   - 443: User portal / VPN portal
//   - 8090: Captive portal (HTTP)
//   - 8091: Captive portal (HTTPS)
//   - 4443: Alternative admin port
//
// Version Detection:
// SFOS version extracted from CSS asset paths in the login page body:
//   - typography.css?version=X.X.X.XXX (newer SFOS)
//   - loginstylesheet.css?ver=X.X.X.XXX (older SFOS ≤17.x)
//
// Version format is always 4 dotted decimal groups (e.g., 19.5.3.652, 17.5.9.577).
// CPE uses only the first 3 components: cpe:2.3:o:sophos:sfos:<major.minor.patch>:*:*:*:*:*:*:*
//
// Security Risks:
//   - CVE-2020-12271: Pre-auth SQL injection (Asnarök trojan), CVSS 9.8
//   - CVE-2022-1040: Authentication bypass in User Portal and Webadmin, CVSS 9.8
//   - CVE-2022-3236: Code injection in User Portal and Webadmin, CVSS 9.8
//   - CVE-2023-1671: Pre-auth command injection, CVSS 9.8
type SophosFirewallFingerprinter struct{}

func init() {
	Register(&SophosFirewallFingerprinter{})
}

// sophosVersionPattern extracts SFOS version from CSS asset paths in the login page.
// Matches:
//   - typography.css?version=19.5.3.652
//   - loginstylesheet.css?ver=17.5.9.577
var sophosVersionPattern = regexp.MustCompile(`(?:typography\.css\?version=|loginstylesheet\.css\?ver=)(\d+\.\d+\.\d+\.\d+)`)

// sophosVersionValidRegex validates extracted version format for CPE injection safety.
// Accepts: 19.5.3.652, 17.5.9.577
var sophosVersionValidRegex = regexp.MustCompile(`^\d+\.\d+\.\d+\.\d+$`)

func (f *SophosFirewallFingerprinter) Name() string {
	return "sophos-firewall"
}

func (f *SophosFirewallFingerprinter) ProbeEndpoint() string {
	return "/webconsole/webpages/login.jsp"
}

// Match is a fast pre-filter. Accepts text/html responses or responses with
// the Sophos-specific Server header ("xxxx", exactly 4 x's).
func (f *SophosFirewallFingerprinter) Match(resp *http.Response) bool {
	// Only accept 2xx-4xx responses (reject 5xx server errors)
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Primary indicator: Sophos-specific obfuscated Server header (exactly "xxxx")
	if strings.EqualFold(resp.Header.Get("Server"), "xxxx") {
		return true
	}

	// Accept text/html responses for body-based detection
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full detection and returns a result if this is a Sophos device.
// Returns nil, nil for non-matching responses.
func (f *SophosFirewallFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Only accept 2xx-4xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	bodyStr := string(body)

	// Signal 1: Sophos-specific obfuscated Server header (exactly "xxxx", 4 x's)
	serverHeader := strings.EqualFold(resp.Header.Get("Server"), "xxxx")

	// Signal 2: HTML title contains Sophos branding
	titleMatch := sophosContainsTitle(bodyStr)

	// Signal 3: Unique Sophos JavaScript identifier
	jsMarkerMatch := strings.Contains(bodyStr, "uiLangToHTMLLangAttributeValueMapping")

	// Signal 4: Sophos path markers in body or Location header
	location := resp.Header.Get("Location")
	hasWebconsole := strings.Contains(bodyStr, "/webconsole/") || strings.Contains(location, "/webconsole/")
	hasUserportal := strings.Contains(bodyStr, "/userportal/") || strings.Contains(location, "/userportal/")
	pathMarkerMatch := hasWebconsole || hasUserportal

	// Detection requires corroborating signals to prevent false positives:
	// - Server header "xxxx" alone is too generic (any server could emit it),
	//   so it requires at least a Sophos path marker in body/Location header.
	// - Title "Sophos" alone requires at least one body marker (JS or path).
	bodyConfirmed := titleMatch && (jsMarkerMatch || pathMarkerMatch)
	serverConfirmed := serverHeader && pathMarkerMatch
	if !serverConfirmed && !bodyConfirmed {
		return nil, nil
	}

	// Build metadata
	metadata := make(map[string]any)
	metadata["vendor"] = "Sophos"
	metadata["product"] = "Sophos Firewall"

	if serverHeader {
		metadata["server_header"] = "xxxx"
	}

	// Determine interface type from path markers
	if hasWebconsole {
		metadata["interface_type"] = "web-admin"
	} else if hasUserportal {
		metadata["interface_type"] = "user-portal"
	}

	// Extract SFOS version from CSS asset paths
	fullVersion := extractSophosVersion(body)
	if fullVersion != "" {
		metadata["firmware_version"] = fullVersion
	}

	// Build 3-part CPE version (strip build number)
	cpeVersion := buildSophosCPEVersion(fullVersion)

	return &FingerprintResult{
		Technology: "sophos-firewall",
		Version:    cpeVersion,
		CPEs:       buildSophosCPEs(cpeVersion),
		Metadata:   metadata,
	}, nil
}

// sophosContainsTitle checks whether the response body contains <title>Sophos</title>
// (case-insensitive). This matches the exact Sophos login page title.
func sophosContainsTitle(bodyStr string) bool {
	lower := strings.ToLower(bodyStr)
	return strings.Contains(lower, "<title>sophos</title>")
}

// extractSophosVersion extracts the full 4-part SFOS version from CSS asset paths.
// Returns empty string if not found or format is invalid.
func extractSophosVersion(body []byte) string {
	matches := sophosVersionPattern.FindSubmatch(body)
	if len(matches) < 2 {
		return ""
	}

	version := string(matches[1])

	// Validate format to prevent CPE injection
	if !sophosVersionValidRegex.MatchString(version) {
		return ""
	}

	return version
}

// buildSophosCPEVersion converts a full 4-part SFOS version (e.g., "19.5.3.652")
// to a 3-part CPE version (e.g., "19.5.3") by stripping the build number.
// Returns "*" if the input is empty or invalid.
func buildSophosCPEVersion(fullVersion string) string {
	if fullVersion == "" {
		return ""
	}

	// Validate the full version
	if !sophosVersionValidRegex.MatchString(fullVersion) {
		return ""
	}

	// Split on "." and take first 3 components
	parts := strings.SplitN(fullVersion, ".", 4)
	if len(parts) < 3 {
		return ""
	}

	return parts[0] + "." + parts[1] + "." + parts[2]
}

// buildSophosCPEs returns CPE strings for both current (sfos) and legacy (xg_firewall_firmware)
// NVD naming conventions. Older CVEs (e.g., CVE-2020-12271) use xg_firewall_firmware.
func buildSophosCPEs(version string) []string {
	if version == "" {
		return []string{
			"cpe:2.3:o:sophos:sfos:*:*:*:*:*:*:*:*",
			"cpe:2.3:o:sophos:xg_firewall_firmware:*:*:*:*:*:*:*:*",
		}
	}
	return []string{
		fmt.Sprintf("cpe:2.3:o:sophos:sfos:%s:*:*:*:*:*:*:*", version),
		fmt.Sprintf("cpe:2.3:o:sophos:xg_firewall_firmware:%s:*:*:*:*:*:*:*", version),
	}
}
