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

// SonicWallFingerprinter detects SonicWall firewall and VPN appliances.
//
// Detection Strategy:
// SonicWall appliances expose distinctive login pages and management interfaces.
// Detection uses multiple signals:
//
//  1. Server Header: "SonicWALL" in Server header (definitive indicator)
//  2. Login Page: /auth1.html — works on both SSL-VPN portals and admin interfaces,
//     contains version-bearing JS/CSS asset filenames in the response body
//  3. API Endpoint: /api/sonicos — SonicOS REST API responses with version info
//  4. Body Patterns: SonicWall branding, NetExtender/Virtual Office references,
//     SonicOS version strings, product model identifiers
//
// Security Risks:
//   - CVE-2021-20016: SQL injection in SMA 100 series
//   - CVE-2024-40766: Authentication bypass in SonicOS
//   - SSL-VPN portal exposure via NetExtender
//   - Management interface brute-force via admin panel
type SonicWallFingerprinter struct{}

func init() {
	Register(&SonicWallFingerprinter{})
}

// sonicWallVersionRegex validates SonicOS version format (prevents CPE injection).
// Accepts: 7, 7.0.1, 6.5.4.4, 7.1.1-7040, 6.5.4.15-116n
var sonicWallVersionRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,4}(?:-[0-9a-zA-Z]+)?$`)

// SonicOS version extraction patterns from response body
var (
	// Matches: SonicOS 7.0.1, SonicOS Enhanced 6.5.4.4
	sonicOSVersionPattern = regexp.MustCompile(`(?i)SonicOS\s+(?:Enhanced\s+)?([0-9]+(?:\.[0-9]+){2,4}(?:-[0-9a-zA-Z]+)?)`)
	// Matches: firmware-version="7.0.1-5035" or firmware_version: "7.0.1"
	sonicWallFirmwarePattern = regexp.MustCompile(`(?i)firmware[_-]version[=:]["']?\s*([0-9]+(?:\.[0-9]+){2,4}(?:-[0-9a-zA-Z]+)?)`)
	// Matches: "firmware_version":"7.0.1-5035" in SonicOS API JSON responses
	sonicOSAPIVersionPattern = regexp.MustCompile(`(?i)"firmware_version"\s*:\s*"([0-9]+(?:\.[0-9]+){2,4}(?:-[0-9a-zA-Z]+)?)"`)

	// Real-world patterns from live SonicWall devices:
	// Matches JS asset filenames: auth-5.0.0-2655861013.js, md5-5.0.0-4190932482.js
	// Also handles language-suffix variants: auth-6.2.5-2996728830(eng).js
	// The "o" suffix (e.g., "5.0o") is a build variant marker and is stripped.
	sonicWallJSVersionPattern = regexp.MustCompile(`(?:auth|md5|browserCheck|jquery|cookies)-(\d+\.\d+(?:\.\d+)?)o?-\d+(?:\([a-z]+\))?\.js`)
	// Matches CSS asset filenames: swl_login-5.0o-586369509.css
	// Also handles language-suffix variants: swl_login-6.2.5-4163414724(eng).css
	sonicWallCSSVersionPattern = regexp.MustCompile(`swl_login-(\d+\.\d+(?:\.\d+)?)o?-\d+(?:\([a-z]+\))?\.css`)
	// Matches NetExtender version variable: var nelaunchxpsversion = "7.0.0.107";
	sonicWallNEVersionPattern = regexp.MustCompile(`nelaunchxpsversion\s*=\s*"(\d+\.\d+\.\d+\.\d+)"`)
	// Matches NetExtender download URL: /netextender/plugin/7.0/npNELaunch.xpi
	sonicWallNEURLPattern = regexp.MustCompile(`/netextender/plugin/(\d+\.\d+)/`)
	// Matches SonicUI version in redirect URL: /sonicui/7/login/ or /sonicui/7/m/mgmt/
	sonicWallUIVersionPattern = regexp.MustCompile(`/sonicui/(\d+)(?:/|$)`)
)

// SonicWall product model patterns
var sonicWallModelPattern = regexp.MustCompile(`(?i)(?:SonicWall|SonicWALL)\s+(TZ\s*\d+|NSA\s*\d+|NSsp\s*\d+|SuperMassive\s*\d+|SOHO\s*\w*|SMA\s*\d+)`)

// Body patterns for SonicWall detection (require header confirmation or multiple matches)
var sonicWallBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SonicWALL`),
	regexp.MustCompile(`(?i)NetExtender`),
	regexp.MustCompile(`(?i)Virtual\s+Office`),
	regexp.MustCompile(`(?i)/cgi-bin/welcome`),
	regexp.MustCompile(`(?i)SonicOS`),
	regexp.MustCompile(`(?i)swl_portal`),
	regexp.MustCompile(`(?i)sslvpn/login`),
	regexp.MustCompile(`(?i)/api/sonicos`),
	regexp.MustCompile(`(?i)sonicos_api`),
	regexp.MustCompile(`(?i)sslvpnLogin`),
	regexp.MustCompile(`(?i)auth1\.html.*authFrm`),
	regexp.MustCompile(`nelaunchxpsversion`),
	regexp.MustCompile(`(?i)/sonicui/`),
}

func (f *SonicWallFingerprinter) Name() string {
	return "sonicwall"
}

func (f *SonicWallFingerprinter) ProbeEndpoint() string {
	return "/auth1.html"
}

func (f *SonicWallFingerprinter) Match(resp *http.Response) bool {
	// Only accept 2xx-4xx responses (reject 5xx server errors)
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Primary indicator: SonicWALL in Server header (definitive)
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverHeader, "sonicwall") {
		return true
	}

	// Secondary indicator: SonicWall-specific headers
	if resp.Header.Get("X-Sonicwall-Cfs-Policy") != "" {
		return true
	}

	return false
}

func (f *SonicWallFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Only accept 2xx-4xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Check Server header
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	headerMatch := strings.Contains(serverHeader, "sonicwall")

	// Check SonicWall-specific headers
	if resp.Header.Get("X-Sonicwall-Cfs-Policy") != "" {
		headerMatch = true
	}

	// Check body for SonicWall markers
	bodyStr := string(body)
	bodyMatchCount := 0
	for _, pattern := range sonicWallBodyPatterns {
		if pattern.MatchString(bodyStr) {
			bodyMatchCount++
		}
	}

	// Require header match OR at least 2 distinct body pattern matches
	// to reduce false positives from pages that merely mention "SonicWall"
	if !headerMatch && bodyMatchCount < 2 {
		return nil, nil
	}

	// Build metadata
	metadata := make(map[string]any)
	metadata["vendor"] = "SonicWall"
	metadata["product"] = "SonicWall Firewall"

	// Detect DELL branding (older devices)
	if strings.Contains(bodyStr, "DELL SonicWALL") || strings.Contains(bodyStr, "Dell SonicWALL") {
		metadata["vendor"] = "Dell SonicWall"
	}

	// Extract version from body
	version := extractSonicWallVersion(body)

	// Try extracting version from Location header (SonicOS 7.x redirects to /sonicui/7/login/)
	if version == "" {
		if loc := resp.Header.Get("Location"); loc != "" {
			if matches := sonicWallUIVersionPattern.FindStringSubmatch(loc); len(matches) > 1 {
				version = matches[1]
			}
		}
	}

	// Validate version format if present (prevent CPE injection)
	if version != "" && !sonicWallVersionRegex.MatchString(version) {
		version = "" // Invalid format, discard
	}

	// Detect product model
	if model := extractSonicWallModel(bodyStr); model != "" {
		metadata["productModel"] = model
	}

	// Detect SSL-VPN
	if detectSonicWallSSLVPN(bodyStr, resp.Header) {
		metadata["sslVPN"] = true
	}

	// Check Location header for SonicOS 7.x management redirect
	locationHeader := resp.Header.Get("Location")
	if strings.Contains(locationHeader, "/sonicui/") || strings.Contains(bodyStr, "/sonicui/") {
		metadata["managementInterface"] = "web-admin"
	}

	// Detect management interface type
	if strings.Contains(bodyStr, "/cgi-bin/welcome") || strings.Contains(bodyStr, "managementLogin") ||
		strings.Contains(bodyStr, "auth1.html") || strings.Contains(bodyStr, "authFrm") {
		metadata["managementInterface"] = "web-admin"
	}
	if strings.Contains(bodyStr, "sslvpn") || strings.Contains(bodyStr, "NetExtender") ||
		strings.Contains(bodyStr, "Virtual Office") {
		metadata["managementInterface"] = "ssl-vpn"
	}

	// Detect SonicOS REST API responses
	if strings.Contains(bodyStr, "/api/sonicos") || strings.Contains(bodyStr, "sonicos_api") ||
		strings.Contains(bodyStr, `"status"`) && strings.Contains(bodyStr, `"sonicos"`) {
		metadata["managementInterface"] = "rest-api"
	}

	// Default to web-admin if we detected SonicWall but couldn't determine specific interface
	if _, ok := metadata["managementInterface"]; !ok {
		if headerMatch {
			metadata["managementInterface"] = "web-admin"
		}
	}

	result := &FingerprintResult{
		Technology: "sonicwall",
		Version:    version,
		CPEs:       []string{buildSonicWallCPE(version)},
		Metadata:   metadata,
	}

	return result, nil
}

// extractSonicWallVersion attempts to extract SonicOS version from the response body.
func extractSonicWallVersion(body []byte) string {
	// Try SonicOS version pattern first (most common)
	if matches := sonicOSVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	// Try firmware version pattern
	if matches := sonicWallFirmwarePattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	// Try SonicOS API JSON response pattern
	if matches := sonicOSAPIVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	// Fallback: JS asset filename version (real SonicWall devices embed version in filenames)
	// e.g., auth-5.0.0-2655861013.js, md5-5.0.0-4190932482.js
	if matches := sonicWallJSVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	// Fallback: CSS asset filename version
	// e.g., swl_login-5.0o-586369509.css (the "o" suffix is stripped by the regex)
	if matches := sonicWallCSSVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	// Fallback: NetExtender version variable
	// e.g., var nelaunchxpsversion = "7.0.0.107";
	if matches := sonicWallNEVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	// Fallback: NetExtender download URL version
	// e.g., /netextender/plugin/7.0/npNELaunch.xpi
	if matches := sonicWallNEURLPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	// Fallback: SonicUI version from URL path in body (e.g., /sonicui/7/login/)
	if matches := sonicWallUIVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	return ""
}

// extractSonicWallModel attempts to extract the product model from the response body.
func extractSonicWallModel(bodyStr string) string {
	if matches := sonicWallModelPattern.FindStringSubmatch(bodyStr); len(matches) > 1 {
		return strings.TrimSpace(matches[1])
	}
	return ""
}

// detectSonicWallSSLVPN checks for SSL-VPN indicators in the response.
func detectSonicWallSSLVPN(bodyStr string, headers http.Header) bool {
	sslVPNPatterns := []string{
		"NetExtender",
		"Virtual Office",
		"sslvpn",
		"SSL-VPN",
		"SSLVPN",
		"swl_portal",
		"sslvpnLogin",
	}
	for _, pattern := range sslVPNPatterns {
		if strings.Contains(bodyStr, pattern) {
			return true
		}
	}

	// Check for SSL-VPN cookie
	for _, cookie := range headers["Set-Cookie"] {
		if strings.Contains(cookie, "swap") || strings.Contains(cookie, "SonicWall") {
			return true
		}
	}

	return false
}

// buildSonicWallCPE constructs a CPE string for SonicWall/SonicOS.
// CPE format: cpe:2.3:o:sonicwall:sonicos:<version>:*:*:*:*:*:*:*
func buildSonicWallCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:o:sonicwall:sonicos:%s:*:*:*:*:*:*:*", version)
}
