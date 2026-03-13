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

// CheckPointFingerprinter detects Check Point Security Gateway appliances.
//
// Detection Strategy:
// Check Point security gateways expose Gaia Portal and Mobile Access Portal
// interfaces. Detection uses active probing and passive header/body analysis:
//
//  1. Active Probe: GET /cgi-bin/home.tcl (Gaia Portal login page)
//  2. Body Patterns: Check Point-specific HTML content (Gaia Portal, Mobile Access)
//  3. Header Patterns: Check Point server identifiers and cookie patterns
//
// Security Risks:
//   - CVE-2024-24919: Information disclosure vulnerability
//   - CVE-2024-24920: Additional known vulnerability
//   - VPN portal exposure via Mobile Access Portal
//   - Management exposure via SmartConsole/Gaia Portal
//
// Metadata extracted: Gaia OS version, product type, VPN status, blade info.
type CheckPointFingerprinter struct{}

func init() {
	Register(&CheckPointFingerprinter{})
}

// gaiaVersionRegex validates Gaia OS version format to prevent CPE injection.
// Accepts versions like: R81, R81.10, R81.20, R80.40, R77.30
var gaiaVersionRegex = regexp.MustCompile(`^R\d+(\.\d+)?$`)

// gaiaVersionJSPattern extracts Gaia OS version from JavaScript variable in the
// Gaia Portal login page. Real devices embed the version as a JS variable:
//
//	var version='R81.20';var formAction="/cgi-bin/home.tcl";
var gaiaVersionJSPattern = regexp.MustCompile(`(?i)var\s+version\s*=\s*'(R\d+(?:\.\d+)?)'`)

// gaiaVersionExtract extracts Gaia OS version from response body.
// Looks for patterns like "Gaia R81.20", "Check Point Gaia R80.40".
// Used as a fallback when gaiaVersionJSPattern does not match.
var gaiaVersionExtract = regexp.MustCompile(`(?i)Gaia\s+(R\d+(?:\.\d+)?)`)

// Check Point body detection patterns
var (
	checkPointGaiaPortalPattern   = regexp.MustCompile(`(?i)(?:Check\s*Point\s*Gaia\s*Portal|/cgi-bin/home\.tcl|Gaia\s+Portal)`)
	checkPointMobileAccessPattern = regexp.MustCompile(`(?i)(?:Check\s*Point\s*Mobile\s*Access|SNX\s+VPN|sslvpn|/sslvpn/)`)
	checkPointSmartConsolePattern = regexp.MustCompile(`(?i)(?:SmartConsole|Smart\s*Dashboard|Check\s*Point\s*SmartCenter)`)
	checkPointVendorRefPattern    = regexp.MustCompile(`(?i)Check\s*Point\s+Software\s+Technologies`)
	checkPointLoginPattern        = regexp.MustCompile(`(?i)(?:cp_login|cpauth)`)
)

func (f *CheckPointFingerprinter) Name() string {
	return "checkpoint-gateway"
}

func (f *CheckPointFingerprinter) ProbeEndpoint() string {
	return "/cgi-bin/home.tcl"
}

func (f *CheckPointFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return isCheckPointHeader(resp)
}

func (f *CheckPointFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Accept 2xx-4xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	bodyStr := string(body)

	// Determine if this is a Check Point device via headers or body
	headerMatch := isCheckPointHeader(resp)

	bodyMatchCount := 0
	if checkPointGaiaPortalPattern.MatchString(bodyStr) { bodyMatchCount++ }
	if checkPointMobileAccessPattern.MatchString(bodyStr) { bodyMatchCount++ }
	if checkPointSmartConsolePattern.MatchString(bodyStr) { bodyMatchCount++ }
	if checkPointVendorRefPattern.MatchString(bodyStr) { bodyMatchCount++ }
	if checkPointLoginPattern.MatchString(bodyStr) { bodyMatchCount++ }

	// Require header match OR at least 2 distinct body pattern matches
	// to reduce false positives from pages that merely mention "Check Point"
	if !headerMatch && bodyMatchCount < 2 {
		return nil, nil
	}

	// Build metadata
	metadata := make(map[string]any)
	metadata["vendor"] = "Check Point"

	// Determine product type
	metadata["product"] = detectCheckPointProduct(bodyStr)

	// Detect VPN (Mobile Access)
	location := strings.ToLower(resp.Header.Get("Location"))
	if checkPointMobileAccessPattern.MatchString(bodyStr) ||
		strings.Contains(location, "/sslvpn/") {
		metadata["vpnEnabled"] = true
	}

	// Detect blade info from body hints
	if checkPointSmartConsolePattern.MatchString(bodyStr) {
		metadata["managementBlade"] = true
	}

	// Extract Gaia OS version
	version := extractGaiaVersion(body)

	return &FingerprintResult{
		Technology: "checkpoint-gateway",
		Version:    version,
		CPEs:       []string{buildCheckPointCPE(version)},
		Metadata:   metadata,
	}, nil
}

// isCheckPointHeader checks response headers for Check Point indicators.
func isCheckPointHeader(resp *http.Response) bool {
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverHeader, "check point") || strings.Contains(serverHeader, "cpws") {
		return true
	}
	if resp.Header.Get("X-Check-Point") != "" {
		return true
	}
	location := strings.ToLower(resp.Header.Get("Location"))
	if strings.Contains(location, "/cgi-bin/home.tcl") || strings.Contains(location, "/sslvpn/") {
		return true
	}
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		cookieLower := strings.ToLower(cookie)
		if strings.Contains(cookieLower, "cpsession") ||
			strings.Contains(cookieLower, "cpreferenceid") {
			return true
		}
	}
	return false
}

// detectCheckPointProduct identifies the specific Check Point product type.
func detectCheckPointProduct(bodyStr string) string {
	if checkPointSmartConsolePattern.MatchString(bodyStr) {
		return "Management Server"
	}
	if checkPointGaiaPortalPattern.MatchString(bodyStr) {
		return "Security Gateway"
	}
	if checkPointMobileAccessPattern.MatchString(bodyStr) {
		return "Mobile Access Portal"
	}
	return "Security Gateway"
}

// extractGaiaVersion extracts the Gaia OS version from response body.
// It tries gaiaVersionJSPattern first (matches real-world Gaia Portal login pages
// that embed the version as "var version='R81.20'"), then falls back to
// gaiaVersionExtract (matches "Gaia R81.20" text patterns).
func extractGaiaVersion(body []byte) string {
	// Try JS variable pattern first — most common on real devices
	if matches := gaiaVersionJSPattern.FindSubmatch(body); len(matches) >= 2 {
		version := string(matches[1])
		if gaiaVersionRegex.MatchString(version) {
			return version
		}
	}

	// Fall back to "Gaia R81.20" text pattern
	matches := gaiaVersionExtract.FindSubmatch(body)
	if len(matches) < 2 {
		return ""
	}

	version := string(matches[1])

	// Validate version format to prevent CPE injection
	if !gaiaVersionRegex.MatchString(version) {
		return ""
	}

	return version
}

// buildCheckPointCPE constructs a CPE string for Check Point Gaia OS.
// CPE format: cpe:2.3:o:checkpoint:gaia:<version>:*:*:*:*:*:*:*
func buildCheckPointCPE(version string) string {
	if version == "" {
		return "cpe:2.3:o:checkpoint:gaia:*:*:*:*:*:*:*:*"
	}
	// Normalize version for CPE: R81.20 -> r81.20 (CPE uses lowercase)
	cpeVersion := strings.ToLower(version)
	return fmt.Sprintf("cpe:2.3:o:checkpoint:gaia:%s:*:*:*:*:*:*:*", cpeVersion)
}
