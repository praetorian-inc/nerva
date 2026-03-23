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

// PfSenseFingerprinter detects pfSense firewall management interfaces.
//
// Detection Strategy:
// pfSense exposes a distinctive login page at / with unique HTML markers.
// Detection uses multiple signals from the root response body:
//
//  1. PRIMARY:   name="usernamefld" AND name="passwordfld" (form fields unique to pfSense)
//  2. SECONDARY: id="pfsense-logo-svg" (inline SVG logo element)
//
// Must match PRIMARY or SECONDARY to confirm detection.
//
// Version Detection:
// - jQuery version extracted from asset paths in body, mapped to pfSense version ranges
// - Fallback to Server header hinting (lighttpd → "pre-2.3", nginx → no version)
//
// Security Risks:
//   - CVE-2023-42325: XSS in pfSense web interface
//   - CVE-2022-31814: Remote code execution via pfBlockerNG
//   - Exposed management interface allows credential brute-force
type PfSenseFingerprinter struct{}

func init() {
	Register(&PfSenseFingerprinter{})
}

// jQueryToPfSenseVersion maps jQuery versions found in pfSense assets to pfSense version ranges.
// Source: pfSense changelog and repository history.
var jQueryToPfSenseVersion = map[string]string{
	"3.7.1":  "2.7.x+",
	"3.5.1":  "2.5.x-2.6.x",
	"3.4.1":  "2.4.5-2.5.x",
	"3.3.1":  "2.4.x",
	"1.12.4": "2.3.x",
	"1.11.1": "2.2.x",
}

// pfSenseJQueryPattern extracts the jQuery version from asset paths.
// Matches: /jquery-3.7.1.min.js, jquery-1.12.4.min.js, etc.
var pfSenseJQueryPattern = regexp.MustCompile(`jquery-(\d+\.\d+\.\d+)\.min\.js`)

// pfSenseTitlePattern extracts hostname from pfSense title.
// pfSense titles follow: "[hostname] - Login" or "pfSense - Login"
var pfSenseTitlePattern = regexp.MustCompile(`(?i)<title>\s*(.+?)\s*-\s*Login\s*</title>`)

// pfSensePagebodyPattern extracts the background color from the pagebody div.
// Handles both attribute orderings: style before class, and class before style.
var pfSensePagebodyPattern = regexp.MustCompile(`(?:style="[^"]*background:\s*([#\w]+)[^"]*"\s*class="pagebody"|class="pagebody"[^>]*style="[^"]*background:\s*([#\w]+))`)

// pfSenseThemeColors maps known pfSense background colors to theme names.
var pfSenseThemeColors = map[string]string{
	"#1e3f75": "pfSense",
	"#212121": "pfSense-dark",
}

// pfSenseCEViewBox is the SVG viewBox value unique to pfSense CE logo.
const pfSenseCEViewBox = `"0 0 282.8 84.2"`

func (f *PfSenseFingerprinter) Name() string {
	return "pfsense"
}

// Match returns true for any 200 OK response.
// pfSense has no distinctive headers to pre-filter on, so detection
// is deferred to Fingerprint() which checks body markers.
func (f *PfSenseFingerprinter) Match(resp *http.Response) bool {
	return resp.StatusCode == 200
}

// Fingerprint performs pfSense detection from the HTTP response body.
// Returns nil if the page does not contain pfSense markers.
func (f *PfSenseFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode != 200 {
		return nil, nil
	}

	bodyStr := string(body)

	// PRIMARY detection: both form field names must be present
	primaryMatch := strings.Contains(bodyStr, `name="usernamefld"`) &&
		strings.Contains(bodyStr, `name="passwordfld"`)

	// SECONDARY detection: pfSense SVG logo element
	secondaryMatch := strings.Contains(bodyStr, `id="pfsense-logo-svg"`)

	if !primaryMatch && !secondaryMatch {
		return nil, nil
	}

	metadata := make(map[string]any)
	metadata["vendor"] = "Netgate"
	metadata["product"] = "pfSense"
	metadata["management_interface"] = "web-admin"

	// Extract Server header for metadata and version fallback
	serverInfo := resp.Header.Get("Server")
	if serverInfo != "" {
		metadata["server_info"] = serverInfo
	}

	// Version detection: jQuery version → pfSense version range
	version := extractPfSenseVersion(bodyStr, serverInfo)
	if version != "" {
		metadata["version"] = version
	}

	// Edition detection: CE-specific SVG markers
	if isPfSenseCE(bodyStr) {
		metadata["edition"] = "CE"
	}

	// Hostname extraction from title
	if hostname := extractPfSenseHostname(bodyStr); hostname != "" {
		metadata["hostname"] = hostname
	}

	// Theme detection from pagebody background color
	if theme := extractPfSenseTheme(bodyStr); theme != "" {
		metadata["theme"] = theme
	}

	// Build CPE
	cpeVersion := version
	if cpeVersion == "" {
		cpeVersion = "*"
	}
	cpe := fmt.Sprintf("cpe:2.3:a:netgate:pfsense:%s:*:*:*:*:*:*:*", cpeVersion)

	return &FingerprintResult{
		Technology: "pfsense",
		Version:    version,
		CPEs:       []string{cpe},
		Metadata:   metadata,
	}, nil
}

// extractPfSenseVersion returns a pfSense version string by inspecting the response.
// It first attempts jQuery version mapping, then falls back to Server header hinting.
func extractPfSenseVersion(bodyStr, serverInfo string) string {
	// Try jQuery version → pfSense version mapping
	if matches := pfSenseJQueryPattern.FindStringSubmatch(bodyStr); len(matches) > 1 {
		jqVersion := matches[1]
		if pfVersion, ok := jQueryToPfSenseVersion[jqVersion]; ok {
			return pfVersion
		}
	}

	// Fallback: Server header hinting
	lower := strings.ToLower(serverInfo)
	if strings.Contains(lower, "lighttpd") {
		return "pre-2.3"
	}
	// nginx indicates 2.3+ but we cannot determine more precisely
	return ""
}

// isPfSenseCE reports whether the body contains CE-specific SVG markers.
func isPfSenseCE(bodyStr string) bool {
	if strings.Contains(bodyStr, pfSenseCEViewBox) {
		return true
	}
	if strings.Contains(bodyStr, "logo-st0") && strings.Contains(bodyStr, "logo-st1") && strings.Contains(bodyStr, "logo-st2") {
		return true
	}
	if strings.Contains(bodyStr, "Community Edition") {
		return true
	}
	return false
}

// extractPfSenseHostname extracts the custom hostname from the pfSense login page title.
// Returns empty string if the title is the default "pfSense - Login" or not found.
func extractPfSenseHostname(bodyStr string) string {
	matches := pfSenseTitlePattern.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return ""
	}
	prefix := strings.TrimSpace(matches[1])
	if strings.EqualFold(prefix, "pfSense") {
		return ""
	}
	return prefix
}

// extractPfSenseTheme extracts the theme from the pagebody div's background color.
// Returns the mapped theme name for known colors, the raw color value for unknown colors,
// or empty string if no pagebody background color is found.
func extractPfSenseTheme(bodyStr string) string {
	matches := pfSensePagebodyPattern.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return ""
	}
	// Group 1: style-before-class ordering; Group 2: class-before-style ordering
	color := matches[1]
	if color == "" {
		color = matches[2]
	}
	if color == "" {
		return ""
	}
	if name, ok := pfSenseThemeColors[color]; ok {
		return name
	}
	return color
}

// buildPfSenseCPE constructs a CPE string for pfSense with the given version.
func buildPfSenseCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:netgate:pfsense:%s:*:*:*:*:*:*:*", version)
}
