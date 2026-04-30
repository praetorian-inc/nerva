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

// ZyxelFingerprinter detects Zyxel ATP/USG FLEX firewall appliances.
//
// Detection Strategy:
// Zyxel ZLD-firmware appliances expose a web management interface. Detection
// uses multiple signals:
//
//  1. ZTP Handler Path: `/ztp/cgi-bin/handler` in body — unique to Zyxel ZLD firmware
//  2. Redirect to ZTP/weblogin: Location header pointing to `/ztp/cgi-bin/` or
//     `/weblogin.cgi` — standalone-sufficient
//  3. Corroborated Brand + Model: "Zyxel" in body AND a model identifier
//     (ATP, USG FLEX, USG, VPN) — both required together
//  4. weblogin.cgi + Brand: "weblogin.cgi" in body AND "Zyxel" branding —
//     both required together
//
// "Zyxel" brand alone is NOT sufficient — the brand name appears on security
// news sites, vendor comparison pages, and third-party documentation.
//
// Active Probe: GET /weblogin.cgi (standard Zyxel ZLD login endpoint)
//
// Default Ports:
//   - 443: HTTPS management interface
//   - 80: HTTP management interface
//
// Version Detection:
// Zyxel firmware versions appear in several formats:
//   - "5.38" (bare numeric)
//   - "5.38(ABZH.0)" (with build qualifier in parens)
//   - "V5.38" (V-prefix)
//
// The V prefix and parenthesized build qualifier are stripped; only the
// numeric version (e.g., "5.38") is stored in the CPE.
//
// Model Detection:
// ATP series: ATP100, ATP200, ATP500, ATP700, ATP800
// USG FLEX series: USG FLEX 50, USG FLEX 100, USG FLEX 200, USG FLEX 500
// VPN series: VPN50, VPN100, VPN300
// USG series: USG20-VPN, USG40, USG60
//
// CPE Generation (per model family):
//   - ATP              → cpe:2.3:o:zyxel:atp_firmware:{version}:*:*:*:*:*:*:*
//   - USG FLEX H       → cpe:2.3:o:zyxel:usg_flex_h_firmware:{version}:*:*:*:*:*:*:*
//   - USG FLEX         → cpe:2.3:o:zyxel:usg_flex_firmware:{version}:*:*:*:*:*:*:*
//   - VPN              → cpe:2.3:o:zyxel:vpn_firmware:{version}:*:*:*:*:*:*:*
//   - USG series       → cpe:2.3:o:zyxel:usg_firmware:{version}:*:*:*:*:*:*:*
//   - Unknown/no model → cpe:2.3:o:zyxel:zld_firmware:{version}:*:*:*:*:*:*:*
//
// Security Risks:
//   - CVE-2024-11667 (CVSS 9.8): Directory traversal in web management interface;
//     exploited by Helldown ransomware; listed on CISA KEV catalog.
//   - CVE-2023-28771 (CVSS 9.8): Unauthenticated OS command injection via IKEv2
//     packet handling in IPsec VPN feature.
//   - CVE-2022-30525 (CVSS 9.8): Unauthenticated OS command injection via HTTP
//     management interface ZTP handler (/ztp/cgi-bin/).
type ZyxelFingerprinter struct{}

func init() {
	Register(&ZyxelFingerprinter{})
}

// zyxelFirmwareContextPattern extracts firmware version when preceded by a keyword
// that establishes firmware context (firmware, version, fw, fw_ver). This is the
// primary pattern and avoids matching version numbers in unrelated JS/CSS paths.
//
// Matches:
//   - "Firmware 5.38"       → captures "5.38"
//   - "Version: V5.38"      → captures "5.38"
//   - "fw_ver=5.38.1"       → captures "5.38.1"
//   - "fw: V5.38(ABZH.0)"   → captures "5.38"
//
// Requires a word boundary or non-alphanumeric character after the version to
// prevent matching "5.38abc".
var zyxelFirmwareContextPattern = regexp.MustCompile(
	`(?i)(?:firmware|version|fw_?ver|fw)[:\s=]*V?(\d+\.\d+(?:\.\d+)?)(?:\([^)]*\))?(?:[^0-9a-zA-Z]|$)`,
)

// zyxelVPrefixPattern is a fallback that matches a version with an explicit
// uppercase-V prefix. The V prefix is a Zyxel firmware convention not used by
// JS/CSS library paths (e.g., jquery-3.7.1.min.js has no V prefix).
//
// Matches:
//   - "V5.38"          → captures "5.38"
//   - "V5.38(ABZH.0)"  → captures "5.38"
//
// Requires a word boundary or non-alphanumeric character after the version to
// prevent matching "V5.38abc".
var zyxelVPrefixPattern = regexp.MustCompile(
	`V(\d+\.\d+(?:\.\d+)?)(?:\([A-Za-z0-9.]+\))?(?:[^0-9a-zA-Z]|$)`,
)

// zyxelVersionValidRegex validates extracted version strings before CPE use.
// Accepts: "5.38", "5.38.1" — rejects anything with non-numeric, injection chars.
var zyxelVersionValidRegex = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)

// zyxelMaxVersionLen caps version string length to guard against pathologically
// long strings before the regex runs. 20 chars is generous for Zyxel versions
// (e.g., "5.38" is 4 chars).
const zyxelMaxVersionLen = 20

// zyxelBrandPattern is a precompiled case-insensitive regex for Zyxel brand detection.
// Used in Fingerprint() to avoid strings.ToLower allocation on the full body.
var zyxelBrandPattern = regexp.MustCompile(`(?i)zyxel`)

// zyxelModelPattern matches Zyxel model identifiers in page body.
// Trailing optional letters cover product variants (ATP100W, USG FLEX 50AX, USG FLEX 200H).
var zyxelModelPattern = regexp.MustCompile(
	`(?i)\b(ATP\d{3,4}[A-Z]{0,2}|USG\s+FLEX\s+\d+[A-Z]{0,2}|USG\d+(?:-VPN)?|VPN\d+[A-Z]?)\b`,
)

func (f *ZyxelFingerprinter) Name() string {
	return "zyxel-firewall"
}

func (f *ZyxelFingerprinter) ProbeEndpoint() string {
	return "/weblogin.cgi"
}

// Match is a fast pre-filter. Accepts redirects to Zyxel-specific paths and
// text/html responses. Rejects 5xx server errors.
func (f *ZyxelFingerprinter) Match(resp *http.Response) bool {
	// Reject 5xx server errors
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Accept redirects to known Zyxel paths
	location := resp.Header.Get("Location")
	if location != "" {
		if strings.Contains(location, "/ztp/cgi-bin/") || strings.Contains(location, "/weblogin.cgi") {
			return true
		}
	}

	// Accept text/html for body-based detection (case-insensitive)
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(strings.ToLower(ct), "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full detection and returns a result if this is a Zyxel device.
// Returns nil, nil for non-matching responses.
func (f *ZyxelFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Reject 5xx server errors
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	bodyStr := string(body)
	location := resp.Header.Get("Location")

	// Signal 1 (standalone): ZTP handler path — unique to Zyxel ZLD firmware.
	// The string "/ztp/cgi-bin/handler" does not appear on generic web pages.
	ztpInBody := strings.Contains(bodyStr, "/ztp/cgi-bin/handler")

	// Signal 2 (standalone): Redirect to Zyxel-specific paths.
	redirectToZTP := strings.Contains(location, "/ztp/cgi-bin/")
	redirectToWeblogin := strings.Contains(location, "/weblogin.cgi")

	// Signal 3 (corroborated): Zyxel brand + model identifier in body.
	// Brand alone is insufficient — it appears on comparison pages and news sites.
	hasZyxelBrand := zyxelBrandPattern.MatchString(bodyStr)
	hasModelID := zyxelModelPattern.MatchString(bodyStr)
	brandPlusModel := hasZyxelBrand && hasModelID

	// Signal 4 (corroborated): weblogin.cgi path + Zyxel brand in body.
	webloginInBody := strings.Contains(bodyStr, "weblogin.cgi")
	webloginPlusBrand := webloginInBody && hasZyxelBrand

	detected := ztpInBody || redirectToZTP || redirectToWeblogin || brandPlusModel || webloginPlusBrand
	if !detected {
		return nil, nil
	}

	// Build metadata
	metadata := make(map[string]any)
	metadata["vendor"] = "Zyxel"
	metadata["product"] = "Zyxel Firewall"

	// Extract model from body
	model := extractZyxelModel(bodyStr)
	if model != "" {
		metadata["product_model"] = model
	}

	// Extract firmware version from body
	version := extractZyxelVersion(bodyStr)

	// Build CPE product string based on model family
	cpeProduct := zyxelCPEProduct(model)

	return &FingerprintResult{
		Technology: "zyxel-firewall",
		Version:    version,
		CPEs:       buildZyxelCPEs(cpeProduct, version),
		Metadata:   metadata,
	}, nil
}

// extractZyxelVersion extracts and normalizes the firmware version from a Zyxel
// management page body. It strips the optional "V" prefix and parenthesized build
// qualifier, returning only the numeric portion (e.g., "5.38").
//
// Strategy: try the firmware-context pattern first (requires "firmware", "version",
// "fw", or "fw_ver" keyword). Fall back to the V-prefix pattern if no context match
// is found. Bare numeric versions without context (e.g., "5.38" alone) are not
// extracted to avoid false matches on JS/CSS library version numbers.
//
// Returns empty string if no version is found or validation fails.
func extractZyxelVersion(bodyStr string) string {
	for _, pat := range []*regexp.Regexp{zyxelFirmwareContextPattern, zyxelVPrefixPattern} {
		allMatches := pat.FindAllStringSubmatch(bodyStr, -1)
		for _, matches := range allMatches {
			if len(matches) < 2 {
				continue
			}
			version := matches[1]
			if len(version) > zyxelMaxVersionLen {
				continue
			}
			if !zyxelVersionValidRegex.MatchString(version) {
				continue
			}
			return version
		}
	}
	return ""
}

// extractZyxelModel extracts a Zyxel model identifier from the page body.
// Returns the matched model string (e.g., "ATP200", "USG FLEX 100").
// Returns empty string if no model is identified.
func extractZyxelModel(bodyStr string) string {
	matches := zyxelModelPattern.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// zyxelCPEProduct maps a model identifier to the NVD CPE product string.
// The mapping follows Zyxel's NVD CPE naming conventions.
func zyxelCPEProduct(model string) string {
	if model == "" {
		return "zld_firmware"
	}
	upper := strings.ToUpper(model)
	switch {
	case strings.HasPrefix(upper, "ATP"):
		return "atp_firmware"
	case strings.Contains(upper, "FLEX") && strings.HasSuffix(upper, "H"):
		return "usg_flex_h_firmware"
	case strings.Contains(upper, "FLEX"):
		return "usg_flex_firmware"
	case strings.HasPrefix(upper, "VPN"):
		return "vpn_firmware"
	case strings.HasPrefix(upper, "USG"):
		return "usg_firmware"
	default:
		// Unknown model: use generic ZLD firmware CPE to avoid misclassifying as ATP
		return "zld_firmware"
	}
}

// buildZyxelCPEs constructs CPE strings for a Zyxel device.
// When version is empty, uses "*" per CPE 2.3 spec.
func buildZyxelCPEs(product, version string) []string {
	v := version
	if v == "" {
		v = "*"
	}
	return []string{
		fmt.Sprintf("cpe:2.3:o:zyxel:%s:%s:*:*:*:*:*:*:*", product, v),
	}
}
