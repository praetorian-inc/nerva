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

// CiscoASAFTDFingerprinter detects Cisco ASA (Adaptive Security Appliance) and
// FTD (Firepower Threat Defense) appliances via their HTTP login portal.
//
// Detection Strategy:
// Both ASA and FTD devices expose a CSCOE/WebVPN login portal at /+CSCOE+/logon.html.
// This fingerprinter identifies the underlying appliance (ASA or FTD) via headers and
// body signals, complementing the AnyConnect fingerprinter which reports VPN service.
// Both fingerprinters can fire on the same response.
//
// Detection indicators (in priority order):
//  1. X-ASA-Version header — definitive ASA indicator
//  2. X-Transcend-Version header — definitive FTD indicator
//  3. Server header containing "cisco" (case-insensitive)
//  4. Set-Cookie header containing "webvpn" (case-insensitive)
//
// ASA vs FTD distinction:
//   - X-Transcend-Version present → FTD
//   - Server header contains "firepower threat defense" → FTD
//   - Otherwise → ASA (more common deployment)
//
// Security Risks:
//   - CVE-2023-20269: Cisco ASA and FTD unauthorized VPN brute force
//   - CVE-2023-20109: Cisco ASA and FTD group policy bypass
//   - CVE-2024-20353: Cisco ASA and FTD denial of service
//   - WebVPN portal exposure enabling credential harvesting
//
// Metadata extracted: platform_type (asa/ftd), vendor, product, webvpn_enabled,
// asdm_available, asdm_version.
type CiscoASAFTDFingerprinter struct{}

func init() {
	Register(&CiscoASAFTDFingerprinter{})
}

// asaFTDVersionRegex validates ASA/FTD version format to prevent CPE injection.
// Accepts versions like: 9.16(4), 9.8(2), 9.16, 7.2.0, 6.7.0.2
var asaFTDVersionRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,4}(?:\([0-9]+\))?$`)

// asaFTDServerVersionRegex extracts version from Server header.
// Matches patterns like: ASDM/7.18(1), ASA/9.16(4), Firepower/7.2.0
var asaFTDServerVersionRegex = regexp.MustCompile(`(?i)(?:ASDM|ASA|Firepower)[/\s]+([0-9]+(?:\.[0-9]+)+(?:\([0-9]+\))?)`)

// asdmVersionRegex extracts ASDM version from Server header.
// Matches: Cisco ASDM/7.18(1)
var asdmVersionRegex = regexp.MustCompile(`(?i)ASDM/(\d+\.\d+(?:\(\d+\))?)`)

// asaFTDModelPattern extracts hardware model from Server header or body.
// Matches: ASA 5506, ASA 5525-X, Firepower 2110, FPR-2130, ASA5506, Firepower-1010
var asaFTDModelPattern = regexp.MustCompile(`(?i)(?:ASA[\s-]?(\d{4}(?:-X)?)|(?:Firepower|FPR)[\s-]?(\d{4}))`)

// anyconnectVersionPattern extracts AnyConnect client version from body.
// Matches: anyconnect-win-4.10.07073, anyconnect-macos-4.10.07073, AnyConnect version 4.10.07073
var anyconnectVersionPattern = regexp.MustCompile(`(?i)anyconnect[-\s]+(?:win|macos|linux|version)[-\s]+(\d+\.\d+\.\d+)`)

// ASA/FTD body detection patterns (for metadata enrichment only)
var (
	asaFTDCSCOEPattern      = regexp.MustCompile(`(?i)CSCOE`)
	asaFTDWebVPNPattern     = regexp.MustCompile(`(?i)webvpn`)
	asaFTDAnyConnectPattern = regexp.MustCompile(`(?i)anyconnect`)
	asaFTDASAPattern        = regexp.MustCompile(`(?i)\basa\b`)
	asaFTDFirepowerPattern  = regexp.MustCompile(`(?i)firepower`)
)

func (f *CiscoASAFTDFingerprinter) Name() string {
	return "cisco-asa-ftd"
}

func (f *CiscoASAFTDFingerprinter) ProbeEndpoint() string {
	return "/+CSCOE+/logon.html"
}

func (f *CiscoASAFTDFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return isASAFTDHeaderMatch(resp)
}

func (f *CiscoASAFTDFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Require at least one header indicator — body alone is insufficient
	if !isASAFTDHeaderMatch(resp) {
		return nil, nil
	}

	bodyStr := string(body)

	// Determine ASA vs FTD
	platformType := detectPlatformType(resp)

	// Extract version
	version := extractASAFTDVersion(resp.Header, body, platformType)

	// Validate version format to prevent CPE injection
	if version != "" && !asaFTDVersionRegex.MatchString(version) {
		version = ""
	}

	// Build metadata
	metadata := make(map[string]any)
	metadata["vendor"] = "Cisco"
	metadata["platform_type"] = platformType

	if platformType == "ftd" {
		metadata["product"] = "FTD"
	} else {
		metadata["product"] = "ASA"
	}

	// Detect WebVPN from body or cookies
	webvpnEnabled := false
	if asaFTDCSCOEPattern.MatchString(bodyStr) ||
		asaFTDWebVPNPattern.MatchString(bodyStr) ||
		asaFTDAnyConnectPattern.MatchString(bodyStr) {
		webvpnEnabled = true
	}
	if !webvpnEnabled {
		for _, cookie := range resp.Header.Values("Set-Cookie") {
			if strings.Contains(strings.ToLower(cookie), "webvpn") {
				webvpnEnabled = true
				break
			}
		}
	}
	if webvpnEnabled {
		metadata["webvpn_enabled"] = true
	}

	// Detect ASDM from Server header
	serverHeader := resp.Header.Get("Server")
	if strings.Contains(strings.ToLower(serverHeader), "asdm") {
		metadata["asdm_available"] = true
		if matches := asdmVersionRegex.FindStringSubmatch(serverHeader); len(matches) > 1 {
			asdmVer := matches[1]
			if asaFTDVersionRegex.MatchString(asdmVer) {
				metadata["asdm_version"] = asdmVer
			}
		}
	}

	// Extract platform model from Server header and body
	if model := extractASAFTDModel(serverHeader, bodyStr); model != "" {
		metadata["platform_model"] = model
	}

	// Extract AnyConnect client version from body
	if matches := anyconnectVersionPattern.FindStringSubmatch(bodyStr); len(matches) > 1 {
		metadata["anyconnect_version"] = matches[1]
	}

	// Build technology name and CPE
	var technology string
	var cpe string
	if platformType == "ftd" {
		technology = "cisco-ftd"
		cpe = buildCiscoFTDCPE(version)
	} else {
		technology = "cisco-asa"
		cpe = buildCiscoASACPE(version)
	}

	return &FingerprintResult{
		Technology: technology,
		Version:    version,
		CPEs:       []string{cpe},
		Metadata:   metadata,
	}, nil
}

// isASAFTDHeaderMatch returns true if the response has a header indicator of ASA/FTD.
func isASAFTDHeaderMatch(resp *http.Response) bool {
	if resp.Header.Get("X-Asa-Version") != "" {
		return true
	}
	if resp.Header.Get("X-Transcend-Version") != "" {
		return true
	}
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverHeader, "cisco") {
		return true
	}
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		if strings.Contains(strings.ToLower(cookie), "webvpn") {
			return true
		}
	}
	return false
}

// detectPlatformType returns "ftd" if the response indicates Firepower Threat Defense,
// "asa" otherwise (ASA is the more common deployment).
//
// X-Transcend-Version alone signals FTD only when X-ASA-Version is absent.
// When both headers are present, the Server header is used to decide:
// "firepower threat defense" in Server → FTD, otherwise → ASA.
func detectPlatformType(resp *http.Response) string {
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverHeader, "firepower threat defense") {
		return "ftd"
	}
	// X-Transcend-Version alone (without X-ASA-Version) is a definitive FTD indicator
	if resp.Header.Get("X-Transcend-Version") != "" && resp.Header.Get("X-Asa-Version") == "" {
		return "ftd"
	}
	return "asa"
}

// extractASAFTDVersion attempts to extract the appliance version from headers and body.
// For FTD, X-Transcend-Version is preferred (the FTD-specific version).
// For ASA, X-ASA-Version is preferred.
// Falls back to Server header regex for both.
func extractASAFTDVersion(headers http.Header, body []byte, platformType string) string {
	if platformType == "ftd" {
		// For FTD, prefer X-Transcend-Version first
		if v := headers.Get("X-Transcend-Version"); v != "" {
			return v
		}
		if v := headers.Get("X-Asa-Version"); v != "" {
			return v
		}
	} else {
		// For ASA, prefer X-ASA-Version first
		if v := headers.Get("X-Asa-Version"); v != "" {
			return v
		}
		if v := headers.Get("X-Transcend-Version"); v != "" {
			return v
		}
	}

	// Fallback: try Server header
	serverHeader := headers.Get("Server")
	if matches := asaFTDServerVersionRegex.FindStringSubmatch(serverHeader); len(matches) > 1 {
		return matches[1]
	}

	return ""
}

// extractASAFTDModel extracts the hardware model number from the Server header or body.
// Server header is checked first; body is the fallback.
func extractASAFTDModel(serverHeader string, bodyStr string) string {
	// Try Server header first
	if matches := asaFTDModelPattern.FindStringSubmatch(serverHeader); len(matches) > 0 {
		for i := 1; i < len(matches); i++ {
			if matches[i] != "" {
				return matches[i]
			}
		}
	}
	// Try body
	if matches := asaFTDModelPattern.FindStringSubmatch(bodyStr); len(matches) > 0 {
		for i := 1; i < len(matches); i++ {
			if matches[i] != "" {
				return matches[i]
			}
		}
	}
	return ""
}

// buildCiscoASACPE constructs a CPE string for Cisco ASA software.
// CPE format: cpe:2.3:o:cisco:adaptive_security_appliance_software:<version>:*:*:*:*:*:*:*
func buildCiscoASACPE(version string) string {
	if version == "" {
		return "cpe:2.3:o:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:o:cisco:adaptive_security_appliance_software:%s:*:*:*:*:*:*:*", version)
}

// buildCiscoFTDCPE constructs a CPE string for Cisco Firepower Threat Defense.
// CPE format: cpe:2.3:a:cisco:firepower_threat_defense:<version>:*:*:*:*:*:*:*
func buildCiscoFTDCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:cisco:firepower_threat_defense:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:cisco:firepower_threat_defense:%s:*:*:*:*:*:*:*", version)
}
