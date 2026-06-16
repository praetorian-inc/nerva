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

// PAN-OS Management Interface fingerprinter.
//
// Detection Strategy:
// The PAN-OS management interface is a distinct attack surface from the
// GlobalProtect VPN portal. It is exposed via the web admin UI at
// /php/login.php and serves a login form for firewall administrators.
//
// Detection uses a two-stage approach:
//
//  1. Match (fast pre-filter): Server header contains "PanWeb Server" or
//     "pan-os" (case-insensitive), OR Location header contains /php/login.php.
//
//  2. Fingerprint (body corroboration): At least one HTML body signal:
//     - <form name="login_form"
//     - <title> containing "palo alto" (case-insensitive)
//     - Management-specific asset paths (/php/utils/combined.js or /login/css/)
//
// Negative match: If the body contains any GlobalProtect marker
// (global-protect, prelogin-response, PAN_FORM, portal-prelogin), return nil
// to avoid overlap with the GlobalProtect fingerprinter.
//
// Default Ports:
//   - 443/tcp: HTTPS management interface
//   - 4443/tcp: Alternate HTTPS management interface
//
// CPE:
//
//	cpe:2.3:o:paloaltonetworks:pan-os:{version}:*:*:*:*:*:*:*
//
// Version Detection:
//  1. Server header: "PAN-OS 10.2.3" → panOSServerPattern (shared with GlobalProtect)
//  2. Asset query param: combined.js?v=10.2.3 → panOSMgmtAssetVersionPattern
//
// Security Context:
//   - CVE-2024-3400: OS command injection in GlobalProtect (CVSS 10.0), affects management interface too
//   - CVE-2022-0028: Reflected amplification DoS (CVSS 8.6)
//   - CVE-2020-2021: Authentication bypass (CVSS 10.0, Kerberos/SAML)
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// PanosMgmtFingerprinter detects the Palo Alto PAN-OS web management interface.
type PanosMgmtFingerprinter struct{}

func init() {
	Register(&PanosMgmtFingerprinter{})
}

// panOSMgmtLoginFormPattern matches <form name="login_form" (anchored).
var panOSMgmtLoginFormPattern = regexp.MustCompile(`(?i)<form[^>]+name\s*=\s*["']?login_form["']?`)

// panOSMgmtAssetVersionPattern extracts version from asset query params,
// e.g., combined.js?v=10.2.3
var panOSMgmtAssetVersionPattern = regexp.MustCompile(`(?i)combined\.js\?v=([0-9]+(?:\.[0-9]+)+)`)

// panOSMgmtVersionValidPattern validates extracted version strings before
// they are stored in metadata or CPE. Accepts dotted-decimal versions with
// an optional hotfix suffix (e.g., "10.2.3", "10.2.3-h1").
var panOSMgmtVersionValidPattern = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)+(?:-h[0-9]+)?$`)

// panOSMgmtMaxVersionLen caps extracted version strings before regex validation,
// providing defense-in-depth against pathologically long strings. 24 chars is
// generous for PAN-OS versions (e.g., "10.2.3-h1" is 9 chars).
const panOSMgmtMaxVersionLen = 24

// globalProtectMarkers lists body strings whose presence indicates a
// GlobalProtect VPN response rather than a management interface response.
// Any match causes an early nil return.
var globalProtectMarkers = []string{
	"global-protect",
	"prelogin-response",
	"PAN_FORM",
	"portal-prelogin",
}

func (f *PanosMgmtFingerprinter) Name() string {
	return "panos-mgmt"
}

func (f *PanosMgmtFingerprinter) ProbeEndpoint() string {
	return "/php/login.php"
}

// Match is a fast pre-filter. Returns true if any of the following hold:
//   - Server header contains "PanWeb Server" (case-insensitive)
//   - Server header contains "pan-os" (case-insensitive)
//   - Location header contains "/php/login.php"
func (f *PanosMgmtFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	server := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(server, "panweb server") || strings.Contains(server, "pan-os") {
		return true
	}

	location := resp.Header.Get("Location")
	if strings.Contains(location, "/php/login.php") {
		return true
	}

	return false
}

// Fingerprint performs full detection. Returns nil, nil for non-matching responses.
//
// Detection requires:
//  1. A header signal (Server or Location, same as Match).
//  2. At least one HTML body signal corroborating that this is the management UI.
//  3. No GlobalProtect markers in the body (negative match).
func (f *PanosMgmtFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Header signal check (same logic as Match).
	server := strings.ToLower(resp.Header.Get("Server"))
	headerMatch := strings.Contains(server, "panweb server") || strings.Contains(server, "pan-os")
	if !headerMatch {
		location := resp.Header.Get("Location")
		headerMatch = strings.Contains(location, "/php/login.php")
	}
	if !headerMatch {
		return nil, nil
	}

	bodyStr := string(body)

	// Negative match: GlobalProtect markers take precedence. If any marker is
	// present the response is from the VPN portal, not the management interface.
	lowerBody := strings.ToLower(bodyStr)
	for _, marker := range globalProtectMarkers {
		if strings.Contains(lowerBody, strings.ToLower(marker)) {
			return nil, nil
		}
	}

	// Body corroboration: require at least one management-specific HTML signal.
	bodyConfirmed := panOSMgmtLoginFormPattern.MatchString(bodyStr) ||
		strings.Contains(lowerBody, "<title>") && strings.Contains(lowerBody, "palo alto") ||
		strings.Contains(bodyStr, "/php/utils/combined.js") ||
		strings.Contains(bodyStr, "/login/css/")
	if !bodyConfirmed {
		return nil, nil
	}

	version := extractPanosMgmtVersion(body, resp.Header)

	return &FingerprintResult{
		Technology: "palo-alto-panos-management",
		Version:    version,
		CPEs:       []string{buildPanOSMgmtCPE(version)},
		Metadata: map[string]any{
			"vendor":         "Palo Alto Networks",
			"product":        "PAN-OS Management Interface",
			"interface_type": "management",
		},
	}, nil
}

// extractPanosMgmtVersion extracts the PAN-OS version using two strategies:
//  1. Server header via the shared panOSServerPattern (e.g., "PAN-OS 10.2.3").
//  2. Asset path query param (e.g., combined.js?v=10.2.3).
func extractPanosMgmtVersion(body []byte, headers http.Header) string {
	// Strategy 1: Server header (shared regex from globalprotect.go).
	if matches := panOSServerPattern.FindStringSubmatch(headers.Get("Server")); len(matches) > 1 {
		v := matches[1]
		if len(v) <= panOSMgmtMaxVersionLen && panOSMgmtVersionValidPattern.MatchString(v) {
			return v
		}
	}

	// Strategy 2: Asset path query param.
	if matches := panOSMgmtAssetVersionPattern.FindSubmatch(body); len(matches) > 1 {
		v := string(matches[1])
		if len(v) <= panOSMgmtMaxVersionLen && panOSMgmtVersionValidPattern.MatchString(v) {
			return v
		}
	}

	return ""
}

// buildPanOSMgmtCPE constructs a CPE 2.3 string for PAN-OS.
// The CPE type is "o:" (operating system) matching the NVD naming convention.
// This is intentionally the same CPE structure as GlobalProtect — both
// fingerprint the same underlying OS. The technology name distinguishes the
// interface type.
func buildPanOSMgmtCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:o:paloaltonetworks:pan-os:%s:*:*:*:*:*:*:*", version)
}
