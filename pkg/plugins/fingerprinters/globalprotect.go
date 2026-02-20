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

// GlobalProtectFingerprinter detects Palo Alto GlobalProtect SSL VPN
type GlobalProtectFingerprinter struct{}

func init() {
	Register(&GlobalProtectFingerprinter{})
}

// GlobalProtect detection patterns in response body
var globalProtectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)global-?protect`),
	regexp.MustCompile(`(?i)PAN_FORM`),
	regexp.MustCompile(`(?i)palo\s*alto`),
	regexp.MustCompile(`(?i)pan-os`),
	regexp.MustCompile(`(?i)/global-protect/`),
	regexp.MustCompile(`(?i)<prelogin-response>`),
	regexp.MustCompile(`(?i)<saml-auth-method>`),
	regexp.MustCompile(`(?i)saml-auth-status`),
	regexp.MustCompile(`(?i)<portal>`),
	regexp.MustCompile(`(?i)portal-prelogin`),
}

// PAN-OS version extraction patterns
var (
	panOSServerPattern          = regexp.MustCompile(`(?i)PAN-OS\s+([0-9]+(?:\.[0-9]+)+)`)
	panOSPreloginVersionPattern = regexp.MustCompile(`(?i)<sw-version>([0-9]+(?:\.[0-9]+)+(?:-h[0-9]+)?)</sw-version>`)
	panOSAppVersionPattern      = regexp.MustCompile(`(?i)<app-version>([0-9]+(?:\.[0-9]+)+)</app-version>`)
	panOSVersionPattern         = regexp.MustCompile(`(?i)(?:pan-os|panos)[:\s]+([0-9]+(?:\.[0-9]+)+)`)
)

func (f *GlobalProtectFingerprinter) Name() string {
	return "globalprotect"
}

func (f *GlobalProtectFingerprinter) ProbeEndpoint() string {
	return "/global-protect/prelogin.esp"
}

func (f *GlobalProtectFingerprinter) Match(resp *http.Response) bool {
	// Accept 2xx and 3xx responses (redirects to /global-protect/ are common)
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false
	}

	// Check for definitive header indicators first (these are reliable)
	if resp.Header.Get("X-Private-Pan-Sslvpn") != "" {
		return true
	}

	// Check Server header for Palo Alto
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverHeader, "palo alto") || strings.Contains(serverHeader, "pan-os") {
		return true
	}

	// For 2xx responses, check Location header
	// For 3xx redirects, Location alone is NOT sufficient (may just echo the requested path)
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		location := strings.ToLower(resp.Header.Get("Location"))
		if strings.Contains(location, "global-protect") {
			return true
		}
	}

	return false
}

func (f *GlobalProtectFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Accept 2xx and 3xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, nil
	}

	// Check Location header for GlobalProtect redirect
	headerMatch := false
	location := strings.ToLower(resp.Header.Get("Location"))
	if strings.Contains(location, "global-protect") {
		headerMatch = true
	}

	// Check Server header for Palo Alto
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverHeader, "palo alto") || strings.Contains(serverHeader, "pan-os") {
		headerMatch = true
	}
	if resp.Header.Get("X-Private-Pan-Sslvpn") != "" {
		headerMatch = true
	}

	// Check response body for GlobalProtect markers
	bodyStr := string(body)
	bodyMatch := false
	for _, pattern := range globalProtectPatterns {
		if pattern.MatchString(bodyStr) {
			bodyMatch = true
			break
		}
	}

	// Require header indicators for detection; body-only matches produce false positives
	// (e.g., marketing sites mentioning "Palo Alto" or "<portal>" in content)
	if !headerMatch {
		return nil, nil
	}
	_ = bodyMatch // Body patterns contribute to confidence but are not sufficient alone

	// Extract version
	version := extractGlobalProtectVersion(body, resp.Header)

	return &FingerprintResult{
		Technology: "palo-alto-globalprotect",
		Version:    version,
		CPEs:       []string{buildGlobalProtectCPE(version)},
		Metadata: map[string]any{
			"vendor":  "Palo Alto",
			"product": "GlobalProtect",
		},
	}, nil
}

func extractGlobalProtectVersion(body []byte, headers http.Header) string {
	// Check Server header first
	serverHeader := headers.Get("Server")
	if matches := panOSServerPattern.FindStringSubmatch(serverHeader); len(matches) > 1 {
		return matches[1]
	}

	// Check for prelogin.esp XML response (most reliable for version)
	// Format: <sw-version>10.2.3</sw-version> or <sw-version>10.2.3-h1</sw-version>
	if matches := panOSPreloginVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	// Check for app-version in XML
	if matches := panOSAppVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	// Check body for general version patterns
	if matches := panOSVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	return ""
}

func buildGlobalProtectCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:o:paloaltonetworks:pan-os:%s:*:*:*:*:*:*:*", version)
}
