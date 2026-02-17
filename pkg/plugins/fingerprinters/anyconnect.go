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

// AnyConnectFingerprinter detects Cisco AnyConnect SSL VPN
type AnyConnectFingerprinter struct{}

func init() {
	Register(&AnyConnectFingerprinter{})
}

// AnyConnect detection patterns in response body
var anyConnectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)webvpn`),
	regexp.MustCompile(`(?i)CSCOE`),
	regexp.MustCompile(`(?i)CSCOT`),
	regexp.MustCompile(`(?i)CSCOU`),
	regexp.MustCompile(`(?i)anyconnect`),
	regexp.MustCompile(`(?i)cisco.*vpn`),
	regexp.MustCompile(`(?i)\basa\b`),
	regexp.MustCompile(`(?i)firepower`),
	regexp.MustCompile(`(?i)adaptivesecurityappliance`),
	regexp.MustCompile(`(?i)sdesktop`),
}

// AnyConnect cookie names that indicate Cisco ASA
var anyConnectCookies = []string{
	"webvpn",
	"webvpnlogin",
	"webvpncontext",
	"webvpnLang",
	"webvpnSharePoint",
}

// ASA version extraction pattern
var asaVersionPattern = regexp.MustCompile(`(?i)(?:version|asa)[:\s]+([0-9]+(?:\.[0-9]+)+(?:\([0-9]+\))?)`)

func (f *AnyConnectFingerprinter) Name() string {
	return "anyconnect"
}

func (f *AnyConnectFingerprinter) ProbeEndpoint() string {
	return "/+CSCOE+/logon.html"
}

func (f *AnyConnectFingerprinter) Match(resp *http.Response) bool {
	// Accept 2xx and 3xx responses (redirects to VPN paths are common)
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false
	}

	// Check Location header for AnyConnect redirect paths
	location := strings.ToLower(resp.Header.Get("Location"))
	if strings.Contains(location, "cscoe") || strings.Contains(location, "webvpn") {
		return true
	}

	// Check Server header for Cisco
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverHeader, "cisco") {
		return true
	}

	// Check for X-ASA-Version header (definitive indicator)
	if resp.Header.Get("X-ASA-Version") != "" {
		return true
	}

	// Check for X-Transcend-Version header (another ASA indicator)
	if resp.Header.Get("X-Transcend-Version") != "" {
		return true
	}

	// Check cookies for AnyConnect indicators
	cookies := resp.Header.Values("Set-Cookie")
	for _, cookie := range cookies {
		cookieLower := strings.ToLower(cookie)
		for _, vpnCookie := range anyConnectCookies {
			if strings.Contains(cookieLower, strings.ToLower(vpnCookie)) {
				return true
			}
		}
	}

	return false // Only match if header indicators found; body-only detection is too prone to false positives
}

func (f *AnyConnectFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Accept 2xx and 3xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, nil
	}

	// Check headers
	headerMatch := false

	// Check Location header for AnyConnect redirect paths
	location := strings.ToLower(resp.Header.Get("Location"))
	if strings.Contains(location, "cscoe") || strings.Contains(location, "webvpn") {
		headerMatch = true
	}

	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverHeader, "cisco") {
		headerMatch = true
	}
	if resp.Header.Get("X-ASA-Version") != "" {
		headerMatch = true
	}
	if resp.Header.Get("X-Transcend-Version") != "" {
		headerMatch = true
	}

	// Check cookies
	cookies := resp.Header.Values("Set-Cookie")
	for _, cookie := range cookies {
		cookieLower := strings.ToLower(cookie)
		for _, vpnCookie := range anyConnectCookies {
			if strings.Contains(cookieLower, strings.ToLower(vpnCookie)) {
				headerMatch = true
				break
			}
		}
	}

	// Check response body for AnyConnect markers
	bodyStr := string(body)
	bodyMatch := false
	for _, pattern := range anyConnectPatterns {
		if pattern.MatchString(bodyStr) {
			bodyMatch = true
			break
		}
	}

	if !bodyMatch && !headerMatch {
		return nil, nil
	}

	// Extract version
	version := extractAnyConnectVersion(body, resp.Header)

	return &FingerprintResult{
		Technology: "cisco-anyconnect",
		Version:    version,
		CPEs:       []string{buildAnyConnectCPE(version)},
		Metadata: map[string]any{
			"vendor":  "Cisco",
			"product": "AnyConnect",
		},
	}, nil
}

func extractAnyConnectVersion(body []byte, headers http.Header) string {
	// First check X-ASA-Version header (most reliable)
	if version := headers.Get("X-ASA-Version"); version != "" {
		return version
	}

	// Check X-Transcend-Version header
	if version := headers.Get("X-Transcend-Version"); version != "" {
		return version
	}

	// Check Server header for version
	serverHeader := headers.Get("Server")
	if matches := asaVersionPattern.FindStringSubmatch(serverHeader); len(matches) > 1 {
		return matches[1]
	}

	// Check body for version strings
	if matches := asaVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	return ""
}

func buildAnyConnectCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:cisco:adaptive_security_appliance_software:%s:*:*:*:*:*:*:*", version)
}
