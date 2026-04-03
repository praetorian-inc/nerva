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

// MikroTikFingerprinter detects MikroTik RouterOS web management interfaces.
//
// Detection Strategy:
// MikroTik RouterOS exposes a web management interface called WebFig.
// Detection uses multiple signals to identify RouterOS. At least one
// MikroTik-exclusive signal (webfig or data-defaultuser) plus one
// corroborating signal must match. Generic signals alone (mikrotik,
// routeros, title) are insufficient since the fingerprinter runs against
// both "/" and "/webfig/" responses:
//
//  1. PRIMARY:   Body contains "webfig" or "/webfig/" path reference
//  2. SECONDARY: Body contains "mikrotik" (case-insensitive)
//  3. TERTIARY:  Body contains "RouterOS" string
//  4. TITLE:     Title contains "RouterOS" or "MikroTik"
//  5. LOGIN:     Body contains "data-defaultuser" (MikroTik-specific login form attribute)
//
// Version Detection:
// - Regex scan for patterns like "RouterOS v7.22.1" or version strings near MikroTik references
// - Validated against format ^\d+\.\d+(?:\.\d+)?$ for CPE safety
//
// Security Risks:
//   - Default credentials (admin with empty password) frequently unchanged
//   - CVE-2018-14847: WinBox credential disclosure (unauthenticated)
//   - Exposed management interface allows credential brute-force
//   - Winbox port (8291) allows remote code execution in unpatched versions
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// mikrotikVersionRegex matches version patterns like "RouterOS v7.22.1" or "6.49.7".
var mikrotikVersionRegex = regexp.MustCompile(`(?i)routeros\s+v?(\d+\.\d+(?:\.\d+)?)`)

// mikrotikVersionValidateRegex validates extracted version format for CPE safety.
var mikrotikVersionValidateRegex = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)

// MikroTikFingerprinter detects MikroTik RouterOS web management interfaces.
type MikroTikFingerprinter struct{}

func init() {
	Register(&MikroTikFingerprinter{})
}

func (f *MikroTikFingerprinter) Name() string {
	return "mikrotik-routeros"
}

func (f *MikroTikFingerprinter) ProbeEndpoint() string {
	return "/webfig/"
}

func (f *MikroTikFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Accept HTML responses for body-based detection.
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		return true
	}

	return false
}

func (f *MikroTikFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)

	// Signal 1: Body contains "webfig" (case-insensitive).
	hasWebFig := strings.Contains(bodyLower, "webfig")

	// Signal 2: Body contains "mikrotik" (case-insensitive).
	hasMikroTik := strings.Contains(bodyLower, "mikrotik")

	// Signal 3: Body contains "RouterOS" (case-insensitive).
	hasRouterOS := strings.Contains(bodyLower, "routeros")

	// Signal 4: Title contains "RouterOS" or "MikroTik".
	hasTitle := extractMikroTikTitle(bodyLower)

	// Signal 5: MikroTik-specific login form attribute (survives custom branding).
	hasLoginForm := strings.Contains(bodyLower, "data-defaultuser")

	// Require at least one MikroTik-exclusive signal (webfig or data-defaultuser)
	// plus at least one corroborating signal. Generic signals alone (mikrotik,
	// routeros, title) are insufficient because the fingerprinter runs against
	// both the root "/" response and the "/webfig/" probe — any page mentioning
	// "MikroTik RouterOS" would otherwise false-positive on the root response.
	hasExclusiveSignal := hasWebFig || hasLoginForm
	signalCount := 0
	for _, signal := range []bool{hasWebFig, hasMikroTik, hasRouterOS, hasTitle, hasLoginForm} {
		if signal {
			signalCount++
		}
	}
	if !hasExclusiveSignal || signalCount < 2 {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":               "MikroTik",
		"product":              "RouterOS",
		"management_interface": "webfig",
	}

	version := extractMikroTikVersion(bodyStr)

	return &FingerprintResult{
		Technology: "mikrotik-routeros",
		Version:    version,
		CPEs:       []string{BuildMikroTikRouterOSCPE(version)},
		Metadata:   metadata,
	}, nil
}

// extractMikroTikTitle returns true if the HTML title contains "routeros" or "mikrotik".
// Expects a lowercased body string.
func extractMikroTikTitle(bodyLower string) bool {
	start := strings.Index(bodyLower, "<title>")
	if start == -1 {
		return false
	}
	start += len("<title>")
	end := strings.Index(bodyLower[start:], "</title>")
	if end == -1 {
		return false
	}
	title := bodyLower[start : start+end]
	return strings.Contains(title, "routeros") || strings.Contains(title, "mikrotik")
}

// extractMikroTikVersion extracts RouterOS version from the response body.
// Looks for patterns like "RouterOS v7.22.1" or "RouterOS 6.49.7".
// Returns empty string if no valid version found.
func extractMikroTikVersion(bodyStr string) string {
	matches := mikrotikVersionRegex.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return ""
	}

	version := strings.TrimSpace(matches[1])
	if version == "" {
		return ""
	}

	// Validate version format for CPE safety.
	if !mikrotikVersionValidateRegex.MatchString(version) {
		return ""
	}

	return version
}

// BuildMikroTikRouterOSCPE generates a CPE string for MikroTik RouterOS.
// Uses the OS component type ("o") since RouterOS is an operating system.
// CPE format: cpe:2.3:o:mikrotik:routeros:{version}:*:*:*:*:*:*:*
func BuildMikroTikRouterOSCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:o:mikrotik:routeros:%s:*:*:*:*:*:*:*", version)
}
