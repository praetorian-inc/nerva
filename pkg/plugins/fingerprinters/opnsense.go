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

// OPNsenseFingerprinter detects OPNsense firewall management interfaces.
//
// Detection Strategy:
// OPNsense is a pfSense fork with a distinct web interface. Detection uses
// multiple signals to identify OPNsense and distinguish it from pfSense:
//
//  1. PRIMARY:   Server header == "OPNsense" (lighttpd server.tag config)
//  2. SECONDARY: HTML title contains "| OPNsense</title>"
//  3. TERTIARY:  Body contains "login-modal-container" (OPNsense-specific CSS class)
//     or /ui/themes/opnsense/ asset paths, or Deciso B.V. copyright
//
// Version Detection:
// - Not available from unauthenticated responses
// - /api/core/firmware/info requires authentication
//
// Security Risks:
//   - Default credentials: root/opnsense often unchanged
//   - Known XSS, CSRF, and privilege escalation CVEs
//   - Exposed admin interface allows credential brute-force
//   - REST API may be enabled without proper access controls
package fingerprinters

import (
	"fmt"
	"net/http"
	"strings"
)

type OPNsenseFingerprinter struct{}

func init() {
	Register(&OPNsenseFingerprinter{})
}

func (f *OPNsenseFingerprinter) Name() string {
	return "opnsense"
}

func (f *OPNsenseFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Primary: Server header set by OPNsense's lighttpd config.
	if strings.EqualFold(resp.Header.Get("Server"), "OPNsense") {
		return true
	}

	// Accept HTML responses for body-based detection.
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		return true
	}

	return false
}

func (f *OPNsenseFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	bodyStr := string(body)

	// Signal 1: Server header.
	hasServerHeader := strings.EqualFold(resp.Header.Get("Server"), "OPNsense")

	// Signal 2: Login page title "Login | OPNsense".
	hasTitle := strings.Contains(bodyStr, "| OPNsense</title>")

	// Signal 3: OPNsense-specific CSS class (not in pfSense).
	hasLoginModal := strings.Contains(bodyStr, "login-modal-container")

	// Signal 4: OPNsense theme/JS asset paths.
	hasAssetPath := strings.Contains(bodyStr, "/ui/themes/opnsense/") ||
		strings.Contains(bodyStr, "/ui/js/opnsense")

	// Signal 5: Deciso B.V. copyright (OPNsense's parent company).
	hasDeciso := strings.Contains(bodyStr, "Deciso B.V.")

	if !hasServerHeader && !hasTitle && !hasLoginModal && !hasAssetPath && !hasDeciso {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":  "Deciso B.V.",
		"product": "OPNsense",
	}

	if hasServerHeader {
		metadata["server_header"] = "OPNsense"
	}

	// Hostname extraction from title: "Login | {hostname}" or "{page} | {hostname}"
	if hostname := extractOPNsenseHostname(bodyStr); hostname != "" {
		metadata["hostname"] = hostname
	}

	// Detect if this looks like a login page specifically.
	if strings.Contains(bodyStr, `class="page-login"`) ||
		strings.Contains(bodyStr, `name="usernamefld"`) {
		metadata["management_interface"] = "web-admin"
	}

	return &FingerprintResult{
		Technology: "opnsense",
		Version:    "",
		CPEs:       []string{buildOPNsenseCPE("")},
		Metadata:   metadata,
	}, nil
}

// extractOPNsenseHostname extracts a custom hostname from the OPNsense page title.
// OPNsense titles follow: "Login | OPNsense" or "Login | custom-hostname".
// Returns empty if the title uses the default "OPNsense" or is not found.
func extractOPNsenseHostname(bodyStr string) string {
	// Find title content between <title> tags.
	start := strings.Index(bodyStr, "<title>")
	if start == -1 {
		return ""
	}
	start += len("<title>")
	end := strings.Index(bodyStr[start:], "</title>")
	if end == -1 {
		return ""
	}
	title := strings.TrimSpace(bodyStr[start : start+end])

	// OPNsense format: "{page} | {hostname_or_product}"
	parts := strings.SplitN(title, "|", 2)
	if len(parts) != 2 {
		return ""
	}
	suffix := strings.TrimSpace(parts[1])
	if strings.EqualFold(suffix, "OPNsense") {
		return ""
	}
	return suffix
}

func buildOPNsenseCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:opnsense:opnsense:%s:*:*:*:*:*:*:*", version)
}
