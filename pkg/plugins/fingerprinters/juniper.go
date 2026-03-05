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

// JuniperFingerprinter detects Juniper SRX/Junos firewalls via J-Web management interface.
//
// Detection Strategy:
// Juniper SRX series firewalls run Junos OS and expose the J-Web management
// interface over HTTPS. Detection is security-critical due to:
//
//   - CVE-2023-36844: Remote Code Execution via J-Web
//   - CVE-2024-21591: Authentication bypass in Junos OS
//   - J-Web management interface exposure enables direct appliance compromise
//   - Dynamic VPN portal may expose client download and VPN access
//   - Some models ship with default credentials (root / no password)
//
// Detection uses:
//
//  1. Body Patterns: J-Web login page markers (jweb, juniper, srx references)
//  2. Headers: Juniper-specific response headers (X-Juniper-*, antiCSRFToken)
//  3. API: Junos REST API endpoint patterns (/api/, rpc-reply, junos: namespace)
type JuniperFingerprinter struct{}

func init() {
	Register(&JuniperFingerprinter{})
}

// J-Web body detection patterns
var juniperBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)j-web`),
	regexp.MustCompile(`(?i)jweb`),
	regexp.MustCompile(`(?i)juniper\s+networks`),
	regexp.MustCompile(`(?i)/jweb/`),
	regexp.MustCompile(`(?i)junos\s+web`),
	regexp.MustCompile(`(?i)SRX\d{2,4}`),
	regexp.MustCompile(`(?i)Juniper\s+Web\s+Device\s+Manager`),
	regexp.MustCompile(`(?i)/stylesheet/juniper\.css`),
}

// Junos REST API body detection patterns
var juniperAPIPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<rpc-reply\b`),
	regexp.MustCompile(`(?i)xmlns:junos=`),
	regexp.MustCompile(`(?i)<junos:version>`),
	regexp.MustCompile(`(?i)"junos-version"\s*:`),
	regexp.MustCompile(`(?i)"host-name"\s*:`),
	regexp.MustCompile(`(?i)/api/`),
}

// junosVersionRegex validates Junos version format to prevent CPE injection.
// Accepts: 21.4R3-S5, 22.2R1, 23.1R1-S1, 20.4R3-S9.2
var junosVersionRegex = regexp.MustCompile(`^\d+\.\d+R\d+(-S\d+(\.\d+)?)?$`)

// Junos version extraction patterns from body/headers
var (
	junosVersionBodyPattern   = regexp.MustCompile(`(?i)(?:junos|junos-version|version)[:\s]+(\d+\.\d+R\d+(?:-S\d+(?:\.\d+)?)?)`)
	junosVersionMetaPattern   = regexp.MustCompile(`(?i)<meta[^>]+content=["'](\d+\.\d+R\d+(?:-S\d+(?:\.\d+)?)?)["']`)
	junosVersionScriptPattern = regexp.MustCompile(`(?i)(?:version|junosVersion|JUNOS_VERSION)\s*[:=]\s*["'](\d+\.\d+R\d+(?:-S\d+(?:\.\d+)?)?)["']`)
)

// Junos REST API version extraction patterns (XML and JSON)
var (
	junosAPIVersionXMLPattern  = regexp.MustCompile(`(?i)<junos:version>(\d+\.\d+R\d+(?:-S\d+(?:\.\d+)?)?)</junos:version>`)
	junosAPIVersionJSONPattern = regexp.MustCompile(`(?i)"junos-version"\s*:\s*"(\d+\.\d+R\d+(?:-S\d+(?:\.\d+)?)?)"`)
	junosAPIHostnamePattern    = regexp.MustCompile(`(?i)"host-name"\s*:\s*"([^"]+)"`)
	junosXMLHostnamePattern    = regexp.MustCompile(`(?i)<host-name>([^<]+)</host-name>`)
)

// SRX model extraction pattern
var srxModelPattern = regexp.MustCompile(`(?i)(SRX\d{2,4}[A-Z]?)`)

// juniperModelJSPattern extracts the model from the J-Web login page JavaScript variable.
// Matches: var modelphpStr = "srx345-dc"
var juniperModelJSPattern = regexp.MustCompile(`(?i)modelphpStr\s*=\s*"(SRX\d{2,4}[A-Z]?)`)

func (f *JuniperFingerprinter) Name() string {
	return "juniper-srx"
}

func (f *JuniperFingerprinter) ProbeEndpoint() string {
	return "/"
}

func (f *JuniperFingerprinter) Match(resp *http.Response) bool {
	// Accept 2xx-4xx responses (reject 5xx server errors)
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Check for Juniper-specific headers
	if resp.Header.Get("X-Juniper-Version") != "" {
		return true
	}

	// Check Set-Cookie for J-Web session cookies
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		cookieLower := strings.ToLower(cookie)
		if strings.Contains(cookieLower, "jweb") || strings.Contains(cookieLower, "juniper") {
			return true
		}
	}

	// Check Server header for Juniper indicators
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverHeader, "juniper") || strings.Contains(serverHeader, "junos") {
		return true
	}

	// Embedthis-Appweb is the embedded web server used by Junos J-Web interface.
	// Matching here allows Fingerprint() to run body analysis for proper validation.
	// Anticsrftoken alone is insufficient; it must appear alongside Embedthis-Appweb.
	if strings.Contains(serverHeader, "embedthis-appweb") {
		return true
	}

	// Check for Junos REST API response: XML content type with junos namespace indicators
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(contentType, "application/xml") || strings.Contains(contentType, "text/xml") {
		// XML responses from /api/ endpoints may include X-Juniper-Version or junos namespace
		// Content-Type alone is insufficient; require a Junos-specific header alongside it
		if resp.Header.Get("X-Juniper-Version") != "" {
			return true
		}
	}

	return false
}

func (f *JuniperFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Accept 2xx-4xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Check header indicators
	headerMatch := false

	if resp.Header.Get("X-Juniper-Version") != "" {
		headerMatch = true
	}

	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverHeader, "juniper") || strings.Contains(serverHeader, "junos") {
		headerMatch = true
	}

	for _, cookie := range resp.Header.Values("Set-Cookie") {
		cookieLower := strings.ToLower(cookie)
		if strings.Contains(cookieLower, "jweb") || strings.Contains(cookieLower, "juniper") {
			headerMatch = true
			break
		}
	}

	// Check body for J-Web markers
	bodyStr := string(body)
	bodyMatch := false
	for _, pattern := range juniperBodyPatterns {
		if pattern.MatchString(bodyStr) {
			bodyMatch = true
			break
		}
	}

	// Check body for Junos REST API markers
	apiMatch := false
	for _, pattern := range juniperAPIPatterns {
		if pattern.MatchString(bodyStr) {
			apiMatch = true
			break
		}
	}

	// Require at least one header indicator OR body match OR API match for detection
	if !headerMatch && !bodyMatch && !apiMatch {
		return nil, nil
	}

	// Build metadata
	metadata := make(map[string]any)
	metadata["vendor"] = "Juniper Networks"
	metadata["product"] = "Junos OS"

	// Detect J-Web interface
	bodyLower := strings.ToLower(bodyStr)
	if strings.Contains(bodyLower, "jweb") ||
		strings.Contains(bodyLower, "j-web") ||
		resp.Header.Get("Anticsrftoken") != "" {
		metadata["jweb"] = true
	}

	// Detect Junos REST API
	if apiMatch {
		metadata["restAPI"] = true
	}

	// Detect Dynamic VPN portal
	if strings.Contains(bodyLower, "dynamic vpn") ||
		strings.Contains(bodyLower, "dynamicvpn") {
		metadata["dynamicVPN"] = true
	}

	// Extract platform model (SRX300, SRX1500, etc.)
	// Try the J-Web modelphpStr JavaScript variable first (more reliable on real devices).
	if matches := juniperModelJSPattern.FindStringSubmatch(bodyStr); len(matches) > 1 {
		metadata["model"] = strings.ToUpper(matches[1])
	} else if matches := srxModelPattern.FindStringSubmatch(bodyStr); len(matches) > 1 {
		metadata["model"] = matches[1]
	}

	// Extract hostname from Junos API response (JSON or XML)
	if apiMatch {
		if matches := junosAPIHostnamePattern.FindStringSubmatch(bodyStr); len(matches) > 1 {
			metadata["hostname"] = matches[1]
		} else if matches := junosXMLHostnamePattern.FindStringSubmatch(bodyStr); len(matches) > 1 {
			metadata["hostname"] = matches[1]
		}
	}

	// Extract cluster status from body
	if strings.Contains(bodyLower, "cluster") &&
		(strings.Contains(bodyLower, "node0") || strings.Contains(bodyLower, "node1")) {
		metadata["cluster"] = true
	}

	// Extract version
	version := extractJunosVersion(body, resp.Header)

	result := &FingerprintResult{
		Technology: "juniper-srx",
		Version:    version,
		CPEs:       []string{buildJuniperCPE(version)},
		Metadata:   metadata,
	}

	return result, nil
}

// extractJunosVersion attempts to extract the Junos OS version from response headers and body.
func extractJunosVersion(body []byte, headers http.Header) string {
	// Check X-Juniper-Version header first (most reliable)
	if version := headers.Get("X-Juniper-Version"); version != "" {
		if junosVersionRegex.MatchString(version) {
			return version
		}
	}

	// Try Junos REST API XML version (e.g., <junos:version>21.4R3-S5</junos:version>)
	if matches := junosAPIVersionXMLPattern.FindSubmatch(body); len(matches) > 1 {
		version := string(matches[1])
		if junosVersionRegex.MatchString(version) {
			return version
		}
	}

	// Try Junos REST API JSON version (e.g., "junos-version": "21.4R3-S5")
	if matches := junosAPIVersionJSONPattern.FindSubmatch(body); len(matches) > 1 {
		version := string(matches[1])
		if junosVersionRegex.MatchString(version) {
			return version
		}
	}

	// Try script variable pattern (e.g., junosVersion = "21.4R3-S5")
	if matches := junosVersionScriptPattern.FindSubmatch(body); len(matches) > 1 {
		version := string(matches[1])
		if junosVersionRegex.MatchString(version) {
			return version
		}
	}

	// Try meta tag pattern
	if matches := junosVersionMetaPattern.FindSubmatch(body); len(matches) > 1 {
		version := string(matches[1])
		if junosVersionRegex.MatchString(version) {
			return version
		}
	}

	// Try general version pattern in body
	if matches := junosVersionBodyPattern.FindSubmatch(body); len(matches) > 1 {
		version := string(matches[1])
		if junosVersionRegex.MatchString(version) {
			return version
		}
	}

	return ""
}

// buildJuniperCPE constructs a CPE string for Juniper Junos OS.
// CPE format: cpe:2.3:o:juniper:junos:<version>:*:*:*:*:*:*:*
func buildJuniperCPE(version string) string {
	if version == "" {
		return "cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:o:juniper:junos:%s:*:*:*:*:*:*:*", version)
}
