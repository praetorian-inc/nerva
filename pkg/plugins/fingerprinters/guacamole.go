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

/*
Package fingerprinters provides HTTP fingerprinting for Apache Guacamole.

# Detection Strategy

Apache Guacamole is a clientless remote desktop gateway supporting VNC, RDP,
SSH, and Telnet through a web browser. Exposed instances represent a security
concern due to:
  - Credential harvesting via brute-force on the login page
  - Session hijacking of existing remote desktop sessions
  - Internal network pivoting through the gateway
  - Known CVEs including authentication bypass vulnerabilities

Detection uses two complementary approaches:

Primary: Active probe of /guacamole/api/languages (no authentication required).
This endpoint returns a JSON object mapping language codes to display names and
is unique to Apache Guacamole installations.

Secondary: Active probe of /guacamole/ login page. The HTML contains
Guacamole-specific markers including guac-login elements, guacamole-common-js
scripts, and a build timestamp meta tag.

# Version Detection

Guacamole does not expose its version through unauthenticated API endpoints.
Version information is embedded in extension JAR manifests (guac-manifest.json)
which are not accessible without authentication.

The login page includes a build timestamp in a meta tag:

	<meta name="build" content="20260319005723">

This timestamp is captured in metadata as a weak version indicator that can help
distinguish between deployments.

# Port Configuration

Guacamole typically runs on:
  - 8080: Default Tomcat HTTP port
  - 8443: Tomcat HTTPS

# Example Usage

	fp := &GuacamoleFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s\n", result.Technology)
		}
	}
*/
package fingerprinters

import (
	"encoding/json"
	"net/http"
	"regexp"
	"strings"
)

// GuacamoleFingerprinter detects Apache Guacamole via /guacamole/api/languages endpoint.
// This is the primary detection method using the unauthenticated languages API.
type GuacamoleFingerprinter struct{}

// GuacamoleLoginFingerprinter detects Apache Guacamole via /guacamole/ login page.
// This is the secondary detection method using HTML markers.
type GuacamoleLoginFingerprinter struct{}

// guacamoleBuildRegex extracts the build timestamp from the login page.
// Matches: <meta name="build" content="20260319005723">
var guacamoleBuildRegex = regexp.MustCompile(`<meta\s+name="build"\s+content="(\d+)"`)

func init() {
	Register(&GuacamoleFingerprinter{})
	Register(&GuacamoleLoginFingerprinter{})
}

// --- GuacamoleFingerprinter (API languages endpoint) ---

func (f *GuacamoleFingerprinter) Name() string {
	return "guacamole"
}

func (f *GuacamoleFingerprinter) ProbeEndpoint() string {
	return "/guacamole/api/languages"
}

func (f *GuacamoleFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *GuacamoleFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Parse as a map of language code to display name
	var languages map[string]string
	if err := json.Unmarshal(body, &languages); err != nil {
		return nil, nil
	}

	// Validate this is actually Guacamole's languages endpoint:
	// - Must be a non-empty object (not an empty JSON object or array)
	// - Must contain "en" key (English is always present in Guacamole)
	// - Values must be non-empty strings (language display names)
	if len(languages) == 0 {
		return nil, nil
	}

	enName, hasEnglish := languages["en"]
	if !hasEnglish || enName == "" {
		return nil, nil
	}

	// Additional validation: check for known Guacamole language patterns.
	// Guacamole uses ISO 639-1 codes and always ships with multiple languages.
	// A single-language response is suspicious (most i18n APIs return >= 5).
	if len(languages) < 3 {
		return nil, nil
	}

	// Validate all values are non-empty strings (language display names)
	for _, name := range languages {
		if name == "" {
			return nil, nil
		}
	}

	// Build language list for metadata
	langCodes := make([]string, 0, len(languages))
	for code := range languages {
		langCodes = append(langCodes, code)
	}

	metadata := map[string]any{
		"language_count": len(languages),
		"languages":      langCodes,
	}

	return &FingerprintResult{
		Technology: "apache-guacamole",
		Version:    "",
		CPEs:       []string{buildGuacamoleCPE("")},
		Metadata:   metadata,
	}, nil
}

// --- GuacamoleLoginFingerprinter (login page) ---

func (f *GuacamoleLoginFingerprinter) Name() string {
	return "guacamole-login"
}

func (f *GuacamoleLoginFingerprinter) ProbeEndpoint() string {
	return "/guacamole/"
}

func (f *GuacamoleLoginFingerprinter) Match(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "text/html")
}

func (f *GuacamoleLoginFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	bodyStr := string(body)

	// Score-based detection using multiple Guacamole-specific markers.
	// Require at least 2 markers to reduce false positives.
	score := 0
	var markers []string

	// Strong markers (unique to Guacamole)
	if strings.Contains(bodyStr, "guac-login") {
		score += 2
		markers = append(markers, "guac-login")
	}
	if strings.Contains(bodyStr, "guacamole-common-js") {
		score += 2
		markers = append(markers, "guacamole-common-js")
	}
	if strings.Contains(bodyStr, "Guacamole.Client") {
		score += 2
		markers = append(markers, "Guacamole.Client")
	}

	// Medium markers (common in Guacamole but could appear elsewhere)
	if strings.Contains(bodyStr, "guacamole.") && (strings.Contains(bodyStr, ".js") || strings.Contains(bodyStr, ".css")) {
		score++
		markers = append(markers, "guacamole-assets")
	}
	if strings.Contains(bodyStr, "Apache Guacamole") {
		score++
		markers = append(markers, "Apache Guacamole")
	}
	if strings.Contains(bodyStr, "guac-modal") {
		score++
		markers = append(markers, "guac-modal")
	}
	if strings.Contains(bodyStr, "guac-notification") {
		score++
		markers = append(markers, "guac-notification")
	}

	// Require score >= 2 for detection
	if score < 2 {
		return nil, nil
	}

	metadata := map[string]any{
		"detection_method": "login_page",
		"markers":          markers,
	}

	// Extract build timestamp if present
	if matches := guacamoleBuildRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
		metadata["build_timestamp"] = matches[1]
	}

	return &FingerprintResult{
		Technology: "apache-guacamole",
		Version:    "",
		CPEs:       []string{buildGuacamoleCPE("")},
		Metadata:   metadata,
	}, nil
}

// --- Helper functions ---

// buildGuacamoleCPE generates a CPE string for Apache Guacamole.
// CPE format: cpe:2.3:a:apache:guacamole:{version}:*:*:*:*:*:*:*
//
// Since Guacamole does not expose version information through unauthenticated
// endpoints, the version field is typically "*".
func buildGuacamoleCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return "cpe:2.3:a:apache:guacamole:" + version + ":*:*:*:*:*:*:*"
}
