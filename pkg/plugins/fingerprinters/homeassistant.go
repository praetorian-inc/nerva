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
Package fingerprinters provides HTTP fingerprinting for Home Assistant.

# Detection Strategy

Home Assistant is an open-source smart home automation platform. Exposed instances
represent a security concern due to:
  - Physical access control: unlocking doors, disarming security systems
  - Camera and sensor access: privacy exposure
  - Network pivot: access to internal IoT devices
  - Automation manipulation: could cause physical harm

Detection uses two complementary approaches:

Primary: Active probe of /manifest.json (PWA manifest). Home Assistant serves
a Progressive Web App manifest with unique markers: "name" or "short_name"
containing "Home Assistant".

Secondary: Active probe of / root page. The HTML contains Home Assistant-specific
markers including:
  - Title containing "Home Assistant"
  - <home-assistant> custom element
  - Scripts containing "hass" or "home-assistant"
  - Link to /manifest.json

Score-based detection requires ≥2 markers to reduce false positives.

# Version Detection

Home Assistant does not expose version information through unauthenticated
endpoints. Version information requires authentication and access to the
/api/config endpoint.

# Port Configuration

Home Assistant typically runs on:
  - 8123: Default Home Assistant HTTP port
  - 443:  HTTPS in production

# Example Usage

	fp := &HomeAssistantManifestFingerprinter{}
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
	"strings"
)

// HomeAssistantManifestFingerprinter detects Home Assistant via /manifest.json PWA manifest.
// This is the primary detection method using the PWA manifest file.
type HomeAssistantManifestFingerprinter struct{}

// HomeAssistantFingerprinter detects Home Assistant via / root page HTML markers.
// This is the secondary detection method using score-based HTML analysis.
type HomeAssistantFingerprinter struct{}

// homeAssistantManifest represents the JSON structure from /manifest.json
type homeAssistantManifest struct {
	Name            string `json:"name"`
	ShortName       string `json:"short_name"`
	StartURL        string `json:"start_url"`
	Display         string `json:"display"`
	ThemeColor      string `json:"theme_color"`
	BackgroundColor string `json:"background_color"`
}

func init() {
	Register(&HomeAssistantManifestFingerprinter{})
	Register(&HomeAssistantFingerprinter{})
}

// --- HomeAssistantManifestFingerprinter (PWA manifest) ---

func (f *HomeAssistantManifestFingerprinter) Name() string {
	return "homeassistant-manifest"
}

func (f *HomeAssistantManifestFingerprinter) ProbeEndpoint() string {
	return "/manifest.json"
}

func (f *HomeAssistantManifestFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *HomeAssistantManifestFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Parse as Home Assistant PWA manifest
	var manifest homeAssistantManifest
	if err := json.Unmarshal(body, &manifest); err != nil {
		return nil, nil // Not valid JSON
	}

	// Check for Home Assistant markers in name or short_name fields
	isHomeAssistant := strings.Contains(manifest.Name, "Home Assistant") ||
		strings.Contains(manifest.ShortName, "Home Assistant")

	if !isHomeAssistant {
		return nil, nil
	}

	// Build metadata
	metadata := map[string]any{
		"detection_method": "manifest",
	}

	if manifest.Name != "" {
		metadata["pwa_name"] = manifest.Name
	}

	if manifest.ThemeColor != "" {
		metadata["theme_color"] = manifest.ThemeColor
	}

	return &FingerprintResult{
		Technology: "home-assistant",
		Version:    "",
		CPEs:       []string{buildHomeAssistantCPE("")},
		Metadata:   metadata,
	}, nil
}

// --- HomeAssistantFingerprinter (root page HTML) ---

func (f *HomeAssistantFingerprinter) Name() string {
	return "homeassistant"
}

func (f *HomeAssistantFingerprinter) ProbeEndpoint() string {
	return "/"
}

func (f *HomeAssistantFingerprinter) Match(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "text/html")
}

func (f *HomeAssistantFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	bodyStr := string(body)

	// Score-based detection using multiple Home Assistant-specific markers.
	// Require at least 2 markers to reduce false positives.
	score := 0
	var markers []string

	// Check for title containing "Home Assistant"
	if strings.Contains(bodyStr, "<title>") && strings.Contains(bodyStr, "Home Assistant") {
		score++
		markers = append(markers, "title_home_assistant")
	}

	// Check for <home-assistant> custom element
	if strings.Contains(bodyStr, "<home-assistant>") || strings.Contains(bodyStr, "<home-assistant ") {
		score++
		markers = append(markers, "home_assistant_element")
	}

	// Check for scripts containing "home-assistant"
	if strings.Contains(bodyStr, "home-assistant") && (strings.Contains(bodyStr, ".js") || strings.Contains(bodyStr, "<script")) {
		score++
		markers = append(markers, "script_home_assistant")
	}

	// Check for scripts containing "hass"
	if (strings.Contains(bodyStr, "hass") || strings.Contains(bodyStr, "Hass")) &&
		(strings.Contains(bodyStr, "<script") || strings.Contains(bodyStr, "window.")) {
		score++
		markers = append(markers, "script_hass")
	}

	// Check for link to /manifest.json
	if strings.Contains(bodyStr, `rel="manifest"`) && strings.Contains(bodyStr, "manifest.json") {
		score++
		markers = append(markers, "manifest_link")
	}

	// Require score >= 2 for detection
	if score < 2 {
		return nil, nil
	}

	metadata := map[string]any{
		"detection_method": "html_markers",
		"markers":          markers,
	}

	return &FingerprintResult{
		Technology: "home-assistant",
		Version:    "",
		CPEs:       []string{buildHomeAssistantCPE("")},
		Metadata:   metadata,
	}, nil
}

// --- Helper functions ---

// buildHomeAssistantCPE generates a CPE string for Home Assistant.
// CPE format: cpe:2.3:a:home-assistant:home-assistant:{version}:*:*:*:*:*:*:*
//
// Since Home Assistant does not expose version information through unauthenticated
// endpoints, the version field is typically "*".
func buildHomeAssistantCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return "cpe:2.3:a:home-assistant:home-assistant:" + version + ":*:*:*:*:*:*:*"
}
