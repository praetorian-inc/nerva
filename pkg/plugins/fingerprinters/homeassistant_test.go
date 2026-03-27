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
	"net/http"
	"testing"
)

// --- HomeAssistantManifestFingerprinter Tests ---

func TestHomeAssistantManifestFingerprinter_Name(t *testing.T) {
	fp := &HomeAssistantManifestFingerprinter{}
	if got := fp.Name(); got != "homeassistant-manifest" {
		t.Errorf("Name() = %q, want %q", got, "homeassistant-manifest")
	}
}

func TestHomeAssistantManifestFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &HomeAssistantManifestFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/manifest.json" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/manifest.json")
	}
}

func TestHomeAssistantManifestFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "json content type",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "json with charset",
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "html content type",
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "empty content type",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HomeAssistantManifestFingerprinter{}
			resp := &http.Response{
				Header: http.Header{"Content-Type": []string{tt.contentType}},
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHomeAssistantManifestFingerprinter_Fingerprint(t *testing.T) {
	tests := []struct {
		name          string
		body          []byte
		wantTech      string
		wantDetected  bool
		wantPWAName   string
		wantTheme     string
		wantMethod    string
	}{
		{
			name: "valid manifest with name field",
			body: []byte(`{
				"name": "Home Assistant",
				"short_name": "HA",
				"start_url": "/",
				"display": "standalone",
				"theme_color": "#03A9F4",
				"background_color": "#FFFFFF"
			}`),
			wantTech:     "home-assistant",
			wantDetected: true,
			wantPWAName:  "Home Assistant",
			wantTheme:    "#03A9F4",
			wantMethod:   "manifest",
		},
		{
			name: "valid manifest with short_name only",
			body: []byte(`{
				"name": "My Home",
				"short_name": "Home Assistant",
				"start_url": "/",
				"display": "standalone"
			}`),
			wantTech:     "home-assistant",
			wantDetected: true,
			wantPWAName:  "My Home",
			wantMethod:   "manifest",
		},
		{
			name: "valid manifest with both name and short_name",
			body: []byte(`{
				"name": "Home Assistant",
				"short_name": "Home Assistant",
				"start_url": "/",
				"display": "standalone",
				"theme_color": "#FF5722"
			}`),
			wantTech:     "home-assistant",
			wantDetected: true,
			wantPWAName:  "Home Assistant",
			wantTheme:    "#FF5722",
			wantMethod:   "manifest",
		},
		{
			name: "manifest without Home Assistant markers",
			body: []byte(`{
				"name": "Other App",
				"short_name": "App",
				"start_url": "/",
				"display": "standalone"
			}`),
			wantDetected: false,
		},
		{
			name:         "invalid JSON",
			body:         []byte(`{invalid json`),
			wantDetected: false,
		},
		{
			name:         "empty JSON object",
			body:         []byte(`{}`),
			wantDetected: false,
		},
		{
			name:         "empty body",
			body:         []byte(``),
			wantDetected: false,
		},
		{
			name:         "JSON array instead of object",
			body:         []byte(`["Home Assistant"]`),
			wantDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HomeAssistantManifestFingerprinter{}
			resp := &http.Response{
				Header: http.Header{"Content-Type": []string{"application/json"}},
			}

			result, err := fp.Fingerprint(resp, tt.body)
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}

			if tt.wantDetected {
				if result == nil {
					t.Fatalf("Fingerprint() returned nil, want detection")
				}
				if result.Technology != tt.wantTech {
					t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
				}
				if result.Version != "" {
					t.Errorf("Version = %q, want empty (no version detection)", result.Version)
				}
				if len(result.CPEs) != 1 {
					t.Fatalf("len(CPEs) = %d, want 1", len(result.CPEs))
				}
				wantCPE := "cpe:2.3:a:home-assistant:home-assistant:*:*:*:*:*:*:*:*"
				if result.CPEs[0] != wantCPE {
					t.Errorf("CPE = %q, want %q", result.CPEs[0], wantCPE)
				}

				// Check metadata
				if method, ok := result.Metadata["detection_method"].(string); !ok || method != tt.wantMethod {
					t.Errorf("detection_method = %v, want %q", result.Metadata["detection_method"], tt.wantMethod)
				}
				if tt.wantPWAName != "" {
					if name, ok := result.Metadata["pwa_name"].(string); !ok || name != tt.wantPWAName {
						t.Errorf("pwa_name = %v, want %q", result.Metadata["pwa_name"], tt.wantPWAName)
					}
				}
				if tt.wantTheme != "" {
					if theme, ok := result.Metadata["theme_color"].(string); !ok || theme != tt.wantTheme {
						t.Errorf("theme_color = %v, want %q", result.Metadata["theme_color"], tt.wantTheme)
					}
				}
			} else {
				if result != nil {
					t.Errorf("Fingerprint() = %+v, want nil (no detection)", result)
				}
			}
		})
	}
}

// --- HomeAssistantFingerprinter Tests ---

func TestHomeAssistantFingerprinter_Name(t *testing.T) {
	fp := &HomeAssistantFingerprinter{}
	if got := fp.Name(); got != "homeassistant" {
		t.Errorf("Name() = %q, want %q", got, "homeassistant")
	}
}

func TestHomeAssistantFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &HomeAssistantFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/")
	}
}

func TestHomeAssistantFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "html content type",
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "html with charset",
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "json content type",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "empty content type",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HomeAssistantFingerprinter{}
			resp := &http.Response{
				Header: http.Header{"Content-Type": []string{tt.contentType}},
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHomeAssistantFingerprinter_Fingerprint(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantDetected bool
		wantMarkers  []string
		wantScore    int
	}{
		{
			name: "all markers present",
			body: `<!DOCTYPE html>
<html>
<head>
    <title>Home Assistant</title>
    <link rel="manifest" href="/manifest.json">
    <script src="/frontend_latest/home-assistant.js"></script>
</head>
<body>
    <home-assistant></home-assistant>
    <script>
        // Initialize Home Assistant
        window.hassConnection = true;
    </script>
</body>
</html>`,
			wantDetected: true,
			wantMarkers:  []string{"title_home_assistant", "home_assistant_element", "script_hass", "manifest_link"},
			wantScore:    4,
		},
		{
			name: "title and custom element (score 2)",
			body: `<!DOCTYPE html>
<html>
<head>
    <title>My Home Assistant</title>
</head>
<body>
    <home-assistant></home-assistant>
</body>
</html>`,
			wantDetected: true,
			wantMarkers:  []string{"title_home_assistant", "home_assistant_element"},
			wantScore:    2,
		},
		{
			name: "script markers only (score 2)",
			body: `<!DOCTYPE html>
<html>
<head>
    <script src="/home-assistant-frontend.js"></script>
    <script>
        const hass = window.hass;
    </script>
</head>
</html>`,
			wantDetected: true,
			wantMarkers:  []string{"script_home_assistant", "script_hass"},
			wantScore:    2,
		},
		{
			name: "manifest link and hass script (score 2)",
			body: `<!DOCTYPE html>
<html>
<head>
    <link rel="manifest" href="/manifest.json">
    <script>
        window.hassConnection = { connected: true };
    </script>
</head>
</html>`,
			wantDetected: true,
			wantMarkers:  []string{"manifest_link", "script_hass"},
			wantScore:    2,
		},
		{
			name: "only one marker (insufficient)",
			body: `<!DOCTYPE html>
<html>
<head>
    <title>Home Assistant</title>
</head>
</html>`,
			wantDetected: false,
		},
		{
			name: "no markers",
			body: `<!DOCTYPE html>
<html>
<head>
    <title>My Smart Home</title>
</head>
</html>`,
			wantDetected: false,
		},
		{
			name:         "empty HTML",
			body:         ``,
			wantDetected: false,
		},
		{
			name: "false positive: title only mentions assistant",
			body: `<!DOCTYPE html>
<html>
<head>
    <title>Google Assistant Integration</title>
</head>
</html>`,
			wantDetected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HomeAssistantFingerprinter{}
			resp := &http.Response{
				Header: http.Header{"Content-Type": []string{"text/html"}},
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}

			if tt.wantDetected {
				if result == nil {
					t.Fatalf("Fingerprint() returned nil, want detection")
				}
				if result.Technology != "home-assistant" {
					t.Errorf("Technology = %q, want %q", result.Technology, "home-assistant")
				}
				if result.Version != "" {
					t.Errorf("Version = %q, want empty (no version detection)", result.Version)
				}
				if len(result.CPEs) != 1 {
					t.Fatalf("len(CPEs) = %d, want 1", len(result.CPEs))
				}
				wantCPE := "cpe:2.3:a:home-assistant:home-assistant:*:*:*:*:*:*:*:*"
				if result.CPEs[0] != wantCPE {
					t.Errorf("CPE = %q, want %q", result.CPEs[0], wantCPE)
				}

				// Check metadata
				if method, ok := result.Metadata["detection_method"].(string); !ok || method != "html_markers" {
					t.Errorf("detection_method = %v, want %q", result.Metadata["detection_method"], "html_markers")
				}

				// Check markers
				markers, ok := result.Metadata["markers"].([]string)
				if !ok {
					t.Fatalf("markers not found or wrong type in metadata")
				}
				if len(markers) < 2 {
					t.Errorf("len(markers) = %d, want >= 2", len(markers))
				}

				// Verify expected markers are present
				markerMap := make(map[string]bool)
				for _, m := range markers {
					markerMap[m] = true
				}
				for _, want := range tt.wantMarkers {
					if !markerMap[want] {
						t.Errorf("marker %q not found in %v", want, markers)
					}
				}
			} else {
				if result != nil {
					t.Errorf("Fingerprint() = %+v, want nil (no detection)", result)
				}
			}
		})
	}
}
