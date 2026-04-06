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

func TestGradioFingerprinter_Name(t *testing.T) {
	fp := &GradioFingerprinter{}
	if got := fp.Name(); got != "gradio" {
		t.Errorf("Name() = %q, want %q", got, "gradio")
	}
}

func TestGradioFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &GradioFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/config" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/config")
	}
}

func TestGradioFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "application/json returns true",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "application/json; charset=utf-8 returns true",
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "text/html returns false",
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "empty content type returns false",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GradioFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGradioFingerprinter_Fingerprint_Valid_Config(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		wantVersion      string
		wantMode         string
		wantProtocol     string
		wantIsSpace      bool
		wantSpaceID      string
		wantComponentMin int    // minimum component_count expected (-1 means don't check)
		wantCPEVersion   string // when empty, defaults to wantVersion
	}{
		{
			name: "Gradio 3.x config (no protocol field, has enable_queue)",
			body: `{
				"version": "3.50.2",
				"mode": "blocks",
				"title": "My App",
				"is_space": false,
				"components": [{"id": 1, "type": "textbox"}, {"id": 2, "type": "button"}],
				"dependencies": [{"id": 0, "targets": [1]}]
			}`,
			wantVersion:      "3.50.2",
			wantMode:         "blocks",
			wantProtocol:     "",
			wantIsSpace:      false,
			wantComponentMin: 2,
		},
		{
			name: "Gradio 4.x config (protocol: sse_v3)",
			body: `{
				"version": "4.44.1",
				"mode": "blocks",
				"title": "Stable Diffusion",
				"protocol": "sse_v3",
				"is_space": false,
				"app_id": 1234567890,
				"components": [{"id": 1, "type": "image"}],
				"dependencies": []
			}`,
			wantVersion:      "4.44.1",
			wantMode:         "blocks",
			wantProtocol:     "sse_v3",
			wantIsSpace:      false,
			wantComponentMin: 1,
		},
		{
			name: "Gradio 5.x config (protocol: sse_v4)",
			body: `{
				"version": "5.12.0",
				"mode": "interface",
				"title": "Text Classifier",
				"protocol": "sse_v4",
				"is_space": false,
				"components": [{"id": 1, "type": "textbox"}, {"id": 2, "type": "label"}],
				"dependencies": [{"id": 0, "targets": [1, 2]}]
			}`,
			wantVersion:      "5.12.0",
			wantMode:         "interface",
			wantProtocol:     "sse_v4",
			wantIsSpace:      false,
			wantComponentMin: 2,
		},
		{
			name: "Config with is_space true and space_id",
			body: `{
				"version": "4.20.0",
				"mode": "blocks",
				"title": "HF Demo",
				"protocol": "sse_v3",
				"is_space": true,
				"space_id": "stabilityai/stable-diffusion",
				"components": [{"id": 1, "type": "image"}],
				"dependencies": []
			}`,
			wantVersion:  "4.20.0",
			wantIsSpace:  true,
			wantSpaceID:  "stabilityai/stable-diffusion",
			wantMode:     "blocks",
			wantProtocol: "sse_v3",
		},
		{
			name: "Config with empty components array but mode present",
			body: `{
				"version": "4.10.0",
				"mode": "blocks",
				"is_space": false,
				"components": [],
				"dependencies": []
			}`,
			wantVersion:      "4.10.0",
			wantMode:         "blocks",
			wantComponentMin: -1, // empty array, component_count not expected
		},
		{
			name: "Gradio pre-release version (4.0.0b1)",
			body: `{
				"version": "4.0.0b1",
				"mode": "blocks",
				"is_space": false,
				"components": [{"id": 1, "type": "textbox"}],
				"dependencies": []
			}`,
			wantVersion:      "4.0.0b1",
			wantMode:         "blocks",
			wantComponentMin: 1,
			wantCPEVersion:   "4.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GradioFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want non-nil result")
			}

			if result.Technology != "gradio" {
				t.Errorf("Technology = %q, want %q", result.Technology, "gradio")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			} else {
				cpeVersion := tt.wantVersion
				if tt.wantCPEVersion != "" {
					cpeVersion = tt.wantCPEVersion
				}
				wantCPE := "cpe:2.3:a:gradio_project:gradio:" + cpeVersion + ":*:*:*:*:python:*:*"
				if result.CPEs[0] != wantCPE {
					t.Errorf("CPE = %q, want %q", result.CPEs[0], wantCPE)
				}
			}

			if result.Metadata == nil {
				t.Fatal("Expected metadata, got nil")
			}

			if tt.wantMode != "" {
				if mode, ok := result.Metadata["mode"].(string); !ok || mode != tt.wantMode {
					t.Errorf("Metadata[mode] = %v, want %q", result.Metadata["mode"], tt.wantMode)
				}
			}

			if tt.wantProtocol != "" {
				if protocol, ok := result.Metadata["protocol"].(string); !ok || protocol != tt.wantProtocol {
					t.Errorf("Metadata[protocol] = %v, want %q", result.Metadata["protocol"], tt.wantProtocol)
				}
			}

			if isSpace, ok := result.Metadata["is_space"].(bool); !ok || isSpace != tt.wantIsSpace {
				t.Errorf("Metadata[is_space] = %v, want %v", result.Metadata["is_space"], tt.wantIsSpace)
			}

			if tt.wantSpaceID != "" {
				if spaceID, ok := result.Metadata["space_id"].(string); !ok || spaceID != tt.wantSpaceID {
					t.Errorf("Metadata[space_id] = %v, want %q", result.Metadata["space_id"], tt.wantSpaceID)
				}
			}

			if tt.wantComponentMin > 0 {
				if count, ok := result.Metadata["component_count"].(int); !ok || count < tt.wantComponentMin {
					t.Errorf("Metadata[component_count] = %v, want >= %d", result.Metadata["component_count"], tt.wantComponentMin)
				}
			}
		})
	}
}

func TestGradioFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Non-JSON body",
			body: "OK",
		},
		{
			name: "Empty JSON object",
			body: `{}`,
		},
		{
			name: "JSON with version but no Gradio-specific fields",
			body: `{"version": "1.2.3", "status": "ok"}`,
		},
		{
			name: "Version with CPE injection attempt (colons)",
			body: `{"version": "4.0.0:*:*:*", "mode": "blocks", "components": []}`,
		},
		{
			name: "Missing version field",
			body: `{"mode": "blocks", "components": [{"id": 1}], "dependencies": []}`,
		},
		{
			name: "Malformed components (not an array) and no other structural fields",
			body: `{"version": "4.0.0", "components": "not-an-array"}`,
		},
		{
			name: "Version with special characters (CPE injection)",
			body: `{"version": "4.0.0; rm -rf /", "mode": "blocks", "components": []}`,
		},
		{
			name: "JSON with version and unknown mode but no components/dependencies",
			body: `{"version": "4.0.0", "mode": "custom_unknown"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GradioFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

func TestBuildGradioCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version 4.44.1",
			version: "4.44.1",
			want:    "cpe:2.3:a:gradio_project:gradio:4.44.1:*:*:*:*:python:*:*",
		},
		{
			name:    "With version 3.50.2",
			version: "3.50.2",
			want:    "cpe:2.3:a:gradio_project:gradio:3.50.2:*:*:*:*:python:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:gradio_project:gradio:*:*:*:*:*:python:*:*",
		},
		{
			name:    "Pre-release version (base extracted before calling)",
			version: "4.0.0",
			want:    "cpe:2.3:a:gradio_project:gradio:4.0.0:*:*:*:*:python:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildGradioCPE(tt.version); got != tt.want {
				t.Errorf("buildGradioCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGradioFingerprinter_Integration(t *testing.T) {
	// Save and restore global state to prevent test pollution
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &GradioFingerprinter{}
	Register(fp)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	// Test with a valid Gradio 4.x config response
	body := []byte(`{
		"version": "4.44.1",
		"mode": "blocks",
		"title": "My ML App",
		"protocol": "sse_v3",
		"is_space": false,
		"components": [{"id": 1, "type": "textbox"}],
		"dependencies": []
	}`)

	results := RunFingerprinters(resp, body)

	found := false
	for _, result := range results {
		if result.Technology == "gradio" {
			found = true
			if result.Version != "4.44.1" {
				t.Errorf("Version = %q, want %q", result.Version, "4.44.1")
			}
			if mode, ok := result.Metadata["mode"].(string); !ok || mode != "blocks" {
				t.Errorf("Metadata[mode] = %v, want %q", result.Metadata["mode"], "blocks")
			}
			if protocol, ok := result.Metadata["protocol"].(string); !ok || protocol != "sse_v3" {
				t.Errorf("Metadata[protocol] = %v, want %q", result.Metadata["protocol"], "sse_v3")
			}
		}
	}

	if !found {
		t.Error("GradioFingerprinter not found in RunFingerprinters results")
	}
}
