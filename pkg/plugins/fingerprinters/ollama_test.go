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

func TestOllamaFingerprinter_Name(t *testing.T) {
	fp := &OllamaFingerprinter{}
	if got := fp.Name(); got != "ollama" {
		t.Errorf("Name() = %q, want %q", got, "ollama")
	}
}

func TestOllamaFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &OllamaFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/api/version" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/api/version")
	}
}

func TestOllamaFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "Content-Type: application/json returns true",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "Content-Type: application/json; charset=utf-8 returns true",
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "Content-Type: text/html returns false",
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "No Content-Type header returns false",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OllamaFingerprinter{}
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

func TestOllamaFingerprinter_Fingerprint_Valid_Version(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantVersion string
	}{
		{
			name:        "Version endpoint response 0.5.1",
			body:        `{"version": "0.5.1"}`,
			wantVersion: "0.5.1",
		},
		{
			name:        "Version endpoint response 0.4.0",
			body:        `{"version": "0.4.0"}`,
			wantVersion: "0.4.0",
		},
		{
			name:        "Version endpoint response 1.0.0",
			body:        `{"version": "1.0.0"}`,
			wantVersion: "1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OllamaFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "ollama" {
				t.Errorf("Technology = %q, want %q", result.Technology, "ollama")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}

			// Metadata should be empty for version-only responses (no model info available)
			if result.Metadata != nil && len(result.Metadata) > 0 {
				t.Errorf("Expected empty metadata for version-only response, got %v", result.Metadata)
			}
		})
	}
}

func TestOllamaFingerprinter_Fingerprint_Valid_Tags(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantModelCount int
		wantModels     int // Number of model names expected
	}{
		{
			name: "Tags response with single model",
			body: `{
				"models": [
					{
						"name": "llama3.2:latest",
						"model": "llama3.2:latest",
						"size": 2019393189,
						"digest": "sha256:a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72",
						"details": {
							"family": "llama",
							"parameter_size": "3.2B",
							"quantization_level": "Q4_K_M"
						}
					}
				]
			}`,
			wantModelCount: 1,
			wantModels:     1,
		},
		{
			name: "Tags response with multiple models",
			body: `{
				"models": [
					{
						"name": "llama3.2:latest",
						"model": "llama3.2:latest",
						"size": 2019393189,
						"digest": "sha256:abc123",
						"details": {
							"family": "llama",
							"parameter_size": "3.2B",
							"quantization_level": "Q4_K_M"
						}
					},
					{
						"name": "codellama:7b",
						"model": "codellama:7b",
						"size": 3826793677,
						"digest": "sha256:def456",
						"details": {
							"family": "llama",
							"parameter_size": "7B",
							"quantization_level": "Q4_0"
						}
					}
				]
			}`,
			wantModelCount: 2,
			wantModels:     2,
		},
		{
			name: "Tags response with empty models array",
			body: `{
				"models": []
			}`,
			wantModelCount: 0,
			wantModels:     0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OllamaFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "ollama" {
				t.Errorf("Technology = %q, want %q", result.Technology, "ollama")
			}

			// Check metadata
			if result.Metadata == nil {
				t.Fatal("Expected metadata, got nil")
			}

			if modelCount, ok := result.Metadata["model_count"].(int); !ok || modelCount != tt.wantModelCount {
				t.Errorf("Metadata[model_count] = %v, want %v", modelCount, tt.wantModelCount)
			}

			if models, ok := result.Metadata["models"].([]string); ok {
				if len(models) != tt.wantModels {
					t.Errorf("len(Metadata[models]) = %v, want %v", len(models), tt.wantModels)
				}
			} else if tt.wantModels > 0 {
				t.Error("Expected models array in metadata")
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
		})
	}
}

func TestOllamaFingerprinter_Fingerprint_Invalid(t *testing.T) {
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
			name: "Empty string",
			body: "",
		},
		{
			name: "Version with CPE injection attempt (colons)",
			body: `{"version": "0.5.1:*:*:*:*:*:*:*"}`,
		},
		{
			name: "Version with CPE injection attempt (slashes)",
			body: `{"version": "../../../etc/passwd"}`,
		},
		{
			name: "Version with special characters",
			body: `{"version": "0.5.1; rm -rf /"}`,
		},
		{
			name: "JSON with wrong structure (not version or models)",
			body: `{"status": "ok"}`,
		},
		{
			name: "Malformed models array",
			body: `{"models": "not-an-array"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OllamaFingerprinter{}
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

func TestBuildOllamaCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version 0.5.1",
			version: "0.5.1",
			want:    "cpe:2.3:a:ollama:ollama:0.5.1:*:*:*:*:*:*:*",
		},
		{
			name:    "With version 1.0.0",
			version: "1.0.0",
			want:    "cpe:2.3:a:ollama:ollama:1.0.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:ollama:ollama:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildOllamaCPE(tt.version); got != tt.want {
				t.Errorf("buildOllamaCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOllamaFingerprinter_Integration(t *testing.T) {
	// Save and restore global state to prevent test pollution
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &OllamaFingerprinter{}
	Register(fp)

	// Test with version response
	versionBody := []byte(`{"version": "0.5.1"}`)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	results := RunFingerprinters(resp, versionBody)

	// Should find at least the Ollama fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "ollama" {
			found = true
			if result.Version != "0.5.1" {
				t.Errorf("Version = %q, want %q", result.Version, "0.5.1")
			}
		}
	}

	if !found {
		t.Error("OllamaFingerprinter not found in results")
	}

	// Test with tags response
	tagsBody := []byte(`{
		"models": [
			{
				"name": "llama3.2:latest",
				"model": "llama3.2:latest",
				"size": 2019393189,
				"digest": "sha256:a80c4f17acd55265feec403c7aef86be0c25983ab279d83f3bcd3abbcb5b8b72"
			}
		]
	}`)

	results = RunFingerprinters(resp, tagsBody)

	found = false
	for _, result := range results {
		if result.Technology == "ollama" {
			found = true
			if modelCount, ok := result.Metadata["model_count"].(int); !ok || modelCount != 1 {
				t.Errorf("model_count = %v, want 1", modelCount)
			}
		}
	}

	if !found {
		t.Error("OllamaFingerprinter not found in results for tags response")
	}
}
