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

func TestGrafanaFingerprinter_Name(t *testing.T) {
	fp := &GrafanaFingerprinter{}
	if got := fp.Name(); got != "grafana" {
		t.Errorf("Name() = %q, want %q", got, "grafana")
	}
}

func TestGrafanaFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &GrafanaFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/api/health" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/api/health")
	}
}

func TestGrafanaFingerprinter_Match(t *testing.T) {
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
			fp := &GrafanaFingerprinter{}
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

func TestGrafanaFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantVersion  string
		wantDatabase string
		wantCommit   string
	}{
		{
			name: "Full health response (10.4.1)",
			body: `{
				"commit": "abc123def456",
				"database": "ok",
				"version": "10.4.1"
			}`,
			wantVersion:  "10.4.1",
			wantDatabase: "ok",
			wantCommit:   "abc123def456",
		},
		{
			name: "Older version (9.5.2)",
			body: `{
				"commit": "xyz789",
				"database": "ok",
				"version": "9.5.2"
			}`,
			wantVersion:  "9.5.2",
			wantDatabase: "ok",
			wantCommit:   "xyz789",
		},
		{
			name: "Another version (8.2.0)",
			body: `{
				"commit": "abcdef123456",
				"database": "ok",
				"version": "8.2.0"
			}`,
			wantVersion:  "8.2.0",
			wantDatabase: "ok",
			wantCommit:   "abcdef123456",
		},
		{
			name: "Security patch version (12.3.2+security-01)",
			body: `{
				"commit": "1b895f16a067",
				"database": "ok",
				"version": "12.3.2+security-01"
			}`,
			wantVersion:  "12.3.2+security-01",
			wantDatabase: "ok",
			wantCommit:   "1b895f16a067",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GrafanaFingerprinter{}
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

			if result.Technology != "grafana" {
				t.Errorf("Technology = %q, want %q", result.Technology, "grafana")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check metadata
			if commit, ok := result.Metadata["commit"].(string); !ok || commit != tt.wantCommit {
				t.Errorf("Metadata[commit] = %v, want %v", commit, tt.wantCommit)
			}
			if database, ok := result.Metadata["database"].(string); !ok || database != tt.wantDatabase {
				t.Errorf("Metadata[database] = %v, want %v", database, tt.wantDatabase)
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:grafana:grafana:" + tt.wantVersion + ":*:*:*:*:*:*:*"
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}

		})
	}
}

func TestGrafanaFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Non-JSON body",
			body: "OK",
		},
		{
			name: "JSON without version",
			body: `{"database": "ok", "commit": "abc123"}`,
		},
		{
			name: "JSON without database",
			body: `{"version": "10.4.1", "commit": "abc123"}`,
		},
		{
			name: "JSON without commit",
			body: `{"version": "10.4.1", "database": "ok"}`,
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
			name: "Version with CPE injection attempt",
			body: `{"version": "10.0.0:*:*:*:*:*:*:*", "database": "ok", "commit": "abc"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GrafanaFingerprinter{}
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

func TestBuildGrafanaCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "10.4.1",
			want:    "cpe:2.3:a:grafana:grafana:10.4.1:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:grafana:grafana:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildGrafanaCPE(tt.version); got != tt.want {
				t.Errorf("buildGrafanaCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGrafanaFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &GrafanaFingerprinter{}
	Register(fp)

	// Create a valid Grafana health response
	body := []byte(`{
		"commit": "abc123def456",
		"database": "ok",
		"version": "10.4.1"
	}`)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	results := RunFingerprinters(resp, body)

	// Should find at least the Grafana fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "grafana" {
			found = true
			if result.Version != "10.4.1" {
				t.Errorf("Version = %q, want %q", result.Version, "10.4.1")
			}
		}
	}

	if !found {
		t.Error("GrafanaFingerprinter not found in results")
	}
}
