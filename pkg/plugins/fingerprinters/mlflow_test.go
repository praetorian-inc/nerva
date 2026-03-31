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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// ---------------------------------------------------------------------------
// MLflowFingerprinter tests
// ---------------------------------------------------------------------------

func TestMLflowFingerprinter_Name(t *testing.T) {
	fp := &MLflowFingerprinter{}
	if got := fp.Name(); got != "mlflow" {
		t.Errorf("Name() = %q, want %q", got, "mlflow")
	}
}

func TestMLflowFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &MLflowFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/api/2.0/mlflow/experiments/search?max_results=10" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/api/2.0/mlflow/experiments/search?max_results=10")
	}
}

func TestMLflowFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "Content-Type application/json returns true",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "Content-Type application/json with charset returns true",
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "Content-Type text/html returns false",
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
			fp := &MLflowFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMLflowFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantExpCount    int
		wantExpNames    []string
	}{
		{
			name: "Single experiment (Default)",
			body: `{"experiments": [{"experiment_id": "0", "name": "Default", "artifact_location": "mlflow-artifacts:/0", "lifecycle_stage": "active"}]}`,
			wantExpCount: 1,
			wantExpNames: []string{"Default"},
		},
		{
			name: "Multiple experiments",
			body: `{"experiments": [
				{"experiment_id": "0", "name": "Default", "artifact_location": "mlflow-artifacts:/0", "lifecycle_stage": "active"},
				{"experiment_id": "1", "name": "MyExperiment", "artifact_location": "mlflow-artifacts:/1", "lifecycle_stage": "active"}
			]}`,
			wantExpCount: 2,
			wantExpNames: []string{"Default", "MyExperiment"},
		},
		{
			name:         "Empty experiments array",
			body:         `{"experiments": []}`,
			wantExpCount: 0,
			wantExpNames: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MLflowFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "mlflow" {
				t.Errorf("Technology = %q, want %q", result.Technology, "mlflow")
			}

			count, ok := result.Metadata["experiment_count"].(int)
			if !ok {
				t.Fatalf("Metadata[experiment_count] type assertion failed, got %T", result.Metadata["experiment_count"])
			}
			if count != tt.wantExpCount {
				t.Errorf("experiment_count = %d, want %d", count, tt.wantExpCount)
			}

			names, ok := result.Metadata["experiment_names"].([]string)
			if !ok {
				t.Fatalf("Metadata[experiment_names] type assertion failed, got %T", result.Metadata["experiment_names"])
			}
			if len(names) != len(tt.wantExpNames) {
				t.Fatalf("experiment_names length = %d, want %d", len(names), len(tt.wantExpNames))
			}
			for i, want := range tt.wantExpNames {
				if names[i] != want {
					t.Errorf("experiment_names[%d] = %q, want %q", i, names[i], want)
				}
			}

			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:mlflow:mlflow:*:*:*:*:*:*:*:*"
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestMLflowFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Non-JSON body",
			body: "OK",
		},
		{
			name: "Missing experiments key",
			body: `{"status": "ok"}`,
		},
		{
			name: "Null experiments value",
			body: `{"experiments": null}`,
		},
		{
			name: "Empty string",
			body: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MLflowFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}

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

// ---------------------------------------------------------------------------
// MLflowVersionFingerprinter tests
// ---------------------------------------------------------------------------

func TestMLflowVersionFingerprinter_Name(t *testing.T) {
	fp := &MLflowVersionFingerprinter{}
	if got := fp.Name(); got != "mlflow-version" {
		t.Errorf("Name() = %q, want %q", got, "mlflow-version")
	}
}

func TestMLflowVersionFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &MLflowVersionFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/version" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/version")
	}
}

func TestMLflowVersionFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "Content-Type text/plain returns true",
			contentType: "text/plain",
			want:        true,
		},
		{
			name:        "Content-Type text/html returns true",
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "Content-Type application/json returns true",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "Content-Type application/octet-stream returns false",
			contentType: "application/octet-stream",
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
			fp := &MLflowVersionFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMLflowVersionFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantVersion string
	}{
		{
			name:        "Plain version string",
			body:        "2.3.0",
			wantVersion: "2.3.0",
		},
		{
			name:        "Quoted version string",
			body:        `"2.3.0"`,
			wantVersion: "2.3.0",
		},
		{
			name:        "Version with rc suffix",
			body:        "2.3.0rc1",
			wantVersion: "2.3.0rc1",
		},
		{
			name:        "Version with dev suffix",
			body:        "2.3.0.dev0",
			wantVersion: "2.3.0.dev0",
		},
		{
			name:        "Version with trailing newline",
			body:        "2.12.1\n",
			wantVersion: "2.12.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MLflowVersionFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "mlflow" {
				t.Errorf("Technology = %q, want %q", result.Technology, "mlflow")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			src, ok := result.Metadata["version_source"].(string)
			if !ok || src != "/version" {
				t.Errorf("Metadata[version_source] = %v, want %q", result.Metadata["version_source"], "/version")
			}

			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := fmt.Sprintf("cpe:2.3:a:mlflow:mlflow:%s:*:*:*:*:*:*:*", tt.wantVersion)
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestMLflowVersionFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Empty string",
			body: "",
		},
		{
			name: "Invalid version format (letters only)",
			body: "notaversion",
		},
		{
			name: "CPE injection attempt",
			body: "2.3.0:*:*:*:*:*:*:*",
		},
		{
			name: "Partial version (missing patch)",
			body: "2.3",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MLflowVersionFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}

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

// ---------------------------------------------------------------------------
// buildMLflowCPE tests
// ---------------------------------------------------------------------------

func TestBuildMLflowCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "2.3.0",
			want:    "cpe:2.3:a:mlflow:mlflow:2.3.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:mlflow:mlflow:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildMLflowCPE(tt.version); got != tt.want {
				t.Errorf("buildMLflowCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Integration test
// ---------------------------------------------------------------------------

func TestMLflowFingerprinter_Integration(t *testing.T) {
	fp := &MLflowFingerprinter{}
	Register(fp)

	body := []byte(`{"experiments": [{"experiment_id": "0", "name": "Default", "artifact_location": "mlflow-artifacts:/0", "lifecycle_stage": "active"}]}`)
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	results := RunFingerprinters(resp, body)

	found := false
	for _, result := range results {
		if result.Technology == "mlflow" {
			found = true
			count, ok := result.Metadata["experiment_count"].(int)
			if !ok || count != 1 {
				t.Errorf("experiment_count = %v, want 1", result.Metadata["experiment_count"])
			}
		}
	}

	if !found {
		t.Error("MLflowFingerprinter not found in results")
	}
}

// ---------------------------------------------------------------------------
// Live Docker integration test
// ---------------------------------------------------------------------------

func TestMLflowFingerprinter_LiveDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live Docker test in short mode")
	}
	// Test against live MLflow Docker container.
	// Expects: docker run -d --name mlflow-test -p 15000:5000 ghcr.io/mlflow/mlflow mlflow server --host 0.0.0.0
	baseURL := "http://localhost:15000"

	t.Run("experiments search endpoint", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/api/2.0/mlflow/experiments/search?max_results=10")
		if err != nil {
			t.Skipf("MLflow server not available at %s: %v", baseURL, err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		fp := &MLflowFingerprinter{}
		if !fp.Match(resp) {
			t.Skip("Content-Type does not match; MLflow may not be running")
		}

		result, err := fp.Fingerprint(resp, body)
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil; experiments endpoint did not match")
		}
		if result.Technology != "mlflow" {
			t.Errorf("Technology = %q, want %q", result.Technology, "mlflow")
		}
		t.Logf("Detected MLflow with %d experiment(s)", result.Metadata["experiment_count"])
	})

	t.Run("version endpoint", func(t *testing.T) {
		resp, err := http.Get(baseURL + "/version")
		if err != nil {
			t.Skipf("MLflow server not available at %s: %v", baseURL, err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}

		fp := &MLflowVersionFingerprinter{}
		if !fp.Match(resp) {
			t.Skip("Content-Type does not match version endpoint expectation")
		}

		result, err := fp.Fingerprint(resp, body)
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil; version endpoint did not match")
		}
		if result.Technology != "mlflow" {
			t.Errorf("Technology = %q, want %q", result.Technology, "mlflow")
		}
		if result.Version == "" {
			t.Error("Version is empty; expected a version string")
		}
		t.Logf("Detected MLflow version %s", result.Version)
	})
}

// ---------------------------------------------------------------------------
// httptest-based smoke test for Match + Fingerprint pipeline
// ---------------------------------------------------------------------------

func TestMLflowFingerprinter_HTTPTest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintln(w, `{"experiments": [{"experiment_id": "0", "name": "Default", "artifact_location": "mlflow-artifacts:/0", "lifecycle_stage": "active"}]}`)
	}))
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	fp := &MLflowFingerprinter{}
	if !fp.Match(resp) {
		t.Fatal("Match() returned false, want true")
	}

	result, err := fp.Fingerprint(resp, body)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}
	if result.Technology != "mlflow" {
		t.Errorf("Technology = %q, want %q", result.Technology, "mlflow")
	}
}
