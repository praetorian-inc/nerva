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

func TestBackstageFingerprinter_Name(t *testing.T) {
	fp := &BackstageFingerprinter{}
	if got := fp.Name(); got != "backstage" {
		t.Errorf("Name() = %q, want %q", got, "backstage")
	}
}

func TestBackstageFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &BackstageFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/.backstage/health/v1/readiness" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/.backstage/health/v1/readiness")
	}
}

func TestBackstageFingerprinter_Match(t *testing.T) {
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
			fp := &BackstageFingerprinter{}
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

func TestBackstageFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantStatus     string
		wantMessage    string
		wantHasMessage bool
	}{
		{
			name:           "Healthy Backstage instance",
			body:           `{"status": "ok"}`,
			wantStatus:     "ok",
			wantHasMessage: false,
		},
		{
			name:           "Backend has not started yet",
			body:           `{"message": "Backend has not started yet", "status": "error"}`,
			wantStatus:     "error",
			wantMessage:    "Backend has not started yet",
			wantHasMessage: true,
		},
		{
			name:           "Backend is shutting down",
			body:           `{"message": "Backend is shutting down", "status": "error"}`,
			wantStatus:     "error",
			wantMessage:    "Backend is shutting down",
			wantHasMessage: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &BackstageFingerprinter{}
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

			if result.Technology != "backstage" {
				t.Errorf("Technology = %q, want %q", result.Technology, "backstage")
			}
			if result.Version != "" {
				t.Errorf("Version = %q, want empty string", result.Version)
			}

			// Check metadata status
			if status, ok := result.Metadata["status"].(string); !ok || status != tt.wantStatus {
				t.Errorf("Metadata[status] = %v, want %q", result.Metadata["status"], tt.wantStatus)
			}

			// Check metadata message
			if tt.wantHasMessage {
				if msg, ok := result.Metadata["message"].(string); !ok || msg != tt.wantMessage {
					t.Errorf("Metadata[message] = %v, want %q", result.Metadata["message"], tt.wantMessage)
				}
			} else {
				if _, ok := result.Metadata["message"]; ok {
					t.Errorf("Metadata[message] should not be present for status=ok")
				}
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:spotify:backstage:*:*:*:*:*:*:*:*"
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestBackstageFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Non-JSON body",
			body: "OK",
		},
		{
			name: "Empty body",
			body: "",
		},
		{
			name: "JSON without status field",
			body: `{"message": "something"}`,
		},
		{
			name: "JSON with unrecognized status value",
			body: `{"status": "healthy"}`,
		},
		{
			name: "JSON with only unrelated fields",
			body: `{"foo": "bar", "baz": 42}`,
		},
		{
			name: "Empty JSON object",
			body: `{}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &BackstageFingerprinter{}
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

func TestBuildBackstageCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "1.0.0",
			want:    "cpe:2.3:a:spotify:backstage:1.0.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:spotify:backstage:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildBackstageCPE(tt.version); got != tt.want {
				t.Errorf("buildBackstageCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBackstageFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &BackstageFingerprinter{}
	Register(fp)

	// Create a valid Backstage readiness response
	body := []byte(`{"status": "ok"}`)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	results := RunFingerprinters(resp, body)

	// Should find at least the Backstage fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "backstage" {
			found = true
			if result.Version != "" {
				t.Errorf("Version = %q, want empty string", result.Version)
			}
		}
	}

	if !found {
		t.Error("BackstageFingerprinter not found in results")
	}
}
