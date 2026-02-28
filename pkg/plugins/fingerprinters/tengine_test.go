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

func TestTengineFingerprinter_Name(t *testing.T) {
	fp := &TengineFingerprinter{}
	if got := fp.Name(); got != "tengine" {
		t.Errorf("Name() = %q, want %q", got, "tengine")
	}
}

func TestTengineFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   bool
	}{
		{
			name:   "Server: Tengine/2.3.3 returns true",
			server: "Tengine/2.3.3",
			want:   true,
		},
		{
			name:   "Server: Tengine returns true",
			server: "Tengine",
			want:   true,
		},
		{
			name:   "Server: tengine/2.4.0 returns true (case-insensitive)",
			server: "tengine/2.4.0",
			want:   true,
		},
		{
			name:   "Server: nginx/1.18.0 (Tengine/2.3.3) returns true (contains Tengine)",
			server: "nginx/1.18.0 (Tengine/2.3.3)",
			want:   true,
		},
		{
			name:   "Server: nginx/1.18.0 returns false",
			server: "nginx/1.18.0",
			want:   false,
		},
		{
			name:   "Server: Apache/2.4.41 returns false",
			server: "Apache/2.4.41",
			want:   false,
		},
		{
			name:   "No Server header returns false",
			server: "",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TengineFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTengineFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name         string
		server       string
		wantVersion  string
		wantNginxBase string
	}{
		{
			name:          "Server: Tengine/2.3.3",
			server:        "Tengine/2.3.3",
			wantVersion:   "2.3.3",
			wantNginxBase: "1.18.0",
		},
		{
			name:          "Server: Tengine/2.4.0",
			server:        "Tengine/2.4.0",
			wantVersion:   "2.4.0",
			wantNginxBase: "1.23.0",
		},
		{
			name:          "Server: Tengine/3.0.0",
			server:        "Tengine/3.0.0",
			wantVersion:   "3.0.0",
			wantNginxBase: "",
		},
		{
			name:          "Server: Tengine (no version)",
			server:        "Tengine",
			wantVersion:   "",
			wantNginxBase: "",
		},
		{
			name:          "Server: tengine/2.3.3 (case-insensitive)",
			server:        "tengine/2.3.3",
			wantVersion:   "2.3.3",
			wantNginxBase: "1.18.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TengineFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Server", tt.server)

			result, err := fp.Fingerprint(resp, nil)
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "tengine" {
				t.Errorf("Technology = %q, want %q", result.Technology, "tengine")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check nginx_base metadata if expected
			if tt.wantNginxBase != "" {
				if nginxBase, ok := result.Metadata["nginx_base"].(string); !ok || nginxBase != tt.wantNginxBase {
					t.Errorf("Metadata[nginx_base] = %v, want %v", nginxBase, tt.wantNginxBase)
				}
			} else if _, ok := result.Metadata["nginx_base"]; ok {
				t.Errorf("Metadata[nginx_base] should not be present for version %q", tt.wantVersion)
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := buildTengineCPE(tt.wantVersion)
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestTengineFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		server string
	}{
		{
			name:   "Server: nginx/1.18.0",
			server: "nginx/1.18.0",
		},
		{
			name:   "Server: Apache/2.4.41",
			server: "Apache/2.4.41",
		},
		{
			name:   "Server: Tengine/2.3.3:*:*:*:*:*:*:* (CPE injection attempt)",
			server: "Tengine/2.3.3:*:*:*:*:*:*:*",
		},
		{
			name:   "No Server header",
			server: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TengineFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, nil)
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

func TestBuildTengineCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "2.3.3",
			want:    "cpe:2.3:a:alibaba:tengine:2.3.3:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:alibaba:tengine:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildTengineCPE(tt.version); got != tt.want {
				t.Errorf("buildTengineCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTengineFingerprinter_Integration(t *testing.T) {
	// Save current registry state before modifying and restore after test
	originalCount := len(GetFingerprinters())
	t.Cleanup(func() {
		// Restore registry to original state by removing what we added
		httpFingerprinters = httpFingerprinters[:originalCount]
	})

	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &TengineFingerprinter{}
	Register(fp)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Server", "Tengine/2.3.3")

	results := RunFingerprinters(resp, nil)

	// Should find at least the Tengine fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "tengine" {
			found = true
			if result.Version != "2.3.3" {
				t.Errorf("Version = %q, want %q", result.Version, "2.3.3")
			}
		}
	}

	if !found {
		t.Error("TengineFingerprinter not found in results")
	}
}
