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

func TestBoaFingerprinter_Name(t *testing.T) {
	fp := &BoaFingerprinter{}
	if got := fp.Name(); got != "boa" {
		t.Errorf("Name() = %q, want %q", got, "boa")
	}
}

func TestBoaFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
		want       bool
	}{
		{
			name:       "Server: Boa/0.94.14rc21 returns true",
			server:     "Boa/0.94.14rc21",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: Boa/0.94.13 returns true",
			server:     "Boa/0.94.13",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: boa/0.94.13 (lowercase) returns true",
			server:     "boa/0.94.13",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: BOA/0.94.13 (uppercase) returns true",
			server:     "BOA/0.94.13",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: Apache/2.4.41 returns false",
			server:     "Apache/2.4.41",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "Empty Server header returns false",
			server:     "",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "Status 500 returns false (even with Boa header)",
			server:     "Boa/0.94.13",
			statusCode: 500,
			want:       false,
		},
		{
			name:       "Status 404 returns true (client error accepted)",
			server:     "Boa/0.94.13",
			statusCode: 404,
			want:       true,
		},
		{
			name:       "Server: Aboard/1.0 returns false (must not match 'aboard')",
			server:     "Aboard/1.0",
			statusCode: 200,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &BoaFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
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

func TestBoaFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		wantVersion string
	}{
		{
			name:        "Boa/0.94.14rc21",
			server:      "Boa/0.94.14rc21",
			wantVersion: "0.94.14rc21",
		},
		{
			name:        "Boa/0.94.13",
			server:      "Boa/0.94.13",
			wantVersion: "0.94.13",
		},
		{
			name:        "Boa/0.94.7",
			server:      "Boa/0.94.7",
			wantVersion: "0.94.7",
		},
		{
			name:        "Boa/0.92o (early version with letter suffix)",
			server:      "Boa/0.92o",
			wantVersion: "0.92o",
		},
		{
			name:        "Boa/0.94.101wk (vendor-modified variant)",
			server:      "Boa/0.94.101wk",
			wantVersion: "0.94.101wk",
		},
		{
			name:        "Boa (no version)",
			server:      "Boa",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &BoaFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Server", tt.server)

			result, err := fp.Fingerprint(resp, []byte{})
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "boa" {
				t.Errorf("Technology = %q, want %q", result.Technology, "boa")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check metadata
			vendor, ok := result.Metadata["vendor"].(string)
			if !ok || vendor != "Boa" {
				t.Errorf("Metadata[vendor] = %v, want %q", vendor, "Boa")
			}
			product, ok := result.Metadata["product"].(string)
			if !ok || product != "Boa" {
				t.Errorf("Metadata[product] = %v, want %q", product, "Boa")
			}
			serverHeader, ok := result.Metadata["server_header"].(string)
			if !ok || serverHeader != tt.server {
				t.Errorf("Metadata[server_header] = %v, want %q", serverHeader, tt.server)
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:boa:boa:"
			if tt.wantVersion != "" {
				expectedCPE += tt.wantVersion
			} else {
				expectedCPE += "*"
			}
			expectedCPE += ":*:*:*:*:*:*:*"
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestBoaFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
	}{
		{
			name:       "Server: Apache/2.4.41",
			server:     "Apache/2.4.41",
			statusCode: 200,
		},
		{
			name:       "Server: empty",
			server:     "",
			statusCode: 200,
		},
		{
			name:       "CPE injection attempt in Server header",
			server:     "Boa/1.0.0:*:*:*:*:*:*:*",
			statusCode: 200,
		},
		{
			name:       "Status 500",
			server:     "Boa/0.94.13",
			statusCode: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &BoaFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, []byte{})
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

func TestBuildBoaCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version 0.94.14rc21",
			version: "0.94.14rc21",
			want:    "cpe:2.3:a:boa:boa:0.94.14rc21:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:boa:boa:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildBoaCPE(tt.version); got != tt.want {
				t.Errorf("buildBoaCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBoaFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &BoaFingerprinter{}
	Register(fp)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Boa/0.94.13")

	results := RunFingerprinters(resp, []byte{})

	// Should find at least the Boa fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "boa" {
			found = true
			if result.Version != "0.94.13" {
				t.Errorf("Version = %q, want %q", result.Version, "0.94.13")
			}
		}
	}

	if !found {
		t.Error("BoaFingerprinter not found in results")
	}
}
