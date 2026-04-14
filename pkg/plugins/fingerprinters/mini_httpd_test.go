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

func TestMiniHTTPDFingerprinter_Name(t *testing.T) {
	fp := &MiniHTTPDFingerprinter{}
	if got := fp.Name(); got != "mini_httpd" {
		t.Errorf("Name() = %q, want %q", got, "mini_httpd")
	}
}

func TestMiniHTTPDFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   bool
	}{
		{
			name:   "Server: mini_httpd/1.30 26Oct2018 returns true",
			server: "mini_httpd/1.30 26Oct2018",
			want:   true,
		},
		{
			name:   "Server: mini_httpd/1.19 19dec2003 returns true",
			server: "mini_httpd/1.19 19dec2003",
			want:   true,
		},
		{
			name:   "Server: mini_httpd (exact, no version) returns true",
			server: "mini_httpd",
			want:   true,
		},
		{
			name:   "Server: micro_httpd returns true",
			server: "micro_httpd",
			want:   true,
		},
		{
			name:   "Server: nginx returns false",
			server: "nginx",
			want:   false,
		},
		{
			name:   "No Server header returns false",
			server: "",
			want:   false,
		},
		{
			name:   "Server: Apache/2.4.52 returns false",
			server: "Apache/2.4.52",
			want:   false,
		},
		{
			name:   "Server: mini_httpd_modified returns false",
			server: "mini_httpd_modified",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MiniHTTPDFingerprinter{}
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

func TestMiniHTTPDFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name          string
		serverHdr     string
		wantVersion   string
		wantVariant   string
		wantBuildDate string
		wantCPE       string
	}{
		{
			name:          "mini_httpd/1.30 with build date",
			serverHdr:     "mini_httpd/1.30 26Oct2018",
			wantVersion:   "1.30",
			wantVariant:   "mini_httpd",
			wantBuildDate: "26Oct2018",
			wantCPE:       "cpe:2.3:a:acme:mini_httpd:1.30:*:*:*:*:*:*:*",
		},
		{
			name:          "mini_httpd/1.19 with build date",
			serverHdr:     "mini_httpd/1.19 19dec2003",
			wantVersion:   "1.19",
			wantVariant:   "mini_httpd",
			wantBuildDate: "19dec2003",
			wantCPE:       "cpe:2.3:a:acme:mini_httpd:1.19:*:*:*:*:*:*:*",
		},
		{
			name:        "mini_httpd without version",
			serverHdr:   "mini_httpd",
			wantVersion: "",
			wantVariant: "mini_httpd",
			wantCPE:     "cpe:2.3:a:acme:mini_httpd:*:*:*:*:*:*:*:*",
		},
		{
			name:        "micro_httpd",
			serverHdr:   "micro_httpd",
			wantVersion: "",
			wantVariant: "micro_httpd",
			wantCPE:     "cpe:2.3:a:acme:micro_httpd:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MiniHTTPDFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Server", tt.serverHdr)

			result, err := fp.Fingerprint(resp, []byte{})
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "mini_httpd" {
				t.Errorf("Technology = %q, want %q", result.Technology, "mini_httpd")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check variant metadata
			if variant, ok := result.Metadata["variant"].(string); !ok || variant != tt.wantVariant {
				t.Errorf("Metadata[variant] = %v, want %q", result.Metadata["variant"], tt.wantVariant)
			}

			// Check build_date metadata
			if tt.wantBuildDate != "" {
				if buildDate, ok := result.Metadata["build_date"].(string); !ok || buildDate != tt.wantBuildDate {
					t.Errorf("Metadata[build_date] = %v, want %q", result.Metadata["build_date"], tt.wantBuildDate)
				}
			} else {
				if _, hasBuildDate := result.Metadata["build_date"]; hasBuildDate {
					t.Errorf("Metadata[build_date] should not be present, got %v", result.Metadata["build_date"])
				}
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			} else if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], tt.wantCPE)
			}
		})
	}
}

func TestMiniHTTPDFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		server string
	}{
		{
			name:   "nginx (not mini/micro_httpd)",
			server: "nginx/1.18.0",
		},
		{
			name:   "No Server header",
			server: "",
		},
		{
			name:   "Apache (different server)",
			server: "Apache/2.4.52",
		},
		{
			name:   "CPE injection attempt in version",
			server: "mini_httpd/1.30:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MiniHTTPDFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
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

func TestBuildMiniHTTPDCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version 1.30",
			version: "1.30",
			want:    "cpe:2.3:a:acme:mini_httpd:1.30:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:acme:mini_httpd:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildMiniHTTPDCPE(tt.version); got != tt.want {
				t.Errorf("buildMiniHTTPDCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildMicroHTTPDCPE(t *testing.T) {
	want := "cpe:2.3:a:acme:micro_httpd:*:*:*:*:*:*:*:*"
	if got := buildMicroHTTPDCPE(); got != want {
		t.Errorf("buildMicroHTTPDCPE() = %q, want %q", got, want)
	}
}

func TestMiniHTTPDFingerprinter_Integration(t *testing.T) {
	// Save current registry state and restore after test
	originalCount := len(GetFingerprinters())
	t.Cleanup(func() {
		httpFingerprinters = httpFingerprinters[:originalCount]
	})

	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &MiniHTTPDFingerprinter{}
	Register(fp)

	// Create a valid mini_httpd response
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Server", "mini_httpd/1.30 26Oct2018")

	results := RunFingerprinters(resp, []byte{})

	// Should find at least the mini_httpd fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "mini_httpd" {
			found = true
			if result.Version != "1.30" {
				t.Errorf("Version = %q, want %q", result.Version, "1.30")
			}
			if variant, ok := result.Metadata["variant"].(string); !ok || variant != "mini_httpd" {
				t.Errorf("Metadata[variant] = %v, want %q", result.Metadata["variant"], "mini_httpd")
			}
		}
	}

	if !found {
		t.Error("MiniHTTPDFingerprinter not found in results")
	}
}
