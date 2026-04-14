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

func TestMicroHTTPDFingerprinter_Name(t *testing.T) {
	fp := &MicroHTTPDFingerprinter{}
	if got := fp.Name(); got != "micro_httpd" {
		t.Errorf("Name() = %q, want %q", got, "micro_httpd")
	}
}

func TestMicroHTTPDFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   bool
	}{
		{
			name:   "Server: micro_httpd returns true",
			server: "micro_httpd",
			want:   true,
		},
		{
			name:   "Server: micro_httpd/1.0 returns true (hypothetical version)",
			server: "micro_httpd/1.0",
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
			name:   "Server: mini_httpd/1.30 returns false (different product)",
			server: "mini_httpd/1.30",
			want:   false,
		},
		{
			name:   "Server: micro_httpd_modified returns false",
			server: "micro_httpd_modified",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MicroHTTPDFingerprinter{}
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

func TestMicroHTTPDFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name        string
		serverHdr   string
		wantVersion string
		wantCPE     string
	}{
		{
			name:        "micro_httpd (standard, no version)",
			serverHdr:   "micro_httpd",
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:acme:micro_httpd:*:*:*:*:*:*:*:*",
		},
		{
			name:        "micro_httpd/1.0 (hypothetical version)",
			serverHdr:   "micro_httpd/1.0",
			wantVersion: "1.0",
			wantCPE:     "cpe:2.3:a:acme:micro_httpd:1.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MicroHTTPDFingerprinter{}
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

			if result.Technology != "micro_httpd" {
				t.Errorf("Technology = %q, want %q", result.Technology, "micro_httpd")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
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

func TestMicroHTTPDFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		server string
	}{
		{
			name:   "nginx (not micro_httpd)",
			server: "nginx/1.18.0",
		},
		{
			name:   "No Server header",
			server: "",
		},
		{
			name:   "mini_httpd (different product)",
			server: "mini_httpd/1.30",
		},
		{
			name:   "CPE injection attempt in version",
			server: "micro_httpd/1.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MicroHTTPDFingerprinter{}
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

func TestBuildMicroHTTPDCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version 1.0",
			version: "1.0",
			want:    "cpe:2.3:a:acme:micro_httpd:1.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:acme:micro_httpd:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildMicroHTTPDCPE(tt.version); got != tt.want {
				t.Errorf("buildMicroHTTPDCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMicroHTTPDFingerprinter_Integration(t *testing.T) {
	// Save current registry state and restore after test
	originalCount := len(GetFingerprinters())
	t.Cleanup(func() {
		httpFingerprinters = httpFingerprinters[:originalCount]
	})

	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &MicroHTTPDFingerprinter{}
	Register(fp)

	// Create a valid micro_httpd response
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Server", "micro_httpd")

	results := RunFingerprinters(resp, []byte{})

	// Should find at least the micro_httpd fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "micro_httpd" {
			found = true
		}
	}

	if !found {
		t.Error("MicroHTTPDFingerprinter not found in results")
	}
}
