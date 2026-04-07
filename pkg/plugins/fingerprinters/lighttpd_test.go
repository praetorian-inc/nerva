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

func TestLighttpdFingerprinter_Name(t *testing.T) {
	fp := &LighttpdFingerprinter{}
	if got := fp.Name(); got != "lighttpd" {
		t.Errorf("Name() = %q, want %q", got, "lighttpd")
	}
}

func TestLighttpdFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   bool
	}{
		{
			name:   "Server: lighttpd/1.4.69 returns true",
			server: "lighttpd/1.4.69",
			want:   true,
		},
		{
			name:   "Server: lighttpd returns true",
			server: "lighttpd",
			want:   true,
		},
		{
			name:   "Server: Lighttpd/1.4.69 returns true (case-insensitive)",
			server: "Lighttpd/1.4.69",
			want:   true,
		},
		{
			name:   "Server: LIGHTTPD/1.4.35 returns true (case-insensitive)",
			server: "LIGHTTPD/1.4.35",
			want:   true,
		},
		{
			name:   "Server: lighttpd/1.4.64 returns true",
			server: "lighttpd/1.4.64",
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
			name:   "Server: OPNsense returns false",
			server: "OPNsense",
			want:   false,
		},
		{
			name: "No headers returns false",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &LighttpdFingerprinter{}
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

func TestLighttpdFingerprinter_Fingerprint_ServerHeader(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		wantVersion string
	}{
		{
			name:        "lighttpd/1.4.69",
			server:      "lighttpd/1.4.69",
			wantVersion: "1.4.69",
		},
		{
			name:        "lighttpd/1.4.35",
			server:      "lighttpd/1.4.35",
			wantVersion: "1.4.35",
		},
		{
			name:        "lighttpd/2.0.0",
			server:      "lighttpd/2.0.0",
			wantVersion: "2.0.0",
		},
		{
			name:        "Lighttpd/1.4.64 (case-insensitive)",
			server:      "Lighttpd/1.4.64",
			wantVersion: "1.4.64",
		},
		{
			name:        "lighttpd (no version)",
			server:      "lighttpd",
			wantVersion: "",
		},
		{
			name:        "lighttpd/ (trailing slash, no version)",
			server:      "lighttpd/",
			wantVersion: "",
		},
		{
			name:        "lighttpd/abc (non-numeric version)",
			server:      "lighttpd/abc",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &LighttpdFingerprinter{}
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

			if result.Technology != "lighttpd" {
				t.Errorf("Technology = %q, want %q", result.Technology, "lighttpd")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := buildLighttpdCPE(tt.wantVersion)
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}

			// Check metadata
			if vendor, ok := result.Metadata["vendor"].(string); !ok || vendor != "lighttpd" {
				t.Errorf("Metadata[vendor] = %v, want %q", result.Metadata["vendor"], "lighttpd")
			}
			if product, ok := result.Metadata["product"].(string); !ok || product != "lighttpd" {
				t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], "lighttpd")
			}
		})
	}
}

func TestLighttpdFingerprinter_Fingerprint_Invalid(t *testing.T) {
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
			name:   "Server: lighttpd/1.4.69:*:*:*:*:*:*:* (CPE injection via colon)",
			server: "lighttpd/1.4.69:*:*:*:*:*:*:*",
		},
		{
			name:   "No Server header",
			server: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &LighttpdFingerprinter{}
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

func TestBuildLighttpdCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version 1.4.69",
			version: "1.4.69",
			want:    "cpe:2.3:a:lighttpd:lighttpd:1.4.69:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:lighttpd:lighttpd:*:*:*:*:*:*:*:*",
		},
		{
			name:    "With version 2.0.0",
			version: "2.0.0",
			want:    "cpe:2.3:a:lighttpd:lighttpd:2.0.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildLighttpdCPE(tt.version); got != tt.want {
				t.Errorf("buildLighttpdCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestLighttpdFingerprinter_Integration(t *testing.T) {
	originalCount := len(GetFingerprinters())
	t.Cleanup(func() {
		httpFingerprinters = httpFingerprinters[:originalCount]
	})

	fp := &LighttpdFingerprinter{}
	Register(fp)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Server", "lighttpd/1.4.69")

	results := RunFingerprinters(resp, nil)

	found := false
	for _, result := range results {
		if result.Technology == "lighttpd" {
			found = true
			if result.Version != "1.4.69" {
				t.Errorf("Version = %q, want %q", result.Version, "1.4.69")
			}
			expectedCPE := "cpe:2.3:a:lighttpd:lighttpd:1.4.69:*:*:*:*:*:*:*"
			if len(result.CPEs) == 0 || result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %v, want %q", result.CPEs, expectedCPE)
			}
		}
	}

	if !found {
		t.Error("LighttpdFingerprinter not found in results")
	}
}
