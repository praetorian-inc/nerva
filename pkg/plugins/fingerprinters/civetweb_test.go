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

func TestCivetWebFingerprinter_Name(t *testing.T) {
	fp := &CivetWebFingerprinter{}
	if got := fp.Name(); got != "civetweb" {
		t.Errorf("Name() = %q, want %q", got, "civetweb")
	}
}

func TestCivetWebFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
		want       bool
	}{
		{
			name:       "versioned CivetWeb",
			server:     "CivetWeb/1.15",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "three-part version",
			server:     "CivetWeb/1.9.1",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "lowercase Civetweb",
			server:     "Civetweb/1.8",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "uppercase CIVETWEB",
			server:     "CIVETWEB/1.15",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "bare CivetWeb",
			server:     "CivetWeb",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "bare lowercase civetweb",
			server:     "civetweb",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "404 still matches",
			server:     "CivetWeb/1.15",
			statusCode: 404,
			want:       true,
		},
		{
			name:       "499 still matches",
			server:     "CivetWeb/1.15",
			statusCode: 499,
			want:       true,
		},
		{
			name:       "500 rejected",
			server:     "CivetWeb/1.15",
			statusCode: 500,
			want:       false,
		},
		{
			name:       "503 rejected",
			server:     "CivetWeb/1.15",
			statusCode: 503,
			want:       false,
		},
		{
			name:       "199 rejected",
			server:     "CivetWeb/1.15",
			statusCode: 199,
			want:       false,
		},
		{
			name:       "empty Server",
			server:     "",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "nginx",
			server:     "nginx/1.18.0",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "Apache",
			server:     "Apache/2.4.41",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "substring-only no slash",
			server:     "MyCivetWebProxy",
			statusCode: 200,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CivetWebFingerprinter{}
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

func TestCivetWebFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		wantVersion string
	}{
		{
			name:        "two-part 1.15",
			server:      "CivetWeb/1.15",
			wantVersion: "1.15",
		},
		{
			name:        "three-part 1.9.1",
			server:      "CivetWeb/1.9.1",
			wantVersion: "1.9.1",
		},
		{
			name:        "lowercase Civetweb/1.6",
			server:      "Civetweb/1.6",
			wantVersion: "1.6",
		},
		{
			name:        "version with trailing space token",
			server:      "CivetWeb/1.15 (extra)",
			wantVersion: "1.15",
		},
		{
			name:        "version with paren",
			server:      "CivetWeb/1.12(custom)",
			wantVersion: "1.12",
		},
		{
			name:        "bare CivetWeb -> empty version",
			server:      "CivetWeb",
			wantVersion: "",
		},
		{
			name:        "bare lowercase civetweb -> empty",
			server:      "civetweb",
			wantVersion: "",
		},
		{
			name:        "present-but-malformed token -> empty (degrades to wildcard, NOT nil)",
			server:      "CivetWeb/abc",
			wantVersion: "",
		},
		{
			name:        "full-caps name extracts version",
			server:      "CIVETWEB/1.15",
			wantVersion: "1.15",
		},
		{
			name:        "whitespace right after slash -> empty",
			server:      "CivetWeb/ ",
			wantVersion: "",
		},
		{
			name:        "leading v prefix rejected",
			server:      "CivetWeb/v1.15",
			wantVersion: "",
		},
		{
			name:        "single-component version rejected",
			server:      "CivetWeb/1",
			wantVersion: "",
		},
		{
			name:        "four-part version rejected",
			server:      "CivetWeb/1.15.0.1",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CivetWebFingerprinter{}
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

			if result.Technology != "civetweb" {
				t.Errorf("Technology = %q, want %q", result.Technology, "civetweb")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			vendor, ok := result.Metadata["vendor"].(string)
			if !ok || vendor != "CivetWeb" {
				t.Errorf("Metadata[vendor] = %v, want %q", result.Metadata["vendor"], "CivetWeb")
			}
			product, ok := result.Metadata["product"].(string)
			if !ok || product != "CivetWeb" {
				t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], "CivetWeb")
			}
			serverHeader, ok := result.Metadata["server_header"].(string)
			if !ok || serverHeader != tt.server {
				t.Errorf("Metadata[server_header] = %v, want %q", result.Metadata["server_header"], tt.server)
			}

			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			var expectedCPE string
			if tt.wantVersion != "" {
				expectedCPE = "cpe:2.3:a:civetweb_project:civetweb:" + tt.wantVersion + ":*:*:*:*:*:*:*"
			} else {
				expectedCPE = "cpe:2.3:a:civetweb_project:civetweb:*:*:*:*:*:*:*:*"
			}
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestCivetWebFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
	}{
		{
			name:       "nginx",
			server:     "nginx/1.18.0",
			statusCode: 200,
		},
		{
			name:       "Apache",
			server:     "Apache/2.4.41",
			statusCode: 200,
		},
		{
			name:       "empty Server",
			server:     "",
			statusCode: 200,
		},
		{
			name:       "status 500 with CivetWeb",
			server:     "CivetWeb/1.15",
			statusCode: 500,
		},
		{
			name:       "status 503 with CivetWeb",
			server:     "CivetWeb/1.15",
			statusCode: 503,
		},
		{
			name:       "CPE injection :*:",
			server:     "CivetWeb/1.0.0:*:*:*:*:*:*:*",
			statusCode: 200,
		},
		{
			name:       "CPE injection lowercase",
			server:     "civetweb/1.0:*:*:*",
			statusCode: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CivetWebFingerprinter{}
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

func TestBuildCivetWebCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "two-part version",
			version: "1.15",
			want:    "cpe:2.3:a:civetweb_project:civetweb:1.15:*:*:*:*:*:*:*",
		},
		{
			name:    "three-part version",
			version: "1.9.1",
			want:    "cpe:2.3:a:civetweb_project:civetweb:1.9.1:*:*:*:*:*:*:*",
		},
		{
			name:    "empty -> wildcard",
			version: "",
			want:    "cpe:2.3:a:civetweb_project:civetweb:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildCivetWebCPE(tt.version); got != tt.want {
				t.Errorf("buildCivetWebCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCivetWebFingerprinter_MongooseNonCollision(t *testing.T) {
	// Sub-check 1: CivetWeb header with HTML content type
	// Mongoose Match returns true due to text/html, but Fingerprint returns nil,nil (no mongoose signal)
	// CivetWeb fingerprinter should correctly identify this as civetweb
	t.Run("CivetWeb header with text/html - mongoose does not produce result", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Server", "CivetWeb/1.15")
		resp.Header.Set("Content-Type", "text/html")
		body := []byte("<html><body><h1>Hello</h1></body></html>")

		mongooseResult, err := (&MongooseFingerprinter{}).Fingerprint(resp, body)
		if err != nil {
			t.Fatalf("MongooseFingerprinter.Fingerprint() error = %v", err)
		}
		if mongooseResult != nil {
			t.Errorf("MongooseFingerprinter.Fingerprint() = %+v, want nil for CivetWeb header", mongooseResult)
		}

		civetResult, err := (&CivetWebFingerprinter{}).Fingerprint(resp, body)
		if err != nil {
			t.Fatalf("CivetWebFingerprinter.Fingerprint() error = %v", err)
		}
		if civetResult == nil {
			t.Fatal("CivetWebFingerprinter.Fingerprint() returned nil result")
		}
		if civetResult.Technology != "civetweb" {
			t.Errorf("Technology = %q, want %q", civetResult.Technology, "civetweb")
		}
	})

	// Sub-check 2: Mongoose header does not match CivetWeb fingerprinter
	t.Run("Mongoose header does not match CivetWeb", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Server", "Mongoose/7.14")

		if got := (&CivetWebFingerprinter{}).Match(resp); got {
			t.Error("CivetWebFingerprinter.Match() = true for Mongoose header, want false")
		}
	})
}

func TestCivetWebFingerprinter_Integration(t *testing.T) {
	originalCount := len(GetFingerprinters())
	t.Cleanup(func() {
		httpFingerprinters = httpFingerprinters[:originalCount]
	})

	Register(&CivetWebFingerprinter{})

	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Server", "CivetWeb/1.15")

	results := RunFingerprinters(resp, []byte{})

	found := false
	for _, r := range results {
		if r.Technology == "civetweb" {
			found = true
			if r.Version != "1.15" {
				t.Errorf("Version = %q, want %q", r.Version, "1.15")
			}
			want := "cpe:2.3:a:civetweb_project:civetweb:1.15:*:*:*:*:*:*:*"
			if len(r.CPEs) == 0 || r.CPEs[0] != want {
				t.Errorf("CPE = %v, want %q", r.CPEs, want)
			}
		}
	}
	if !found {
		t.Error("CivetWebFingerprinter not found in results")
	}
}
