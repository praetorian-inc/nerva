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

// ---------------------------------------------------------------------------
// X-Powered-By detection tests (LAB-1831 enhancement)
// ---------------------------------------------------------------------------

// TestCivetWebFingerprinter_XPoweredBy_Match covers Match() with X-Powered-By.
func TestCivetWebFingerprinter_XPoweredBy_Match(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		xPoweredBy string
		statusCode int
		want       bool
	}{
		{
			name:       "iSYS server + XPB 1.7",
			server:     "iSYS Embedded Web Server",
			xPoweredBy: "Civetweb 1.7",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "iSYS server + XPB 1.11",
			server:     "iSYS Embedded Web Server",
			xPoweredBy: "Civetweb 1.11",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "nginx + XPB 1.11",
			server:     "nginx/1.26.2",
			xPoweredBy: "Civetweb 1.11",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "XPB alone no Server",
			xPoweredBy: "Civetweb 1.7",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "XPB bare Civetweb",
			xPoweredBy: "Civetweb",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "XPB civetwebproxy no boundary - false positive guard",
			xPoweredBy: "civetwebproxy/1.0",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "500 with XPB rejected",
			xPoweredBy: "Civetweb 1.7",
			statusCode: 500,
			want:       false,
		},
		{
			name:       "neither header - still false",
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
			if tt.xPoweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.xPoweredBy)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestCivetWebFingerprinter_XPoweredBy_Fingerprint covers Fingerprint() with real-world banners.
func TestCivetWebFingerprinter_XPoweredBy_Fingerprint(t *testing.T) {
	tests := []struct {
		name           string
		server         string
		xPoweredBy     string
		wantVersion    string
		wantMetaKeys   []string // keys that must be present in Metadata
		wantMatchedHdr string   // value of "matched_header" key
	}{
		{
			name:           "iSYS + Civetweb 1.7",
			server:         "iSYS Embedded Web Server",
			xPoweredBy:     "Civetweb 1.7",
			wantVersion:    "1.7",
			wantMetaKeys:   []string{"x_powered_by", "matched_header"},
			wantMatchedHdr: "x-powered-by",
		},
		{
			name:           "iSYS + Civetweb 1.11",
			server:         "iSYS Embedded Web Server",
			xPoweredBy:     "Civetweb 1.11",
			wantVersion:    "1.11",
			wantMetaKeys:   []string{"x_powered_by", "matched_header"},
			wantMatchedHdr: "x-powered-by",
		},
		{
			name:           "nginx + Civetweb 1.11",
			server:         "nginx/1.26.2",
			xPoweredBy:     "Civetweb 1.11",
			wantVersion:    "1.11",
			wantMetaKeys:   []string{"x_powered_by", "matched_header"},
			wantMatchedHdr: "x-powered-by",
		},
		{
			name:           "XPB alone no Server",
			xPoweredBy:     "Civetweb 1.7",
			wantVersion:    "1.7",
			wantMetaKeys:   []string{"x_powered_by", "matched_header"},
			wantMatchedHdr: "x-powered-by",
		},
		{
			name:           "bare XPB Civetweb -> wildcard version",
			xPoweredBy:     "Civetweb",
			wantVersion:    "",
			wantMetaKeys:   []string{"x_powered_by", "matched_header"},
			wantMatchedHdr: "x-powered-by",
		},
		{
			// Server has CivetWeb signal and valid version -> matched_header = "server"
			name:           "Server-only detection still works",
			server:         "CivetWeb/1.15",
			wantVersion:    "1.15",
			wantMetaKeys:   []string{"server_header", "matched_header"},
			wantMatchedHdr: "server",
		},
		{
			// Both Server and XPB carry civetweb; prefer first valid version (Server wins).
			name:           "both headers - Server version preferred",
			server:         "CivetWeb/1.15",
			xPoweredBy:     "Civetweb 1.7",
			wantVersion:    "1.15",
			wantMetaKeys:   []string{"server_header", "x_powered_by", "matched_header"},
			wantMatchedHdr: "both",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CivetWebFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.xPoweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.xPoweredBy)
			}

			result, err := fp.Fingerprint(resp, []byte{})
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result, want detection")
			}

			if result.Technology != "civetweb" {
				t.Errorf("Technology = %q, want %q", result.Technology, "civetweb")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			for _, key := range tt.wantMetaKeys {
				if _, ok := result.Metadata[key]; !ok {
					t.Errorf("Metadata missing key %q", key)
				}
			}

			if mh, ok := result.Metadata["matched_header"].(string); !ok || mh != tt.wantMatchedHdr {
				t.Errorf("Metadata[matched_header] = %v, want %q", result.Metadata["matched_header"], tt.wantMatchedHdr)
			}

			// CPE must never contain attacker-controlled bytes from injection attempts.
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedVersion := tt.wantVersion
			if expectedVersion == "" {
				expectedVersion = "*"
			}
			wantCPE := "cpe:2.3:a:civetweb_project:civetweb:" + expectedVersion + ":*:*:*:*:*:*:*"
			if result.CPEs[0] != wantCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], wantCPE)
			}
		})
	}
}

// TestCivetWebFingerprinter_XPoweredBy_InjectionGuard verifies CPE injection via XPB is rejected.
func TestCivetWebFingerprinter_XPoweredBy_InjectionGuard(t *testing.T) {
	fp := &CivetWebFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	// Attacker-controlled X-Powered-By with CPE injection pattern.
	resp.Header.Set("X-Powered-By", "Civetweb 1.0:*:*:*")

	result, err := fp.Fingerprint(resp, []byte{})
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	// Either nil (rejected entirely) or a result with a safe CPE (wildcard, no injection bytes).
	if result != nil {
		if len(result.CPEs) > 0 {
			cpe := result.CPEs[0]
			if cpe != "cpe:2.3:a:civetweb_project:civetweb:*:*:*:*:*:*:*:*" {
				t.Errorf("injection not rejected: CPE = %q, want wildcard CPE", cpe)
			}
		}
	}
}

// TestCivetWebFingerprinter_XPoweredBy_BoundaryFalsePositive verifies "civetwebproxy/1.0"
// is NOT detected (no word boundary after "civetweb").
func TestCivetWebFingerprinter_XPoweredBy_BoundaryFalsePositive(t *testing.T) {
	fp := &CivetWebFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-Powered-By", "civetwebproxy/1.0")

	if fp.Match(resp) {
		t.Error("Match() = true for 'civetwebproxy/1.0', want false (no boundary after civetweb)")
	}
	result, err := fp.Fingerprint(resp, []byte{})
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result != nil {
		t.Errorf("Fingerprint() = %+v, want nil for civetwebproxy", result)
	}
}

// ---------------------------------------------------------------------------
// Leading-boundary false-positive guard (LAB-1831 correctness fix)
// ---------------------------------------------------------------------------

// TestCivetWebFingerprinter_LeadingBoundary verifies that tokens where the character
// immediately preceding "civetweb" is a letter are NOT detected.
func TestCivetWebFingerprinter_LeadingBoundary(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		xPoweredBy string
		wantMatch  bool
		wantNil    bool // Fingerprint must return nil
	}{
		{
			name:      "mycivetweb/1.0 in Server - leading letter rejects",
			server:    "mycivetweb/1.0",
			wantMatch: false,
			wantNil:   true,
		},
		{
			name:       "mycivetweb/1.0 in X-Powered-By - leading letter rejects",
			xPoweredBy: "mycivetweb/1.0",
			wantMatch:  false,
			wantNil:    true,
		},
		{
			name:      "x-civetweb/1.0 in Server - non-letter leading char ok",
			server:    "x-civetweb/1.0",
			wantMatch: true,
			wantNil:   false,
		},
		{
			name:      "foo civetweb/1.15 in Server - space leading char ok",
			server:    "foo civetweb/1.15",
			wantMatch: true,
			wantNil:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CivetWebFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.xPoweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.xPoweredBy)
			}
			if got := fp.Match(resp); got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
			result, err := fp.Fingerprint(resp, []byte{})
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if tt.wantNil && result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
			if !tt.wantNil && result == nil {
				t.Error("Fingerprint() returned nil, want non-nil")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Multi-occurrence / all-occurrences scanning (LAB-1831 correctness fix)
// ---------------------------------------------------------------------------

// TestCivetWebFingerprinter_MultiOccurrence verifies that when the first "civetweb"
// token fails the boundary check the scanner continues to find a later valid one.
func TestCivetWebFingerprinter_MultiOccurrence(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		wantMatch   bool
		wantVersion string
	}{
		{
			name:        "civetwebproxy first then civetweb/1.15 - second occurrence wins",
			server:      "civetwebproxy/1.0 civetweb/1.15",
			wantMatch:   true,
			wantVersion: "1.15",
		},
		{
			name:        "Civetweb 1.7 extra - space separator ok",
			server:      "Civetweb 1.7 extra",
			wantMatch:   true,
			wantVersion: "1.7",
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

			if got := fp.Match(resp); got != tt.wantMatch {
				t.Errorf("Match() = %v, want %v", got, tt.wantMatch)
			}
			result, err := fp.Fingerprint(resp, []byte{})
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if tt.wantMatch {
				if result == nil {
					t.Fatal("Fingerprint() returned nil, want detection")
				}
				if result.Version != tt.wantVersion {
					t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
				}
			} else if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Version terminator tests (LAB-1831 suggestion)
// ---------------------------------------------------------------------------

// TestCivetWebFingerprinter_VersionTerminators verifies that ';' and ',' are
// treated as version token boundaries, consistent with real-world header values.
func TestCivetWebFingerprinter_VersionTerminators(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		wantVersion string
	}{
		{
			name:        "CivetWeb/1.15; terminated by semicolon",
			server:      "CivetWeb/1.15;",
			wantVersion: "1.15",
		},
		{
			name:        "CivetWeb/1.15,gzip terminated by comma",
			server:      "CivetWeb/1.15,gzip",
			wantVersion: "1.15",
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
				t.Fatal("Fingerprint() returned nil, want detection")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Real Shodan banners regression (LAB-1831)
// ---------------------------------------------------------------------------

// TestCivetWebFingerprinter_ShodanBanners confirms the three known real-world
// Shodan banners (iSYS+1.7, iSYS+1.11, nginx+1.11) still detect correctly.
func TestCivetWebFingerprinter_ShodanBanners(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		xPoweredBy  string
		wantVersion string
	}{
		{
			name:        "iSYS + Civetweb 1.7",
			server:      "iSYS Embedded Web Server",
			xPoweredBy:  "Civetweb 1.7",
			wantVersion: "1.7",
		},
		{
			name:        "iSYS + Civetweb 1.11",
			server:      "iSYS Embedded Web Server",
			xPoweredBy:  "Civetweb 1.11",
			wantVersion: "1.11",
		},
		{
			name:        "nginx + Civetweb 1.11",
			server:      "nginx/1.26.2",
			xPoweredBy:  "Civetweb 1.11",
			wantVersion: "1.11",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CivetWebFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.xPoweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.xPoweredBy)
			}

			if !fp.Match(resp) {
				t.Error("Match() = false, want true for Shodan banner")
			}
			result, err := fp.Fingerprint(resp, []byte{})
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want detection")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
		})
	}
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
