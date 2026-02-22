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

func TestGoAheadFingerprinter_Name(t *testing.T) {
	fp := &GoAheadFingerprinter{}
	if got := fp.Name(); got != "goahead" {
		t.Errorf("Name() = %q, want %q", got, "goahead")
	}
}

func TestGoAheadFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
		want       bool
	}{
		{
			name:       "Server: GoAhead-http returns true",
			server:     "GoAhead-http",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: GoAhead-Webs returns true",
			server:     "GoAhead-Webs",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: GoAhead-Webs/2.5.0 returns true",
			server:     "GoAhead-Webs/2.5.0",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: goahead-http (lowercase) returns true",
			server:     "goahead-http",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: GOAHEAD-WEBS (uppercase) returns true",
			server:     "GOAHEAD-WEBS",
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
			name:       "Status 500 returns false (even with GoAhead header)",
			server:     "GoAhead-http",
			statusCode: 500,
			want:       false,
		},
		{
			name:       "Status 404 returns true (client error accepted)",
			server:     "GoAhead-Webs",
			statusCode: 404,
			want:       true,
		},
		{
			name:       "Server: Webs (legacy Maipu branding) returns true",
			server:     "Webs",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: webs (lowercase) returns true",
			server:     "webs",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: WEBS (uppercase) returns true",
			server:     "WEBS",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: WebServer returns false (not exact match)",
			server:     "WebServer",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "Server: Webs/1.0 returns false (not exact match)",
			server:     "Webs/1.0",
			statusCode: 200,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GoAheadFingerprinter{}
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

func TestGoAheadFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		wantVersion string
	}{
		{
			name:        "GoAhead-http (no version)",
			server:      "GoAhead-http",
			wantVersion: "",
		},
		{
			name:        "GoAhead-Webs/2.5.0 (version extraction)",
			server:      "GoAhead-Webs/2.5.0",
			wantVersion: "2.5.0",
		},
		{
			name:        "GoAhead-Webs/3.6.5 PeerSec-MatrixSSL/3.4.2-OPEN (version with SSL info)",
			server:      "GoAhead-Webs/3.6.5 PeerSec-MatrixSSL/3.4.2-OPEN",
			wantVersion: "3.6.5",
		},
		{
			name:        "GoAhead-Webs (legacy, no version)",
			server:      "GoAhead-Webs",
			wantVersion: "",
		},
		{
			name:        "GoAhead-Webs/2.1.8",
			server:      "GoAhead-Webs/2.1.8",
			wantVersion: "2.1.8",
		},
		{
			name:        "Server: Webs (legacy Maipu, no version)",
			server:      "Webs",
			wantVersion: "",
		},
		{
			name:        "Server: webs (lowercase, no version)",
			server:      "webs",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GoAheadFingerprinter{}
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

			if result.Technology != "goahead" {
				t.Errorf("Technology = %q, want %q", result.Technology, "goahead")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check metadata
			vendor, ok := result.Metadata["vendor"].(string)
			if !ok || vendor != "Embedthis" {
				t.Errorf("Metadata[vendor] = %v, want %q", vendor, "Embedthis")
			}
			product, ok := result.Metadata["product"].(string)
			if !ok || product != "GoAhead" {
				t.Errorf("Metadata[product] = %v, want %q", product, "GoAhead")
			}
			serverHeader, ok := result.Metadata["serverHeader"].(string)
			if !ok || serverHeader != tt.server {
				t.Errorf("Metadata[serverHeader] = %v, want %q", serverHeader, tt.server)
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:embedthis:goahead:"
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

func TestGoAheadFingerprinter_Fingerprint_Invalid(t *testing.T) {
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
			server:     "GoAhead-Webs/1.0.0:*:*:*:*:*:*:*",
			statusCode: 200,
		},
		{
			name:       "Status 500",
			server:     "GoAhead-http",
			statusCode: 500,
		},
		{
			name:       "Status 503",
			server:     "GoAhead-Webs",
			statusCode: 503,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GoAheadFingerprinter{}
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

func TestBuildGoAheadCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "2.5.0",
			want:    "cpe:2.3:a:embedthis:goahead:2.5.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:embedthis:goahead:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildGoAheadCPE(tt.version); got != tt.want {
				t.Errorf("buildGoAheadCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGoAheadFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &GoAheadFingerprinter{}
	Register(fp)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "GoAhead-Webs/2.5.0")

	results := RunFingerprinters(resp, []byte{})

	// Should find at least the GoAhead fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "goahead" {
			found = true
			if result.Version != "2.5.0" {
				t.Errorf("Version = %q, want %q", result.Version, "2.5.0")
			}
		}
	}

	if !found {
		t.Error("GoAheadFingerprinter not found in results")
	}
}
