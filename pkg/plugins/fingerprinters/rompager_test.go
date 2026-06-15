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

func TestRomPagerFingerprinter_Name(t *testing.T) {
	fp := &RomPagerFingerprinter{}
	if got := fp.Name(); got != "rompager" {
		t.Errorf("Name() = %q, want %q", got, "rompager")
	}
}

func TestRomPagerFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
		want       bool
	}{
		{
			name:       "Server: RomPager/4.07 UPnP/1.0 returns true",
			server:     "RomPager/4.07 UPnP/1.0",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: Allegro-Software-RomPager/4.34 returns true",
			server:     "Allegro-Software-RomPager/4.34",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: rompager/4.07 (lowercase) returns true",
			server:     "rompager/4.07",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: ROMPAGER/4.07 (uppercase) returns true",
			server:     "ROMPAGER/4.07",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: RomPager (bare, no version) returns true",
			server:     "RomPager",
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
			name:       "Status 500 returns false (even with RomPager header)",
			server:     "RomPager/4.07",
			statusCode: 500,
			want:       false,
		},
		{
			name:       "Status 404 returns true (client error accepted)",
			server:     "RomPager/4.07",
			statusCode: 404,
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RomPagerFingerprinter{}
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

func TestRomPagerFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name            string
		server          string
		wantVersion     string
		wantUPnPVersion string
	}{
		{
			name:            "RomPager/4.07 UPnP/1.0 extracts version and upnp_version",
			server:          "RomPager/4.07 UPnP/1.0",
			wantVersion:     "4.07",
			wantUPnPVersion: "1.0",
		},
		{
			name:            "Allegro-Software-RomPager/4.34 extracts version, no upnp_version",
			server:          "Allegro-Software-RomPager/4.34",
			wantVersion:     "4.34",
			wantUPnPVersion: "",
		},
		{
			name:            "RomPager/4.51 UPnP/1.0 extracts version",
			server:          "RomPager/4.51 UPnP/1.0",
			wantVersion:     "4.51",
			wantUPnPVersion: "1.0",
		},
		{
			name:            "RomPager (bare, no version) returns empty version",
			server:          "RomPager",
			wantVersion:     "",
			wantUPnPVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RomPagerFingerprinter{}
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

			if result.Technology != "rompager" {
				t.Errorf("Technology = %q, want %q", result.Technology, "rompager")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check metadata
			vendor, ok := result.Metadata["vendor"].(string)
			if !ok || vendor != "Allegro" {
				t.Errorf("Metadata[vendor] = %v, want %q", result.Metadata["vendor"], "Allegro")
			}
			product, ok := result.Metadata["product"].(string)
			if !ok || product != "RomPager" {
				t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], "RomPager")
			}
			serverHeader, ok := result.Metadata["server_header"].(string)
			if !ok || serverHeader != tt.server {
				t.Errorf("Metadata[server_header] = %v, want %q", result.Metadata["server_header"], tt.server)
			}

			// Check upnp_version metadata
			if tt.wantUPnPVersion != "" {
				upnpVersion, ok := result.Metadata["upnp_version"].(string)
				if !ok || upnpVersion != tt.wantUPnPVersion {
					t.Errorf("Metadata[upnp_version] = %v, want %q", result.Metadata["upnp_version"], tt.wantUPnPVersion)
				}
			} else {
				if _, present := result.Metadata["upnp_version"]; present {
					t.Errorf("Metadata[upnp_version] should not be present, got %v", result.Metadata["upnp_version"])
				}
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:allegrosoft:rompager:"
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

func TestRomPagerFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
	}{
		{
			name:       "Non-RomPager server header returns nil",
			server:     "Apache/2.4.41",
			statusCode: 200,
		},
		{
			name:       "Empty server header returns nil",
			server:     "",
			statusCode: 200,
		},
		{
			name:       "CPE injection attempt in Server header returns nil",
			server:     "RomPager/1.0:*:*:*:*:*:*:*",
			statusCode: 200,
		},
		{
			name:       "Status 500 returns nil",
			server:     "RomPager/4.07",
			statusCode: 500,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RomPagerFingerprinter{}
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

func TestBuildRomPagerCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version 4.07",
			version: "4.07",
			want:    "cpe:2.3:a:allegrosoft:rompager:4.07:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:allegrosoft:rompager:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildRomPagerCPE(tt.version); got != tt.want {
				t.Errorf("buildRomPagerCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRomPagerFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &RomPagerFingerprinter{}
	Register(fp)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "RomPager/4.07 UPnP/1.0")

	results := RunFingerprinters(resp, []byte{})

	// Should find at least the RomPager fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "rompager" {
			found = true
			if result.Version != "4.07" {
				t.Errorf("Version = %q, want %q", result.Version, "4.07")
			}
		}
	}

	if !found {
		t.Error("RomPagerFingerprinter not found in results")
	}
}
