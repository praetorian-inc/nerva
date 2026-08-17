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

func TestAppwebFingerprinter_Name(t *testing.T) {
	fp := &AppwebFingerprinter{}
	if got := fp.Name(); got != "appweb" {
		t.Errorf("Name() = %q, want %q", got, "appweb")
	}
}

func TestAppwebFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
		want       bool
	}{
		{
			name:       "Server: Embedthis-Appweb/4.1.0 returns true",
			server:     "Embedthis-Appweb/4.1.0",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: Mbedthis-Appweb/2.4.2 returns true",
			server:     "Mbedthis-Appweb/2.4.2",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: Appweb/7.0.1 returns true",
			server:     "Appweb/7.0.1",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: Appweb (bare, no version) returns true",
			server:     "Appweb",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: embedthis-appweb/8.2.1 (lowercase) returns true",
			server:     "embedthis-appweb/8.2.1",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Server: EMBEDTHIS-APPWEB/4.1.0 (uppercase) returns true",
			server:     "EMBEDTHIS-APPWEB/4.1.0",
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
			name:       "Server: Embedthis-http returns false (v5+ out of scope)",
			server:     "Embedthis-http",
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
			name:       "Status 500 returns false (even with Appweb header)",
			server:     "Embedthis-Appweb/4.1.0",
			statusCode: 500,
			want:       false,
		},
		{
			name:       "Status 503 returns false",
			server:     "Appweb",
			statusCode: 503,
			want:       false,
		},
		{
			name:       "Status 404 returns true (client error accepted)",
			server:     "Embedthis-Appweb/4.1.0",
			statusCode: 404,
			want:       true,
		},
		{
			name:       "Status 401 returns true (auth required accepted)",
			server:     "Appweb/7.0.1",
			statusCode: 401,
			want:       true,
		},
		{
			name:       "Server: GoAhead-http returns false",
			server:     "GoAhead-http",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "Server: nginx returns false",
			server:     "nginx/1.18.0",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "Server: NotAppweb/1.2.3 returns false (not a valid product token)",
			server:     "NotAppweb/1.2.3",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "Server: MyAppWebProxy/1.0 returns false (embedded substring)",
			server:     "MyAppWebProxy/1.0",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "Server: Appweb/1.2.3.4 returns false (4-part version rejected)",
			server:     "Appweb/1.2.3.4",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "Server: Appweb/1.2.3beta returns false (version suffix rejected)",
			server:     "Appweb/1.2.3beta",
			statusCode: 200,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AppwebFingerprinter{}
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

func TestAppwebFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		wantVersion string
	}{
		{
			name:        "Embedthis-Appweb/4.1.0 (version extraction)",
			server:      "Embedthis-Appweb/4.1.0",
			wantVersion: "4.1.0",
		},
		{
			name:        "Mbedthis-Appweb/2.4.2 (legacy version extraction)",
			server:      "Mbedthis-Appweb/2.4.2",
			wantVersion: "2.4.2",
		},
		{
			name:        "Appweb/7.0.1 (OEM version extraction)",
			server:      "Appweb/7.0.1",
			wantVersion: "7.0.1",
		},
		{
			name:        "Embedthis-Appweb/8.2.1",
			server:      "Embedthis-Appweb/8.2.1",
			wantVersion: "8.2.1",
		},
		{
			name:        "Appweb (bare, no version)",
			server:      "Appweb",
			wantVersion: "",
		},
		{
			name:        "embedthis-appweb/4.1.0 (lowercase, version extraction)",
			server:      "embedthis-appweb/4.1.0",
			wantVersion: "4.1.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AppwebFingerprinter{}
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

			if result.Technology != "appweb" {
				t.Errorf("Technology = %q, want %q", result.Technology, "appweb")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check metadata
			vendor, ok := result.Metadata["vendor"].(string)
			if !ok || vendor != "Embedthis" {
				t.Errorf("Metadata[vendor] = %v, want %q", result.Metadata["vendor"], "Embedthis")
			}
			product, ok := result.Metadata["product"].(string)
			if !ok || product != "Appweb" {
				t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], "Appweb")
			}
			serverHeader, ok := result.Metadata["server_header"].(string)
			if !ok || serverHeader != tt.server {
				t.Errorf("Metadata[server_header] = %v, want %q", result.Metadata["server_header"], tt.server)
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:embedthis:appweb:"
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

func TestAppwebFingerprinter_Fingerprint_Invalid(t *testing.T) {
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
			name:       "Server: Embedthis-http (v5+ out of scope)",
			server:     "Embedthis-http",
			statusCode: 200,
		},
		{
			name:       "CPE injection attempt in Server header",
			server:     "Embedthis-Appweb/1.0.0:*:*:*:*:*:*:*",
			statusCode: 200,
		},
		{
			name:       "Status 500",
			server:     "Embedthis-Appweb/4.1.0",
			statusCode: 500,
		},
		{
			name:       "Status 503",
			server:     "Appweb/7.0.1",
			statusCode: 503,
		},
		{
			name:       "Server: NotAppweb/1.2.3 (not a valid product token)",
			server:     "NotAppweb/1.2.3",
			statusCode: 200,
		},
		{
			name:       "Server: Appweb/1.2.3.4 (4-part version rejected)",
			server:     "Appweb/1.2.3.4",
			statusCode: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AppwebFingerprinter{}
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

func TestBuildAppwebCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "4.1.0",
			want:    "cpe:2.3:a:embedthis:appweb:4.1.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:embedthis:appweb:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Legacy version",
			version: "2.4.2",
			want:    "cpe:2.3:a:embedthis:appweb:2.4.2:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildAppwebCPE(tt.version); got != tt.want {
				t.Errorf("buildAppwebCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestAppwebFingerprinter_Integration(t *testing.T) {
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Embedthis-Appweb/4.1.0")

	results := RunFingerprinters(resp, []byte{})

	found := false
	for _, result := range results {
		if result.Technology == "appweb" {
			found = true
			if result.Version != "4.1.0" {
				t.Errorf("Version = %q, want %q", result.Version, "4.1.0")
			}
		}
	}

	if !found {
		t.Error("AppwebFingerprinter not found in results")
	}
}
