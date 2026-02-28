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

func TestApacheHTTPDFingerprinter_Name(t *testing.T) {
	fp := &ApacheHTTPDFingerprinter{}
	if got := fp.Name(); got != "apache_httpd" {
		t.Errorf("Name() = %q, want %q", got, "apache_httpd")
	}
}

func TestApacheHTTPDFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name   string
		server string
		want   bool
	}{
		{
			name:   "Server: Apache/2.4.52 returns true",
			server: "Apache/2.4.52",
			want:   true,
		},
		{
			name:   "Server: Apache/2.4.52 (Ubuntu) returns true",
			server: "Apache/2.4.52 (Ubuntu)",
			want:   true,
		},
		{
			name:   "Server: Apache returns true",
			server: "Apache",
			want:   true,
		},
		{
			name:   "Server: Apache/2.2.15 returns true",
			server: "Apache/2.2.15",
			want:   true,
		},
		{
			name:   "Server: Apache Tomcat/9.0.1 returns false (not Apache httpd)",
			server: "Apache Tomcat/9.0.1",
			want:   false,
		},
		{
			name:   "Server: Apache-Coyote/1.1 returns false (not Apache httpd)",
			server: "Apache-Coyote/1.1",
			want:   false,
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ApacheHTTPDFingerprinter{}
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

func TestApacheHTTPDFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name        string
		serverHdr   string
		phpHdr      string
		wantVersion string
		wantOS      string
		wantModules map[string]string
		wantPHP     string
	}{
		{
			name:        "Apache/2.4.52 with version",
			serverHdr:   "Apache/2.4.52",
			wantVersion: "2.4.52",
		},
		{
			name:        "Apache/2.4.52 (Ubuntu) with OS",
			serverHdr:   "Apache/2.4.52 (Ubuntu)",
			wantVersion: "2.4.52",
			wantOS:      "Ubuntu",
		},
		{
			name:        "Apache/2.2.15",
			serverHdr:   "Apache/2.2.15",
			wantVersion: "2.2.15",
		},
		{
			name:        "Apache without version",
			serverHdr:   "Apache",
			wantVersion: "",
		},
		{
			name:        "Apache with PHP module via X-Powered-By",
			serverHdr:   "Apache/2.4.52 (Ubuntu)",
			phpHdr:      "PHP/8.1.2",
			wantVersion: "2.4.52",
			wantOS:      "Ubuntu",
			wantPHP:     "8.1.2",
		},
		{
			name:        "Full Server header with modules",
			serverHdr:   "Apache/2.2.31 (Unix) mod_ssl/2.2.31 OpenSSL/1.0.1e-fips Resin/3.1.6",
			wantVersion: "2.2.31",
			wantOS:      "Unix",
			wantModules: map[string]string{
				"mod_ssl": "2.2.31",
				"OpenSSL": "1.0.1e-fips",
				"Resin":   "3.1.6",
			},
		},
		{
			name:        "Server header with mod_perl",
			serverHdr:   "Apache/2.4.6 (CentOS) OpenSSL/1.0.2k-fips mod_perl/2.0.11 Perl/v5.16.3",
			wantVersion: "2.4.6",
			wantOS:      "CentOS",
			wantModules: map[string]string{
				"OpenSSL":  "1.0.2k-fips",
				"mod_perl": "2.0.11",
				"Perl":     "v5.16.3",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ApacheHTTPDFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Server", tt.serverHdr)
			if tt.phpHdr != "" {
				resp.Header.Set("X-Powered-By", tt.phpHdr)
			}

			result, err := fp.Fingerprint(resp, []byte{})
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "apache_httpd" {
				t.Errorf("Technology = %q, want %q", result.Technology, "apache_httpd")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check OS metadata
			if tt.wantOS != "" {
				if os, ok := result.Metadata["os"].(string); !ok || os != tt.wantOS {
					t.Errorf("Metadata[os] = %v, want %v", result.Metadata["os"], tt.wantOS)
				}
			}

			// Check modules metadata
			if tt.wantModules != nil {
				modulesRaw, ok := result.Metadata["modules"]
				if !ok {
					t.Fatal("Metadata[modules] not found")
				}
				modules, ok := modulesRaw.(map[string]string)
				if !ok {
					t.Fatalf("Metadata[modules] is %T, want map[string]string", modulesRaw)
				}
				for name, wantVer := range tt.wantModules {
					if gotVer, exists := modules[name]; !exists {
						t.Errorf("Module %q not found in metadata", name)
					} else if gotVer != wantVer {
						t.Errorf("Module %q version = %q, want %q", name, gotVer, wantVer)
					}
				}
				// Check no extra modules
				if len(modules) != len(tt.wantModules) {
					t.Errorf("Got %d modules, want %d: %v", len(modules), len(tt.wantModules), modules)
				}
			}

			// Check PHP metadata if present
			if tt.wantPHP != "" {
				if php, ok := result.Metadata["php_version"].(string); !ok || php != tt.wantPHP {
					t.Errorf("Metadata[php_version] = %v, want %v", result.Metadata["php_version"], tt.wantPHP)
				}
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:apache:http_server:" + tt.wantVersion + ":*:*:*:*:*:*:*"
			if tt.wantVersion == "" {
				expectedCPE = "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"
			}
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestApacheHTTPDFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		server string
	}{
		{
			name:   "Apache Tomcat (not httpd)",
			server: "Apache Tomcat/9.0.1",
		},
		{
			name:   "Apache-Coyote (not httpd)",
			server: "Apache-Coyote/1.1",
		},
		{
			name:   "nginx",
			server: "nginx/1.18.0",
		},
		{
			name:   "No Server header",
			server: "",
		},
		{
			name:   "CPE injection attempt in version",
			server: "Apache/2.4.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ApacheHTTPDFingerprinter{}
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

func TestBuildApacheHTTPDCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "2.4.52",
			want:    "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildApacheHTTPDCPE(tt.version); got != tt.want {
				t.Errorf("buildApacheHTTPDCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestApacheHTTPDFingerprinter_Integration(t *testing.T) {
	// Save current registry state and restore after test
	originalCount := len(GetFingerprinters())
	t.Cleanup(func() {
		httpFingerprinters = httpFingerprinters[:originalCount]
	})

	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &ApacheHTTPDFingerprinter{}
	Register(fp)

	// Create a valid Apache httpd response
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Server", "Apache/2.4.52 (Ubuntu)")

	results := RunFingerprinters(resp, []byte{})

	// Should find at least the Apache httpd fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "apache_httpd" {
			found = true
			if result.Version != "2.4.52" {
				t.Errorf("Version = %q, want %q", result.Version, "2.4.52")
			}
		}
	}

	if !found {
		t.Error("ApacheHTTPDFingerprinter not found in results")
	}
}
