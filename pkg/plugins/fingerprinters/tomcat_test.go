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

func TestTomcatFingerprinter_Name(t *testing.T) {
	fp := &TomcatFingerprinter{}
	if got := fp.Name(); got != "tomcat" {
		t.Errorf("Name() = %q, want %q", got, "tomcat")
	}
}

func TestTomcatFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &TomcatFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "" {
		t.Errorf("ProbeEndpoint() = %q, want empty string (use default)", got)
	}
}

func TestTomcatFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name   string
		server string
		body   string
		want   bool
	}{
		{
			name:   "Server: Apache-Coyote/1.1 returns true",
			server: "Apache-Coyote/1.1",
			want:   true,
		},
		{
			name:   "Server: Apache Tomcat/9.0.98 returns true",
			server: "Apache Tomcat/9.0.98",
			want:   true,
		},
		{
			name:   "Tomcat error page in body returns false (Match only checks headers)",
			server: "",
			body:   "<h3>Apache Tomcat/9.0.98</h3>",
			want:   false,
		},
		{
			name:   "Server: nginx returns false",
			server: "nginx",
			want:   false,
		},
		{
			name:   "No Server header and no Tomcat in body returns false",
			server: "",
			body:   "Generic error page",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TomcatFingerprinter{}
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

func TestTomcatFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name            string
		server          string
		xPoweredBy      string
		body            string
		wantVersion     string
		wantCoyote      string
		wantServlet     string
		wantJSP         string
	}{
		{
			name:        "Version from Server header (Apache Tomcat/9.0.98)",
			server:      "Apache Tomcat/9.0.98",
			wantVersion: "9.0.98",
		},
		{
			name:        "Version from error page body",
			body:        "<html><head><title>Error</title></head><body><h3>Apache Tomcat/9.0.98</h3><p>Status: 404</p></body></html>",
			wantVersion: "9.0.98",
		},
		{
			name:        "Coyote version from Server header",
			server:      "Apache-Coyote/1.1",
			wantCoyote:  "1.1",
			wantVersion: "",
		},
		{
			name:        "Servlet version from X-Powered-By",
			xPoweredBy:  "Servlet/4.0 JSP/2.3",
			wantServlet: "4.0",
			wantJSP:     "2.3",
		},
		{
			name:        "Combined: Tomcat version + Coyote + Servlet/JSP",
			server:      "Apache Tomcat/10.1.34",
			xPoweredBy:  "Servlet/5.0 JSP/3.0",
			wantVersion: "10.1.34",
			wantServlet: "5.0",
			wantJSP:     "3.0",
		},
		{
			name:        "Tomcat 11.0.2 with Servlet 6.0",
			server:      "Apache Tomcat/11.0.2",
			xPoweredBy:  "Servlet/6.0 JSP/3.1",
			wantVersion: "11.0.2",
			wantServlet: "6.0",
			wantJSP:     "3.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TomcatFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.xPoweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.xPoweredBy)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "tomcat" {
				t.Errorf("Technology = %q, want %q", result.Technology, "tomcat")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check metadata
			if tt.wantCoyote != "" {
				if coyote, ok := result.Metadata["coyote_version"].(string); !ok || coyote != tt.wantCoyote {
					t.Errorf("Metadata[coyote_version] = %v, want %v", coyote, tt.wantCoyote)
				}
			}
			if tt.wantServlet != "" {
				if servlet, ok := result.Metadata["servlet_version"].(string); !ok || servlet != tt.wantServlet {
					t.Errorf("Metadata[servlet_version] = %v, want %v", servlet, tt.wantServlet)
				}
			}
			if tt.wantJSP != "" {
				if jsp, ok := result.Metadata["jsp_version"].(string); !ok || jsp != tt.wantJSP {
					t.Errorf("Metadata[jsp_version] = %v, want %v", jsp, tt.wantJSP)
				}
			}

			// Check CPE
			if tt.wantVersion != "" {
				if len(result.CPEs) == 0 {
					t.Error("Expected at least one CPE")
				}
				expectedCPE := "cpe:2.3:a:apache:tomcat:" + tt.wantVersion + ":*:*:*:*:*:*:*"
				if result.CPEs[0] != expectedCPE {
					t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
				}
			}
		})
	}
}

func TestTomcatFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		server string
		body   string
	}{
		{
			name:   "Non-Tomcat server",
			server: "nginx/1.21.0",
			body:   "",
		},
		{
			name:   "Empty response",
			server: "",
			body:   "",
		},
		{
			name:   "Invalid version format (letters in version)",
			server: "Apache Tomcat/9.0.x",
			body:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TomcatFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

func TestBuildTomcatCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version 9.0.98",
			version: "9.0.98",
			want:    "cpe:2.3:a:apache:tomcat:9.0.98:*:*:*:*:*:*:*",
		},
		{
			name:    "With version 10.1.34",
			version: "10.1.34",
			want:    "cpe:2.3:a:apache:tomcat:10.1.34:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildTomcatCPE(tt.version); got != tt.want {
				t.Errorf("buildTomcatCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestTomcatFingerprinter_Integration(t *testing.T) {
	// Save current registry state and restore after test
	originalCount := len(GetFingerprinters())
	t.Cleanup(func() {
		httpFingerprinters = httpFingerprinters[:originalCount]
	})

	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &TomcatFingerprinter{}
	Register(fp)

	// Create a valid Tomcat response
	body := []byte(`<html><head><title>Error</title></head><body><h3>Apache Tomcat/9.0.98</h3></body></html>`)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Server", "Apache Tomcat/9.0.98")

	results := RunFingerprinters(resp, body)

	// Should find at least the Tomcat fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "tomcat" {
			found = true
			if result.Version != "9.0.98" {
				t.Errorf("Version = %q, want %q", result.Version, "9.0.98")
			}
		}
	}

	if !found {
		t.Error("TomcatFingerprinter not found in results")
	}
}
