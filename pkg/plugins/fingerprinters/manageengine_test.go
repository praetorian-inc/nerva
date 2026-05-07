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

func TestManageEngineFingerprinter_Name(t *testing.T) {
	f := &ManageEngineFingerprinter{}
	if name := f.Name(); name != "manageengine" {
		t.Errorf("Name() = %q, expected %q", name, "manageengine")
	}
}

func TestManageEngineFingerprinter_Match(t *testing.T) {
	f := &ManageEngineFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches X-ManageEngine custom header",
			statusCode: 200,
			headers:    http.Header{"X-Manageengine-Productcode": []string{"SDP"}},
			want:       true,
		},
		{
			name:       "matches Server header containing ManageEngine",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"ManageEngine ServiceDesk Plus"}},
			want:       true,
		},
		{
			name:       "matches text/html content type",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			want:       true,
		},
		{
			name:       "rejects 500 status",
			statusCode: 500,
			headers:    http.Header{"Server": []string{"ManageEngine"}},
			want:       false,
		},
		{
			name:       "rejects status below 200",
			statusCode: 199,
			headers:    http.Header{"Server": []string{"ManageEngine"}},
			want:       false,
		},
		{
			name:       "rejects non-html content type with no headers",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"application/octet-stream"}},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.headers,
			}
			if got := f.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestManageEngineFingerprinter_Fingerprint(t *testing.T) {
	f := &ManageEngineFingerprinter{}

	tests := []struct {
		name          string
		statusCode    int
		headers       http.Header
		body          string
		wantResult    bool
		wantTech      string
		wantVersion   string
		wantCPEPrefix string
		wantComponent string
		wantBuild     string
	}{
		// --- Product variant detection ---
		{
			name:          "detects ServiceDesk Plus via title",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<html><head><title>ManageEngine ServiceDesk Plus</title></head></html>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantComponent: "ServiceDesk Plus",
			wantCPEPrefix: "cpe:2.3:a:zohocorp:manageengine_servicedesk_plus:",
		},
		{
			name:          "detects ServiceDesk Plus via showLogin.cc URL",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<html><body><a href="/showLogin.cc">Login</a></body></html>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantComponent: "ServiceDesk Plus",
		},
		{
			name:          "detects ADSelfService Plus",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<html><title>ManageEngine ADSelfService Plus</title><script src="/adsspscripts/login.js"></script></html>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantComponent: "ADSelfService Plus",
			wantCPEPrefix: "cpe:2.3:a:zohocorp:manageengine_adselfservice_plus:",
		},
		{
			name:          "detects Endpoint Central (formerly Desktop Central)",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<html><title>ManageEngine Endpoint Central</title></html>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantComponent: "Endpoint Central",
			wantCPEPrefix: "cpe:2.3:a:zohocorp:manageengine_endpoint_central:",
		},
		{
			name:          "detects legacy Desktop Central branding",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<html><title>ManageEngine Desktop Central</title></html>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantComponent: "Endpoint Central",
		},
		{
			name:          "detects PAM360",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<html><title>ManageEngine PAM360</title></html>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantComponent: "PAM360",
			wantCPEPrefix: "cpe:2.3:a:zohocorp:manageengine_pam360:",
		},
		{
			name:          "detects Password Manager Pro",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<html><title>ManageEngine Password Manager Pro</title></html>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantComponent: "Password Manager Pro",
			wantCPEPrefix: "cpe:2.3:a:zohocorp:manageengine_password_manager_pro:",
		},
		{
			name:          "detects OpManager",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<html><title>ManageEngine OpManager</title></html>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantComponent: "OpManager",
		},
		{
			name:          "detects ADAudit Plus",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<html><title>ManageEngine ADAudit Plus</title></html>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantComponent: "ADAudit Plus",
		},
		{
			name:          "detects ADManager Plus",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<html><title>ManageEngine ADManager Plus</title></html>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantComponent: "ADManager Plus",
		},
		{
			name:          "detects Applications Manager",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<html><title>ManageEngine Applications Manager</title></html>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantComponent: "Applications Manager",
		},
		{
			name:          "detects EventLog Analyzer",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<html><title>ManageEngine EventLog Analyzer</title></html>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantComponent: "EventLog Analyzer",
		},
		{
			name:          "detects Log360",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<html><title>ManageEngine Log360</title></html>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantComponent: "Log360",
		},

		// --- Header-only detection ---
		{
			name:          "detects via Server header",
			statusCode:    200,
			headers:       http.Header{"Server": []string{"ManageEngine"}},
			body:          ``,
			wantResult:    true,
			wantTech:      "manageengine",
			wantCPEPrefix: "cpe:2.3:a:zohocorp:manageengine_manageengine:",
		},
		{
			name:       "detects via X-ManageEngine custom header",
			statusCode: 200,
			headers:    http.Header{"X-Manageengine-Productcode": []string{"SDP"}},
			body:       ``,
			wantResult: true,
			wantTech:   "manageengine",
		},

		// --- Generic ManageEngine detection without product ---
		{
			name:       "detects generic ManageEngine branding",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>Powered by ManageEngine, a division of Zoho Corp.</body></html>`,
			wantResult: true,
			wantTech:   "manageengine",
		},
		{
			name:       "detects via Zoho Corp copyright",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<footer>Copyright (c) 2024 Zoho Corp. All rights reserved.</footer>`,
			wantResult: true,
			wantTech:   "manageengine",
		},

		// --- Version extraction ---
		{
			name:          "extracts version from ServiceDesk Plus title",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<title>ManageEngine ServiceDesk Plus 14.0</title>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantVersion:   "14.0",
			wantComponent: "ServiceDesk Plus",
			wantCPEPrefix: "cpe:2.3:a:zohocorp:manageengine_servicedesk_plus:14.0",
		},
		{
			name:          "extracts version and build from ADSelfService Plus title",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<title>ManageEngine ADSelfService Plus 6.2 Build 6203</title>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantVersion:   "6.2",
			wantBuild:     "6203",
			wantComponent: "ADSelfService Plus",
		},
		{
			name:          "extracts three-part version",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<title>ManageEngine OpManager 12.5.300</title>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantVersion:   "12.5.300",
			wantComponent: "OpManager",
		},

		// --- CPE construction ---
		{
			name:          "CPE uses wildcard when no version available",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<title>ManageEngine ServiceDesk Plus</title>`,
			wantResult:    true,
			wantTech:      "manageengine",
			wantCPEPrefix: "cpe:2.3:a:zohocorp:manageengine_servicedesk_plus:*",
		},

		// --- Negative cases ---
		{
			name:       "returns nil for 500 status",
			statusCode: 500,
			headers:    http.Header{"Server": []string{"ManageEngine"}},
			body:       `ManageEngine`,
			wantResult: false,
		},
		{
			name:       "returns nil with no signals",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>Some other site</body></html>`,
			wantResult: false,
		},
		{
			name:       "returns nil for unrelated Java app with showlogin elsewhere",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/login">Sign in</a></body></html>`,
			wantResult: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.headers,
			}
			result, err := f.Fingerprint(resp, []byte(tt.body))

			if err != nil {
				t.Errorf("Fingerprint() error = %v", err)
				return
			}

			if tt.wantResult && result == nil {
				t.Error("Fingerprint() returned nil, expected result")
				return
			}
			if !tt.wantResult && result != nil {
				t.Errorf("Fingerprint() returned result, expected nil")
				return
			}
			if result == nil {
				return
			}

			if result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}

			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if tt.wantVersion == "" && result.Version != "" {
				t.Errorf("Version = %q, expected empty", result.Version)
			}

			if tt.wantCPEPrefix != "" {
				if len(result.CPEs) == 0 {
					t.Errorf("CPEs empty, want prefix %q", tt.wantCPEPrefix)
				} else {
					cpe := result.CPEs[0]
					if len(cpe) < len(tt.wantCPEPrefix) || cpe[:len(tt.wantCPEPrefix)] != tt.wantCPEPrefix {
						t.Errorf("CPE = %q, want prefix %q", cpe, tt.wantCPEPrefix)
					}
				}
			}

			if tt.wantComponent != "" {
				if got, _ := result.Metadata["component"].(string); got != tt.wantComponent {
					t.Errorf("component = %q, want %q", got, tt.wantComponent)
				}
			}

			if tt.wantBuild != "" {
				if got, _ := result.Metadata["build"].(string); got != tt.wantBuild {
					t.Errorf("build = %q, want %q", got, tt.wantBuild)
				}
			}

			if vendor, _ := result.Metadata["vendor"].(string); vendor != "Zoho" {
				t.Errorf("vendor = %q, want %q", vendor, "Zoho")
			}
		})
	}
}

func TestBuildManageEngineCPE(t *testing.T) {
	tests := []struct {
		product string
		version string
		want    string
	}{
		{
			product: "servicedesk_plus",
			version: "14.0",
			want:    "cpe:2.3:a:zohocorp:manageengine_servicedesk_plus:14.0:*:*:*:*:*:*:*",
		},
		{
			product: "adselfservice_plus",
			version: "6.2",
			want:    "cpe:2.3:a:zohocorp:manageengine_adselfservice_plus:6.2:*:*:*:*:*:*:*",
		},
		{
			product: "endpoint_central",
			version: "",
			want:    "cpe:2.3:a:zohocorp:manageengine_endpoint_central:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.product+"_"+tt.version, func(t *testing.T) {
			if got := buildManageEngineCPE(tt.product, tt.version); got != tt.want {
				t.Errorf("buildManageEngineCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestManageEngineVersionRegex(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantVer string
	}{
		{
			name:    "ServiceDesk Plus with version",
			input:   "ManageEngine ServiceDesk Plus 14.0",
			wantVer: "14.0",
		},
		{
			name:    "ADSelfService Plus with version",
			input:   "ManageEngine ADSelfService Plus 6.2",
			wantVer: "6.2",
		},
		{
			name:    "OpManager with three-part version",
			input:   "ManageEngine OpManager 12.5.300",
			wantVer: "12.5.300",
		},
		{
			name:    "Endpoint Central with version",
			input:   "ManageEngine Endpoint Central 11.2",
			wantVer: "11.2",
		},
		{
			name:    "no version present",
			input:   "ManageEngine ServiceDesk Plus",
			wantVer: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := manageEngineVersionRegex.FindStringSubmatch(tt.input)
			got := ""
			if matches != nil {
				got = matches[1]
			}
			if got != tt.wantVer {
				t.Errorf("manageEngineVersionRegex match = %q, want %q", got, tt.wantVer)
			}
		})
	}
}

func TestManageEngineSafeVersionRegex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"14.0", true},
		{"6.2.1.3", true},
		{"12", true},
		{"abc", false},
		{"14.0;DROP", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := manageEngineSafeVersionRegex.MatchString(tt.input); got != tt.want {
				t.Errorf("manageEngineSafeVersionRegex.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

func TestClassifyManageEngineProduct(t *testing.T) {
	// Verify ADSelfService Plus is classified before generic ManageEngine.
	tests := []struct {
		body string
		want string
	}{
		{"manageengine adselfservice plus", "ADSelfService Plus"},
		{"manageengine adaudit plus", "ADAudit Plus"},
		{"manageengine admanager plus", "ADManager Plus"},
		{"manageengine servicedesk plus", "ServiceDesk Plus"},
		{"manageengine endpoint central", "Endpoint Central"},
		{"manageengine desktop central", "Endpoint Central"},
		{"manageengine pam360", "PAM360"},
		{"manageengine password manager pro", "Password Manager Pro"},
		{"manageengine opmanager", "OpManager"},
		{"manageengine applications manager", "Applications Manager"},
		{"manageengine eventlog analyzer", "EventLog Analyzer"},
		{"manageengine log360", "Log360"},
		{"random unrelated content", ""},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := classifyManageEngineProduct(tt.body)
			if tt.want == "" {
				if got != nil {
					t.Errorf("classifyManageEngineProduct() = %v, want nil", got)
				}
				return
			}
			if got == nil {
				t.Errorf("classifyManageEngineProduct() = nil, want %q", tt.want)
				return
			}
			if got.component != tt.want {
				t.Errorf("classifyManageEngineProduct() = %q, want %q", got.component, tt.want)
			}
		})
	}
}
