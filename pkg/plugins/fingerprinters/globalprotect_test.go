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

func TestGlobalProtectFingerprinter_Name(t *testing.T) {
	f := &GlobalProtectFingerprinter{}
	if name := f.Name(); name != "globalprotect" {
		t.Errorf("Name() = %q, expected %q", name, "globalprotect")
	}
}

func TestGlobalProtectFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &GlobalProtectFingerprinter{}
	if endpoint := f.ProbeEndpoint(); endpoint != "/global-protect/prelogin.esp" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", endpoint, "/global-protect/prelogin.esp")
	}
}

func TestGlobalProtectFingerprinter_Match(t *testing.T) {
	f := &GlobalProtectFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches with X-Private-Pan-Sslvpn header",
			statusCode: 200,
			headers: http.Header{
				"X-Private-Pan-Sslvpn": []string{"auth-ok"},
			},
			want: true,
		},
		{
			name:       "matches with PAN-OS Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"PAN-OS 10.2.3"},
			},
			want: true,
		},
		{
			name:       "matches with Palo Alto Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Palo Alto Networks"},
			},
			want: true,
		},
		{
			name:       "does not match 404 response",
			statusCode: 404,
			headers:    http.Header{},
			want:       false,
		},
		{
			name:       "matches 302 redirect with global-protect in Location and PAN-OS Server header",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/global-protect/login.esp"},
				"Server":   []string{"PAN-OS 10.2.3"},
			},
			want: true,
		},
		{
			name:       "does not match 301 redirect that echoes back requested path without additional headers",
			statusCode: 301,
			headers: http.Header{
				"Location": []string{"https://www.example.com/global-protect/prelogin.esp"},
			},
			want: false,
		},
		{
			name:       "does not match 302 redirect with global-protect in Location but no other indicators",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"https://www.example.com/global-protect/login.esp"},
			},
			want: false,
		},
		{
			name:       "matches 301 redirect with global-protect in Location AND PAN-OS Server header",
			statusCode: 301,
			headers: http.Header{
				"Location": []string{"https://vpn.example.com/global-protect/prelogin.esp"},
				"Server":   []string{"PAN-OS 10.2.3"},
			},
			want: true,
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

func TestGlobalProtectFingerprinter_Fingerprint(t *testing.T) {
	f := &GlobalProtectFingerprinter{}

	tests := []struct {
		name          string
		statusCode    int
		headers       http.Header
		body          string
		wantResult    bool
		wantTech      string
		wantVersion   string
		wantCPEPrefix string
	}{
		{
			name:       "detects GlobalProtect from prelogin-response XML",
			statusCode: 200,
			headers:    http.Header{},
			body: `<?xml version="1.0" encoding="UTF-8"?>
<prelogin-response>
<status>Success</status>
<sw-version>10.2.3</sw-version>
</prelogin-response>`,
			wantResult:    false,
			wantTech:      "palo-alto-globalprotect",
			wantVersion:   "10.2.3",
			wantCPEPrefix: "cpe:2.3:o:paloaltonetworks:pan-os:10.2.3",
		},
		{
			name:       "detects GlobalProtect from prelogin-response with hotfix version",
			statusCode: 200,
			headers:    http.Header{},
			body: `<?xml version="1.0" encoding="UTF-8"?>
<prelogin-response>
<status>Success</status>
<sw-version>10.1.9-h1</sw-version>
</prelogin-response>`,
			wantResult:    false,
			wantTech:      "palo-alto-globalprotect",
			wantVersion:   "10.1.9-h1",
			wantCPEPrefix: "cpe:2.3:o:paloaltonetworks:pan-os:10.1.9-h1",
		},
		{
			name:       "detects GlobalProtect from global-protect keyword in body",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>GlobalProtect Portal</body></html>`,
			wantResult: false,
			wantTech:   "palo-alto-globalprotect",
		},
		{
			name:       "detects GlobalProtect from PAN_FORM keyword",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><form name="PAN_FORM" method="POST"></form></html>`,
			wantResult: false,
			wantTech:   "palo-alto-globalprotect",
		},
		{
			name:       "detects GlobalProtect from palo alto keyword",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Powered by Palo Alto Networks</body></html>`,
			wantResult: false,
			wantTech:   "palo-alto-globalprotect",
		},
		{
			name:       "extracts version from Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"PAN-OS 11.0.1"},
			},
			body:          `<html></html>`,
			wantResult:    true,
			wantTech:      "palo-alto-globalprotect",
			wantVersion:   "11.0.1",
			wantCPEPrefix: "cpe:2.3:o:paloaltonetworks:pan-os:11.0.1",
		},
		{
			name:       "does not detect from 404 response",
			statusCode: 404,
			headers:    http.Header{},
			body:       `<html><body>Not Found - global-protect</body></html>`,
			wantResult: false,
		},
		{
			name:       "detects from 302 redirect with global-protect Location and PAN-OS Server header",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/global-protect/login.esp"},
				"Server":   []string{"PAN-OS 10.2.3"},
			},
			body:       ``,
			wantResult: true,
			wantTech:   "palo-alto-globalprotect",
		},
		{
			name:       "does not detect non-GlobalProtect content",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Welcome to our website</body></html>`,
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

			if result != nil {
				if result.Technology != tt.wantTech {
					t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
				}
				if tt.wantVersion != "" && result.Version != tt.wantVersion {
					t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
				}
				if tt.wantCPEPrefix != "" && len(result.CPEs) > 0 {
					if result.CPEs[0][:len(tt.wantCPEPrefix)] != tt.wantCPEPrefix {
						t.Errorf("CPE = %q, want prefix %q", result.CPEs[0], tt.wantCPEPrefix)
					}
				}
			}
		})
	}
}

// TestGlobalProtectFingerprinter_FalsePositives tests that body-only matches
// do NOT produce false positives. This was a bug where generic body patterns
// like "<portal>" or "palo alto" would match non-VPN websites.
func TestGlobalProtectFingerprinter_FalsePositives(t *testing.T) {
	f := &GlobalProtectFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		body       string
		wantResult bool
	}{
		{
			name:       "does not match generic '<portal>' tag without header indicators",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><portal>Employee Portal</portal></html>`,
			wantResult: false,
		},
		{
			name:       "does not match 'Palo Alto' company name in marketing content",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>We partner with Palo Alto Networks for security</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not match 'global-protect' keyword in documentation",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Learn about Global-Protect VPN configuration</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not match 'PAN' keyword alone",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>PAN card application form</body></html>`,
			wantResult: false,
		},
		{
			name:       "still matches with header indicator present",
			statusCode: 200,
			headers: http.Header{
				"X-Private-Pan-Sslvpn": []string{"auth-ok"},
			},
			body:       `<html><body>Welcome</body></html>`,
			wantResult: true,
		},
		{
			name:       "still matches with PAN-OS Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"PAN-OS 10.2.3"},
			},
			body:       `<html><body>Login</body></html>`,
			wantResult: true,
		},
		{
			name:       "still matches with global-protect Location redirect",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/global-protect/login.esp"},
			},
			body:       ``,
			wantResult: true,
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
				t.Errorf("Fingerprint() returned result for false positive case, expected nil")
				return
			}
		})
	}
}

func TestBuildGlobalProtectCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "10.2.3",
			want:    "cpe:2.3:o:paloaltonetworks:pan-os:10.2.3:*:*:*:*:*:*:*",
		},
		{
			version: "10.1.9-h1",
			want:    "cpe:2.3:o:paloaltonetworks:pan-os:10.1.9-h1:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildGlobalProtectCPE(tt.version); got != tt.want {
				t.Errorf("buildGlobalProtectCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestGlobalProtectFingerprinter_ShodanVectors tests detection against real-world
// response patterns observed via Shodan reconnaissance.
// Shodan dorks: http.favicon.hash:-631559155, app:"paloalto-GlobalProtect"
func TestGlobalProtectFingerprinter_ShodanVectors(t *testing.T) {
	f := &GlobalProtectFingerprinter{}

	tests := []struct {
		name        string
		description string
		statusCode  int
		headers     http.Header
		body        string
		wantTech    string
		wantVersion string
	}{
		{
			name:        "Shodan Vector 1: PAN-OS 10.2 prelogin.esp response",
			description: "GlobalProtect portal prelogin XML response with version",
			statusCode:  200,
			headers: http.Header{
				"Content-Type":              []string{"application/xml; charset=UTF-8"},
				"X-Private-Pan-Sslvpn":      []string{"auth-ok"},
				"Cache-Control":             []string{"no-store, no-cache, must-revalidate"},
				"Strict-Transport-Security": []string{"max-age=31536000; includeSubDomains"},
			},
			body: `<?xml version="1.0" encoding="UTF-8" ?>
<prelogin-response>
<status>Success</status>
<ccusername/>
<autosubmit>false</autosubmit>
<msg/>
<newmsg/>
<authentication-message>Enter login credentials</authentication-message>
<username-label>Username</username-label>
<password-label>Password</password-label>
<panos-version>1</panos-version>
<sw-version>10.2.4</sw-version>
<region>Americas</region>
<saml-default-browser>yes</saml-default-browser>
<saml-auth-method>POST</saml-auth-method>
</prelogin-response>`,
			wantTech:    "palo-alto-globalprotect",
			wantVersion: "10.2.4",
		},
		{
			name:        "Shodan Vector 2: PAN-OS 11.0 with hotfix version",
			description: "GlobalProtect with hotfix version in sw-version tag",
			statusCode:  200,
			headers: http.Header{
				"Content-Type":         []string{"application/xml; charset=UTF-8"},
				"X-Private-Pan-Sslvpn": []string{"auth-ok"},
			},
			body: `<?xml version="1.0" encoding="UTF-8" ?>
<prelogin-response>
<status>Success</status>
<ccusername></ccusername>
<autosubmit>false</autosubmit>
<msg></msg>
<newmsg></newmsg>
<authentication-message>Please authenticate</authentication-message>
<username-label>Username</username-label>
<password-label>Password</password-label>
<panos-version>1</panos-version>
<sw-version>11.0.3-h1</sw-version>
<app-version>11.0.3-h1</app-version>
<saml-default-browser>yes</saml-default-browser>
<saml-auth-method>REDIRECT</saml-auth-method>
<saml-request></saml-request>
</prelogin-response>`,
			wantTech:    "palo-alto-globalprotect",
			wantVersion: "11.0.3-h1",
		},
		{
			name:        "Shodan Vector 3: GlobalProtect portal redirect",
			description: "302 redirect to GlobalProtect login page",
			statusCode:  302,
			headers: http.Header{
				"Location":                  []string{"/global-protect/login.esp"},
				"Content-Type":              []string{"text/html; charset=UTF-8"},
				"Cache-Control":             []string{"no-store, no-cache"},
				"Strict-Transport-Security": []string{"max-age=31536000;"},
				"X-Frame-Options":           []string{"DENY"},
			},
			body: `<script LANGUAGE="JavaScript">
window.location="/global-protect/login.esp";
</script>
<html><head></head><body><p>JavaScript must be enabled to continue!</p></body></html>`,
			wantTech:    "palo-alto-globalprotect",
			wantVersion: "",
		},
		{
			name:        "Shodan Vector 4: PAN-OS 10.1 with SAML auth status",
			description: "GlobalProtect prelogin response with SAML authentication",
			statusCode:  200,
			headers: http.Header{
				"Content-Type":         []string{"application/xml; charset=UTF-8"},
				"X-Private-Pan-Sslvpn": []string{"auth-ok"},
				"Connection":           []string{"keep-alive"},
			},
			body: `<?xml version="1.0" encoding="UTF-8" ?>
<prelogin-response>
<status>Success</status>
<ccusername></ccusername>
<autosubmit></autosubmit>
<msg></msg>
<newmsg></newmsg>
<authentication-message></authentication-message>
<username-label></username-label>
<password-label></password-label>
<panos-version>1</panos-version>
<sw-version>10.1.11</sw-version>
<saml-default-browser>yes</saml-default-browser>
<krb-norm-username></krb-norm-username>
<krb-auth-status>0</krb-auth-status>
<cas-auth></cas-auth>
<saml-auth-status>1</saml-auth-status>
<saml-auth-method>POST</saml-auth-method>
<saml-request-timeout>60</saml-request-timeout>
<saml-request-id>ONELOGIN_abc123</saml-request-id>
</prelogin-response>`,
			wantTech:    "palo-alto-globalprotect",
			wantVersion: "10.1.11",
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

			if result == nil {
				t.Errorf("Fingerprint() returned nil for Shodan vector: %s", tt.description)
				return
			}

			if result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}

			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
		})
	}
}
