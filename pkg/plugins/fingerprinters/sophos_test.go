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

func TestSophosFirewallFingerprinter_Name(t *testing.T) {
	f := &SophosFirewallFingerprinter{}
	if name := f.Name(); name != "sophos-firewall" {
		t.Errorf("Name() = %q, expected %q", name, "sophos-firewall")
	}
}

func TestSophosFirewallFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &SophosFirewallFingerprinter{}
	if ep := f.ProbeEndpoint(); ep != "/webconsole/webpages/login.jsp" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", ep, "/webconsole/webpages/login.jsp")
	}
}

func TestSophosFirewallFingerprinter_Match(t *testing.T) {
	f := &SophosFirewallFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches with Sophos Server header (exact xxxx)",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"xxxx"},
			},
			want: true,
		},
		{
			name:       "matches with Sophos Server header (uppercase XXXX)",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"XXXX"},
			},
			want: true,
		},
		{
			name:       "matches text/html content type",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html; charset=utf-8"},
			},
			want: true,
		},
		{
			name:       "matches 302 redirect with Sophos Server header",
			statusCode: 302,
			headers: http.Header{
				"Server":   []string{"xxxx"},
				"Location": []string{"/webconsole/webpages/login.jsp"},
			},
			want: true,
		},
		{
			name:       "does not match 5xx server errors",
			statusCode: 500,
			headers: http.Header{
				"Server": []string{"xxxx"},
			},
			want: false,
		},
		{
			name:       "does not match FortiGate Server header (different string)",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"xxxxxxxx-xxxxx"},
			},
			want: false,
		},
		{
			name:       "does not match generic non-html content type without Server header",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			want: false,
		},
		{
			name:       "does not match 5-char xxxxx Server header (not Sophos)",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"xxxxx"},
			},
			want: false,
		},
		{
			name:       "matches 404 with text/html (pre-filter only)",
			statusCode: 404,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
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

func TestSophosFirewallFingerprinter_Fingerprint(t *testing.T) {
	f := &SophosFirewallFingerprinter{}

	tests := []struct {
		name              string
		statusCode        int
		headers           http.Header
		body              string
		wantResult        bool
		wantTech          string
		wantCPEPrefix     string
		wantVersion       string
		wantFirmware      string
		wantInterfaceType string
		wantServerHeader  string
	}{
		{
			name:       "detects from Server header + webconsole path in body",
			statusCode: 200,
			headers: http.Header{
				"Server":       []string{"xxxx"},
				"Content-Type": []string{"text/html"},
			},
			body:              `<html><body><a href="/webconsole/webpages/login.jsp">Login</a></body></html>`,
			wantResult:        true,
			wantTech:          "sophos-firewall",
			wantCPEPrefix:     "cpe:2.3:o:sophos:sfos:",
			wantInterfaceType: "web-admin",
			wantServerHeader:  "xxxx",
		},
		{
			name:       "detects from Server header + userportal path in body",
			statusCode: 200,
			headers: http.Header{
				"Server":       []string{"xxxx"},
				"Content-Type": []string{"text/html"},
			},
			body:              `<html><body><a href="/userportal/webpages/myaccount/login.jsp">Login</a></body></html>`,
			wantResult:        true,
			wantTech:          "sophos-firewall",
			wantInterfaceType: "user-portal",
			wantServerHeader:  "xxxx",
		},
		{
			name:       "detects from title + JS marker (no Server header)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<html><head><title>Sophos</title></head><body>
<script>var uiLangToHTMLLangAttributeValueMapping = {};</script>
</body></html>`,
			wantResult: true,
			wantTech:   "sophos-firewall",
		},
		{
			name:       "detects from title + webconsole path marker (no Server header)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<html><head><title>Sophos</title></head><body>
<link href="/webconsole/assets/css/typography.css?version=19.5.3.652" rel="stylesheet">
</body></html>`,
			wantResult:        true,
			wantTech:          "sophos-firewall",
			wantVersion:       "19.5.3",
			wantFirmware:      "19.5.3.652",
			wantInterfaceType: "web-admin",
		},
		{
			name:       "extracts version from typography.css asset path (newer SFOS)",
			statusCode: 200,
			headers: http.Header{
				"Server":       []string{"xxxx"},
				"Content-Type": []string{"text/html"},
			},
			body: `<html><head><title>Sophos</title>
<link rel="stylesheet" href="/webconsole/webpages/css/typography.css?version=19.5.3.652">
</head><body><script>var uiLangToHTMLLangAttributeValueMapping={};</script></body></html>`,
			wantResult:   true,
			wantTech:     "sophos-firewall",
			wantVersion:  "19.5.3",
			wantFirmware: "19.5.3.652",
		},
		{
			name:       "extracts version from loginstylesheet.css (older SFOS ≤17.x)",
			statusCode: 200,
			headers: http.Header{
				"Server":       []string{"xxxx"},
				"Content-Type": []string{"text/html"},
			},
			body: `<html><head>
<link rel="stylesheet" href="/webconsole/webpages/css/loginstylesheet.css?ver=17.5.9.577">
</head><body></body></html>`,
			wantResult:   true,
			wantTech:     "sophos-firewall",
			wantVersion:  "17.5.9",
			wantFirmware: "17.5.9.577",
		},
		{
			name:       "detects via Location header redirect to webconsole",
			statusCode: 302,
			headers: http.Header{
				"Server":   []string{"xxxx"},
				"Location": []string{"/webconsole/webpages/login.jsp"},
			},
			body:              ``,
			wantResult:        true,
			wantTech:          "sophos-firewall",
			wantInterfaceType: "web-admin",
		},
		{
			name:       "detects via Location header redirect to userportal",
			statusCode: 302,
			headers: http.Header{
				"Server":   []string{"xxxx"},
				"Location": []string{"/userportal/webpages/myaccount/login.jsp"},
			},
			body:              ``,
			wantResult:        true,
			wantTech:          "sophos-firewall",
			wantInterfaceType: "user-portal",
		},
		{
			name:       "does not detect from Server header alone without path markers",
			statusCode: 200,
			headers: http.Header{
				"Server":       []string{"xxxx"},
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>Hello world</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect title-only without body marker",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><head><title>Sophos</title></head><body>Generic page</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect from generic page mentioning Sophos in text",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>We support Sophos products. Visit sophos.com.</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect 5xx responses",
			statusCode: 503,
			headers: http.Header{
				"Server": []string{"xxxx"},
			},
			body:       `<html><body>Service Unavailable</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect FortiGate Server header (different 8x-5x format)",
			statusCode: 200,
			headers: http.Header{
				"Server":       []string{"xxxxxxxx-xxxxx"},
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body></body></html>`,
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
				t.Errorf("Fingerprint() returned result, expected nil; got Technology=%q", result.Technology)
				return
			}

			if result == nil {
				return
			}

			if tt.wantTech != "" && result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}

			if tt.wantCPEPrefix != "" && len(result.CPEs) > 0 {
				if len(result.CPEs[0]) < len(tt.wantCPEPrefix) || result.CPEs[0][:len(tt.wantCPEPrefix)] != tt.wantCPEPrefix {
					t.Errorf("CPE = %q, want prefix %q", result.CPEs[0], tt.wantCPEPrefix)
				}
			}

			if tt.wantVersion != "" {
				if result.Version != tt.wantVersion {
					t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
				}
			}

			if tt.wantFirmware != "" {
				if fv, ok := result.Metadata["firmware_version"]; ok {
					if fv != tt.wantFirmware {
						t.Errorf("firmware_version = %q, want %q", fv, tt.wantFirmware)
					}
				} else {
					t.Errorf("firmware_version not in metadata, wanted %q", tt.wantFirmware)
				}
			}

			if tt.wantInterfaceType != "" {
				if it, ok := result.Metadata["interface_type"]; ok {
					if it != tt.wantInterfaceType {
						t.Errorf("interface_type = %q, want %q", it, tt.wantInterfaceType)
					}
				} else {
					t.Errorf("interface_type not in metadata, wanted %q", tt.wantInterfaceType)
				}
			}

			if tt.wantServerHeader != "" {
				if sh, ok := result.Metadata["server_header"]; ok {
					if sh != tt.wantServerHeader {
						t.Errorf("server_header = %q, want %q", sh, tt.wantServerHeader)
					}
				} else {
					t.Errorf("server_header not in metadata, wanted %q", tt.wantServerHeader)
				}
			}
		})
	}
}

func TestBuildSophosCPEs(t *testing.T) {
	tests := []struct {
		version  string
		wantLen  int
		wantSFOS string
		wantXG   string
	}{
		{
			version:  "19.5.3",
			wantLen:  2,
			wantSFOS: "cpe:2.3:o:sophos:sfos:19.5.3:*:*:*:*:*:*:*",
			wantXG:   "cpe:2.3:o:sophos:xg_firewall_firmware:19.5.3:*:*:*:*:*:*:*",
		},
		{
			version:  "",
			wantLen:  2,
			wantSFOS: "cpe:2.3:o:sophos:sfos:*:*:*:*:*:*:*:*",
			wantXG:   "cpe:2.3:o:sophos:xg_firewall_firmware:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			cpes := buildSophosCPEs(tt.version)
			if len(cpes) != tt.wantLen {
				t.Errorf("buildSophosCPEs() returned %d CPEs, want %d", len(cpes), tt.wantLen)
			}
			if cpes[0] != tt.wantSFOS {
				t.Errorf("CPE[0] = %q, want %q", cpes[0], tt.wantSFOS)
			}
			if cpes[1] != tt.wantXG {
				t.Errorf("CPE[1] = %q, want %q", cpes[1], tt.wantXG)
			}
		})
	}
}

func TestBuildSophosCPEVersion(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{input: "19.5.3.652", want: "19.5.3"},
		{input: "17.5.9.577", want: "17.5.9"},
		{input: "20.0.0.100", want: "20.0.0"},
		{input: "", want: ""},
		{input: "invalid", want: ""},
		{input: "19.5.3", want: ""},    // only 3 parts, fails 4-part validation
		{input: "19.5.3.x", want: ""}, // non-numeric build number
	}

	for _, tt := range tests {
		t.Run("input_"+tt.input, func(t *testing.T) {
			if got := buildSophosCPEVersion(tt.input); got != tt.want {
				t.Errorf("buildSophosCPEVersion(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestExtractSophosVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "extracts from typography.css newer format",
			body: `<link rel="stylesheet" href="/css/typography.css?version=19.5.3.652">`,
			want: "19.5.3.652",
		},
		{
			name: "extracts from loginstylesheet.css older format",
			body: `<link rel="stylesheet" href="/css/loginstylesheet.css?ver=17.5.9.577">`,
			want: "17.5.9.577",
		},
		{
			name: "returns empty when no version present",
			body: `<html><head><title>Sophos</title></head><body></body></html>`,
			want: "",
		},
		{
			name: "rejects non-4-part version (injection guard)",
			body: `<link rel="stylesheet" href="/css/typography.css?version=19.5">`,
			want: "",
		},
		{
			name: "rejects non-numeric version (injection guard)",
			body: `<link rel="stylesheet" href="/css/typography.css?version=19.5.x.abc">`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractSophosVersion([]byte(tt.body)); got != tt.want {
				t.Errorf("extractSophosVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestSophosFirewallFingerprinter_ShodanVectors tests detection against real-world
// response patterns representative of Sophos XG/XGS firewall login pages.
func TestSophosFirewallFingerprinter_ShodanVectors(t *testing.T) {
	f := &SophosFirewallFingerprinter{}

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
			name:        "Shodan Vector 1: Sophos XGS admin console (port 4444)",
			description: "Admin web console with Server: xxxx header, typography.css version marker",
			statusCode:  200,
			headers: http.Header{
				"Server":                    []string{"xxxx"},
				"Content-Type":              []string{"text/html; charset=UTF-8"},
				"X-Frame-Options":           []string{"SAMEORIGIN"},
				"Strict-Transport-Security": []string{"max-age=31536000"},
			},
			body: `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sophos</title>
<link rel="stylesheet" href="/webconsole/webpages/css/typography.css?version=19.5.3.652">
</head>
<body>
<script>var uiLangToHTMLLangAttributeValueMapping = {"en":"en-US"};</script>
<div id="login-container">
<a href="/webconsole/webpages/login.jsp">Admin Login</a>
</div>
</body>
</html>`,
			wantTech:    "sophos-firewall",
			wantVersion: "19.5.3",
		},
		{
			name:        "Shodan Vector 2: Sophos XG user portal (port 443)",
			description: "User portal redirect with Server: xxxx and userportal path",
			statusCode:  302,
			headers: http.Header{
				"Server":   []string{"xxxx"},
				"Location": []string{"/userportal/webpages/myaccount/login.jsp"},
			},
			body:        ``,
			wantTech:    "sophos-firewall",
			wantVersion: "",
		},
		{
			name:        "Shodan Vector 3: Sophos XG older firmware 17.x (loginstylesheet.css)",
			description: "Older SFOS firmware using loginstylesheet.css?ver= version format",
			statusCode:  200,
			headers: http.Header{
				"Server":       []string{"xxxx"},
				"Content-Type": []string{"text/html"},
			},
			body: `<!DOCTYPE html>
<html>
<head>
<title>Sophos</title>
<link rel="stylesheet" type="text/css" href="/webconsole/webpages/css/loginstylesheet.css?ver=17.5.9.577">
</head>
<body>
<a href="/webconsole/webpages/login.jsp">Login</a>
</body>
</html>`,
			wantTech:    "sophos-firewall",
			wantVersion: "17.5.9",
		},
		{
			name:        "Shodan Vector 4: Sophos captive portal (port 8090)",
			description: "Captive portal with title and JS marker, no Server header",
			statusCode:  200,
			headers: http.Header{
				"Content-Type": []string{"text/html; charset=UTF-8"},
			},
			body: `<!DOCTYPE html>
<html>
<head><title>Sophos</title></head>
<body>
<script>
var uiLangToHTMLLangAttributeValueMapping = {"en":"en-US","de":"de-DE"};
</script>
<div>Please authenticate to continue.</div>
</body>
</html>`,
			wantTech:    "sophos-firewall",
			wantVersion: "",
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

			if tt.wantVersion != "" {
				if result.Version != tt.wantVersion {
					t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
				}
			}

			if len(result.CPEs) != 2 {
				t.Errorf("CPEs length = %d, want 2", len(result.CPEs))
			}
		})
	}
}

// TestSophosNotFortiGate verifies that the Sophos fingerprinter does NOT trigger
// on FortiGate responses (which use "xxxxxxxx-xxxxx" Server header).
func TestSophosNotFortiGate(t *testing.T) {
	f := &SophosFirewallFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Server":       []string{"xxxxxxxx-xxxxx"},
			"Content-Type": []string{"text/html"},
		},
	}

	// FortiGate uses Content-Type: text/html, so Match() passes the pre-filter.
	// However, Fingerprint() must return nil because "xxxxxxxx-xxxxx" does not
	// match the "xxxx" Server header check, and the body has no Sophos markers.
	body := []byte(`<html><head><script>top.location="/remote/login";</script></head><body></body></html>`)
	result, err := f.Fingerprint(resp, body)

	if err != nil {
		t.Errorf("Fingerprint() error = %v", err)
	}

	if result != nil {
		t.Errorf("Fingerprint() should return nil for FortiGate response (Server: xxxxxxxx-xxxxx), got Technology=%q", result.Technology)
	}
}
