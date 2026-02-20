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

func TestFortiGateFingerprinter_Name(t *testing.T) {
	f := &FortiGateFingerprinter{}
	if name := f.Name(); name != "fortinet-fortigate" {
		t.Errorf("Name() = %q, expected %q", name, "fortinet-fortigate")
	}
}

func TestFortiGateFingerprinter_Match(t *testing.T) {
	f := &FortiGateFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches with obfuscated Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"xxxxxxxx-xxxxx"},
			},
			want: true,
		},
		{
			name:       "matches with FortiOS ETag format",
			statusCode: 200,
			headers: http.Header{
				"Etag": []string{`"83-6011f49f"`},
			},
			want: true,
		},
		{
			name:       "matches with 302 redirect",
			statusCode: 302,
			headers: http.Header{
				"Server":   []string{"xxxxxxxx-xxxxx"},
				"Location": []string{"/remote/login"},
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
			name:       "does not match generic Apache server",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Apache/2.4.41"},
			},
			want: false,
		},
		{
			name:       "does not match nginx",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"nginx/1.18.0"},
			},
			want: false,
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

func TestFortiGateFingerprinter_Fingerprint(t *testing.T) {
	f := &FortiGateFingerprinter{}

	tests := []struct {
		name          string
		statusCode    int
		headers       http.Header
		body          string
		wantResult    bool
		wantTech      string
		wantCPEPrefix string
		wantBuildDate string
	}{
		{
			name:       "detects FortiGate from Server header + redirect body",
			statusCode: 200,
			headers: http.Header{
				"Server":        []string{"xxxxxxxx-xxxxx"},
				"Etag":          []string{`"83-6011f49f"`},
				"Last-Modified": []string{"Wed, 27 Jan 2021 23:17:51 GMT"},
				"Content-Type":  []string{"text/html"},
			},
			body:          `<html><head><script>top.location="/remote/login";</script></head><body></body></html>`,
			wantResult:    true,
			wantTech:      "fortinet-fortigate",
			wantCPEPrefix: "cpe:2.3:o:fortinet:fortios:",
			wantBuildDate: "2021-01-27",
		},
		{
			name:       "detects FortiGate admin panel without SSL VPN",
			statusCode: 403,
			headers: http.Header{
				"Server":       []string{"xxxxxxxx-xxxxx"},
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><body>/remote/login</body></html>`,
			wantResult: true,
			wantTech:   "fortinet-fortigate",
		},
		{
			name:       "detects FortiGate from ftnt-fortinet-grid icon",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"xxxxxxxx-xxxxx"},
			},
			body:       `<html><body><f-icon class="ftnt-fortinet-grid"></f-icon></body></html>`,
			wantResult: true,
			wantTech:   "fortinet-fortigate",
		},
		{
			name:       "extracts build date from ETag hex timestamp",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"xxxxxxxx-xxxxx"},
				"Etag":   []string{`"83-67a94180"`},
			},
			body:          `<html><head><script>top.location="/remote/login";</script></head><body></body></html>`,
			wantResult:    true,
			wantTech:      "fortinet-fortigate",
			wantBuildDate: "2025-02-10",
		},
		{
			name:       "does not detect non-FortiGate content",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Apache/2.4.41"},
			},
			body:       `<html><body>Welcome to our website</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect from 404 with FortiGate-like content",
			statusCode: 404,
			headers:    http.Header{},
			body:       `<html><body>Not found - /remote/login</body></html>`,
			wantResult: false,
		},
		{
			name:       "detects with only Server header and empty body",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"xxxxxxxx-xxxxx"},
			},
			body:       ``,
			wantResult: true,
			wantTech:   "fortinet-fortigate",
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
				if tt.wantCPEPrefix != "" && len(result.CPEs) > 0 {
					if len(result.CPEs[0]) < len(tt.wantCPEPrefix) || result.CPEs[0][:len(tt.wantCPEPrefix)] != tt.wantCPEPrefix {
						t.Errorf("CPE = %q, want prefix %q", result.CPEs[0], tt.wantCPEPrefix)
					}
				}
				if tt.wantBuildDate != "" {
					if bd, ok := result.Metadata["firmwareBuildDate"]; ok {
						if bd != tt.wantBuildDate {
							t.Errorf("firmwareBuildDate = %q, want %q", bd, tt.wantBuildDate)
						}
					} else {
						t.Errorf("firmwareBuildDate not in metadata")
					}
				}
			}
		})
	}
}

func TestBuildFortiGateCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "7.2.3",
			want:    "cpe:2.3:o:fortinet:fortios:7.2.3:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildFortiGateCPE(tt.version); got != tt.want {
				t.Errorf("buildFortiGateCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseFortiGateETagTimestamp(t *testing.T) {
	tests := []struct {
		name    string
		etag    string
		want    string
		wantOK  bool
	}{
		{
			name:   "valid FortiOS ETag - Jan 2021",
			etag:   `"83-6011f49f"`,
			want:   "2021-01-27",
			wantOK: true,
		},
		{
			name:   "valid FortiOS ETag - Feb 2025",
			etag:   `"83-67a94180"`,
			want:   "2025-02-10",
			wantOK: true,
		},
		{
			name:   "invalid ETag format",
			etag:   `W/"abc123"`,
			want:   "",
			wantOK: false,
		},
		{
			name:   "empty ETag",
			etag:   "",
			want:   "",
			wantOK: false,
		},
		{
			name:   "non-hex value",
			etag:   `"83-zzzzzzzz"`,
			want:   "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := parseFortiGateETagTimestamp(tt.etag)
			if ok != tt.wantOK {
				t.Errorf("parseFortiGateETagTimestamp() ok = %v, want %v", ok, tt.wantOK)
			}
			if got != tt.want {
				t.Errorf("parseFortiGateETagTimestamp() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestFortiGateFingerprinter_ShodanVectors tests detection against real-world
// response patterns observed via Shodan and live FortiGate reconnaissance.
// FortiGate appliances run FortiOS with Server: xxxxxxxx-xxxxx header.
func TestFortiGateFingerprinter_ShodanVectors(t *testing.T) {
	f := &FortiGateFingerprinter{}

	tests := []struct {
		name          string
		description   string
		statusCode    int
		headers       http.Header
		body          string
		wantTech      string
		wantBuildDate string
	}{
		{
			name:        "Shodan Vector 1: FortiGate-200E SSL VPN (Lazard 152.165.120.135:55443)",
			description: "FortiGate with SSL VPN active, ~5-year-old firmware, ETag Jan 2021",
			statusCode:  200,
			headers: http.Header{
				"Server":                    []string{"xxxxxxxx-xxxxx"},
				"Etag":                      []string{`"83-6011f49f"`},
				"Last-Modified":             []string{"Wed, 27 Jan 2021 23:17:51 GMT"},
				"Content-Type":              []string{"text/html"},
				"Content-Length":            []string{"131"},
				"Content-Security-Policy":   []string{"object-src 'none'; script-src 'self' https"},
				"X-Frame-Options":           []string{"SAMEORIGIN"},
				"Strict-Transport-Security": []string{"max-age=63072000"},
			},
			body: `<html><head><script language="JavaScript">top.location="/remote/login";
</script></head><body></body></html>`,
			wantTech:      "fortinet-fortigate",
			wantBuildDate: "2021-01-27",
		},
		{
			name:        "Shodan Vector 2: FortiGate-80F admin panel no SSL VPN (150.249.195.76:10443)",
			description: "FortiGate admin panel without SSL VPN, recent firmware Feb 2025",
			statusCode:  200,
			headers: http.Header{
				"Server":                    []string{"xxxxxxxx-xxxxx"},
				"Etag":                      []string{`"83-67a94180"`},
				"Content-Type":              []string{"text/html"},
				"Content-Security-Policy":   []string{"object-src 'self'; script-src 'self' https: blob:"},
				"Strict-Transport-Security": []string{"max-age=63072000"},
			},
			body: `<html><head><script language="JavaScript">top.location="/remote/login";
</script></head><body></body></html>`,
			wantTech:      "fortinet-fortigate",
			wantBuildDate: "2025-02-10",
		},
		{
			name:        "Shodan Vector 3: FortiGate 403 response on API endpoint",
			description: "FortiOS returns 403 with Server header on admin API probe",
			statusCode:  403,
			headers: http.Header{
				"Server":       []string{"xxxxxxxx-xxxxx"},
				"Content-Type": []string{"text/html"},
			},
			body:     `<html><head><title>Forbidden</title></head><body>/remote/login</body></html>`,
			wantTech: "fortinet-fortigate",
		},
		{
			name:        "Shodan Vector 4: FortiGate with SSL VPN login page",
			description: "Full FortiGate SSL VPN login page with Fortinet icon class",
			statusCode:  200,
			headers: http.Header{
				"Server":       []string{"xxxxxxxx-xxxxx"},
				"Content-Type": []string{"text/html; charset=utf-8"},
			},
			body: `<!DOCTYPE html>
<html lang="en">
<head><title>FortiGate SSL VPN</title>
<link href="/css/main-blue.css" rel="stylesheet" type="text/css">
</head><body>
<div id="login-page">
<f-icon class="ftnt-fortinet-grid"></f-icon>
<form action="/remote/logincheck" method="POST">
<input type="text" name="username">
<input type="password" name="credential">
</form></div></body></html>`,
			wantTech: "fortinet-fortigate",
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

			if tt.wantBuildDate != "" {
				if bd, ok := result.Metadata["firmwareBuildDate"]; ok {
					if bd != tt.wantBuildDate {
						t.Errorf("firmwareBuildDate = %q, want %q", bd, tt.wantBuildDate)
					}
				} else {
					t.Errorf("firmwareBuildDate not in metadata")
				}
			}
		})
	}
}
