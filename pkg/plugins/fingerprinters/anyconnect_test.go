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

func TestAnyConnectFingerprinter_Name(t *testing.T) {
	f := &AnyConnectFingerprinter{}
	if name := f.Name(); name != "anyconnect" {
		t.Errorf("Name() = %q, expected %q", name, "anyconnect")
	}
}

func TestAnyConnectFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &AnyConnectFingerprinter{}
	if endpoint := f.ProbeEndpoint(); endpoint != "/+CSCOE+/logon.html" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", endpoint, "/+CSCOE+/logon.html")
	}
}

func TestAnyConnectFingerprinter_Match(t *testing.T) {
	f := &AnyConnectFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches with X-ASA-Version header",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			want: true,
		},
		{
			name:       "matches with X-Transcend-Version header",
			statusCode: 200,
			headers: http.Header{
				"X-Transcend-Version": []string{"9.16"},
			},
			want: true,
		},
		{
			name:       "matches with Cisco Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Cisco ASA"},
			},
			want: true,
		},
		{
			name:       "matches with webvpn cookie",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie": []string{"webvpnlogin=1; path=/"},
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
			name:       "matches 302 redirect with CSCOE in Location",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/+CSCOE+/logon.html"},
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

func TestAnyConnectFingerprinter_Fingerprint(t *testing.T) {
	f := &AnyConnectFingerprinter{}

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
			name:       "detects AnyConnect from body with webvpn keyword",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Welcome to WebVPN Portal</body></html>`,
			wantResult: false,
			wantTech:   "cisco-anyconnect",
		},
		{
			name:       "detects AnyConnect from body with CSCOE",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><script src="/+CSCOE+/scripts.js"></script></html>`,
			wantResult: false,
			wantTech:   "cisco-anyconnect",
		},
		{
			name:       "detects AnyConnect from body with anyconnect keyword",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Please install AnyConnect VPN client</body></html>`,
			wantResult: false,
			wantTech:   "cisco-anyconnect",
		},
		{
			name:       "extracts version from X-ASA-Version header",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			body:          `<html></html>`,
			wantResult:    true,
			wantTech:      "cisco-anyconnect",
			wantVersion:   "9.16(4)",
			wantCPEPrefix: "cpe:2.3:a:cisco:adaptive_security_appliance_software:9.16(4)",
		},
		{
			name:       "extracts version from X-Transcend-Version header",
			statusCode: 200,
			headers: http.Header{
				"X-Transcend-Version": []string{"9.18.1"},
			},
			body:          `<html></html>`,
			wantResult:    true,
			wantTech:      "cisco-anyconnect",
			wantVersion:   "9.18.1",
			wantCPEPrefix: "cpe:2.3:a:cisco:adaptive_security_appliance_software:9.18.1",
		},
		{
			name:       "does not detect from 404 response",
			statusCode: 404,
			headers:    http.Header{},
			body:       `<html><body>Not Found - CSCOE</body></html>`,
			wantResult: false,
		},
		{
			name:       "detects from 302 redirect with CSCOE Location",
			statusCode: 302,
			headers: http.Header{
				"Location": []string{"/+CSCOE+/logon.html"},
			},
			body:       ``,
			wantResult: true,
			wantTech:   "cisco-anyconnect",
		},
		{
			name:       "does not detect non-AnyConnect content",
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

// TestAnyConnectFingerprinter_FalsePositives tests that body-only matches
// do NOT produce false positives. This was a bug where generic body patterns
// like "Portal" or "asa" would match non-VPN websites.
func TestAnyConnectFingerprinter_FalsePositives(t *testing.T) {
	f := &AnyConnectFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		body       string
		wantResult bool
	}{
		{
			name:       "does not match generic 'Portal' text without header indicators",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body><a href="/support">Support Portal</a></body></html>`,
			wantResult: false,
		},
		{
			name:       "does not match 'ASA' abbreviation in non-VPN context",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Welcome to ASA Conference 2024</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not match 'firepower' keyword on marketing site",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Cisco Firepower is a great product for security</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not match 'vpn' keyword alone",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Best VPN services compared</body></html>`,
			wantResult: false,
		},
		{
			name:       "still matches with header indicator present",
			statusCode: 200,
			headers: http.Header{
				"X-Asa-Version": []string{"9.16(4)"},
			},
			body:       `<html><body>Welcome</body></html>`,
			wantResult: true,
		},
		{
			name:       "still matches with webvpn cookie and body content",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie": []string{"webvpnlogin=1; path=/"},
			},
			body:       `<html><body>AnyConnect VPN</body></html>`,
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

func TestBuildAnyConnectCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "9.16(4)",
			want:    "cpe:2.3:a:cisco:adaptive_security_appliance_software:9.16(4):*:*:*:*:*:*:*",
		},
		{
			version: "9.18.1",
			want:    "cpe:2.3:a:cisco:adaptive_security_appliance_software:9.18.1:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:a:cisco:adaptive_security_appliance_software:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildAnyConnectCPE(tt.version); got != tt.want {
				t.Errorf("buildAnyConnectCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestAnyConnectFingerprinter_ShodanVectors tests detection against real-world
// response patterns observed via Shodan reconnaissance.
// Shodan dorks: title:"SSL VPN Service" webvpnlogin=1, ssl:"ASA Temporary Self Signed"
func TestAnyConnectFingerprinter_ShodanVectors(t *testing.T) {
	f := &AnyConnectFingerprinter{}

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
			name:        "Shodan Vector 1: ASA 9.16 with webvpnlogin cookie",
			description: "Cisco ASA with SSL VPN enabled, captured via webvpnlogin cookie presence",
			statusCode:  200,
			headers: http.Header{
				"Server":          []string{"Cisco ASDM"},
				"Set-Cookie":      []string{"webvpnlogin=1; path=/; secure", "webvpnLang=en; path=/"},
				"X-Asa-Version":   []string{"9.16(3)19"},
				"Content-Type":    []string{"text/html; charset=utf-8"},
				"Cache-Control":   []string{"no-store, no-cache, must-revalidate"},
				"X-Frame-Options": []string{"SAMEORIGIN"},
			},
			body: `<!DOCTYPE html>
<html>
<head><title>SSL VPN Service</title></head>
<body>
<form name="frmLogin" action="/+webvpn+/index.html" method="post">
<input type="hidden" name="tgroup" value="">
<div id="logon_form">Cisco AnyConnect</div>
</form>
</body>
</html>`,
			wantTech:    "cisco-anyconnect",
			wantVersion: "9.16(3)19",
		},
		{
			name:        "Shodan Vector 2: ASA 9.18 Firepower with CSCOE login page",
			description: "Cisco Firepower Threat Defense with AnyConnect, detected via CSCOE path",
			statusCode:  200,
			headers: http.Header{
				"Server":                []string{"Cisco Firepower Threat Defense"},
				"X-Transcend-Version":   []string{"9.18.2"},
				"Content-Type":          []string{"text/html"},
				"Strict-Transport-Security": []string{"max-age=31536000"},
			},
			body: `<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8"/>
<title>Secure Desktop</title>
<script type="text/javascript" src="/+CSCOE+/cte.js"></script>
<link rel="stylesheet" type="text/css" href="/+CSCOE+/portal.css"/>
</head>
<body onload="init()">
<div id="cscoe-login">Please enter your credentials</div>
</body>
</html>`,
			wantTech:    "cisco-anyconnect",
			wantVersion: "9.18.2",
		},
		{
			name:        "Shodan Vector 3: ASA with self-signed cert and webvpn context",
			description: "Older ASA device with webvpncontext cookie, no version header",
			statusCode:  200,
			headers: http.Header{
				"Server":       []string{"Cisco ASA"},
				"Set-Cookie":   []string{"webvpncontext=00@portal; path=/; secure; httponly"},
				"Content-Type": []string{"text/html"},
			},
			body: `<html>
<head><title>NetScaler AAA</title></head>
<body>
<script>
document.location='/+webvpn+/webvpn.html';
</script>
<noscript>
<p>JavaScript is required. Enable JavaScript to use AnyConnect.</p>
</noscript>
</body>
</html>`,
			wantTech:    "cisco-anyconnect",
			wantVersion: "",
		},
		{
			name:        "Shodan Vector 4: ASA ASDM redirect to CSCOT",
			description: "ASA redirecting to translation table endpoint",
			statusCode:  302,
			headers: http.Header{
				"Server":       []string{"Cisco ASDM/7.18(1)"},
				"Location":     []string{"/+CSCOT+/translation-table?type=mst&textdomain=AnyConnect"},
				"Content-Type": []string{"text/html"},
				"Set-Cookie":   []string{"webvpn=; path=/; secure"},
			},
			body:        ``,
			wantTech:    "cisco-anyconnect",
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

			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
		})
	}
}
