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

func TestSonicWallFingerprinter_Name(t *testing.T) {
	f := &SonicWallFingerprinter{}
	if name := f.Name(); name != "sonicwall" {
		t.Errorf("Name() = %q, expected %q", name, "sonicwall")
	}
}

func TestSonicWallFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &SonicWallFingerprinter{}
	if endpoint := f.ProbeEndpoint(); endpoint != "/auth1.html" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", endpoint, "/auth1.html")
	}
}

func TestSonicWallFingerprinter_Match(t *testing.T) {
	f := &SonicWallFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches with SonicWALL Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SonicWALL SSL-VPN Web Server"},
			},
			want: true,
		},
		{
			name:       "matches with lowercase sonicwall Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"sonicwall"},
			},
			want: true,
		},
		{
			name:       "matches with X-Sonicwall-Cfs-Policy header",
			statusCode: 200,
			headers: http.Header{
				"X-Sonicwall-Cfs-Policy": []string{"default"},
			},
			want: true,
		},
		{
			name:       "matches with 302 redirect and SonicWALL Server header",
			statusCode: 302,
			headers: http.Header{
				"Server":   []string{"SonicWALL"},
				"Location": []string{"/cgi-bin/welcome"},
			},
			want: true,
		},
		{
			name:       "matches with 403 response and SonicWALL Server header",
			statusCode: 403,
			headers: http.Header{
				"Server": []string{"SonicWALL SSL-VPN Web Server"},
			},
			want: true,
		},
		{
			name:       "does not match 500 server error",
			statusCode: 500,
			headers: http.Header{
				"Server": []string{"SonicWALL"},
			},
			want: false,
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
		{
			name:       "does not match empty headers",
			statusCode: 200,
			headers:    http.Header{},
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

func TestSonicWallFingerprinter_Fingerprint(t *testing.T) {
	f := &SonicWallFingerprinter{}

	tests := []struct {
		name               string
		statusCode         int
		headers            http.Header
		body               string
		wantResult         bool
		wantTech           string
		wantVersion        string
		wantCPEPrefix      string
		wantSSLVPN         bool
		wantModel          string
		wantMgmtInterface  string
	}{
		{
			name:       "detects SonicWall from Server header with SSL VPN body",
			statusCode: 200,
			headers: http.Header{
				"Server":       []string{"SonicWALL SSL-VPN Web Server"},
				"Content-Type": []string{"text/html"},
			},
			body: `<html><head><title>SonicWall - Authentication</title></head>
<body><div id="login"><h1>Virtual Office</h1>
<form action="/cgi-bin/welcome" method="POST">
<input type="text" name="username">
<input type="password" name="password">
</form></div></body></html>`,
			wantResult: true,
			wantTech:   "sonicwall",
			wantSSLVPN: true,
		},
		{
			name:       "detects SonicWall with SonicOS version in body",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SonicWALL"},
			},
			body:          `<html><body><p>SonicOS 7.0.1 Management Interface</p></body></html>`,
			wantResult:    true,
			wantTech:      "sonicwall",
			wantVersion:   "7.0.1",
			wantCPEPrefix: "cpe:2.3:o:sonicwall:sonicos:7.0.1",
		},
		{
			name:       "detects SonicWall with Enhanced SonicOS version",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SonicWALL"},
			},
			body:          `<html><body>SonicOS Enhanced 6.5.4.4 running on SonicWall TZ 300</body></html>`,
			wantResult:    true,
			wantTech:      "sonicwall",
			wantVersion:   "6.5.4.4",
			wantCPEPrefix: "cpe:2.3:o:sonicwall:sonicos:6.5.4.4",
			wantModel:     "TZ 300",
		},
		{
			name:       "detects SonicWall with firmware version",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SonicWALL"},
			},
			body:          `<script>var firmware_version="7.0.1-5035";</script>`,
			wantResult:    true,
			wantTech:      "sonicwall",
			wantVersion:   "7.0.1-5035",
			wantCPEPrefix: "cpe:2.3:o:sonicwall:sonicos:7.0.1-5035",
		},
		{
			name:       "detects SonicWall NSA model",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SonicWALL"},
			},
			body:       `<html><title>SonicWall NSA 2700 - Login</title></html>`,
			wantResult: true,
			wantTech:   "sonicwall",
			wantModel:  "NSA 2700",
		},
		{
			name:       "detects SonicWall SuperMassive model",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SonicWALL"},
			},
			body:       `<html><body>SonicWall SuperMassive 9600</body></html>`,
			wantResult: true,
			wantTech:   "sonicwall",
			wantModel:  "SuperMassive 9600",
		},
		{
			name:       "detects SonicWall via body patterns only (2+ matches)",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><head><title>SonicWALL Authentication</title></head>
<body><form action="/cgi-bin/welcome" method="POST"></form></body></html>`,
			wantResult: true,
			wantTech:   "sonicwall",
		},
		{
			name:       "detects NetExtender SSL-VPN",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SonicWALL SSL-VPN Web Server"},
			},
			body:       `<html><body><a href="/NetExtender">Download NetExtender</a></body></html>`,
			wantResult: true,
			wantTech:   "sonicwall",
			wantSSLVPN: true,
		},
		{
			name:       "does not detect from 500 response",
			statusCode: 500,
			headers: http.Header{
				"Server": []string{"SonicWALL"},
			},
			body:       `<html><body>Internal Server Error</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect non-SonicWall content",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Apache/2.4.41"},
			},
			body:       `<html><body>Welcome to our website</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect single body mention without header",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>We use SonicWALL for network security</body></html>`,
			wantResult: false,
		},
		{
			name:       "detects with X-Sonicwall-Cfs-Policy header and empty body",
			statusCode: 200,
			headers: http.Header{
				"X-Sonicwall-Cfs-Policy": []string{"default"},
			},
			body:       ``,
			wantResult: true,
			wantTech:   "sonicwall",
		},
		{
			name:       "detects with Server header and empty body",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SonicWALL"},
			},
			body:       ``,
			wantResult: true,
			wantTech:   "sonicwall",
		},
		{
			name:       "detects SonicOS API JSON response with version",
			statusCode: 200,
			headers: http.Header{
				"Server":       []string{"SonicWALL"},
				"Content-Type": []string{"application/json"},
			},
			body:          `{"status":"success","sonicos":{"firmware_version":"7.0.1-5035","model":"TZ 370"}}`,
			wantResult:    true,
			wantTech:      "sonicwall",
			wantVersion:   "7.0.1-5035",
			wantCPEPrefix: "cpe:2.3:o:sonicwall:sonicos:7.0.1-5035",
		},
		{
			name:       "detects SonicOS API endpoint reference in body (2+ body patterns)",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body><a href="/api/sonicos/version">API</a><p>SonicWALL Management</p></body></html>`,
			wantResult: true,
			wantTech:   "sonicwall",
		},
		{
			name:       "does not detect single NetExtender mention without header",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Download the NetExtender client from the vendor site</body></html>`,
			wantResult: false,
		},
		{
			name:       "extracts version from JS asset filename on real device",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SonicWALL SSL-VPN Web Server"},
			},
			body: `<html><head>
<script src="md5-5.0.0-4190932482.js"></script>
<script src="auth-5.0.0-2655861013.js"></script>
</head><body></body></html>`,
			wantResult:    true,
			wantTech:      "sonicwall",
			wantVersion:   "5.0.0",
			wantCPEPrefix: "cpe:2.3:o:sonicwall:sonicos:5.0.0",
		},
		{
			name:       "extracts version from CSS filename with o suffix",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SonicWALL"},
			},
			body: `<html><head>
<link rel="stylesheet" href="swl_login-5.0o-586369509.css">
<script src="auth-5.0o-1481342612.js"></script>
</head><body></body></html>`,
			wantResult:    true,
			wantTech:      "sonicwall",
			wantVersion:   "5.0",
			wantCPEPrefix: "cpe:2.3:o:sonicwall:sonicos:5.0",
		},
		{
			name:       "detects SSL-VPN from sslvpnLogin meta tag",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SonicWALL SSL-VPN Web Server"},
			},
			body:       `<html><head><meta name="id" content="sslvpnLogin"></head><body></body></html>`,
			wantResult: true,
			wantTech:   "sonicwall",
			wantSSLVPN: true,
		},
		{
			name:       "detects DELL branding",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SonicWALL SSL-VPN Web Server"},
			},
			body:       `<html><body>window.status="DELL SonicWALL - Virtual Office"</body></html>`,
			wantResult: true,
			wantTech:   "sonicwall",
			wantSSLVPN: true,
		},
		{
			name:       "extracts version from JS filename with language suffix",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"SonicWALL"}},
			body: `<link href="swl_login-6.2.5-4163414724(eng).css" rel="stylesheet">
<script src="auth-6.2.5-2996728830(eng).js"></script>
<title>Dell SonicWALL - Authentication</title>`,
			wantResult:  true,
			wantVersion: "6.2.5",
			wantTech:    "sonicwall",
		},
		{
			name:              "detects web-admin from admin frameset page",
			statusCode:        200,
			headers:           http.Header{"Server": []string{"SonicWALL"}},
			body:              `<frameset rows="*,1"><frame src="auth1.html" name="authFrm"></frameset>`,
			wantResult:        true,
			wantTech:          "sonicwall",
			wantMgmtInterface: "web-admin",
		},
		{
			name:       "detects SonicOS 7.x from redirect to sonicui with version extraction",
			statusCode: 302,
			headers: http.Header{
				"Server":   []string{"SonicWALL"},
				"Location": []string{"https://10.0.0.1/sonicui/7/login/"},
			},
			body:              `<BODY onLoad="location.href = 'https://10.0.0.1/sonicui/7/login/';">`,
			wantResult:        true,
			wantVersion:       "7",
			wantTech:          "sonicwall",
			wantMgmtInterface: "web-admin",
		},
		{
			name:              "defaults to web-admin with Server header and empty body",
			statusCode:        200,
			headers:           http.Header{"Server": []string{"SonicWALL"}},
			body:              ``,
			wantResult:        true,
			wantTech:          "sonicwall",
			wantMgmtInterface: "web-admin",
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
					if len(result.CPEs[0]) < len(tt.wantCPEPrefix) || result.CPEs[0][:len(tt.wantCPEPrefix)] != tt.wantCPEPrefix {
						t.Errorf("CPE = %q, want prefix %q", result.CPEs[0], tt.wantCPEPrefix)
					}
				}
				if tt.wantSSLVPN {
					if sslVPN, ok := result.Metadata["sslVPN"]; !ok || sslVPN != true {
						t.Error("expected sslVPN=true in metadata")
					}
				}
				if tt.wantModel != "" {
					if model, ok := result.Metadata["productModel"]; !ok || model != tt.wantModel {
						t.Errorf("productModel = %q, want %q", model, tt.wantModel)
					}
				}
				if tt.wantMgmtInterface != "" {
					if mgmt, ok := result.Metadata["managementInterface"]; !ok || mgmt != tt.wantMgmtInterface {
						t.Errorf("managementInterface = %q, want %q", mgmt, tt.wantMgmtInterface)
					}
				}
			}
		})
	}
}

func TestSonicWallFingerprinter_VersionValidation(t *testing.T) {
	f := &SonicWallFingerprinter{}

	tests := []struct {
		name        string
		body        string
		wantVersion string
	}{
		{
			name:        "valid 3-part version",
			body:        `SonicOS 7.0.1`,
			wantVersion: "7.0.1",
		},
		{
			name:        "valid 4-part version",
			body:        `SonicOS Enhanced 6.5.4.4`,
			wantVersion: "6.5.4.4",
		},
		{
			name:        "valid version with build suffix",
			body:        `SonicOS 7.1.1-7040`,
			wantVersion: "7.1.1-7040",
		},
		{
			name:        "CPE injection attempt extracts only valid portion",
			body:        `SonicOS 7.0.1:*:*:*:*:*:*:injected`,
			wantVersion: "7.0.1",
		},
		{
			name:        "shell metacharacters do not pollute version extraction",
			body:        `firmware_version="7.0.1$(whoami)"`,
			wantVersion: "7.0.1",
		},
		{
			name:        "no version present",
			body:        `Welcome to SonicWALL login`,
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Server": []string{"SonicWALL"},
				},
			}
			result, err := f.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Errorf("Fingerprint() error = %v", err)
				return
			}
			if result == nil {
				t.Error("Fingerprint() returned nil, expected result")
				return
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
		})
	}
}

func TestBuildSonicWallCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "7.0.1",
			want:    "cpe:2.3:o:sonicwall:sonicos:7.0.1:*:*:*:*:*:*:*",
		},
		{
			version: "6.5.4.4",
			want:    "cpe:2.3:o:sonicwall:sonicos:6.5.4.4:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:o:sonicwall:sonicos:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildSonicWallCPE(tt.version); got != tt.want {
				t.Errorf("buildSonicWallCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSonicWallFingerprinter_FalsePositives(t *testing.T) {
	f := &SonicWallFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		body       string
		wantResult bool
	}{
		{
			name:       "does not match single SonicWall mention in marketing content",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>We partner with SonicWall for network security</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not match SonicWall mention in documentation",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body>Configure your SonicWALL firewall using these steps</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not match generic login page",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body><form action="/login"><input type="password"></form></body></html>`,
			wantResult: false,
		},
		{
			name:       "still matches with Server header present",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"SonicWALL SSL-VPN Web Server"},
			},
			body:       `<html><body>Login</body></html>`,
			wantResult: true,
		},
		{
			name:       "still matches with X-Sonicwall-Cfs-Policy header",
			statusCode: 200,
			headers: http.Header{
				"X-Sonicwall-Cfs-Policy": []string{"block"},
			},
			body:       `<html><body>Blocked</body></html>`,
			wantResult: true,
		},
		{
			name:       "matches with 2+ body patterns and no header",
			statusCode: 200,
			headers:    http.Header{},
			body:       `<html><body><h1>SonicWALL</h1><a href="/cgi-bin/welcome">Login</a></body></html>`,
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

// TestSonicWallFingerprinter_ShodanVectors tests detection against real-world
// response patterns observed via Shodan and live SonicWall reconnaissance.
// Shodan dorks: http.title:"SonicWall", Server:"SonicWALL"
func TestSonicWallFingerprinter_ShodanVectors(t *testing.T) {
	f := &SonicWallFingerprinter{}

	tests := []struct {
		name        string
		description string
		statusCode  int
		headers     http.Header
		body        string
		wantTech    string
		wantVersion string
		wantSSLVPN  bool
		wantModel   string
	}{
		{
			name:        "Shodan Vector 1: SonicWall TZ SSL-VPN login page",
			description: "SonicWall TZ series with SSL-VPN portal and NetExtender download",
			statusCode:  200,
			headers: http.Header{
				"Server":                    []string{"SonicWALL SSL-VPN Web Server"},
				"Content-Type":              []string{"text/html; charset=UTF-8"},
				"Cache-Control":             []string{"no-cache, no-store, must-revalidate"},
				"Strict-Transport-Security": []string{"max-age=31536000"},
			},
			body: `<!DOCTYPE html>
<html><head><title>SonicWall - Virtual Office</title>
<link rel="stylesheet" href="/swl_portal/css/login.css">
</head><body>
<div id="sonicwall-login">
<h1>Virtual Office</h1>
<p>SonicWall TZ 370 - SonicOS 7.0.1</p>
<form action="/cgi-bin/welcome" method="POST">
<input type="text" name="uName" placeholder="Username">
<input type="password" name="pass" placeholder="Password">
<button type="submit">Login</button>
</form>
<a href="/NetExtender" id="netextender-link">Download NetExtender</a>
</div></body></html>`,
			wantTech:    "sonicwall",
			wantVersion: "7.0.1",
			wantSSLVPN:  true,
			wantModel:   "TZ 370",
		},
		{
			name:        "Shodan Vector 2: SonicWall NSA management interface",
			description: "SonicWall NSA series admin panel with SonicOS Enhanced",
			statusCode:  200,
			headers: http.Header{
				"Server":       []string{"SonicWALL"},
				"Content-Type": []string{"text/html"},
			},
			body: `<!DOCTYPE html>
<html><head><title>SonicWall NSA 2700</title></head>
<body>
<div id="mgmt-login">
<h2>SonicWall NSA 2700 Management</h2>
<p>SonicOS Enhanced 6.5.4.4</p>
<form action="/managementLogin" method="POST">
<input type="text" name="userName">
<input type="password" name="pwd">
</form>
</div></body></html>`,
			wantTech:    "sonicwall",
			wantVersion: "6.5.4.4",
			wantModel:   "NSA 2700",
		},
		{
			name:        "Shodan Vector 3: SonicWall SMA SSL-VPN portal",
			description: "SonicWall SMA 200 with SSL-VPN portal redirect",
			statusCode:  302,
			headers: http.Header{
				"Server":       []string{"SonicWALL SSL-VPN Web Server"},
				"Location":     []string{"/cgi-bin/welcome"},
				"Content-Type": []string{"text/html"},
				"Set-Cookie":   []string{"swap=abc123; path=/; secure; HttpOnly"},
			},
			body:       `<html><body>Redirecting to <a href="/cgi-bin/welcome">login</a></body></html>`,
			wantTech:   "sonicwall",
			wantSSLVPN: true,
		},
		{
			name:        "Shodan Vector 4: SonicWall with firmware version in JavaScript",
			description: "SonicWall login page with firmware version exposed in JavaScript",
			statusCode:  200,
			headers: http.Header{
				"Server":       []string{"SonicWALL"},
				"Content-Type": []string{"text/html; charset=utf-8"},
			},
			body: `<!DOCTYPE html>
<html><head>
<title>SonicWALL</title>
<script type="text/javascript">
var firmware_version="7.1.1-7040";
var model="SonicWall SuperMassive 9600";
</script></head>
<body>
<div class="login-container">
<img src="/images/sonicwall_logo.png" alt="SonicWALL">
<form method="POST" action="/cgi-bin/welcome">
<input name="user" type="text">
<input name="pass" type="password">
</form></div></body></html>`,
			wantTech:    "sonicwall",
			wantVersion: "7.1.1-7040",
			wantModel:   "SuperMassive 9600",
		},
		{
			name:        "Shodan Vector 5: Real SSL-VPN portal (31.141.236.4:4433 pattern)",
			description: "Real SonicWall SSL-VPN portal with JS asset versioning and NetExtender",
			statusCode:  200,
			headers: http.Header{
				"Server":       []string{"SonicWALL SSL-VPN Web Server"},
				"Content-Type": []string{"text/html; charset=UTF-8"},
			},
			body: `<!DOCTYPE html>
<html><head>
<meta name="id" content="sslvpnLogin">
<script src="md5-5.0.0-4190932482.js"></script>
<script src="auth-5.0.0-2655861013.js"></script>
<script src="browserCheck-5.0.0-2410815703.js"></script>
<link rel="stylesheet" href="swl_login-5.0.0-3029498498.css">
</head><body>
<script>
window.status="DELL SonicWALL - Virtual Office - Powered by SonicWALL, Inc.";
var nelaunchxpsversion = "7.0.0.107";
var sslvpnSvcObj = new serviceObj('SSLVPN',1,11293,6,4433,4433,0);
</script>
<form method="POST" action="/cgi-bin/welcome">
<input name="uName" type="text">
<input name="pass" type="password">
</form>
<a href="https://software.sonicwall.com/applications/netextender/plugin/7.0/npNELaunch.xpi">NetExtender</a>
</body></html>`,
			wantTech:    "sonicwall",
			wantVersion: "5.0.0",
			wantSSLVPN:  true,
		},
		{
			name:        "Shodan Vector 6: Real admin frameset (72.211.43.91 pattern)",
			description: "Real SonicWall admin interface with frameset loading auth1.html",
			statusCode:  200,
			headers: http.Header{
				"Server":       []string{"SonicWALL"},
				"Content-Type": []string{"text/html"},
			},
			body: `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Transitional//EN">
<html><head><title>SonicWALL</title>
<link rel="stylesheet" href="swl_login-5.0o-586369509.css">
<script src="auth-5.0o-1481342612.js"></script>
</head>
<frameset rows="*,1">
<frame src="auth1.html" name="authFrm">
<frame src="about:blank" name="hiddenFrm">
</frameset></html>`,
			wantTech:    "sonicwall",
			wantVersion: "5.0",
		},
		{
			name:        "Shodan Vector 7: SonicOS REST API JSON response",
			description: "SonicOS REST API returning JSON with firmware version and model",
			statusCode:  200,
			headers: http.Header{
				"Server":                    []string{"SonicWALL"},
				"Content-Type":              []string{"application/json; charset=UTF-8"},
				"Cache-Control":             []string{"no-cache, no-store"},
				"Strict-Transport-Security": []string{"max-age=31536000"},
			},
			body: `{
  "status": "success",
  "sonicos": {
    "firmware_version": "7.0.1-5058",
    "model": "SonicWall TZ 470",
    "serial_number": "XXXXXXXXXXXX",
    "uptime": 8640000,
    "api_version": "sonicos_api/v1"
  }
}`,
			wantTech:    "sonicwall",
			wantVersion: "7.0.1-5058",
			wantModel:   "TZ 470",
		},
		{
			name:        "Shodan Vector 8: Admin interface with (eng) JS/CSS filenames",
			description: "Real SonicWall admin interface (204.122.20.22 style) with language-suffixed asset filenames",
			statusCode:  200,
			headers: http.Header{
				"Server": []string{"SonicWALL"},
			},
			body: `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN">
<html><head>
<meta name="id" content="auth1">
<link href="swl_login-6.2.5-4163414724(eng).css" rel="stylesheet" type="text/css">
<title>Dell SonicWALL - Authentication</title>
<script type="text/JavaScript" src="jquery-6.2.5-3031828635(eng).js"></script>
<script type="text/JavaScript" src="cookies-6.2.5-1331366947(eng).js"></script>
<script type="text/JavaScript" src="md5-6.2.5-4190932482(eng).js"></script>
<script type="text/JavaScript" src="auth-6.2.5-2996728830(eng).js"></script>`,
			wantTech:    "sonicwall",
			wantVersion: "6.2.5",
		},
		{
			name:        "Shodan Vector 9: SonicOS 7.x redirect to sonicui",
			description: "SonicOS 7.x device returning 302 redirect to /sonicui/7/login/ (68.15.167.207 pattern)",
			statusCode:  302,
			headers: http.Header{
				"Server":       []string{"SonicWALL"},
				"Content-Type": []string{"text/html;charset=UTF-8"},
				"Location":     []string{"https://68.15.167.207/sonicui/7/login/"},
			},
			body: `<HTML><HEAD><TITLE>Page Redirecting</TITLE>
<META HTTP-EQUIV="Pragma" CONTENT="no-cache">
</HEAD><BODY onLoad="location.href = 'https://68.15.167.207/sonicui/7/login/';">
This page is redirecting! Click <A HREF="https://68.15.167.207/sonicui/7/login/">here</A>
</BODY></HTML>`,
			wantTech:    "sonicwall",
			wantVersion: "7",
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

			if tt.wantSSLVPN {
				if sslVPN, ok := result.Metadata["sslVPN"]; !ok || sslVPN != true {
					t.Errorf("expected sslVPN=true in metadata for: %s", tt.description)
				}
			}

			if tt.wantModel != "" {
				if model, ok := result.Metadata["productModel"]; !ok || model != tt.wantModel {
					t.Errorf("productModel = %q, want %q for: %s", model, tt.wantModel, tt.description)
				}
			}
		})
	}
}

func TestExtractSonicWallVersion(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
	}{
		{
			name: "extracts SonicOS version",
			body: "SonicOS 7.0.1",
			want: "7.0.1",
		},
		{
			name: "extracts SonicOS Enhanced version",
			body: "SonicOS Enhanced 6.5.4.4",
			want: "6.5.4.4",
		},
		{
			name: "extracts firmware version",
			body: `firmware_version="7.1.1-7040"`,
			want: "7.1.1-7040",
		},
		{
			name: "extracts version from API JSON response",
			body: `{"sonicos":{"firmware_version":"7.0.1-5058"}}`,
			want: "7.0.1-5058",
		},
		{
			name: "extracts version from JS asset filename",
			body: `<script src="auth-5.0.0-2655861013.js"></script>`,
			want: "5.0.0",
		},
		{
			name: "extracts version from CSS asset filename with o suffix",
			body: `<link href="swl_login-5.0o-586369509.css" rel="stylesheet">`,
			want: "5.0",
		},
		{
			name: "extracts NetExtender version variable",
			body: `var nelaunchxpsversion = "7.0.0.107";`,
			want: "7.0.0.107",
		},
		{
			name: "extracts version from NetExtender download URL",
			body: `https://software.sonicwall.com/applications/netextender/plugin/7.0/npNELaunch.xpi`,
			want: "7.0",
		},
		{
			name: "prefers SonicOS version over JS filename version",
			body: `SonicOS 7.0.1 <script src="auth-5.0.0-123.js"></script>`,
			want: "7.0.1",
		},
		{
			name: "no version found",
			body: "Welcome to SonicWall",
			want: "",
		},
		{
			name: "extracts version from JS filename with (eng) suffix",
			body: `<script src="auth-6.2.5-2996728830(eng).js"></script>`,
			want: "6.2.5",
		},
		{
			name: "extracts version from CSS filename with (eng) suffix",
			body: `<link href="swl_login-6.2.5-4163414724(eng).css" rel="stylesheet">`,
			want: "6.2.5",
		},
		{
			name: "extracts major version from sonicui URL in body",
			body: `location.href = '/sonicui/7/login/';`,
			want: "7",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSonicWallVersion([]byte(tt.body))
			if got != tt.want {
				t.Errorf("extractSonicWallVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractSonicWallModel(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "extracts TZ model",
			body: "SonicWall TZ 370 Firewall",
			want: "TZ 370",
		},
		{
			name: "extracts NSA model",
			body: "SonicWall NSA 2700",
			want: "NSA 2700",
		},
		{
			name: "extracts SuperMassive model",
			body: "SonicWall SuperMassive 9600",
			want: "SuperMassive 9600",
		},
		{
			name: "extracts SMA model",
			body: "SonicWall SMA 200",
			want: "SMA 200",
		},
		{
			name: "no model found",
			body: "SonicWall Firewall Login",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractSonicWallModel(tt.body)
			if got != tt.want {
				t.Errorf("extractSonicWallModel() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestDetectSonicWallSSLVPN(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		headers http.Header
		want    bool
	}{
		{
			name:    "detects NetExtender",
			body:    "Download NetExtender client",
			headers: http.Header{},
			want:    true,
		},
		{
			name:    "detects Virtual Office",
			body:    "SonicWall Virtual Office Login",
			headers: http.Header{},
			want:    true,
		},
		{
			name:    "detects sslvpn path",
			body:    `<a href="/sslvpn/login">Login</a>`,
			headers: http.Header{},
			want:    true,
		},
		{
			name:    "detects swl_portal",
			body:    `<link href="/swl_portal/css/login.css">`,
			headers: http.Header{},
			want:    true,
		},
		{
			name: "detects swap cookie",
			body: "",
			headers: http.Header{
				"Set-Cookie": []string{"swap=abc123; path=/; secure"},
			},
			want: true,
		},
		{
			name:    "detects sslvpnLogin meta tag",
			body:    `<meta name="id" content="sslvpnLogin">`,
			headers: http.Header{},
			want:    true,
		},
		{
			name:    "no SSL-VPN indicators",
			body:    "SonicWall Management Login",
			headers: http.Header{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectSonicWallSSLVPN(tt.body, tt.headers)
			if got != tt.want {
				t.Errorf("detectSonicWallSSLVPN() = %v, want %v", got, tt.want)
			}
		})
	}
}
