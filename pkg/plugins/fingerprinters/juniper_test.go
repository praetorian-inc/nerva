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

func TestJuniperFingerprinter_Name(t *testing.T) {
	f := &JuniperFingerprinter{}
	if name := f.Name(); name != "juniper-srx" {
		t.Errorf("Name() = %q, expected %q", name, "juniper-srx")
	}
}

func TestJuniperFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &JuniperFingerprinter{}
	if endpoint := f.ProbeEndpoint(); endpoint != "/" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", endpoint, "/")
	}
}

func TestJuniperFingerprinter_Match(t *testing.T) {
	f := &JuniperFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches with X-Juniper-Version header",
			statusCode: 200,
			headers: http.Header{
				"X-Juniper-Version": []string{"21.4R3-S5"},
			},
			want: true,
		},
		{
			name:       "matches with antiCSRFToken header combined with Embedthis-Appweb",
			statusCode: 200,
			headers: http.Header{
				"Anticsrftoken": []string{"abc123def456"},
				"Server":        []string{"Embedthis-Appweb/3.2.3"},
			},
			want: true,
		},
		{
			name:       "matches with J-Web session cookie",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie": []string{"jweb_session=abc123; path=/; HttpOnly"},
			},
			want: true,
		},
		{
			name:       "matches with Juniper cookie",
			statusCode: 200,
			headers: http.Header{
				"Set-Cookie": []string{"juniper_session=xyz; path=/"},
			},
			want: true,
		},
		{
			name:       "matches with Juniper Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Juniper Web Device Manager"},
			},
			want: true,
		},
		{
			name:       "matches with Junos Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Junos Webserver"},
			},
			want: true,
		},
		{
			name:       "matches with 302 redirect and Juniper header",
			statusCode: 302,
			headers: http.Header{
				"X-Juniper-Version": []string{"22.2R1"},
				"Location":          []string{"/jweb/"},
			},
			want: true,
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
		{
			name:       "does not match 500 server error",
			statusCode: 500,
			headers: http.Header{
				"X-Juniper-Version": []string{"21.4R3-S5"},
			},
			want: false,
		},
		{
			name:       "does not match 503 service unavailable",
			statusCode: 503,
			headers: http.Header{
				"Server": []string{"Juniper"},
			},
			want: false,
		},
		{
			name:       "matches XML content type with X-Juniper-Version",
			statusCode: 200,
			headers: http.Header{
				"Content-Type":      []string{"application/xml"},
				"X-Juniper-Version": []string{"21.4R3-S5"},
			},
			want: true,
		},
		{
			name:       "does not match XML content type alone",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"application/xml"},
			},
			want: false,
		},
		{
			name:       "matches with Embedthis-Appweb server header (J-Web web server)",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"Embedthis-Appweb/3.2.3"}},
			want:       true,
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

func TestJuniperFingerprinter_Fingerprint(t *testing.T) {
	f := &JuniperFingerprinter{}

	tests := []struct {
		name        string
		statusCode  int
		headers     http.Header
		body        string
		wantResult  bool
		wantTech    string
		wantVersion string
		wantModel   string
		wantJWeb    bool
		wantVPN     bool
		wantCluster bool
	}{
		{
			name:       "detects J-Web from header + body",
			statusCode: 200,
			headers: http.Header{
				"X-Juniper-Version": []string{"21.4R3-S5"},
				"Content-Type":      []string{"text/html"},
			},
			body:        `<html><head><title>J-Web Login</title></head><body><div class="jweb-login">Juniper Networks SRX300</div></body></html>`,
			wantResult:  true,
			wantTech:    "juniper-srx",
			wantVersion: "21.4R3-S5",
			wantModel:   "SRX300",
			wantJWeb:    true,
		},
		{
			name:       "detects from antiCSRFToken header with J-Web body",
			statusCode: 200,
			headers: http.Header{
				"Anticsrftoken": []string{"token123"},
				"Content-Type":  []string{"text/html"},
			},
			body:       `<html><head><title>J-Web</title></head><body>Juniper Networks Login</body></html>`,
			wantResult: true,
			wantTech:   "juniper-srx",
			wantJWeb:   true,
		},
		{
			name:       "detects with version in script variable",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Juniper Web Device Manager"},
			},
			body:        `<html><script>var junosVersion = "22.2R1";</script><body>J-Web Login</body></html>`,
			wantResult:  true,
			wantTech:    "juniper-srx",
			wantVersion: "22.2R1",
			wantJWeb:    true,
		},
		{
			name:       "detects SRX1500 model",
			statusCode: 200,
			headers: http.Header{
				"X-Juniper-Version": []string{"23.1R1-S1"},
			},
			body:        `<html><body><h1>Juniper Networks SRX1500</h1><div class="jweb">Login</div></body></html>`,
			wantResult:  true,
			wantTech:    "juniper-srx",
			wantVersion: "23.1R1-S1",
			wantModel:   "SRX1500",
			wantJWeb:    true,
		},
		{
			name:       "detects Dynamic VPN portal",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Junos Webserver"},
			},
			body:       `<html><body><h1>Dynamic VPN Client Download</h1><p>Juniper Networks</p></body></html>`,
			wantResult: true,
			wantTech:   "juniper-srx",
			wantVPN:    true,
		},
		{
			name:       "detects cluster status",
			statusCode: 200,
			headers: http.Header{
				"X-Juniper-Version": []string{"21.4R3-S5"},
			},
			body:        `<html><body><div class="jweb">Cluster Status: node0 primary, node1 secondary</div></body></html>`,
			wantResult:  true,
			wantTech:    "juniper-srx",
			wantVersion: "21.4R3-S5",
			wantJWeb:    true,
			wantCluster: true,
		},
		{
			name:       "detects from body only (no header indicators)",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body:       `<html><head><title>Login</title></head><body><div id="jweb-login">Juniper Networks J-Web</div></body></html>`,
			wantResult: true,
			wantTech:   "juniper-srx",
			wantJWeb:   true,
		},
		{
			name:       "does not detect non-Juniper content",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Apache/2.4.41"},
			},
			body:       `<html><body>Welcome to our website</body></html>`,
			wantResult: false,
		},
		{
			name:       "does not detect from 500 error",
			statusCode: 500,
			headers: http.Header{
				"X-Juniper-Version": []string{"21.4R3-S5"},
			},
			body:       `<html><body>Internal Server Error</body></html>`,
			wantResult: false,
		},
		{
			name:       "detects with header only and empty body",
			statusCode: 200,
			headers: http.Header{
				"X-Juniper-Version": []string{"20.4R3-S9.2"},
			},
			body:        ``,
			wantResult:  true,
			wantTech:    "juniper-srx",
			wantVersion: "20.4R3-S9.2",
		},
		{
			name:       "rejects invalid version format in header",
			statusCode: 200,
			headers: http.Header{
				"X-Juniper-Version": []string{"invalid; DROP TABLE"},
			},
			body:       `<html><body><div class="jweb">Login</div></body></html>`,
			wantResult: true,
			wantTech:   "juniper-srx",
			wantJWeb:   true,
		},
		{
			name:       "extracts version from meta tag",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"Juniper"},
			},
			body:        `<html><head><meta name="version" content="21.4R3-S5"></head><body>J-Web Login</body></html>`,
			wantResult:  true,
			wantTech:    "juniper-srx",
			wantVersion: "21.4R3-S5",
			wantJWeb:    true,
		},
		{
			name:       "extracts version from body text pattern",
			statusCode: 200,
			headers: http.Header{
				"Anticsrftoken": []string{"token"},
			},
			body:        `<html><body>Junos version: 22.2R1 - J-Web Management</body></html>`,
			wantResult:  true,
			wantTech:    "juniper-srx",
			wantVersion: "22.2R1",
			wantJWeb:    true,
		},
		{
			name:       "detects Junos REST API XML response",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"application/xml"},
			},
			body: `<?xml version="1.0" encoding="UTF-8"?>
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R3-S5/junos">
<software-information>
<host-name>fw-edge-01</host-name>
<junos:version>21.4R3-S5</junos:version>
<product-model>SRX345</product-model>
</software-information>
</rpc-reply>`,
			wantResult:  true,
			wantTech:    "juniper-srx",
			wantVersion: "21.4R3-S5",
			wantModel:   "SRX345",
		},
		{
			name:       "detects Junos REST API JSON response",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			body:        `{"software-information":{"host-name":"fw-core-01","junos-version":"22.2R1","product-model":"SRX1500"}}`,
			wantResult:  true,
			wantTech:    "juniper-srx",
			wantVersion: "22.2R1",
		},
		{
			name:       "detects Junos REST API with rpc-reply only",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"application/xml"},
			},
			body:       `<rpc-reply><output>some junos output</output></rpc-reply>`,
			wantResult: true,
			wantTech:   "juniper-srx",
		},
		{
			name:       "detects Juniper J-Web from real device response",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"Embedthis-Appweb/3.2.3"}},
			body: `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head>
<link rel="stylesheet" href="/stylesheet/juniper.css" type="text/css"/>
<title>Log In - Juniper Web Device Manager</title>
</head><body>
<div class="jweb-title uppercase"> - srx345-dc</div>
<script>var modelphpStr = "srx345-dc";</script>
</body></html>`,
			wantResult: true,
			wantTech:   "juniper-srx",
			wantJWeb:   true,
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

				// Verify CPE is present
				if len(result.CPEs) == 0 {
					t.Error("CPEs is empty, expected at least one CPE")
				}

				if tt.wantModel != "" {
					if model, ok := result.Metadata["model"]; ok {
						if model != tt.wantModel {
							t.Errorf("model = %q, want %q", model, tt.wantModel)
						}
					} else {
						t.Errorf("model not in metadata, want %q", tt.wantModel)
					}
				}

				if tt.wantJWeb {
					if jweb, ok := result.Metadata["jweb"]; !ok || jweb != true {
						t.Error("jweb not detected in metadata")
					}
				}

				if tt.wantVPN {
					if vpn, ok := result.Metadata["dynamicVPN"]; !ok || vpn != true {
						t.Error("dynamicVPN not detected in metadata")
					}
				}

				if tt.wantCluster {
					if cluster, ok := result.Metadata["cluster"]; !ok || cluster != true {
						t.Error("cluster not detected in metadata")
					}
				}

				// Verify vendor metadata is always present
				if vendor, ok := result.Metadata["vendor"]; !ok || vendor != "Juniper Networks" {
					t.Errorf("vendor = %v, want %q", vendor, "Juniper Networks")
				}
				if product, ok := result.Metadata["product"]; !ok || product != "Junos OS" {
					t.Errorf("product = %v, want %q", product, "Junos OS")
				}
			}
		})
	}
}

func TestBuildJuniperCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "21.4R3-S5",
			want:    "cpe:2.3:o:juniper:junos:21.4R3-S5:*:*:*:*:*:*:*",
		},
		{
			version: "22.2R1",
			want:    "cpe:2.3:o:juniper:junos:22.2R1:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:o:juniper:junos:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildJuniperCPE(tt.version); got != tt.want {
				t.Errorf("buildJuniperCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractJunosVersion(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		headers http.Header
		want    string
	}{
		{
			name: "extracts from X-Juniper-Version header",
			body: "",
			headers: http.Header{
				"X-Juniper-Version": []string{"21.4R3-S5"},
			},
			want: "21.4R3-S5",
		},
		{
			name: "extracts from script variable",
			body: `<script>var junosVersion = "22.2R1";</script>`,
			headers: http.Header{},
			want: "22.2R1",
		},
		{
			name: "extracts from JUNOS_VERSION constant",
			body: `<script>JUNOS_VERSION = "23.1R1-S1";</script>`,
			headers: http.Header{},
			want: "23.1R1-S1",
		},
		{
			name: "extracts from meta tag",
			body: `<meta name="version" content="20.4R3-S9.2">`,
			headers: http.Header{},
			want: "20.4R3-S9.2",
		},
		{
			name: "extracts from body text",
			body: `Junos version: 21.4R3-S5`,
			headers: http.Header{},
			want: "21.4R3-S5",
		},
		{
			name: "extracts junos-version pattern",
			body: `junos-version: 22.2R1`,
			headers: http.Header{},
			want: "22.2R1",
		},
		{
			name:    "returns empty for no version",
			body:    `<html><body>No version here</body></html>`,
			headers: http.Header{},
			want:    "",
		},
		{
			name: "rejects invalid version format",
			body: "",
			headers: http.Header{
				"X-Juniper-Version": []string{"not-a-version"},
			},
			want: "",
		},
		{
			name: "rejects CPE injection attempt",
			body: "",
			headers: http.Header{
				"X-Juniper-Version": []string{"21.4R3:*:*:*:*:*:*:*"},
			},
			want: "",
		},
		{
			name: "prefers header over body version",
			body: `Junos version: 20.4R3-S9.2`,
			headers: http.Header{
				"X-Juniper-Version": []string{"21.4R3-S5"},
			},
			want: "21.4R3-S5",
		},
		{
			name:    "extracts from Junos API XML response",
			body:    `<rpc-reply xmlns:junos="http://xml.juniper.net/junos/21.4R3-S5/junos"><junos:version>21.4R3-S5</junos:version></rpc-reply>`,
			headers: http.Header{},
			want:    "21.4R3-S5",
		},
		{
			name:    "extracts from Junos API JSON response",
			body:    `{"junos-version": "22.2R1", "host-name": "fw-01"}`,
			headers: http.Header{},
			want:    "22.2R1",
		},
		{
			name: "prefers API XML version over general body pattern",
			body: `<rpc-reply><junos:version>23.1R1-S1</junos:version></rpc-reply>`,
			headers: http.Header{},
			want: "23.1R1-S1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractJunosVersion([]byte(tt.body), tt.headers)
			if got != tt.want {
				t.Errorf("extractJunosVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestJunosVersionRegex(t *testing.T) {
	tests := []struct {
		version string
		valid   bool
	}{
		{"21.4R3-S5", true},
		{"22.2R1", true},
		{"23.1R1-S1", true},
		{"20.4R3-S9.2", true},
		{"21.4R3", true},
		{"10.0R1-S1.1", true},
		{"not-a-version", false},
		{"21.4", false},
		{"21.4R", false},
		{"", false},
		{"21.4R3:*:*:*", false},
		{"1.2.3.4", false},
		{"21.4R3-S5; DROP TABLE", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := junosVersionRegex.MatchString(tt.version); got != tt.valid {
				t.Errorf("junosVersionRegex.MatchString(%q) = %v, want %v", tt.version, got, tt.valid)
			}
		})
	}
}

// TestJuniperFingerprinter_ShodanVectors tests detection against real-world
// response patterns observed via Shodan reconnaissance of Juniper SRX appliances.
// J-Web management interfaces expose Junos OS on ports 443 and 80.
func TestJuniperFingerprinter_ShodanVectors(t *testing.T) {
	f := &JuniperFingerprinter{}

	tests := []struct {
		name        string
		description string
		statusCode  int
		headers     http.Header
		body        string
		wantTech    string
		wantVersion string
		wantModel   string
		wantJWeb    bool
	}{
		{
			name:        "Shodan Vector 1: SRX300 J-Web login with version header",
			description: "Juniper SRX300 with J-Web management, Junos 21.4R3-S5",
			statusCode:  200,
			headers: http.Header{
				"X-Juniper-Version":         []string{"21.4R3-S5"},
				"Content-Type":              []string{"text/html; charset=utf-8"},
				"Strict-Transport-Security": []string{"max-age=31536000"},
				"X-Frame-Options":           []string{"SAMEORIGIN"},
			},
			body: `<!DOCTYPE html>
<html lang="en">
<head><title>Log In - J-Web</title>
<link rel="icon" href="/jweb/favicon.ico">
</head><body>
<div id="jweb-login-container">
<h1>Juniper Networks SRX300</h1>
<form action="/jweb/authenticate" method="POST">
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<button type="submit">Log In</button>
</form></div></body></html>`,
			wantTech:    "juniper-srx",
			wantVersion: "21.4R3-S5",
			wantModel:   "SRX300",
			wantJWeb:    true,
		},
		{
			name:        "Shodan Vector 2: SRX1500 with antiCSRFToken",
			description: "Juniper SRX1500 enterprise firewall with CSRF protection",
			statusCode:  200,
			headers: http.Header{
				"Anticsrftoken":             []string{"0x7f4a3b2c1d0e"},
				"Content-Type":              []string{"text/html; charset=utf-8"},
				"Strict-Transport-Security": []string{"max-age=31536000"},
				"Set-Cookie":               []string{"jweb_session_id=abc123; path=/; Secure; HttpOnly"},
			},
			body: `<!DOCTYPE html>
<html><head><title>J-Web Login</title>
<script>var junosVersion = "22.2R1";</script>
</head><body>
<div class="jweb-main">
<h2>Juniper Networks SRX1500</h2>
<div class="login-form">
<form method="POST" action="/jweb/authenticate">
<input name="username"><input name="password" type="password">
</form></div></div></body></html>`,
			wantTech:    "juniper-srx",
			wantVersion: "22.2R1",
			wantModel:   "SRX1500",
			wantJWeb:    true,
		},
		{
			name:        "Shodan Vector 3: SRX345 with Junos Server header",
			description: "Juniper SRX345 branch office firewall detected via Server header",
			statusCode:  302,
			headers: http.Header{
				"Server":       []string{"Junos Webserver"},
				"Location":     []string{"/jweb/"},
				"Content-Type": []string{"text/html"},
			},
			body: `<html><body>You are being <a href="/jweb/">redirected</a>.</body></html>`,
			wantTech: "juniper-srx",
			wantJWeb: true,
		},
		{
			name:        "Shodan Vector 4: SRX4600 cluster with Dynamic VPN",
			description: "High-end SRX4600 in cluster mode with Dynamic VPN portal",
			statusCode:  200,
			headers: http.Header{
				"X-Juniper-Version": []string{"23.1R1-S1"},
				"Content-Type":      []string{"text/html"},
			},
			body: `<!DOCTYPE html>
<html><head><title>J-Web</title></head>
<body>
<div class="jweb-dashboard">
<h1>Juniper Networks SRX4600</h1>
<p>Cluster Status: node0 primary, node1 secondary</p>
<div class="dynamic-vpn-portal">
<h2>Dynamic VPN Client Download</h2>
<a href="/dynamicvpn/client.exe">Download VPN Client</a>
</div></div></body></html>`,
			wantTech:    "juniper-srx",
			wantVersion: "23.1R1-S1",
			wantJWeb:    true,
		},
		{
			name:        "Shodan Vector 5a: Real J-Web SRX345 login page (103.233.58.86 pattern)",
			description: "Juniper SRX345 with Embedthis-Appweb server, real device pattern",
			statusCode:  200,
			headers: http.Header{
				"Server":        []string{"Embedthis-Appweb/3.2.3"},
				"Cache-Control": []string{"no-cache"},
				"Content-Type":  []string{"text/html"},
			},
			body: `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html><head>
<meta http-equiv="Content-Type" content="text/html"/>
<style id="antiClickjack">body{display:none !important;}</style>
<link rel="stylesheet" href="/stylesheet/juniper.css" type="text/css"/>
<title>Log In - Juniper Web Device Manager</title>
</head><body id='loginbody'>
<div class="jweb-title uppercase"> - srx345-dc</div>
<script>var modelphpStr = "srx345-dc";var useKey = "1";</script>
</body></html>`,
			wantTech: "juniper-srx",
			wantJWeb: true,
		},
		{
			name:        "Shodan Vector 5: Junos REST API XML on /api/ endpoint",
			description: "SRX550M with exposed REST API returning rpc-reply XML with version",
			statusCode:  200,
			headers: http.Header{
				"Content-Type":              []string{"application/xml; charset=utf-8"},
				"Strict-Transport-Security": []string{"max-age=31536000"},
			},
			body: `<?xml version="1.0" encoding="UTF-8"?>
<rpc-reply xmlns:junos="http://xml.juniper.net/junos/20.4R3-S9.2/junos">
<software-information>
<host-name>srx-edge-gw</host-name>
<product-model>SRX550M</product-model>
<junos:version>20.4R3-S9.2</junos:version>
<package-information>
<name>junos</name>
<comment>JUNOS Software Release [20.4R3-S9.2]</comment>
</package-information>
</software-information>
</rpc-reply>`,
			wantTech:    "juniper-srx",
			wantVersion: "20.4R3-S9.2",
			wantModel:   "SRX550M",
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

			if tt.wantModel != "" {
				if model, ok := result.Metadata["model"]; ok {
					if model != tt.wantModel {
						t.Errorf("model = %q, want %q", model, tt.wantModel)
					}
				} else {
					t.Errorf("model not in metadata for: %s", tt.description)
				}
			}

			if tt.wantJWeb {
				if jweb, ok := result.Metadata["jweb"]; !ok || jweb != true {
					t.Errorf("jweb not detected for: %s", tt.description)
				}
			}
		})
	}
}
