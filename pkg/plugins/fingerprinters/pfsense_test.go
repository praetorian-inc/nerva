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

func TestPfSenseFingerprinter_Name(t *testing.T) {
	f := &PfSenseFingerprinter{}
	if name := f.Name(); name != "pfsense" {
		t.Errorf("Name() = %q, expected %q", name, "pfsense")
	}
}

func TestPfSenseFingerprinter_Match(t *testing.T) {
	f := &PfSenseFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{
			name:       "matches 200 OK",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "does not match 302 redirect",
			statusCode: 302,
			want:       false,
		},
		{
			name:       "does not match 401 unauthorized",
			statusCode: 401,
			want:       false,
		},
		{
			name:       "does not match 403 forbidden",
			statusCode: 403,
			want:       false,
		},
		{
			name:       "does not match 404 not found",
			statusCode: 404,
			want:       false,
		},
		{
			name:       "does not match 500 server error",
			statusCode: 500,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     http.Header{},
			}
			if got := f.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPfSenseFingerprinter_Fingerprint(t *testing.T) {
	f := &PfSenseFingerprinter{}

	tests := []struct {
		name          string
		statusCode    int
		headers       http.Header
		body          string
		wantResult    bool
		wantTech      string
		wantVersion   string
		wantCPEPrefix string
		wantEdition   string
		wantHostname  string
		wantTheme     string
	}{
		{
			name:       "detects pfSense with all markers (primary + secondary + CE logo)",
			statusCode: 200,
			headers:    http.Header{},
			body: `<!DOCTYPE html>
<html><head><title>pfSense - Login</title>
<script src="/vendor/jquery/jquery-3.7.1.min.js"></script>
</head><body>
<div id="pfsense-logo-svg"><svg viewBox="0 0 282.8 84.2">
<path class="logo-st0"/><path class="logo-st1"/><path class="logo-st2"/>
</svg></div>
<form method="post" action="/index.php">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult:    true,
			wantTech:      "pfsense",
			wantVersion:   "2.7.x+",
			wantCPEPrefix: "cpe:2.3:a:netgate:pfsense:2.7.x+",
			wantEdition:   "CE",
		},
		{
			name:       "detects pfSense with primary markers only (usernamefld + passwordfld)",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><body>
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult: true,
			wantTech:   "pfsense",
		},
		{
			name:       "detects pfSense with secondary marker only (pfsense-logo-svg)",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><body>
<div id="pfsense-logo-svg"><svg></svg></div>
<form method="post">
<input name="username" type="text">
<input name="password" type="password">
</form></body></html>`,
			wantResult: true,
			wantTech:   "pfsense",
		},
		{
			name:       "returns nil for generic login page with no pfSense markers",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><body>
<form method="post" action="/login">
<input name="username" type="text">
<input name="password" type="password">
</form></body></html>`,
			wantResult: false,
		},
		{
			name:       "returns nil for partial primary match (only usernamefld, no passwordfld)",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><body>
<form method="post">
<input name="usernamefld" type="text">
<input name="pass" type="password">
</form></body></html>`,
			wantResult: false,
		},
		{
			name:       "extracts custom hostname from title",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><head><title>firewall01 - Login</title></head>
<body>
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult:   true,
			wantTech:     "pfsense",
			wantHostname: "firewall01",
		},
		{
			name:       "skips hostname when title is default pfSense - Login",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><head><title>pfSense - Login</title></head>
<body>
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult:   true,
			wantTech:     "pfsense",
			wantHostname: "", // should not be set
		},
		{
			name:       "version pre-2.3 from lighttpd Server header",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"lighttpd/1.4.35"},
			},
			body: `<html><body>
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult:    true,
			wantTech:      "pfsense",
			wantVersion:   "pre-2.3",
			wantCPEPrefix: "cpe:2.3:a:netgate:pfsense:pre-2.3",
		},
		{
			name:       "no version from nginx Server header (jQuery not present)",
			statusCode: 200,
			headers: http.Header{
				"Server": []string{"nginx"},
			},
			body: `<html><body>
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult:  true,
			wantTech:    "pfsense",
			wantVersion: "", // nginx alone does not determine version
		},
		{
			name:       "jQuery 3.7.1 maps to pfSense 2.7.x+",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><head>
<script src="/vendor/jquery/jquery-3.7.1.min.js"></script>
</head><body>
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult:    true,
			wantTech:      "pfsense",
			wantVersion:   "2.7.x+",
			wantCPEPrefix: "cpe:2.3:a:netgate:pfsense:2.7.x+",
		},
		{
			name:       "jQuery 3.5.1 maps to pfSense 2.5.x-2.6.x",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><head>
<script src="/vendor/jquery/jquery-3.5.1.min.js"></script>
</head><body>
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult:  true,
			wantTech:    "pfsense",
			wantVersion: "2.5.x-2.6.x",
		},
		{
			name:       "CE SVG viewBox and CSS classes indicate CE edition",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><body>
<div id="pfsense-logo-svg">
<svg viewBox="0 0 282.8 84.2">
<path class="logo-st0"/><path class="logo-st1"/><path class="logo-st2"/>
</svg>
</div>
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult:  true,
			wantTech:    "pfsense",
			wantEdition: "CE",
		},
		{
			name:       "no CE markers means edition is not set",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><body>
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult:  true,
			wantTech:    "pfsense",
			wantEdition: "", // no CE markers
		},
		{
			name:       "CPE uses version when available",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><head>
<script src="/vendor/jquery/jquery-3.3.1.min.js"></script>
</head><body>
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult:    true,
			wantTech:      "pfsense",
			wantVersion:   "2.4.x",
			wantCPEPrefix: "cpe:2.3:a:netgate:pfsense:2.4.x",
		},
		{
			name:       "CPE uses wildcard when no version available",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><body>
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult:    true,
			wantTech:      "pfsense",
			wantCPEPrefix: "cpe:2.3:a:netgate:pfsense:*",
		},
		{
			name:       "returns nil for non-200 response even with pfSense body",
			statusCode: 302,
			headers:    http.Header{},
			body: `<html><body>
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult: false,
		},
		{
			name:       "Community Edition text triggers CE edition",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><body>
<p>pfSense Community Edition</p>
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form></body></html>`,
			wantResult:  true,
			wantTech:    "pfsense",
			wantEdition: "CE",
		},
		{
			name:       "pagebody background color populates theme metadata",
			statusCode: 200,
			headers:    http.Header{},
			body: `<html><body>
<div style="background: #1e3f75;" class="pagebody">
<form method="post">
<input name="usernamefld" type="text">
<input name="passwordfld" type="password">
</form>
</div></body></html>`,
			wantResult: true,
			wantTech:   "pfsense",
			wantTheme:  "pfSense",
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

			if tt.wantCPEPrefix != "" && len(result.CPEs) > 0 {
				cpe := result.CPEs[0]
				if len(cpe) < len(tt.wantCPEPrefix) || cpe[:len(tt.wantCPEPrefix)] != tt.wantCPEPrefix {
					t.Errorf("CPE = %q, want prefix %q", cpe, tt.wantCPEPrefix)
				}
			}

			if tt.wantEdition != "" {
				edition, _ := result.Metadata["edition"]
				if edition != tt.wantEdition {
					t.Errorf("edition = %q, want %q", edition, tt.wantEdition)
				}
			}

			if tt.wantEdition == "" {
				if edition, ok := result.Metadata["edition"]; ok && edition != "" {
					t.Errorf("edition = %q, expected not set or empty", edition)
				}
			}

			if tt.wantHostname != "" {
				hostname, _ := result.Metadata["hostname"]
				if hostname != tt.wantHostname {
					t.Errorf("hostname = %q, want %q", hostname, tt.wantHostname)
				}
			}

			if tt.wantHostname == "" {
				if hostname, ok := result.Metadata["hostname"]; ok && hostname != "" {
					t.Errorf("hostname = %q, expected not set", hostname)
				}
			}

			if tt.wantTheme != "" {
				theme, _ := result.Metadata["theme"]
				if theme != tt.wantTheme {
					t.Errorf("theme = %q, want %q", theme, tt.wantTheme)
				}
			}
		})
	}
}

func TestBuildPfSenseCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "2.7.x+",
			want:    "cpe:2.3:a:netgate:pfsense:2.7.x+:*:*:*:*:*:*:*",
		},
		{
			version: "2.4.x",
			want:    "cpe:2.3:a:netgate:pfsense:2.4.x:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:a:netgate:pfsense:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildPfSenseCPE(tt.version); got != tt.want {
				t.Errorf("buildPfSenseCPE() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestExtractPfSenseVersion(t *testing.T) {
	tests := []struct {
		name       string
		body       string
		serverInfo string
		want       string
	}{
		{
			name: "jQuery 3.7.1 → 2.7.x+",
			body: `<script src="/vendor/jquery/jquery-3.7.1.min.js"></script>`,
			want: "2.7.x+",
		},
		{
			name: "jQuery 3.5.1 → 2.5.x-2.6.x",
			body: `<script src="jquery-3.5.1.min.js"></script>`,
			want: "2.5.x-2.6.x",
		},
		{
			name: "jQuery 3.4.1 → 2.4.5-2.5.x",
			body: `<script src="jquery-3.4.1.min.js"></script>`,
			want: "2.4.5-2.5.x",
		},
		{
			name: "jQuery 3.3.1 → 2.4.x",
			body: `<script src="jquery-3.3.1.min.js"></script>`,
			want: "2.4.x",
		},
		{
			name: "jQuery 1.12.4 → 2.3.x",
			body: `<script src="jquery-1.12.4.min.js"></script>`,
			want: "2.3.x",
		},
		{
			name: "jQuery 1.11.1 → 2.2.x",
			body: `<script src="jquery-1.11.1.min.js"></script>`,
			want: "2.2.x",
		},
		{
			name:       "lighttpd Server header → pre-2.3",
			body:       "",
			serverInfo: "lighttpd/1.4.35",
			want:       "pre-2.3",
		},
		{
			name:       "nginx Server header → empty (cannot determine version)",
			body:       "",
			serverInfo: "nginx",
			want:       "",
		},
		{
			name: "jQuery takes priority over Server header",
			body: `<script src="jquery-3.7.1.min.js"></script>`,
			serverInfo: "lighttpd/1.4.35",
			want: "2.7.x+",
		},
		{
			name:       "unknown jQuery version → falls back to Server header",
			body:       `<script src="jquery-2.0.0.min.js"></script>`,
			serverInfo: "lighttpd/1.4.35",
			want:       "pre-2.3",
		},
		{
			name: "no version indicators → empty",
			body: "<html><body>Login</body></html>",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPfSenseVersion(tt.body, tt.serverInfo)
			if got != tt.want {
				t.Errorf("extractPfSenseVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractPfSenseHostname(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "extracts custom hostname",
			body: "<html><head><title>firewall01 - Login</title></head></html>",
			want: "firewall01",
		},
		{
			name: "returns empty for default pfSense - Login title",
			body: "<html><head><title>pfSense - Login</title></head></html>",
			want: "",
		},
		{
			name: "returns empty when title has no Login suffix",
			body: "<html><head><title>My Firewall</title></head></html>",
			want: "",
		},
		{
			name: "returns empty when no title tag",
			body: "<html><body>Login</body></html>",
			want: "",
		},
		{
			name: "case-insensitive pfSense check",
			body: "<html><head><title>PFSENSE - Login</title></head></html>",
			want: "",
		},
		{
			name: "handles whitespace around prefix",
			body: "<html><head><title>  router1  - Login</title></head></html>",
			want: "router1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPfSenseHostname(tt.body)
			if got != tt.want {
				t.Errorf("extractPfSenseHostname() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExtractPfSenseTheme(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "default theme color #1e3f75 maps to pfSense",
			body: `<div style="background: #1e3f75;" class="pagebody">`,
			want: "pfSense",
		},
		{
			name: "dark theme color #212121 maps to pfSense-dark",
			body: `<div style="background: #212121;" class="pagebody">`,
			want: "pfSense-dark",
		},
		{
			name: "unknown color preserved as raw value",
			body: `<div style="background: #ff0000;" class="pagebody">`,
			want: "#ff0000",
		},
		{
			name: "no pagebody div returns empty string",
			body: `<div style="background: #1e3f75;" class="otherdiv">`,
			want: "",
		},
		{
			name: "no background style returns empty string",
			body: `<div class="pagebody">`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractPfSenseTheme(tt.body)
			if got != tt.want {
				t.Errorf("extractPfSenseTheme() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsPfSenseCE(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "CE viewBox present",
			body: `<svg viewBox="0 0 282.8 84.2">`,
			want: true,
		},
		{
			name: "CE CSS classes present",
			body: `<path class="logo-st0"/><path class="logo-st1"/><path class="logo-st2"/>`,
			want: true,
		},
		{
			name: "Community Edition text present",
			body: `<p>pfSense Community Edition</p>`,
			want: true,
		},
		{
			name: "no CE markers",
			body: `<html><body><form><input name="usernamefld"></form></body></html>`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isPfSenseCE(tt.body)
			if got != tt.want {
				t.Errorf("isPfSenseCE() = %v, want %v", got, tt.want)
			}
		})
	}
}
