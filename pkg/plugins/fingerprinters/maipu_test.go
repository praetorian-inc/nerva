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

// realMaipuLoginHTML is a representative sample of a real Maipu login page
// containing all 6 scoring indicators (maipu.com, form endpoints, CSS paths, i18n).
const realMaipuLoginHTML = `<!DOCTYPE html>
<html>
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title data-i18n="loginPageTitle"></title>
    <link rel="stylesheet" type="text/css" href="/assets/css/login.css" />
    <link rel="stylesheet" type="text/css" href="/assets/css/ui-dialog.css" />
</head>
<body>
<div>
    <div class="main">
        <div class="pub-width btn">
            <input type="submit" id="loginBtn" value="登录" data-i18n="login" />
        </div>
    </div>
</div>
<div class="copyright">
    <!-- Copyright &copy; 2014 Maipu Communication Technology Co., Ltd. All Rights Reserved. -->
</div>
<script>
function loadVersion(){
    $.get('/form/formDeviceVerGet', function(data){
        var regHardware = /Hardware\s+Model\s*:\s*(\S+)\(\S+\)?\s*with/g;
    });
}
function checkForm(){
    $("#loginform").attr("action","/form/formUserLogin");
    return true;
}
</script>
<label data-i18n="website"></label>http://www.maipu.com
<label data-i18n="mail"></label>support@maipu.com
</body>
</html>`

func TestMaipuFingerprinter_Name(t *testing.T) {
	fp := &MaipuFingerprinter{}
	if got := fp.Name(); got != "maipu-network-device" {
		t.Errorf("Name() = %q, want %q", got, "maipu-network-device")
	}
}

func TestMaipuFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 OK with text/html",
			statusCode:  200,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "200 OK with text/html; charset=utf-8",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 OK with no Content-Type (default to text/html)",
			statusCode:  200,
			contentType: "",
			want:        true,
		},
		{
			name:        "302 redirect",
			statusCode:  302,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "304 Not Modified",
			statusCode:  304,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "401 Unauthorized",
			statusCode:  401,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "404 Not Found",
			statusCode:  404,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "500 Server Error",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "200 OK with application/json",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MaipuFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}

			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMaipuFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		wantTech     string
		wantVersion  string
		scoreAtLeast int // minimum score required
	}{
		{
			name:         "Real Maipu login page (all indicators)",
			body:         realMaipuLoginHTML,
			wantTech:     "maipu-network-device",
			wantVersion:  "",
			scoreAtLeast: 3, // Should have maipu.com + forms + CSS = 5 points
		},
		{
			name: "Maipu domain + form endpoints (4 points)",
			body: `<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <form action="/form/formUserLogin">
        <input type="text" name="username" />
    </form>
    <a href="http://www.maipu.com">Maipu</a>
    <script>
        $.get('/form/formDeviceVerGet', function(data){});
    </script>
</body>
</html>`,
			wantTech:     "maipu-network-device",
			wantVersion:  "",
			scoreAtLeast: 3,
		},
		{
			name: "Maipu domain + CSS paths (3 points)",
			body: `<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="/assets/css/login.css" />
    <link rel="stylesheet" href="/assets/css/ui-dialog.css" />
</head>
<body>
    <p>Support email: support@maipu.com</p>
</body>
</html>`,
			wantTech:     "maipu-network-device",
			wantVersion:  "",
			scoreAtLeast: 3,
		},
		{
			name: "Form endpoints + CSS + i18n (4 points)",
			body: `<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="/assets/css/login.css" />
    <link rel="stylesheet" href="/assets/css/ui-dialog.css" />
</head>
<body>
    <form action="/form/formUserLogin">
        <span data-i18n="loginPageTitle"></span>
    </form>
</body>
</html>`,
			wantTech:     "maipu-network-device",
			wantVersion:  "",
			scoreAtLeast: 3,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MaipuFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check metadata
			if vendor, ok := result.Metadata["vendor"].(string); !ok || vendor != "Maipu" {
				t.Errorf("Metadata[vendor] = %v, want %v", vendor, "Maipu")
			}
			if product, ok := result.Metadata["product"].(string); !ok || product != "Network Equipment" {
				t.Errorf("Metadata[product] = %v, want %v", product, "Network Equipment")
			}

			// Check CPE format
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:h:maipu:network_device:*:*:*:*:*:*:*:*"
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestMaipuFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Generic HTML (no Maipu indicators)",
			body: `<!DOCTYPE html>
<html>
<head>
    <title>Login</title>
</head>
<body>
    <h1>Login Page</h1>
</body>
</html>`,
		},
		{
			name: "Only 1 indicator - maipu.com (2 points, below threshold)",
			body: `<!DOCTYPE html>
<html>
<body>
    <a href="http://www.maipu.com">Maipu</a>
</body>
</html>`,
		},
		{
			name: "Only 1 indicator - CSS path (1 point, below threshold)",
			body: `<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="/assets/css/login.css" />
</head>
<body>
    <h1>Login</h1>
</body>
</html>`,
		},
		{
			name: "Only 1 indicator - form endpoint (2 points, below threshold)",
			body: `<!DOCTYPE html>
<html>
<body>
    <form action="/form/formUserLogin">
        <input type="text" />
    </form>
</body>
</html>`,
		},
		{
			name: "2 indicators but below threshold (2 points)",
			body: `<!DOCTYPE html>
<html>
<head>
    <link rel="stylesheet" href="/assets/css/login.css" />
</head>
<body>
    <span data-i18n="login"></span>
</body>
</html>`,
		},
		{
			name: "Empty body",
			body: "",
		},
		{
			name: "Non-HTML body",
			body: "OK",
		},
		{
			name: "JSON body",
			body: `{"status": "ok"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MaipuFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
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

func TestBuildMaipuCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Empty version (no version available)",
			version: "",
			want:    "cpe:2.3:h:maipu:network_device:*:*:*:*:*:*:*:*",
		},
		{
			name:    "With version (hypothetical)",
			version: "5.2.1",
			want:    "cpe:2.3:h:maipu:network_device:5.2.1:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildMaipuCPE(tt.version); got != tt.want {
				t.Errorf("buildMaipuCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMaipuFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &MaipuFingerprinter{}
	Register(fp)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")

	results := RunFingerprinters(resp, []byte(realMaipuLoginHTML))

	// Should find at least the Maipu fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "maipu-network-device" {
			found = true
			if result.Version != "" {
				t.Errorf("Version = %q, want empty (version not extractable)", result.Version)
			}
			if vendor, ok := result.Metadata["vendor"].(string); !ok || vendor != "Maipu" {
				t.Errorf("Metadata[vendor] = %v, want 'Maipu'", vendor)
			}
		}
	}

	if !found {
		t.Error("MaipuFingerprinter not found in results")
	}
}
