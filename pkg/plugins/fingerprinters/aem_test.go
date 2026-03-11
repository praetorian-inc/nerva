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

func TestAEMFingerprinter_Name(t *testing.T) {
	fp := &AEMFingerprinter{}
	if got := fp.Name(); got != "adobe_experience_manager" {
		t.Errorf("Name() = %q, want %q", got, "adobe_experience_manager")
	}
}

func TestAEMFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &AEMFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/libs/granite/core/content/login.html" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/libs/granite/core/content/login.html")
	}
}

func TestAEMFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		headers     map[string]string
		want        bool
	}{
		{
			name:    "Server: Day-Servlet-Engine returns true",
			headers: map[string]string{"Server": "Day-Servlet-Engine/4.1.22"},
			want:    true,
		},
		{
			name:    "X-Powered-By: Day CQ returns true",
			headers: map[string]string{"X-Powered-By": "Day CQ/5.4"},
			want:    true,
		},
		{
			name:    "X-Powered-By: Communique returns true",
			headers: map[string]string{"X-Powered-By": "Communique/5.3"},
			want:    true,
		},
		{
			name:    "X-Powered-By: Adobe Experience Manager returns true",
			headers: map[string]string{"X-Powered-By": "Adobe Experience Manager/6.5"},
			want:    true,
		},
		{
			name:    "Dispatcher header present returns true",
			headers: map[string]string{"Dispatcher": "1.0"},
			want:    true,
		},
		{
			name:    "Content-Type: text/html returns true",
			headers: map[string]string{"Content-Type": "text/html; charset=utf-8"},
			want:    true,
		},
		{
			name:    "Content-Type: application/json returns false",
			headers: map[string]string{"Content-Type": "application/json"},
			want:    false,
		},
		{
			name:    "No headers returns false",
			headers: map[string]string{},
			want:    false,
		},
		{
			name:    "Unrelated Server header returns false",
			headers: map[string]string{"Server": "nginx/1.24.0", "Content-Type": "application/json"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AEMFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}

			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestAEMFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		headers        map[string]string
		wantVersion    string
		wantDispatcher bool
		wantNilResult  bool
	}{
		{
			name: "AEM login page with granite.version meta tag",
			body: `<!DOCTYPE html>
<html>
<head>
<meta name="granite.version" content="6.5.21.0">
<title>AEM Sign In</title>
</head>
<body>
<div class="granite-login">Adobe Experience Manager</div>
</body>
</html>`,
			headers:     map[string]string{"Content-Type": "text/html"},
			wantVersion: "6.5.21.0",
		},
		{
			name: "AEM login page with AEM version in body",
			body: `<!DOCTYPE html>
<html>
<head><title>AEM Sign In</title></head>
<body>
<p>AEM 6.5 - granite/core/content/login</p>
<form class="cq-login-form"></form>
</body>
</html>`,
			headers:     map[string]string{"Content-Type": "text/html"},
			wantVersion: "6.5",
		},
		{
			name: "AEM login page without version",
			body: `<!DOCTYPE html>
<html>
<head><title>Sign In</title></head>
<body>
<div class="granite-login">Adobe Experience Manager</div>
</body>
</html>`,
			headers:     map[string]string{"Content-Type": "text/html"},
			wantVersion: "*",
		},
		{
			name: "AEM detected via Day-Servlet-Engine Server header (no body markers)",
			body: `<html><head><title>Custom Login</title></head><body></body></html>`,
			headers: map[string]string{
				"Server":       "Day-Servlet-Engine",
				"Content-Type": "text/html",
			},
			wantVersion: "*",
		},
		{
			name: "AEM with dispatcher header",
			body: `<!DOCTYPE html>
<html>
<body>
<div class="granite-login">Adobe Experience Manager</div>
</body>
</html>`,
			headers: map[string]string{
				"Content-Type": "text/html",
				"Dispatcher":   "1.0",
			},
			wantVersion:    "*",
			wantDispatcher: true,
		},
		{
			name: "AEM with Adobe Experience Manager version in body",
			body: `<!DOCTYPE html>
<html>
<head><title>AEM Sign In</title></head>
<body>
<p>Adobe Experience Manager 6.5.0 - granite/core/content/login</p>
</body>
</html>`,
			headers:     map[string]string{"Content-Type": "text/html"},
			wantVersion: "6.5.0",
		},
		{
			name: "AEM with version in Server header only",
			body: `<html><head></head><body>
<div class="granite-login">Welcome</div>
</body></html>`,
			headers: map[string]string{
				"Server":       "Day-Servlet-Engine/4.1.22 AEM/6.4",
				"Content-Type": "text/html",
			},
			wantVersion: "6.4",
		},
		{
			name: "AEM with only servlet version in Server header (no AEM/ prefix)",
			body: `<html><head></head><body>
<div class="granite-login">Welcome</div>
</body></html>`,
			headers: map[string]string{
				"Server":       "Day-Servlet-Engine/4.1.22",
				"Content-Type": "text/html",
			},
			wantVersion: "4.1.22",
		},
		{
			name: "AEM Assets Brand Portal with CSS rgba should not extract false version",
			body: `<!DOCTYPE html>
<html>
<head><title>AEM Sign In</title></head>
<body>
<div class="granite-login">AEM Assets Brand Portal</div>
<style>
.overlay { background: rgba(0,0,0,0.8); }
</style>
</body>
</html>`,
			headers:     map[string]string{"Content-Type": "text/html"},
			wantVersion: "*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AEMFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}

			if tt.wantNilResult {
				if result != nil {
					t.Errorf("Fingerprint() = %+v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Fingerprint() returned nil, want result")
			}

			if result.Technology != "adobe_experience_manager" {
				t.Errorf("Technology = %q, want %q", result.Technology, "adobe_experience_manager")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) != 1 {
				t.Errorf("CPEs count = %d, want 1", len(result.CPEs))
			}

			dispatcher, ok := result.Metadata["dispatcher"].(bool)
			if !ok {
				t.Error("Metadata dispatcher is not a bool")
			} else if dispatcher != tt.wantDispatcher {
				t.Errorf("Metadata dispatcher = %v, want %v", dispatcher, tt.wantDispatcher)
			}
		})
	}
}

func TestAEMFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		headers map[string]string
	}{
		{
			name:    "Non-AEM HTML page",
			body:    `<html><head><title>Welcome to nginx</title></head><body><h1>Welcome</h1></body></html>`,
			headers: map[string]string{"Content-Type": "text/html"},
		},
		{
			name:    "Empty body",
			body:    ``,
			headers: map[string]string{"Content-Type": "text/html"},
		},
		{
			name:    "Random JSON response",
			body:    `{"status":"ok","message":"hello world"}`,
			headers: map[string]string{"Content-Type": "application/json"},
		},
		{
			name:    "WordPress login page",
			body:    `<html><head><title>Log In - WordPress</title></head><body><form id="loginform"><input name="log"></form></body></html>`,
			headers: map[string]string{"Content-Type": "text/html"},
		},
		{
			name:    "Plain text response",
			body:    `This is just a plain text response with no AEM markers`,
			headers: map[string]string{"Content-Type": "text/plain"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AEMFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v, want nil", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil for non-AEM input", result)
			}
		})
	}
}

func TestBuildAEMCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Full version 6.5.21.0",
			version: "6.5.21.0",
			want:    "cpe:2.3:a:adobe:experience_manager:6.5.21.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Short version 6.5",
			version: "6.5",
			want:    "cpe:2.3:a:adobe:experience_manager:6.5:*:*:*:*:*:*:*",
		},
		{
			name:    "Three-part version 6.5.0",
			version: "6.5.0",
			want:    "cpe:2.3:a:adobe:experience_manager:6.5.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Wildcard version",
			version: "*",
			want:    "cpe:2.3:a:adobe:experience_manager:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:adobe:experience_manager:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildAEMCPE(tt.version); got != tt.want {
				t.Errorf("buildAEMCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}
