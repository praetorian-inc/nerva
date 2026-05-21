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
	"net/url"
	"testing"
)

// goAnywhereLoginPage is a realistic GoAnywhere MFT login page body used across
// multiple tests. Version 7.4.1 is extracted from the "Version 7.4.1" footer div.
const goAnywhereLoginPage = `<!DOCTYPE html>
<html>
<head><title>GoAnywhere</title>
<link rel="stylesheet" href="/goanywhere/css/login.css">
</head>
<body>
<div class="login-container">
<img src="/goanywhere/images/logo.png" alt="GoAnywhere MFT">
<h1>GoAnywhere MFT</h1>
<form action="/goanywhere/auth" method="post">
<input type="text" name="username" placeholder="Username">
<input type="password" name="password" placeholder="Password">
<input type="submit" value="Sign In">
</form>
<div class="version-info">Version 7.4.1</div>
</div>
</body>
</html>`

// ── Name / ProbeEndpoint ───────────────────────────────────────────────────────

func TestGoAnywhereFingerprinter_Name(t *testing.T) {
	fp := &GoAnywhereFingerprinter{}
	if got := fp.Name(); got != "goanywhere" {
		t.Errorf("Name() = %q, want %q", got, "goanywhere")
	}
}

func TestGoAnywhereFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &GoAnywhereFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/goanywhere/" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/goanywhere/")
	}
}

// ── Match ──────────────────────────────────────────────────────────────────────

func TestGoAnywhereFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 text/html passes",
			statusCode:  200,
			contentType: "text/html; charset=UTF-8",
			want:        true,
		},
		{
			name:        "302 redirect text/html passes",
			statusCode:  302,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "404 text/html passes (still in 200-499 range)",
			statusCode:  404,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "499 text/html passes (upper boundary of accepted range)",
			statusCode:  499,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "200 application/json rejected (not HTML)",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "100 Informational rejected",
			statusCode:  100,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "500 Internal Server Error rejected",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "503 Service Unavailable rejected",
			statusCode:  503,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "200 no Content-Type rejected",
			statusCode:  200,
			contentType: "",
			want:        false,
		},
		{
			name:        "200 text/plain rejected",
			statusCode:  200,
			contentType: "text/plain",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GoAnywhereFingerprinter{}
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

// ── Fingerprint: positive (valid) ─────────────────────────────────────────────

func TestGoAnywhereFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		body          string
		probePath     string // if set, inject into resp.Request.URL.Path
		wantVersion   string
		wantCPE       string
		wantDetection string
		wantProbePath bool
	}{
		{
			name:          "Login page with version in footer (generic version label)",
			statusCode:    200,
			body:          goAnywhereLoginPage,
			wantVersion:   "7.4.1",
			wantCPE:       "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:7.4.1:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "Title-only detection — title contains GoAnywhere but no version",
			statusCode: 200,
			body: `<!DOCTYPE html>
<html>
<head><title>GoAnywhere</title></head>
<body><p>Login required.</p></body>
</html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:          "Active probe — path /goanywhere/ sets detection_method and probe_path",
			statusCode:    200,
			body:          goAnywhereLoginPage,
			probePath:     "/goanywhere/",
			wantVersion:   "7.4.1",
			wantCPE:       "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:7.4.1:*:*:*:*:*:*:*",
			wantDetection: "active_probe",
			wantProbePath: true,
		},
		{
			name:       "Version extracted via GoAnywhere product string pattern",
			statusCode: 200,
			body: `<html><head><title>GoAnywhere MFT</title></head>
<body><p>GoAnywhere MFT v7.1.3</p></body></html>`,
			wantVersion:   "7.1.3",
			wantCPE:       "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:7.1.3:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "Brand in body with GoAnywhere MFT product string (secondary signal)",
			statusCode: 200,
			body:       `<html><head><title>Login</title></head><body><p>Welcome to GoAnywhere MFT</p></body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "Brand in body with Fortra vendor name (secondary signal)",
			statusCode: 200,
			body:       `<html><head><title>Login</title></head><body><p>GoAnywhere - A Fortra Product</p></body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "Title with GoAnywhere MFT branding",
			statusCode: 200,
			body: `<html><head><title>GoAnywhere MFT</title></head>
<body></body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "GoAnywhere product string without v prefix",
			statusCode: 200,
			body: `<html><head><title>GoAnywhere</title></head>
<body><span>GoAnywhere MFT 6.8.0</span></body></html>`,
			wantVersion:   "6.8.0",
			wantCPE:       "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:6.8.0:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GoAnywhereFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.probePath != "" {
				resp.Request = &http.Request{URL: &url.URL{Path: tt.probePath}}
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want non-nil result")
			}

			if result.Technology != "goanywhere" {
				t.Errorf("Technology = %q, want %q", result.Technology, "goanywhere")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			} else if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], tt.wantCPE)
			}
			if result.Metadata == nil {
				t.Fatal("Metadata is nil")
			}

			if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != tt.wantDetection {
				t.Errorf("Metadata[detection_method] = %v, want %q", result.Metadata["detection_method"], tt.wantDetection)
			}

			if tt.wantProbePath {
				if pp, ok := result.Metadata["probe_path"].(string); !ok || pp != "/goanywhere/" {
					t.Errorf("Metadata[probe_path] = %v, want %q", result.Metadata["probe_path"], "/goanywhere/")
				}
			} else {
				if _, ok := result.Metadata["probe_path"]; ok {
					t.Errorf("Metadata[probe_path] should be absent for non-active-probe responses, got %v", result.Metadata["probe_path"])
				}
			}
		})
	}
}

// ── Fingerprint: negative (invalid — must return nil) ─────────────────────────

func TestGoAnywhereFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "Empty body returns nil",
			statusCode: 200,
			body:       "",
		},
		{
			name:       "Non-GoAnywhere page (Okta)",
			statusCode: 200,
			body:       `<html><head><title>Okta Sign-In</title></head><body></body></html>`,
		},
		{
			name:       "Body length > 2 MiB is rejected",
			statusCode: 200,
			body:       "goanywhere" + string(make([]byte, 2*1024*1024+1)),
		},
		{
			name:       "CPE-injection attempt (contains :*:)",
			statusCode: 200,
			body:       `<html><head><title>GoAnywhere</title></head><body>GoAnywhere MFT v7.4.1:*:malicious</body></html>`,
		},
		{
			name:       "Status 500 rejected even with GoAnywhere content",
			statusCode: 500,
			body:       `<html><head><title>GoAnywhere</title></head><body></body></html>`,
		},
		{
			name:       "Status 503 rejected even with GoAnywhere content",
			statusCode: 503,
			body:       goAnywhereLoginPage,
		},
		{
			name:       "Generic file transfer page without GoAnywhere brand",
			statusCode: 200,
			body:       `<html><head><title>Secure File Transfer</title></head><body><p>Upload your files</p></body></html>`,
		},
		{
			name:       "Jenkins login page",
			statusCode: 200,
			body:       `<html><head><title>Sign in [Jenkins]</title></head><body></body></html>`,
		},
		{
			name:       "Page with 'go' and 'anywhere' separately — not a brand match",
			statusCode: 200,
			body:       `<html><head><title>Go here, go anywhere</title></head><body><p>Go anywhere with us!</p></body></html>`,
		},
		{
			name:       "Brand token in body without secondary signal (bare mention)",
			statusCode: 200,
			body:       `<html><head><title>Login</title></head><body><p>Powered by GoAnywhere</p></body></html>`,
		},
		{
			name:       "Jenkins 403 redirect with URL-encoded probe path",
			statusCode: 403,
			body:       `<html><head><meta http-equiv='refresh' content='1;url=/login?from=%2Fgoanywhere%2F'/></head><body><p>Authentication required</p></body></html>`,
		},
		{
			name:       "Resin 404 with reflected probe path",
			statusCode: 404,
			body:       `<html><body><h1>404 Not Found</h1><p>/goanywhere/ was not found on this server.</p></body></html>`,
		},
		{
			name:       "Express reflected probe path in error body",
			statusCode: 404,
			body:       `<!DOCTYPE html><html><body>Cannot GET /goanywhere/</body></html>`,
		},
		{
			name:       "MFT comparison page with goanywhere mention (no product-specific secondary signal)",
			statusCode: 200,
			body:       `<html><head><title>Managed File Transfer Comparison</title></head><body><p>GoAnywhere is one solution in the managed file transfer space.</p></body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GoAnywhereFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
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

// ── TestExtractGoAnywhereVersion ──────────────────────────────────────────────

func TestExtractGoAnywhereVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "GoAnywhere product string with v prefix",
			body: `<p>GoAnywhere MFT v7.1.3</p>`,
			want: "7.1.3",
		},
		{
			name: "GoAnywhere product string without v prefix",
			body: `<span>GoAnywhere MFT 6.8.0</span>`,
			want: "6.8.0",
		},
		{
			name: "Generic Version label in footer",
			body: `<div class="version-info">Version 7.4.1</div>`,
			want: "7.4.1",
		},
		{
			name: "Generic Version with colon",
			body: `<span>Version: 7.2.0</span>`,
			want: "7.2.0",
		},
		{
			name: "GoAnywhere product string takes priority over generic version label",
			body: `<p>GoAnywhere MFT v7.1.3</p><div>Version 9.9.9</div>`,
			want: "7.1.3",
		},
		{
			name: "No version in body",
			body: `<html><head><title>GoAnywhere</title></head><body></body></html>`,
			want: "",
		},
		{
			name: "Version regex captures digit prefix from alpha-suffix string",
			// The version regex matches \d+\.\d+\.\d+ and stops before '-'; so
			// "Version: 7.4.1-beta" yields capture group "7.4.1" which passes the
			// validator. This mirrors the ScreenConnect extraction behavior.
			body: `<p>Version: 7.4.1-beta</p>`,
			want: "7.4.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractGoAnywhereVersion([]byte(tt.body)); got != tt.want {
				t.Errorf("extractGoAnywhereVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ── TestBuildGoAnywhereCPE ─────────────────────────────────────────────────────

func TestBuildGoAnywhereCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Version 7.4.1",
			version: "7.4.1",
			want:    "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:7.4.1:*:*:*:*:*:*:*",
		},
		{
			name:    "Version 7.1.3",
			version: "7.1.3",
			want:    "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:7.1.3:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Four-component version",
			version: "7.4.1.2",
			want:    "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:7.4.1.2:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildGoAnywhereCPE(tt.version); got != tt.want {
				t.Errorf("buildGoAnywhereCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// ── TestGoAnywhereVersionValidation ───────────────────────────────────────────

func TestGoAnywhereVersionValidation(t *testing.T) {
	tests := []struct {
		version string
		valid   bool
	}{
		{"7.4.1", true},
		{"7.1.3", true},
		{"6.8.0", true},
		{"10.0.1", true},
		{"7.4.1.2", true},
		{"7.4.1.2.0", true},
		{"7.4.1-beta", false},
		{"7.4.1:*:", false},
		{"abc", false},
		{"", false},
		{".1", false},
		{"..", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := goanywhereVersionValidateRegex.MatchString(tt.version)
			if got != tt.valid {
				t.Errorf("goanywhereVersionValidateRegex.MatchString(%q) = %v, want %v", tt.version, got, tt.valid)
			}
		})
	}
}

// ── Integration test ──────────────────────────────────────────────────────────

func TestGoAnywhereFingerprinter_Integration(t *testing.T) {
	// Save and restore global state to prevent test pollution.
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &GoAnywhereFingerprinter{}
	Register(fp)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html; charset=UTF-8")

	results := RunFingerprinters(resp, []byte(goAnywhereLoginPage))

	found := false
	for _, result := range results {
		if result.Technology == "goanywhere" {
			found = true
			if result.Version != "7.4.1" {
				t.Errorf("Version = %q, want %q", result.Version, "7.4.1")
			}
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			} else if result.CPEs[0] != "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:7.4.1:*:*:*:*:*:*:*" {
				t.Errorf("CPE = %q, want canonical CPE", result.CPEs[0])
			}
			if v, ok := result.Metadata["vendor"].(string); !ok || v != "Fortra" {
				t.Errorf("Metadata[vendor] = %v, want Fortra", result.Metadata["vendor"])
			}
			if v, ok := result.Metadata["product"].(string); !ok || v != "GoAnywhere MFT" {
				t.Errorf("Metadata[product] = %v, want GoAnywhere MFT", result.Metadata["product"])
			}
		}
	}

	if !found {
		t.Error("GoAnywhereFingerprinter not found in RunFingerprinters results")
	}
}
