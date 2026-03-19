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
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"
)

// --- GuacamoleFingerprinter (API languages endpoint) tests ---

func TestGuacamoleFingerprinter_Name(t *testing.T) {
	fp := &GuacamoleFingerprinter{}
	if got := fp.Name(); got != "guacamole" {
		t.Errorf("Name() = %q, want %q", got, "guacamole")
	}
}

func TestGuacamoleFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &GuacamoleFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/guacamole/api/languages" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/guacamole/api/languages")
	}
}

func TestGuacamoleFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "application/json returns true",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "application/json with charset returns true",
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "text/html returns false",
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "empty Content-Type returns false",
			contentType: "",
			want:        false,
		},
		{
			name:        "text/plain returns false",
			contentType: "text/plain",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GuacamoleFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGuacamoleFingerprinter_Fingerprint_TypicalResponse(t *testing.T) {
	// Real Guacamole 1.6.0 /api/languages response captured from Docker
	body := `{"de":"Deutsch","no":"Norsk Bokmål","ru":"Русский","ko":"한국어","pt":"Português","en":"English","it":"Italiano","fr":"Français","zh":"简体中文","es":"Spanish","cs":"Čeština","ja":"日本語","pl":"Polski","nl":"Nederlands","ca":"Catalan"}`

	fp := &GuacamoleFingerprinter{}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want result")
	}

	if result.Technology != "apache-guacamole" {
		t.Errorf("Technology = %q, want %q", result.Technology, "apache-guacamole")
	}
	if result.Version != "" {
		t.Errorf("Version = %q, want empty (not available via unauthenticated API)", result.Version)
	}
	if len(result.CPEs) != 1 {
		t.Fatalf("CPEs count = %d, want 1", len(result.CPEs))
	}
	if result.CPEs[0] != "cpe:2.3:a:apache:guacamole:*:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q, want %q", result.CPEs[0], "cpe:2.3:a:apache:guacamole:*:*:*:*:*:*:*:*")
	}

	// Check metadata
	langCount, ok := result.Metadata["language_count"].(int)
	if !ok {
		t.Fatal("Metadata language_count not found or wrong type")
	}
	if langCount != 15 {
		t.Errorf("language_count = %d, want 15", langCount)
	}

	langCodes, ok := result.Metadata["languages"].([]string)
	if !ok {
		t.Fatal("Metadata languages not found or wrong type")
	}
	if len(langCodes) != 15 {
		t.Errorf("languages count = %d, want 15", len(langCodes))
	}
}

func TestGuacamoleFingerprinter_Fingerprint_MinimalLanguages(t *testing.T) {
	// Minimal valid response (3 languages minimum)
	body := `{"en":"English","de":"Deutsch","fr":"Français"}`

	fp := &GuacamoleFingerprinter{}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want result")
	}
	if result.Technology != "apache-guacamole" {
		t.Errorf("Technology = %q, want %q", result.Technology, "apache-guacamole")
	}
}

func TestGuacamoleFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Not JSON",
			body: `This is not JSON`,
		},
		{
			name: "Empty JSON object",
			body: `{}`,
		},
		{
			name: "Empty response",
			body: ``,
		},
		{
			name: "JSON array instead of object",
			body: `["en", "de", "fr"]`,
		},
		{
			name: "Missing English language",
			body: `{"de":"Deutsch","fr":"Français","es":"Spanish"}`,
		},
		{
			name: "Empty English value",
			body: `{"en":"","de":"Deutsch","fr":"Français"}`,
		},
		{
			name: "Too few languages (only 2)",
			body: `{"en":"English","de":"Deutsch"}`,
		},
		{
			name: "Single language",
			body: `{"en":"English"}`,
		},
		{
			name: "Null values in language map",
			body: `{"en":"English","de":null,"fr":"Français"}`,
		},
		{
			name: "Grafana health response (different JSON structure)",
			body: `{"database":"ok","version":"10.4.1","commit":"abc123"}`,
		},
		{
			name: "Keycloak OIDC response",
			body: `{"issuer":"https://example.com/realms/master","grant_types_supported":["authorization_code"]}`,
		},
		{
			name: "Generic key-value with empty value",
			body: `{"en":"English","de":"","fr":"Français"}`,
		},
		{
			name: "Numeric values",
			body: `{"en":1,"de":2,"fr":3}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GuacamoleFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			resp.Header.Set("Content-Type", "application/json")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v, want nil", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil for input: %s", result, tt.name)
			}
		})
	}
}

// --- GuacamoleLoginFingerprinter tests ---

func TestGuacamoleLoginFingerprinter_Name(t *testing.T) {
	fp := &GuacamoleLoginFingerprinter{}
	if got := fp.Name(); got != "guacamole-login" {
		t.Errorf("Name() = %q, want %q", got, "guacamole-login")
	}
}

func TestGuacamoleLoginFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &GuacamoleLoginFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/guacamole/" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/guacamole/")
	}
}

func TestGuacamoleLoginFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "text/html returns true",
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "text/html with charset returns true",
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "application/json returns false",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "empty Content-Type returns false",
			contentType: "",
			want:        false,
		},
		{
			name:        "application/xhtml+xml returns false",
			contentType: "application/xhtml+xml",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GuacamoleLoginFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGuacamoleLoginFingerprinter_Fingerprint_RealLoginPage(t *testing.T) {
	// Real Guacamole 1.6.0 login page HTML captured from Docker (abbreviated)
	body := `<!doctype html><html ng-app="index" ng-controller="indexController"><head>` +
		`<meta http-equiv="Content-Type" content="text/html; charset=UTF-8">` +
		`<meta name="build" content="20260319005723">` +
		`<link rel="stylesheet" href="1.guacamole.c2fc19251fc606ad2140.css">` +
		`</head><body>` +
		`<guac-login ng-switch-when="awaitingCredentials" help-text="loginHelpText"></guac-login>` +
		`<guac-modal class="global-status-modal" ng-if="guacNotification.getStatus()">` +
		`<guac-notification notification="guacNotification.getStatus()"></guac-notification>` +
		`</guac-modal>` +
		`<script src="guacamole-common-js/all.min.js"></script>` +
		`<script src="guacamole.02ba1c394df380a3f7d7.js"></script>` +
		`</body></html>`

	fp := &GuacamoleLoginFingerprinter{}
	resp := &http.Response{Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want result")
	}

	if result.Technology != "apache-guacamole" {
		t.Errorf("Technology = %q, want %q", result.Technology, "apache-guacamole")
	}
	if result.Version != "" {
		t.Errorf("Version = %q, want empty", result.Version)
	}
	if result.CPEs[0] != "cpe:2.3:a:apache:guacamole:*:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q, want wildcard", result.CPEs[0])
	}

	// Check metadata
	detectionMethod, ok := result.Metadata["detection_method"].(string)
	if !ok || detectionMethod != "login_page" {
		t.Errorf("detection_method = %q, want %q", detectionMethod, "login_page")
	}

	buildTimestamp, ok := result.Metadata["build_timestamp"].(string)
	if !ok || buildTimestamp != "20260319005723" {
		t.Errorf("build_timestamp = %q, want %q", buildTimestamp, "20260319005723")
	}

	markers, ok := result.Metadata["markers"].([]string)
	if !ok {
		t.Fatal("Metadata markers not found or wrong type")
	}
	// Should detect: guac-login (2), guacamole-common-js (2), guacamole-assets (1),
	// guac-modal (1), guac-notification (1) = score 7
	if len(markers) < 3 {
		t.Errorf("markers count = %d, want >= 3", len(markers))
	}
}

func TestGuacamoleLoginFingerprinter_Fingerprint_MarkerCombinations(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "guac-login + guacamole-common-js (score 4)",
			body: `<html><body><guac-login></guac-login><script src="guacamole-common-js/all.min.js"></script></body></html>`,
			want: true,
		},
		{
			name: "Guacamole.Client + guac-login (score 4)",
			body: `<html><body><guac-login></guac-login><script>var c = new Guacamole.Client(t);</script></body></html>`,
			want: true,
		},
		{
			name: "guacamole-common-js + Guacamole.Client (score 4)",
			body: `<html><script src="guacamole-common-js/all.min.js"></script><script>new Guacamole.Client(t);</script></html>`,
			want: true,
		},
		{
			name: "guac-login only (score 2, meets threshold)",
			body: `<html><body><guac-login></guac-login></body></html>`,
			want: true,
		},
		{
			name: "guacamole-common-js only (score 2, meets threshold)",
			body: `<html><script src="guacamole-common-js/all.min.js"></script></html>`,
			want: true,
		},
		{
			name: "Guacamole.Client only (score 2, meets threshold)",
			body: `<html><script>var c = new Guacamole.Client(tunnel);</script></html>`,
			want: true,
		},
		{
			name: "Apache Guacamole text + guac-modal (score 2)",
			body: `<html><head><title>Apache Guacamole</title></head><body><guac-modal></guac-modal></body></html>`,
			want: true,
		},
		{
			name: "Only medium markers: guac-modal + guac-notification + guacamole-assets (score 3)",
			body: `<html><body><guac-modal></guac-modal><guac-notification></guac-notification><link href="guacamole.css"></body></html>`,
			want: true,
		},
		{
			name: "Only Apache Guacamole text (score 1, below threshold)",
			body: `<html><head><title>Apache Guacamole</title></head><body></body></html>`,
			want: false,
		},
		{
			name: "Only guac-modal (score 1, below threshold)",
			body: `<html><body><guac-modal></guac-modal></body></html>`,
			want: false,
		},
		{
			name: "Only guacamole asset reference (score 1, below threshold)",
			body: `<html><link href="guacamole.css"></html>`,
			want: false,
		},
		{
			name: "Generic login page (score 0)",
			body: `<html><head><title>Login</title></head><body><form><input type="password"/></form></body></html>`,
			want: false,
		},
		{
			name: "Empty HTML (score 0)",
			body: `<html><body></body></html>`,
			want: false,
		},
		{
			name: "Non-HTML content (score 0)",
			body: `Not HTML at all`,
			want: false,
		},
		{
			name: "Empty body",
			body: ``,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GuacamoleLoginFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			resp.Header.Set("Content-Type", "text/html")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}

			if tt.want {
				if result == nil {
					t.Fatal("Fingerprint() returned nil, want result")
				}
				if result.Technology != "apache-guacamole" {
					t.Errorf("Technology = %q, want %q", result.Technology, "apache-guacamole")
				}
			} else {
				if result != nil {
					t.Errorf("Fingerprint() = %+v, want nil", result)
				}
			}
		})
	}
}

func TestGuacamoleLoginFingerprinter_Fingerprint_BuildTimestamp(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantBuild      string
		wantHasBuild   bool
	}{
		{
			name:         "Build timestamp present",
			body:         `<html><meta name="build" content="20260319005723"><guac-login></guac-login></html>`,
			wantBuild:    "20260319005723",
			wantHasBuild: true,
		},
		{
			name:         "No build timestamp",
			body:         `<html><guac-login></guac-login><script src="guacamole-common-js/all.min.js"></script></html>`,
			wantHasBuild: false,
		},
		{
			name:         "Older build timestamp format",
			body:         `<html><meta name="build" content="20220815120000"><guac-login></guac-login></html>`,
			wantBuild:    "20220815120000",
			wantHasBuild: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GuacamoleLoginFingerprinter{}
			resp := &http.Response{Header: make(http.Header)}
			resp.Header.Set("Content-Type", "text/html")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil")
			}

			buildTimestamp, hasBuild := result.Metadata["build_timestamp"].(string)
			if tt.wantHasBuild {
				if !hasBuild || buildTimestamp != tt.wantBuild {
					t.Errorf("build_timestamp = %q (present=%v), want %q", buildTimestamp, hasBuild, tt.wantBuild)
				}
			} else {
				if hasBuild {
					t.Errorf("build_timestamp = %q, want absent", buildTimestamp)
				}
			}
		})
	}
}

// --- Helper function tests ---

func TestBuildGuacamoleCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:apache:guacamole:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Specific version",
			version: "1.5.5",
			want:    "cpe:2.3:a:apache:guacamole:1.5.5:*:*:*:*:*:*:*",
		},
		{
			name:    "Older version",
			version: "1.0.0",
			want:    "cpe:2.3:a:apache:guacamole:1.0.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildGuacamoleCPE(tt.version); got != tt.want {
				t.Errorf("buildGuacamoleCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- Live Docker integration tests ---

func TestGuacamoleFingerprinter_LiveDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live Docker test in short mode")
	}

	// Test against live Guacamole Docker container
	// Expects: docker run -d --name guacamole-test -p 18080:8080 guacamole/guacamole:latest
	baseURL := "http://localhost:18080"

	// Test /guacamole/api/languages endpoint
	t.Run("API_languages_endpoint", func(t *testing.T) {
		resp, err := httpGetWithTimeout(baseURL + "/guacamole/api/languages")
		if err != nil {
			t.Skipf("Skipping: Guacamole not available at %s: %v", baseURL, err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		fp := &GuacamoleFingerprinter{}
		if !fp.Match(resp) {
			t.Fatalf("Match() returned false for live /api/languages response (Content-Type: %s)",
				resp.Header.Get("Content-Type"))
		}

		result, err := fp.Fingerprint(resp, body)
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatalf("Fingerprint() returned nil for live Guacamole response: %s", string(body))
		}

		if result.Technology != "apache-guacamole" {
			t.Errorf("Technology = %q, want %q", result.Technology, "apache-guacamole")
		}

		langCount, ok := result.Metadata["language_count"].(int)
		if !ok || langCount < 5 {
			t.Errorf("language_count = %v, want >= 5 for real Guacamole instance", langCount)
		}

		t.Logf("Live detection: technology=%s, languages=%d, CPE=%s",
			result.Technology, langCount, result.CPEs[0])
	})

	// Test /guacamole/ login page
	t.Run("Login_page", func(t *testing.T) {
		resp, err := httpGetWithTimeout(baseURL + "/guacamole/")
		if err != nil {
			t.Skipf("Skipping: Guacamole not available at %s: %v", baseURL, err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		fp := &GuacamoleLoginFingerprinter{}
		if !fp.Match(resp) {
			t.Fatalf("Match() returned false for live login page (Content-Type: %s)",
				resp.Header.Get("Content-Type"))
		}

		result, err := fp.Fingerprint(resp, body)
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatalf("Fingerprint() returned nil for live login page")
		}

		if result.Technology != "apache-guacamole" {
			t.Errorf("Technology = %q, want %q", result.Technology, "apache-guacamole")
		}

		markers, ok := result.Metadata["markers"].([]string)
		if !ok || len(markers) < 2 {
			t.Errorf("markers = %v, want >= 2 markers for real login page", markers)
		}

		buildTimestamp, hasBuild := result.Metadata["build_timestamp"].(string)
		if hasBuild {
			t.Logf("Live detection: technology=%s, markers=%v, build=%s",
				result.Technology, markers, buildTimestamp)
		} else {
			t.Logf("Live detection: technology=%s, markers=%v (no build timestamp)",
				result.Technology, markers)
		}
	})

	// Negative test: /guacamole/api/ should NOT produce a false positive
	t.Run("API_root_returns_404", func(t *testing.T) {
		resp, err := httpGetWithTimeout(baseURL + "/guacamole/api/")
		if err != nil {
			t.Skipf("Skipping: Guacamole not available: %v", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != 404 {
			t.Logf("Note: /guacamole/api/ returned %d (expected 404)", resp.StatusCode)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read response body: %v", err)
		}

		// The API fingerprinter should NOT match HTML 404 responses
		fp := &GuacamoleFingerprinter{}
		if fp.Match(resp) {
			result, err := fp.Fingerprint(resp, body)
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() should return nil for /api/ 404 page, got %+v", result)
			}
		}
	})
}

func httpGetWithTimeout(url string) (*http.Response, error) {
	client := &http.Client{
		Timeout: 5 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("HTTP GET %s failed: %w", url, err)
	}
	return resp, nil
}
