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
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Name / ProbeEndpoint ───────────────────────────────────────────────────────

func TestCaddyFingerprinter_Name(t *testing.T) {
	fp := &CaddyFingerprinter{}
	assert.Equal(t, "caddy", fp.Name())
}

func TestCaddyFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &CaddyFingerprinter{}
	assert.Equal(t, "/config/", fp.ProbeEndpoint())
}

// ── Match ──────────────────────────────────────────────────────────────────────

func TestCaddyFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		server      string
		contentType string
		want        bool
	}{
		{
			name:       "200 with Server: Caddy",
			statusCode: 200,
			server:     "Caddy",
			want:       true,
		},
		{
			name:        "200 with text/html Content-Type",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 with application/json Content-Type",
			statusCode:  200,
			contentType: "application/json",
			want:        true,
		},
		{
			name:       "200 with no relevant headers",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "500 error rejected",
			statusCode: 500,
			server:     "Caddy",
			want:       false,
		},
		{
			name:       "199 below range rejected",
			statusCode: 199,
			want:       false,
		},
		{
			name:       "302 with Server: Caddy passes",
			statusCode: 302,
			server:     "Caddy",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CaddyFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint: positive (valid) ─────────────────────────────────────────────

func TestCaddyFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name                string
		statusCode          int
		server              string
		body                string
		probePath           string
		wantVersion         string
		wantCPE             string
		wantDetection       string
		wantAdminAPIKey     bool // admin_api_exposed key is present
		wantAdminAPIValue   bool // admin_api_exposed value
		wantProbePathKey    bool // probe_path key is present
		wantServerHeaderKey bool // server_header key is present
		wantSeverityHigh    bool
		wantAutoHTTPS       bool
	}{
		{
			name:              "Server: Caddy header only — detects with server_header method",
			statusCode:        200,
			server:            "Caddy",
			body:              "",
			wantVersion:       "",
			wantCPE:           "cpe:2.3:a:caddyserver:caddy:*:*:*:*:*:*:*:*",
			wantDetection:     "server_header",
			wantServerHeaderKey: true,
		},
		{
			name:              "Server: Caddy/v2.7.6 — extracts version 2.7.6",
			statusCode:        200,
			server:            "Caddy/v2.7.6",
			body:              "",
			wantVersion:       "2.7.6",
			wantCPE:           "cpe:2.3:a:caddyserver:caddy:2.7.6:*:*:*:*:*:*:*",
			wantDetection:     "server_header",
			wantServerHeaderKey: true,
		},
		{
			name:              "Admin API JSON response — detects with admin_api method and sets admin_api_exposed=true",
			statusCode:        200,
			server:            "Caddy",
			body:              `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"]}}},"tls":{"automation":{}}},"admin":{"listen":"localhost:2019"}}`,
			wantDetection:     "admin_api",
			wantAdminAPIKey:   true,
			wantAdminAPIValue: true,
			wantSeverityHigh:  true,
			wantServerHeaderKey: true,
			wantAutoHTTPS:     true,
		},
		{
			name:   "Body with 'Powered by Caddy' + caddyserver marker — detects via body + server header",
			statusCode: 200,
			server: "Caddy",
			body:   `<html><body><p>Powered by Caddy | caddyserver</p></body></html>`,
			wantDetection: "body",
			wantServerHeaderKey: true,
		},
		{
			name:              "Active probe response — request URL is /config/",
			statusCode:        200,
			server:            "Caddy",
			probePath:         "/config/",
			body:              `{"apps":{"http":{},"tls":{"automation":{}}}}`,
			wantDetection:     "active_probe",
			wantAdminAPIKey:   true,
			wantAdminAPIValue: true,
			wantProbePathKey:  true,
			wantSeverityHigh:  true,
			wantAutoHTTPS:     true,
		},
		{
			name:                "Body with :*: in server header still produces detection — gate removed",
			statusCode:          200,
			server:              "Caddy",
			body:                `{"apps":{"caddy:*:malicious":{}}}`,
			wantDetection:       "admin_api",
			wantAdminAPIKey:     true,
			wantAdminAPIValue:   true,
			wantSeverityHigh:    true,
			wantServerHeaderKey: true,
		},
		{
			name:                "Admin API body with :*: in route config does not block detection",
			statusCode:          200,
			server:              "Caddy/2.7.6",
			body:                `{"apps":{"http":{"servers":{"srv0":{"routes":[{"match":[{"path":[":*:"]}]}]}}}}}`,
			wantVersion:         "2.7.6",
			wantCPE:             "cpe:2.3:a:caddyserver:caddy:2.7.6:*:*:*:*:*:*:*",
			wantDetection:       "admin_api",
			wantAdminAPIKey:     true,
			wantAdminAPIValue:   true,
			wantSeverityHigh:    true,
			wantServerHeaderKey: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CaddyFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.probePath != "" {
				resp.Request = &http.Request{URL: &url.URL{Path: tt.probePath}}
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			assert.NoError(t, err)
			assert.NotNil(t, result, "expected non-nil result")

			if result == nil {
				return
			}

			assert.Equal(t, "caddy", result.Technology)
			assert.NotEmpty(t, result.CPEs)
			assert.NotNil(t, result.Metadata)

			if tt.wantVersion != "" {
				assert.Equal(t, tt.wantVersion, result.Version)
			}
			if tt.wantCPE != "" {
				assert.Equal(t, tt.wantCPE, result.CPEs[0])
			}
			if tt.wantDetection != "" {
				assert.Equal(t, tt.wantDetection, result.Metadata["detection_method"])
			}
			if tt.wantAdminAPIKey {
				exposed, ok := result.Metadata["admin_api_exposed"].(bool)
				assert.True(t, ok, "admin_api_exposed should be bool")
				assert.Equal(t, tt.wantAdminAPIValue, exposed)
			}
			if tt.wantProbePathKey {
				assert.Equal(t, "/config/", result.Metadata["probe_path"])
			} else {
				_, hasProbePath := result.Metadata["probe_path"]
				assert.False(t, hasProbePath, "probe_path should be absent for non-active-probe responses")
			}
			if tt.wantServerHeaderKey {
				_, hasServerHeader := result.Metadata["server_header"]
				assert.True(t, hasServerHeader, "server_header should be present when Server header is set")
			}
			if tt.wantSeverityHigh {
				assert.NotEmpty(t, result.Severity, "expected severity to be set")
			}
			if tt.wantAutoHTTPS {
				assert.Equal(t, true, result.Metadata["auto_https"])
			}
		})
	}
}

// ── Fingerprint: negative (invalid — must return nil) ─────────────────────────

func TestCaddyFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		server     string
		body       string
	}{
		{
			name:       "Status 500 rejected",
			statusCode: 500,
			server:     "Caddy",
			body:       `{"apps":{}}`,
		},
		{
			name:       "Body > 2 MiB rejected",
			statusCode: 200,
			server:     "Caddy",
			body:       "caddy" + strings.Repeat("A", 2*1024*1024+1),
		},
		{
			name:       "Body contains 'caddy' but no definitive signal (no server header, no admin API)",
			statusCode: 200,
			server:     "",
			body:       `<html><body>The golf caddy brought the clubs.</body></html>`,
		},
		{
			name:       "No Server header, no body brand",
			statusCode: 200,
			server:     "",
			body:       `<html><body><h1>Welcome</h1></body></html>`,
		},
		{
			name:       "Empty body, no Server header",
			statusCode: 200,
			server:     "",
			body:       "",
		},
		{
			name:       "Body brand 'Powered by Caddy' alone without server header rejected",
			statusCode: 200,
			server:     "",
			body:       `<html><body><p>Powered by Caddy</p></body></html>`,
		},
		{
			name:       "Body brand 'caddyserver' alone without server header rejected",
			statusCode: 200,
			server:     "",
			body:       `<html><body>caddyserver was here</body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CaddyFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			assert.NoError(t, err)
			assert.Nil(t, result, "expected nil result for negative test case")
		})
	}
}

// ── TestExtractCaddyVersion ────────────────────────────────────────────────────

func TestExtractCaddyVersion(t *testing.T) {
	tests := []struct {
		name   string
		server string
		body   string
		want   string
	}{
		{
			name:   "Server header Caddy/v2.7.6",
			server: "Caddy/v2.7.6",
			want:   "2.7.6",
		},
		{
			name:   "Server header Caddy 2.7.6",
			server: "Caddy 2.7.6",
			want:   "2.7.6",
		},
		{
			name:   "Server header Caddy/2.7",
			server: "Caddy/2.7",
			want:   "2.7",
		},
		{
			name:   "Server header case-insensitive caddy/2.6.0",
			server: "caddy/2.6.0",
			want:   "2.6.0",
		},
		{
			name:   "Version in body when no server header version",
			server: "Caddy",
			body:   "Caddy/2.8.1 running",
			want:   "2.8.1",
		},
		{
			name:   "Server header takes priority over body",
			server: "Caddy/2.7.6",
			body:   "Caddy/99.0.0 old version",
			want:   "2.7.6",
		},
		{
			name:   "No version available",
			server: "Caddy",
			body:   "",
			want:   "",
		},
		{
			name:   "Empty server header and body",
			server: "",
			body:   "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			got := extractCaddyVersion(resp, []byte(tt.body))
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── TestBuildCaddyCPE ──────────────────────────────────────────────────────────

func TestBuildCaddyCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Version 2.7.6",
			version: "2.7.6",
			want:    "cpe:2.3:a:caddyserver:caddy:2.7.6:*:*:*:*:*:*:*",
		},
		{
			name:    "Version 2.8.0",
			version: "2.8.0",
			want:    "cpe:2.3:a:caddyserver:caddy:2.8.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Four-component version 2.7.6.1",
			version: "2.7.6.1",
			want:    "cpe:2.3:a:caddyserver:caddy:2.7.6.1:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:caddyserver:caddy:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildCaddyCPE(tt.version))
		})
	}
}

// ── TestSanitizeCaddyHeaderValue ──────────────────────────────────────────────

func TestSanitizeCaddyHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Normal header value unchanged",
			input: "Caddy/2.7.6",
			want:  "Caddy/2.7.6",
		},
		{
			name:  "Control characters stripped",
			input: "Caddy\x00\x01\x1f/2.7.6",
			want:  "Caddy/2.7.6",
		},
		{
			name:  "DEL character stripped",
			input: "Caddy\x7f/2.7.6",
			want:  "Caddy/2.7.6",
		},
		{
			name:  "Value > 256 chars truncated at rune boundary",
			input: strings.Repeat("A", 300),
			want:  strings.Repeat("A", 256),
		},
		{
			name:  "All control chars produces empty string",
			input: string(make([]byte, 50)), // 50 zero bytes, all stripped
			want:  "",
		},
		{
			name:  "Printable ASCII preserved",
			input: "Caddy",
			want:  "Caddy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sanitizeCaddyHeaderValue(tt.input))
		})
	}
}

// ── TestIsCaddyAdminAPI ───────────────────────────────────────────────────────

func TestIsCaddyAdminAPI(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "Caddy admin API response with apps key",
			body: `{"apps":{"http":{"servers":{"srv0":{}}}}}`,
			want: true,
		},
		{
			name: "Caddy admin API with whitespace around colon",
			body: `{"apps" : {"http":{}}}`,
			want: true,
		},
		{
			name: "Caddy admin API minimal",
			body: `{"apps":{}}`,
			want: true,
		},
		{
			name: "Generic JSON without apps key",
			body: `{"status":"ok","version":"1.0"}`,
			want: false,
		},
		{
			name: "HTML body",
			body: `<html><body>Hello</body></html>`,
			want: false,
		},
		{
			name: "Empty body",
			body: ``,
			want: false,
		},
		{
			name: "JSON with apps as string value (not object)",
			body: `{"apps":"none"}`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isCaddyAdminAPI([]byte(tt.body)))
		})
	}
}

// ── TestDetectCaddyAutoHTTPS ────────────────────────────────────────────────

func TestDetectCaddyAutoHTTPS(t *testing.T) {
	tests := []struct {
		name              string
		scheme            string
		body              string
		hasAdminAPISignal bool
		want              bool
	}{
		{
			name:              "Admin API with TLS config",
			body:              `{"apps":{"http":{},"tls":{"automation":{}}}}`,
			hasAdminAPISignal: true,
			want:              true,
		},
		{
			name:              "Admin API with :443 listener",
			body:              `{"apps":{"http":{"servers":{"srv0":{"listen":[":443"]}}}}}`,
			hasAdminAPISignal: true,
			want:              true,
		},
		{
			name:              "Response served over HTTPS",
			scheme:            "https",
			body:              "",
			hasAdminAPISignal: false,
			want:              true,
		},
		{
			name:              "No admin API, HTTP scheme, no TLS signals",
			scheme:            "http",
			body:              "",
			hasAdminAPISignal: false,
			want:              false,
		},
		{
			name:              "Admin API without TLS config or :443",
			body:              `{"apps":{"http":{"servers":{"srv0":{"listen":[":80"]}}}}}`,
			hasAdminAPISignal: true,
			want:              false,
		},
		{
			name:              "TLS in body but not admin API signal — ignored",
			body:              `"tls":{"automation":{}}`,
			hasAdminAPISignal: false,
			want:              false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: make(http.Header)}
			if tt.scheme != "" {
				resp.Request = &http.Request{URL: &url.URL{Scheme: tt.scheme}}
			}
			got := detectCaddyAutoHTTPS(resp, []byte(tt.body), tt.hasAdminAPISignal)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── Integration test ──────────────────────────────────────────────────────────

func TestCaddyFingerprinter_Integration(t *testing.T) {
	fp := &CaddyFingerprinter{}

	t.Run("server header only triggers detection", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Caddy/2.7.6")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintln(w, "<html><body>Hello</body></html>")
		}))
		defer ts.Close()

		resp, err := http.Get(ts.URL)
		assert.NoError(t, err)
		defer resp.Body.Close()

		body := []byte("<html><body>Hello</body></html>")
		assert.True(t, fp.Match(resp))
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "caddy", result.Technology)
		assert.Equal(t, "2.7.6", result.Version)
		assert.Equal(t, []string{"cpe:2.3:a:caddyserver:caddy:2.7.6:*:*:*:*:*:*:*"}, result.CPEs)
		assert.Equal(t, "caddyserver", result.Metadata["vendor"])
		assert.Equal(t, "Caddy", result.Metadata["product"])
	})

	t.Run("admin API response triggers high severity", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "Caddy")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"apps":{"http":{"servers":{}}}}`)
		}))
		defer ts.Close()

		resp, err := http.Get(ts.URL)
		assert.NoError(t, err)
		defer resp.Body.Close()

		body := []byte(`{"apps":{"http":{"servers":{}}}}`)
		assert.True(t, fp.Match(resp))
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "caddy", result.Technology)
		assert.Equal(t, true, result.Metadata["admin_api_exposed"])
		assert.NotEmpty(t, result.Severity)
	})
}
