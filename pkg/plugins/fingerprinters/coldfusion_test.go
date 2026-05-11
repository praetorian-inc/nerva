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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// realisticColdFusionAdminBody is a representative ColdFusion administrator login page.
// Includes title, version text, CFIDE form action, and explicit version div.
const realisticColdFusionAdminBody = `<!DOCTYPE html>
<html>
<head><title>ColdFusion Administrator</title></head>
<body>
<div class="login-header">Adobe ColdFusion 2023</div>
<form action="/CFIDE/administrator/enter.cfm" method="post">
<input type="text" name="adminpassword">
<input type="submit" value="Login">
</form>
<div class="version">Version 2023.0.6</div>
</body>
</html>`

// ── Name / ProbeEndpoint ──────────────────────────────────────────────────────

func TestColdFusionFingerprinter_Name(t *testing.T) {
	fp := &ColdFusionFingerprinter{}
	assert.Equal(t, "coldfusion", fp.Name())
}

func TestColdFusionFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ColdFusionFingerprinter{}
	assert.Equal(t, "/CFIDE/administrator/", fp.ProbeEndpoint())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestColdFusionFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		poweredBy   string
		server      string
		contentType string
		want        bool
	}{
		{
			name:        "200 OK with text/html passes",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:       "X-Powered-By: ColdFusion header match",
			statusCode: 200,
			poweredBy:  "ColdFusion",
			want:       true,
		},
		{
			name:       "X-Powered-By: ColdFusion/2023.0.1 header match",
			statusCode: 200,
			poweredBy:  "ColdFusion/2023.0.1",
			want:       true,
		},
		{
			name:       "Server: ColdFusion header match",
			statusCode: 200,
			server:     "ColdFusion",
			want:       true,
		},
		{
			name:       "302 redirect passes (in 200-499 range)",
			statusCode: 302,
			want:       true,
		},
		{
			name:       "404 Not Found passes (in 200-499 range)",
			statusCode: 404,
			want:       true,
		},
		{
			name:       "100 Informational rejected",
			statusCode: 100,
			want:       false,
		},
		{
			name:       "500 Internal Server Error rejected",
			statusCode: 500,
			want:       false,
		},
		{
			name:       "503 Service Unavailable rejected",
			statusCode: 503,
			want:       false,
		},
		{
			name:       "199 rejected (below 200)",
			statusCode: 199,
			want:       false,
		},
		{
			name:       "499 passes (upper boundary of accepted range)",
			statusCode: 499,
			want:       true,
		},
		{
			name:       "Server header with unrelated value, no CF header, no content-type still passes on status",
			statusCode: 200,
			server:     "Apache/2.4",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ColdFusionFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.poweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.poweredBy)
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

// ── Fingerprint: positive (valid) ────────────────────────────────────────────

func TestColdFusionFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name            string
		statusCode      int
		poweredBy       string
		server          string
		body            string
		probePath       string
		wantVersion     string
		wantCPE         string
		wantDetection   string
		wantProbePath   bool
		wantPoweredByIn bool // expect powered_by key in metadata
	}{
		{
			name:            "X-Powered-By header detection, empty body",
			statusCode:      200,
			poweredBy:       "ColdFusion",
			body:            "",
			wantVersion:     "",
			wantCPE:         "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
			wantDetection:   "header",
			wantPoweredByIn: true,
		},
		{
			name:            "X-Powered-By header with version ColdFusion/2023.0.1",
			statusCode:      200,
			poweredBy:       "ColdFusion/2023.0.1",
			body:            "",
			wantVersion:     "2023.0.1",
			wantCPE:         "cpe:2.3:a:adobe:coldfusion:2023.0.1:*:*:*:*:*:*:*",
			wantDetection:   "header",
			wantPoweredByIn: true,
		},
		{
			name:          "Server header detection, empty body",
			statusCode:    200,
			server:        "ColdFusion",
			body:          "",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
			wantDetection: "header",
		},
		{
			name:          "Admin page body detection — realistic admin body with version",
			statusCode:    200,
			body:          realisticColdFusionAdminBody,
			wantVersion:   "2023",
			wantCPE:       "cpe:2.3:a:adobe:coldfusion:2023:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:          "Active probe via /CFIDE/administrator/ sets probe_path metadata",
			statusCode:    200,
			body:          realisticColdFusionAdminBody,
			probePath:     "/CFIDE/administrator/",
			wantVersion:   "2023",
			wantCPE:       "cpe:2.3:a:adobe:coldfusion:2023:*:*:*:*:*:*:*",
			wantDetection: "active_probe",
			wantProbePath: true,
		},
		{
			name:            "Version extracted from X-Powered-By: ColdFusion 2021",
			statusCode:      200,
			poweredBy:       "ColdFusion 2021",
			body:            "",
			wantVersion:     "2021",
			wantCPE:         "cpe:2.3:a:adobe:coldfusion:2021:*:*:*:*:*:*:*",
			wantDetection:   "header",
			wantPoweredByIn: true,
		},
		{
			name:       "Version from body 'ColdFusion 2018' — older release year",
			statusCode: 200,
			body: `<html><head><title>ColdFusion Administrator</title></head>
<body>Adobe ColdFusion 2018 <a href="/CFIDE/administrator/enter.cfm">Login</a></body></html>`,
			wantVersion:   "2018",
			wantCPE:       "cpe:2.3:a:adobe:coldfusion:2018:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:            "X-Powered-By version takes priority over body version",
			statusCode:      200,
			poweredBy:       "ColdFusion/2023.0.1",
			body:            realisticColdFusionAdminBody,
			wantVersion:     "2023.0.1",
			wantCPE:         "cpe:2.3:a:adobe:coldfusion:2023.0.1:*:*:*:*:*:*:*",
			wantDetection:   "body",
			wantPoweredByIn: true,
		},
		{
			name:       "Body with .cfm extension links and coldfusion keyword",
			statusCode: 200,
			body: `<html><head><title>Login</title></head>
<body><a href="/app/index.cfm">Home</a> - ColdFusion powered</body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ColdFusionFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.poweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.poweredBy)
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.probePath != "" {
				resp.Request = &http.Request{URL: &url.URL{Path: tt.probePath}}
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result, "Fingerprint() returned nil, want non-nil result")

			assert.Equal(t, "coldfusion", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			require.NotEmpty(t, result.CPEs, "Expected at least one CPE")
			assert.Equal(t, tt.wantCPE, result.CPEs[0])
			require.NotNil(t, result.Metadata)

			assert.Equal(t, plugins.SeverityHigh, result.Severity)

			if tt.wantDetection != "" {
				assert.Equal(t, tt.wantDetection, result.Metadata["detection_method"])
			}

			if tt.wantProbePath {
				assert.Equal(t, "/CFIDE/administrator/", result.Metadata["probe_path"])
			} else {
				assert.NotContains(t, result.Metadata, "probe_path",
					"probe_path should be absent for non-active-probe responses")
			}

			if tt.wantPoweredByIn {
				assert.Contains(t, result.Metadata, "powered_by",
					"powered_by should be present when X-Powered-By header is set")
			}
		})
	}
}

// ── Fingerprint: negative (invalid — must return nil) ─────────────────────────

func TestColdFusionFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		poweredBy  string
		server     string
		body       string
	}{
		{
			name:       "Empty body, no CF headers",
			statusCode: 200,
			body:       "",
		},
		{
			name:       "WordPress login page",
			statusCode: 200,
			body:       `<html><head><title>Log In — WordPress</title></head><body><form id="login" action="/wp-login.php"></form></body></html>`,
		},
		{
			name:       "Generic Apache page",
			statusCode: 200,
			server:     "Apache/2.4.57",
			body:       `<html><head><title>Apache2 Default Page</title></head><body><p>It works!</p></body></html>`,
		},
		{
			name:       "Body with 'coldfusion' only — no corroborating .cfm or cfide or adobe",
			statusCode: 200,
			body:       `<html><head><title>Login</title></head><body>ColdFusion is not what this is.</body></html>`,
		},
		{
			name:       "Body larger than 2 MiB is rejected",
			statusCode: 200,
			body:       "coldfusion adobe cfide" + string(make([]byte, 2*1024*1024+1)),
		},
		{
			name:       "CPE injection attempt in body (contains :*:)",
			statusCode: 200,
			body:       `<html><head><title>ColdFusion Administrator</title></head><body>ColdFusion/2023:*:adobe/cfide</body></html>`,
		},
		{
			name:       "Status 500 rejected",
			statusCode: 500,
			body:       realisticColdFusionAdminBody,
		},
		{
			name:       "Status 503 rejected",
			statusCode: 503,
			body:       realisticColdFusionAdminBody,
		},
		{
			name:       "Status 100 rejected",
			statusCode: 100,
			body:       realisticColdFusionAdminBody,
		},
		{
			name:       "Nginx root page with no CF signals",
			statusCode: 200,
			server:     "nginx/1.24.0",
			body:       `<html><head><title>Welcome to nginx!</title></head><body></body></html>`,
		},
		{
			name:       "IIS page with no CF signals",
			statusCode: 200,
			server:     "Microsoft-IIS/10.0",
			body:       `<html><head><title>IIS Windows Server</title></head><body></body></html>`,
		},
		{
			name:       "X-Powered-By: PHP/8.1 (not ColdFusion)",
			statusCode: 200,
			poweredBy:  "PHP/8.1",
			body:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ColdFusionFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.poweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.poweredBy)
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result, "Fingerprint() should return nil for non-ColdFusion response")
		})
	}
}

// ── TestExtractColdFusionVersion ──────────────────────────────────────────────

func TestExtractColdFusionVersion(t *testing.T) {
	t.Run("from header", func(t *testing.T) {
		tests := []struct {
			header string
			want   string
		}{
			{"ColdFusion/2023.0.1", "2023.0.1"},
			{"ColdFusion 2023", "2023"},
			{"ColdFusion/2021", "2021"},
			{"ColdFusion/2018.0.16", "2018.0.16"},
			{"PHP/8.1", ""},
			{"", ""},
			{"ColdFusion", ""}, // no version part
		}
		for _, tt := range tests {
			t.Run(tt.header, func(t *testing.T) {
				got := extractColdFusionVersionFromHeader(tt.header)
				assert.Equal(t, tt.want, got)
			})
		}
	})

	t.Run("from body", func(t *testing.T) {
		tests := []struct {
			name string
			body string
			want string
		}{
			{
				name: "ColdFusion 2023 in body",
				body: `<div>Adobe ColdFusion 2023</div>`,
				want: "2023",
			},
			{
				name: "ColdFusion 2021 in body",
				body: `<title>ColdFusion 2021 Administrator</title>`,
				want: "2021",
			},
			{
				name: "ColdFusion 2023.0.6 in body",
				body: `<span>ColdFusion 2023.0.6 release</span>`,
				want: "2023.0.6",
			},
			{
				name: "No version in body",
				body: `<html><head><title>ColdFusion Administrator</title></head></html>`,
				want: "",
			},
			{
				name: "ColdFusion without version number",
				body: `<html><body>ColdFusion rocks</body></html>`,
				want: "",
			},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				got := extractColdFusionVersionFromBody([]byte(tt.body))
				assert.Equal(t, tt.want, got)
			})
		}
	})
}

// ── TestBuildColdFusionCPE ────────────────────────────────────────────────────

func TestBuildColdFusionCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "2023",
			want:    "cpe:2.3:a:adobe:coldfusion:2023:*:*:*:*:*:*:*",
		},
		{
			version: "2023.0.1",
			want:    "cpe:2.3:a:adobe:coldfusion:2023.0.1:*:*:*:*:*:*:*",
		},
		{
			version: "2021",
			want:    "cpe:2.3:a:adobe:coldfusion:2021:*:*:*:*:*:*:*",
		},
		{
			version: "2018.0.16",
			want:    "cpe:2.3:a:adobe:coldfusion:2018.0.16:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			assert.Equal(t, tt.want, buildColdFusionCPE(tt.version))
		})
	}
}

// ── TestSanitizeColdFusionHeaderValue ─────────────────────────────────────────

func TestSanitizeColdFusionHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Normal header value unchanged",
			input: "ColdFusion/2023.0.1",
			want:  "ColdFusion/2023.0.1",
		},
		{
			name:  "Control characters stripped",
			input: "ColdFusion\x00\x01\x1f/2023",
			want:  "ColdFusion/2023",
		},
		{
			name:  "DEL character stripped",
			input: "value\x7fafter",
			want:  "valueafter",
		},
		{
			name:  "Value longer than 256 chars truncated",
			input: "ColdFusion/" + string(make([]byte, 300)),
			want: func() string {
				s := "ColdFusion/"
				if len(s) > 256 {
					return s[:256]
				}
				return s
			}(),
		},
		{
			name:  "Printable ASCII preserved",
			input: "ColdFusion 2023.0.1",
			want:  "ColdFusion 2023.0.1",
		},
		{
			name:  "Empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sanitizeColdFusionHeaderValue(tt.input))
		})
	}
}

// ── TestColdFusionVersionValidation ──────────────────────────────────────────

func TestColdFusionVersionValidation(t *testing.T) {
	tests := []struct {
		version string
		valid   bool
	}{
		{"2023", true},
		{"2021", true},
		{"2018", true},
		{"2023.0.1", true},
		{"2018.0.16", true},
		{"1.0", true},
		{"11", true},
		{"2023.0.1.2.3", true}, // 5 groups (1 + 4 dotted) — allowed by {0,4}
		{"2023-beta", false},
		{"2023:*:", false},
		{"abc", false},
		{"", false},
		{".2023", false},
		{"2023.", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := coldfusionVersionValidateRegex.MatchString(tt.version)
			assert.Equal(t, tt.valid, got,
				"coldfusionVersionValidateRegex.MatchString(%q) = %v, want %v", tt.version, got, tt.valid)
		})
	}
}

// ── Active probe tests ────────────────────────────────────────────────────────

func TestColdFusionFingerprinter_ActiveProbeResponse(t *testing.T) {
	fp := &ColdFusionFingerprinter{}

	t.Run("CFIDE/administrator/ probe sets probe_path metadata", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/CFIDE/administrator/"},
			},
		}

		result, err := fp.Fingerprint(resp, []byte(realisticColdFusionAdminBody))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "/CFIDE/administrator/", result.Metadata["probe_path"])
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
	})

	t.Run("nil Request does not panic and does not set probe_path", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    nil,
		}

		result, err := fp.Fingerprint(resp, []byte(realisticColdFusionAdminBody))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.NotContains(t, result.Metadata, "probe_path",
			"probe_path should be absent when Request is nil")
	})

	t.Run("Root response does not set probe_path", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		result, err := fp.Fingerprint(resp, []byte(realisticColdFusionAdminBody))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.NotContains(t, result.Metadata, "probe_path",
			"probe_path should be absent for root response")
	})
}

// ── Integration test ──────────────────────────────────────────────────────────

func TestColdFusionFingerprinter_Integration(t *testing.T) {
	// Save and restore global state to prevent test pollution (mirrors gradio_test.go:355-357).
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &ColdFusionFingerprinter{}
	Register(fp)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	results := RunFingerprinters(resp, []byte(realisticColdFusionAdminBody))

	var found bool
	for _, result := range results {
		if result.Technology == "coldfusion" {
			found = true
			assert.Equal(t, "2023", result.Version)
			require.NotEmpty(t, result.CPEs)
			assert.Equal(t, "cpe:2.3:a:adobe:coldfusion:2023:*:*:*:*:*:*:*", result.CPEs[0])
			assert.Equal(t, plugins.SeverityHigh, result.Severity)
			assert.Equal(t, "Adobe", result.Metadata["vendor"])
			assert.Equal(t, "ColdFusion", result.Metadata["product"])
		}
	}

	assert.True(t, found, "ColdFusionFingerprinter not found in RunFingerprinters results")
}
