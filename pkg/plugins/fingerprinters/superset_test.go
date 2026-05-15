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

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSupersetFingerprinter_Name(t *testing.T) {
	fp := &SupersetFingerprinter{}
	assert.Equal(t, "superset", fp.Name())
}

func TestSupersetFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &SupersetFingerprinter{}
	assert.Equal(t, "/api/v1/info", fp.ProbeEndpoint())
}

func TestSupersetFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		nilResp     bool
		expected    bool
	}{
		{name: "matches text/html", contentType: "text/html", expected: true},
		{
			name:        "matches uppercase TEXT/HTML (RFC 7231 case-insensitive)",
			contentType: "TEXT/HTML",
			expected:    true,
		},
		{name: "matches text/html with charset", contentType: "text/html; charset=utf-8", expected: true},
		{name: "matches application/xhtml+xml", contentType: "application/xhtml+xml", expected: true},
		{name: "matches application/json", contentType: "application/json", expected: true},
		{name: "matches empty content type", contentType: "", expected: true},
		{name: "does not match text/plain", contentType: "text/plain", expected: false},
		{name: "does not match image/png", contentType: "image/png", expected: false},
		{name: "nil response returns false (no panic)", nilResp: true, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SupersetFingerprinter{}
			if tt.nilResp {
				assert.False(t, fp.Match(nil))
				return
			}
			resp := &http.Response{
				Header: http.Header{"Content-Type": []string{tt.contentType}},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestSupersetFingerprinter_Fingerprint(t *testing.T) {
	const (
		titleSignal = `<title>Superset</title>`
		assetSignal = `<link href="/static/appbuilder/css/main.css">`
		fabSignal   = `<div data-bootstrap="{&quot;SUPERSET_WEBSERVER_TIMEOUT&quot;:60}">`
		wantCPE     = "cpe:2.3:a:apache:superset:*:*:*:*:*:*:*:*"
	)

	tests := []struct {
		name    string
		body    string
		wantNil bool
		nilResp bool
	}{
		// Positive rows (>=2 signals -> detect)
		{
			name: "full realistic body with all 3 signals",
			body: `<!doctype html><html><head>` + titleSignal + assetSignal + `</head><body>` + fabSignal + `</body></html>`,
		},
		{
			name: "title + asset path (2 signals)",
			body: `<html><head>` + titleSignal + assetSignal + `</head></html>`,
		},
		{
			name: "title + bootstrap marker (2 signals)",
			body: `<html><head>` + titleSignal + `</head><body>` + fabSignal + `</body></html>`,
		},
		{
			name: "asset + bootstrap marker (2 signals, no title)",
			body: `<html><head>` + assetSignal + `</head><body>` + fabSignal + `</body></html>`,
		},
		{
			name: "case-insensitive title + superset asset path",
			body: `<html><head><TITLE>My SUPERSET Dashboard</TITLE><link href="/superset/static/css/main.css"></head></html>`,
		},
		// Negative rows (< 2 signals -> nil)
		{
			name:    "title only (1 signal) returns nil",
			body:    `<html><head>` + titleSignal + `</head></html>`,
			wantNil: true,
		},
		{
			name:    "asset only (1 signal) returns nil",
			body:    `<html><head>` + assetSignal + `</head></html>`,
			wantNil: true,
		},
		{
			name:    "bootstrap marker only (1 signal) returns nil",
			body:    `<html><body>` + fabSignal + `</body></html>`,
			wantNil: true,
		},
		{
			name:    "empty body returns nil",
			body:    "",
			wantNil: true,
		},
		{
			name:    "non-HTML body with no signals returns nil",
			body:    "plain text response",
			wantNil: true,
		},
		{
			name:    "benign page mentioning superset in prose only returns nil",
			body:    `<html><head><title>Blog</title></head><body><p>We evaluated Apache Superset last week but chose Metabase.</p></body></html>`,
			wantNil: true,
		},
		{
			name:    "nil response returns nil (no panic, not from empty-body guard)",
			body:    `<html><head>` + titleSignal + assetSignal + `</head><body>` + fabSignal + `</body></html>`,
			wantNil: true,
			nilResp: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SupersetFingerprinter{}
			var resp *http.Response
			if !tt.nilResp {
				resp = &http.Response{
					Header: http.Header{"Content-Type": []string{"text/html"}},
				}
			}
			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, "superset", result.Technology)
			assert.Equal(t, "", result.Version)
			require.Len(t, result.CPEs, 1)
			assert.Equal(t, wantCPE, result.CPEs[0])
			assert.Equal(t, "/login/", result.Metadata["login_path"])
			assert.Equal(t, plugins.SeverityHigh, result.Severity)
		})
	}
}

func TestSupersetFingerprinter_Fingerprint_ActiveProbe(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantNil     bool
		wantVersion string
		wantCPE     string
	}{
		{
			name:        "valid version 4.0.1 from /api/v1/info",
			body:        `{"status_code": 200, "result": {"version": "4.0.1", "permissions": ["can_read"]}}`,
			wantVersion: "4.0.1",
			wantCPE:     "cpe:2.3:a:apache:superset:4.0.1:*:*:*:*:*:*:*",
		},
		{
			name:        "valid version 3.1.0 from /api/v1/info",
			body:        `{"status_code": 200, "result": {"version": "3.1.0", "permissions": ["can_read"]}}`,
			wantVersion: "3.1.0",
			wantCPE:     "cpe:2.3:a:apache:superset:3.1.0:*:*:*:*:*:*:*",
		},
		{
			name:    "non-200 status code returns nil",
			body:    `{"status_code": 401, "result": {"version": "4.0.1"}}`,
			wantNil: true,
		},
		{
			name:    "empty version field returns nil",
			body:    `{"status_code": 200, "result": {"version": ""}}`,
			wantNil: true,
		},
		{
			name:        "version too long (>16 chars) sanitized to empty -> result with wildcard CPE",
			body:        `{"status_code": 200, "result": {"version": "1.2.3.4.5.6.7.8.9", "permissions": ["can_read"]}}`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:apache:superset:*:*:*:*:*:*:*:*",
		},
		{
			name:        "version with special characters sanitized to empty -> result with wildcard CPE",
			body:        `{"status_code": 200, "result": {"version": "4.0.1; rm -rf /", "permissions": ["can_read"]}}`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:apache:superset:*:*:*:*:*:*:*:*",
		},
		{
			name:        "non-semver version sanitized to empty -> result with wildcard CPE",
			body:        `{"status_code": 200, "result": {"version": "4.0", "permissions": ["can_read"]}}`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:apache:superset:*:*:*:*:*:*:*:*",
		},
		{
			name:    "missing permissions returns nil (generic FAB false positive prevention)",
			body:    `{"status_code": 200, "result": {"version": "4.0.1"}}`,
			wantNil: true,
		},
		{
			name:    "empty permissions array returns nil",
			body:    `{"status_code": 200, "result": {"version": "4.0.1", "permissions": []}}`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SupersetFingerprinter{}
			resp := &http.Response{
				Header: http.Header{"Content-Type": []string{"application/json"}},
			}
			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			if tt.wantNil {
				assert.Nil(t, result)
				return
			}
			require.NotNil(t, result)
			assert.Equal(t, "superset", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			require.Len(t, result.CPEs, 1)
			assert.Equal(t, tt.wantCPE, result.CPEs[0])
			assert.Equal(t, "/login/", result.Metadata["login_path"])
			assert.Equal(t, plugins.SeverityHigh, result.Severity)
		})
	}
}

func TestSanitizeSupersetVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
	}{
		{name: "valid semver 4.0.1", input: "4.0.1", want: "4.0.1"},
		{name: "valid semver 3.1.0", input: "3.1.0", want: "3.1.0"},
		{name: "hyphen suffix (not pure semver) returns empty", input: "1.0.0-beta", want: ""},
		{name: "too long (>16 chars) returns empty", input: "1.2.3.4.5.6.7.8.9", want: ""},
		{name: "special chars returns empty", input: "4.0.1; rm -rf /", want: ""},
		{name: "non-semver (two parts) returns empty", input: "4.0", want: ""},
		{name: "non-semver (four parts) returns empty", input: "4.0.1.2", want: ""},
		{name: "empty string returns empty", input: "", want: ""},
		{name: "alpha only (not semver) returns empty", input: "latest", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeSupersetVersion(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildSupersetCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "with version 4.0.1",
			version: "4.0.1",
			want:    "cpe:2.3:a:apache:superset:4.0.1:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:apache:superset:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildSupersetCPE(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}
