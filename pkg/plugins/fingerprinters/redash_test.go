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

func TestRedashFingerprinter_Name(t *testing.T) {
	fp := &RedashFingerprinter{}
	assert.Equal(t, "redash", fp.Name())
}

func TestRedashFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &RedashFingerprinter{}
	assert.Equal(t, "/api/session", fp.ProbeEndpoint())
}

func TestRedashFingerprinter_Match(t *testing.T) {
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
		{name: "matches application/json", contentType: "application/json", expected: true},
		{name: "matches application/xhtml+xml", contentType: "application/xhtml+xml", expected: true},
		{name: "matches empty content type", contentType: "", expected: true},
		{name: "does not match text/plain", contentType: "text/plain", expected: false},
		{name: "nil response returns false (no panic)", nilResp: true, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RedashFingerprinter{}
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

func TestRedashFingerprinter_Fingerprint(t *testing.T) {
	const (
		titleSignal     = `<title>Redash</title>`
		assetSignal     = `<link href="/static/images/redash_icon.png">`
		appMarkerSignal = `<div ng-app="redash">`
		wantCPE         = "cpe:2.3:a:redash:redash:*:*:*:*:*:*:*:*"
	)

	tests := []struct {
		name    string
		body    string
		wantNil bool
		nilResp bool
	}{
		// Positive rows (>=2 signals -> detect)
		{
			name: "title + asset path (2 signals)",
			body: `<html><head>` + titleSignal + assetSignal + `</head></html>`,
		},
		{
			name: "title + app marker (2 signals)",
			body: `<html><head>` + titleSignal + `</head><body>` + appMarkerSignal + `</body></html>`,
		},
		{
			name: "asset path + app marker (2 signals, no title)",
			body: `<html><head>` + assetSignal + `</head><body>` + appMarkerSignal + `</body></html>`,
		},
		{
			name: "all 3 signals",
			body: `<!doctype html><html><head>` + titleSignal + assetSignal + `</head><body>` + appMarkerSignal + `</body></html>`,
		},
		{
			name: "case-insensitive title + asset path",
			body: `<html><head><TITLE>My REDASH Dashboard</TITLE>` + assetSignal + `</head></html>`,
		},
		// Negative rows (< 2 signals -> nil)
		{
			name:    "title only (1 signal) returns nil",
			body:    `<html><head>` + titleSignal + `</head></html>`,
			wantNil: true,
		},
		{
			name:    "asset path only (1 signal) returns nil",
			body:    `<html><head>` + assetSignal + `</head></html>`,
			wantNil: true,
		},
		{
			name:    "app marker only (1 signal) returns nil",
			body:    `<html><body>` + appMarkerSignal + `</body></html>`,
			wantNil: true,
		},
		{
			name:    "empty body returns nil",
			body:    "",
			wantNil: true,
		},
		{
			name:    "nil response returns nil (no panic, not from empty-body guard)",
			body:    `<html><head>` + titleSignal + assetSignal + `</head><body>` + appMarkerSignal + `</body></html>`,
			wantNil: true,
			nilResp: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RedashFingerprinter{}
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
			assert.Equal(t, "redash", result.Technology)
			assert.Equal(t, "", result.Version)
			require.Len(t, result.CPEs, 1)
			assert.Equal(t, wantCPE, result.CPEs[0])
			assert.Contains(t, result.CPEs[0], "redash:redash")
			assert.Equal(t, "/login", result.Metadata["login_path"])
			assert.Equal(t, plugins.SeverityHigh, result.Severity)
		})
	}
}

func TestRedashFingerprinter_Fingerprint_ActiveProbe(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantNil     bool
		wantVersion string
		wantCPE     string
	}{
		{
			name:        "org_slug + client_config with version -> detect with version",
			body:        `{"org_slug": "default", "client_config": {"version": "10.1.0"}}`,
			wantVersion: "10.1.0",
			wantCPE:     "cpe:2.3:a:redash:redash:10.1.0:*:*:*:*:*:*:*",
		},
		{
			name:        "org_slug + csrf_token (no client_config version) -> detect with wildcard version",
			body:        `{"org_slug": "default", "csrf_token": "abc123"}`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:redash:redash:*:*:*:*:*:*:*:*",
		},
		{
			name:        "all 3 fields present -> detect",
			body:        `{"org_slug": "default", "csrf_token": "abc123", "client_config": {"version": "8.0.2"}}`,
			wantVersion: "8.0.2",
			wantCPE:     "cpe:2.3:a:redash:redash:8.0.2:*:*:*:*:*:*:*",
		},
		{
			name:    "only org_slug (1 field) -> nil (MLflow false positive prevention)",
			body:    `{"org_slug": "default"}`,
			wantNil: true,
		},
		{
			name:    "only csrf_token (1 field) -> nil",
			body:    `{"csrf_token": "abc123"}`,
			wantNil: true,
		},
		{
			name:    "only client_config (1 field) -> nil",
			body:    `{"client_config": {"version": "10.1.0"}}`,
			wantNil: true,
		},
		{
			name:    "empty JSON body -> nil",
			body:    `{}`,
			wantNil: true,
		},
		{
			name:    "malformed JSON -> nil",
			body:    `{not valid json`,
			wantNil: true,
		},
		{
			name:    "MLflow-like JSON (different fields, no org_slug/csrf_token/client_config) -> nil",
			body:    `{"experiment_id": "0", "name": "Default", "artifact_location": "mlflow-artifacts:/0"}`,
			wantNil: true,
		},
		{
			name:    "csrf_token + client_config without org_slug -> nil",
			body:    `{"csrf_token": "abc123", "client_config": {"version": "10.1.0"}}`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RedashFingerprinter{}
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
			assert.Equal(t, "redash", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			require.Len(t, result.CPEs, 1)
			assert.Equal(t, tt.wantCPE, result.CPEs[0])
			assert.Contains(t, result.CPEs[0], "redash:redash")
			assert.Equal(t, "/login", result.Metadata["login_path"])
			assert.Equal(t, plugins.SeverityHigh, result.Severity)
		})
	}
}

func TestSanitizeRedashVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "valid semver 10.1.0", input: "10.1.0", want: "10.1.0"},
		{name: "valid semver 8.0.2", input: "8.0.2", want: "8.0.2"},
		{name: "empty string returns empty", input: "", want: ""},
		{name: "non-semver (two parts) returns empty", input: "10.1", want: ""},
		{name: "injection attempt returns empty", input: "10.1.0; DROP TABLE", want: ""},
		{name: "too long (>16 chars) returns empty", input: "aaaaaaaaaaaaaaaaaaa", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeRedashVersion(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildRedashCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "with version 10.1.0",
			version: "10.1.0",
			want:    "cpe:2.3:a:redash:redash:10.1.0:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:redash:redash:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildRedashCPE(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}
