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

func TestMetabaseFingerprinter_Name(t *testing.T) {
	fp := &MetabaseFingerprinter{}
	assert.Equal(t, "metabase", fp.Name())
}

func TestMetabaseFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &MetabaseFingerprinter{}
	assert.Equal(t, "/api/session/properties", fp.ProbeEndpoint())
}

func TestMetabaseFingerprinter_Match(t *testing.T) {
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
			fp := &MetabaseFingerprinter{}
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

func TestMetabaseFingerprinter_Fingerprint(t *testing.T) {
	const (
		titleSignal    = `<title>Metabase</title>`
		ogSiteSignal   = `<meta property="og:site_name" content="Metabase">`
		jsBundleSignal = `<script src="/app/dist/app.bundle.js"></script>`
		wantCPE        = "cpe:2.3:a:metabase:metabase:*:*:*:*:*:*:*:*"
	)

	tests := []struct {
		name    string
		body    string
		wantNil bool
		nilResp bool
	}{
		// Positive rows (>=2 signals -> detect)
		{
			name: "title + og:site_name (2 signals)",
			body: `<html><head>` + titleSignal + ogSiteSignal + `</head></html>`,
		},
		{
			name: "title + JS bundle (2 signals)",
			body: `<html><head>` + titleSignal + `</head><body>` + jsBundleSignal + `</body></html>`,
		},
		{
			name: "og:site_name + JS bundle (2 signals, no title)",
			body: `<html><head>` + ogSiteSignal + `</head><body>` + jsBundleSignal + `</body></html>`,
		},
		{
			name: "all 3 signals present",
			body: `<!doctype html><html><head>` + titleSignal + ogSiteSignal + `</head><body>` + jsBundleSignal + `</body></html>`,
		},
		{
			name: "case-insensitive title match",
			body: `<html><head><TITLE>My METABASE Dashboard</TITLE>` + ogSiteSignal + `</head></html>`,
		},
		// Negative rows (< 2 signals -> nil)
		{
			name:    "title only (1 signal) returns nil",
			body:    `<html><head>` + titleSignal + `</head></html>`,
			wantNil: true,
		},
		{
			name:    "og:site_name only (1 signal) returns nil",
			body:    `<html><head>` + ogSiteSignal + `</head></html>`,
			wantNil: true,
		},
		{
			name:    "JS bundle only (1 signal) returns nil",
			body:    `<html><body>` + jsBundleSignal + `</body></html>`,
			wantNil: true,
		},
		{
			name:    "empty body returns nil",
			body:    "",
			wantNil: true,
		},
		{
			name:    "nil response returns nil (no panic, not from empty-body guard)",
			body:    `<html><head>` + titleSignal + ogSiteSignal + `</head><body>` + jsBundleSignal + `</body></html>`,
			wantNil: true,
			nilResp: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MetabaseFingerprinter{}
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
			assert.Equal(t, "metabase", result.Technology)
			assert.Equal(t, "", result.Version)
			require.Len(t, result.CPEs, 1)
			assert.Equal(t, wantCPE, result.CPEs[0])
			assert.Contains(t, result.CPEs[0], "metabase:metabase")
			assert.Equal(t, plugins.SeverityHigh, result.Severity)
		})
	}
}

func TestMetabaseFingerprinter_Fingerprint_ActiveProbe(t *testing.T) {
	tests := []struct {
		name               string
		body               string
		wantNil            bool
		wantVersion        string
		wantCPE            string
		wantSetupToken     bool
	}{
		{
			name:           "valid full /api/session/properties with version tag v0.48.0",
			body:           `{"version": {"tag": "v0.48.0", "date": "2023-10-01", "hash": "abc1234"}, "engines": {"postgres": {}, "mysql": {}}}`,
			wantVersion:    "0.48.0",
			wantCPE:        "cpe:2.3:a:metabase:metabase:0.48.0:*:*:*:*:*:*:*",
			wantSetupToken: false,
		},
		{
			name:           "valid with setup token present - token not in metadata",
			body:           `{"version": {"tag": "v0.47.0", "date": "2023-09-01", "hash": "def5678"}, "engines": {"postgres": {}}, "setup-token": "abc123"}`,
			wantVersion:    "0.47.0",
			wantCPE:        "cpe:2.3:a:metabase:metabase:0.47.0:*:*:*:*:*:*:*",
			wantSetupToken: true,
		},
		{
			name:    "missing engines field returns nil (Grafana false positive prevention)",
			body:    `{"version": {"tag": "v0.48.0", "date": "2023-10-01", "hash": "abc1234"}}`,
			wantNil: true,
		},
		{
			name:    "missing version field returns nil",
			body:    `{"engines": {"postgres": {}, "mysql": {}}}`,
			wantNil: true,
		},
		{
			name:    "empty JSON body returns nil",
			body:    "",
			wantNil: true,
		},
		{
			name:    "malformed JSON returns nil",
			body:    `{not valid json`,
			wantNil: true,
		},
		{
			name:        "unsanitizable version tag falls back to wildcard CPE",
			body:        `{"version": {"tag": "v1.2.3-beta", "date": "2023-10-01", "hash": "abc1234"}, "engines": {"postgres": {}}}`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:metabase:metabase:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MetabaseFingerprinter{}
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
			assert.Equal(t, "metabase", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			require.Len(t, result.CPEs, 1)
			assert.Equal(t, tt.wantCPE, result.CPEs[0])
			assert.Equal(t, plugins.SeverityHigh, result.Severity)
			assert.Equal(t, tt.wantSetupToken, result.Metadata["setup_token_present"])
			// Verify the actual token value is never stored in metadata
			_, hasToken := result.Metadata["setup-token"]
			assert.False(t, hasToken, "setup token value must never be stored in metadata")
		})
	}
}

func TestSanitizeMetabaseVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "valid semver 0.48.0", input: "0.48.0", want: "0.48.0"},
		{name: "valid semver 1.2.3", input: "1.2.3", want: "1.2.3"},
		{name: "empty string returns empty", input: "", want: ""},
		{name: "v-prefixed not semver (prefix not stripped here) returns empty", input: "v0.48.0", want: ""},
		{name: "non-semver (two parts) returns empty", input: "0.48", want: ""},
		{name: "injection attempt returns empty", input: "1.2.3; DROP TABLE", want: ""},
		{name: "too long returns empty", input: "a]]]]]]]]]]]]]]]]]", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeMetabaseVersion(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestBuildMetabaseCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "with version 0.48.0",
			version: "0.48.0",
			want:    "cpe:2.3:a:metabase:metabase:0.48.0:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:metabase:metabase:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildMetabaseCPE(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}
