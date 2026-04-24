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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDoccanoFingerprinter_Name(t *testing.T) {
	fp := &DoccanoFingerprinter{}
	assert.Equal(t, "doccano", fp.Name())
}

func TestDoccanoFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		nilResp     bool
		expected    bool
	}{
		{name: "matches text/html", contentType: "text/html", expected: true},
		{name: "matches text/html with charset", contentType: "text/html; charset=utf-8", expected: true},
		{name: "matches application/xhtml+xml", contentType: "application/xhtml+xml", expected: true},
		{name: "matches empty content type", contentType: "", expected: true},
		{name: "does not match application/json", contentType: "application/json", expected: false},
		{name: "does not match text/plain", contentType: "text/plain", expected: false},
		{name: "nil response returns false (no panic)", nilResp: true, expected: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &DoccanoFingerprinter{}
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

func TestDoccanoFingerprinter_Fingerprint(t *testing.T) {
	const (
		metaDesc    = `<meta name="description" content="doccano is an open source annotation tools for machine learning practitioner.">`
		nuxtDiv     = `<div id="__nuxt"></div>`
		nuxtRuntime = `<script>window.__NUXT__={}</script>`
		wantCPE     = "cpe:2.3:a:doccano:doccano:*:*:*:*:*:*:*:*"
	)

	tests := []struct {
		name     string
		body     string
		wantNil  bool
		nilResp  bool
	}{
		// Positive rows (≥2 signals → detect)
		{
			name: "full realistic body with all 4 signals",
			body: `<!doctype html><html><head><meta charset="utf-8">` + metaDesc +
				`<title>doccano - doccano</title></head><body>` + nuxtDiv + nuxtRuntime + `</body></html>`,
		},
		{
			name: "title + meta description (2 signals)",
			body: `<html><head><title>doccano</title>` + metaDesc + `</head></html>`,
		},
		{
			name: "title + id nuxt container (2 signals)",
			body: `<html><head><title>doccano</title></head><body>` + nuxtDiv + `</body></html>`,
		},
		{
			name: "title + window NUXT runtime (2 signals)",
			body: `<html><head><title>doccano</title></head><body>` + nuxtRuntime + `</body></html>`,
		},
		{
			name: "meta description + id nuxt (2 signals, no title)",
			body: `<html><head>` + metaDesc + `</head><body>` + nuxtDiv + `</body></html>`,
		},
		{
			name: "meta description + window NUXT (2 signals, no title/id)",
			body: `<html><head>` + metaDesc + `</head><body>` + nuxtRuntime + `</body></html>`,
		},
		{
			name: "case-insensitive title + meta description",
			body: `<html><head><TITLE>DOCCANO</TITLE>` +
				`<meta name="description" content="Doccano is an Open Source Annotation Tools for Machine Learning Practitioner">` +
				`</head></html>`,
		},
		// Negative rows (< 2 signals → nil)
		{
			name:    "title only (1 signal) returns nil",
			body:    `<html><head><title>doccano</title></head></html>`,
			wantNil: true,
		},
		{
			name:    "id __nuxt only (generic Nuxt, 1 signal) returns nil",
			body:    `<html><body>` + nuxtDiv + `</body></html>`,
			wantNil: true,
		},
		{
			name:    "meta description only (1 signal) returns nil",
			body:    `<html><head>` + metaDesc + `</head></html>`,
			wantNil: true,
		},
		{
			name:    "window __NUXT__ only (1 signal) returns nil",
			body:    `<html><body>` + nuxtRuntime + `</body></html>`,
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
			name:    "benign page mentioning doccano in prose only returns nil",
			body:    `<html><head><title>Blog</title></head><body><p>We evaluated doccano last week but chose Label Studio.</p></body></html>`,
			wantNil: true,
		},
		{
			name:    "nil response returns nil (no panic)",
			body:    "",
			wantNil: true,
			nilResp: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &DoccanoFingerprinter{}
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
			assert.Equal(t, "doccano", result.Technology)
			assert.Equal(t, "", result.Version)
			require.Len(t, result.CPEs, 1)
			assert.Equal(t, wantCPE, result.CPEs[0])
			assert.Equal(t, "nuxt", result.Metadata["frontend"])
			assert.Equal(t, "/auth/login", result.Metadata["login_path"])
		})
	}
}
