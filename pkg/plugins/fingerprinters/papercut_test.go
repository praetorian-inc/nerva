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

// ── Name / ProbeEndpoint ─────────────────────────────────────────────────────

func TestPaperCutFingerprinter_Name(t *testing.T) {
	fp := &PaperCutFingerprinter{}
	assert.Equal(t, "papercut", fp.Name())
}

func TestPaperCutFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &PaperCutFingerprinter{}
	assert.Equal(t, "/app", fp.ProbeEndpoint())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestPaperCutFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 text/html → true",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "404 text/html → true",
			statusCode:  404,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "499 text/html → true",
			statusCode:  499,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "500 text/html → false",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "200 application/json → false",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:       "200 no content-type → false",
			statusCode: 200,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PaperCutFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint ────────────────────────────────────────────────────────────────

func TestPaperCutFingerprinter_Fingerprint(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		wantResult bool
	}{
		{
			name:       "positive: title contains PaperCut Login",
			statusCode: 200,
			body:       `<html><head><title>PaperCut Login</title></head><body></body></html>`,
			wantResult: true,
		},
		{
			name:       "positive: title contains PaperCut MF variant",
			statusCode: 200,
			body:       `<html><head><title>PaperCut MF</title></head><body></body></html>`,
			wantResult: true,
		},
		{
			name:       "positive: body corroborated - papercut + tapestry service page pattern, no title",
			statusCode: 200,
			body:       `<html><body><a href="/app?service=page/Login">Login to papercut</a></body></html>`,
			wantResult: true,
		},
		{
			name:       "negative: body contains papercut alone, no tapestry pattern, no title",
			statusCode: 200,
			body:       `<html><body>This site mentions papercut in passing.</body></html>`,
			wantResult: false,
		},
		{
			name:       "negative: status 500",
			statusCode: 500,
			body:       `<html><head><title>PaperCut Login</title></head><body></body></html>`,
			wantResult: false,
		},
		{
			name:       "negative: empty body",
			statusCode: 200,
			body:       ``,
			wantResult: false,
		},
		{
			name:       "positive: mixed case title PAPERCUT Login",
			statusCode: 200,
			body:       `<html><head><title>PAPERCUT Login</title></head><body></body></html>`,
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PaperCutFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)

			if !tt.wantResult {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, "papercut", result.Technology)
			assert.Equal(t, "", result.Version)
			assert.Empty(t, result.Severity)
			assert.Empty(t, result.SecurityFindings)
			assert.Contains(t, result.CPEs, "cpe:2.3:a:papercut:papercut_mf:*:*:*:*:*:*:*:*")
			assert.Contains(t, result.CPEs, "cpe:2.3:a:papercut:papercut_ng:*:*:*:*:*:*:*:*")
		})
	}
}

// negative: content-type application/json is rejected by Match, so the real
// pipeline never invokes Fingerprint for such responses.
func TestPaperCutFingerprinter_Match_RejectsNonHTML(t *testing.T) {
	fp := &PaperCutFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	require.False(t, fp.Match(resp))
}

// TestPaperCutFingerprinter_ActiveInterface verifies that PaperCutFingerprinter
// implements ActiveHTTPFingerprinter via its ProbeEndpoint.
func TestPaperCutFingerprinter_ActiveInterface(t *testing.T) {
	var _ ActiveHTTPFingerprinter = (*PaperCutFingerprinter)(nil)
}
