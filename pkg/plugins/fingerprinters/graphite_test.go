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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Name / ProbeEndpoint ─────────────────────────────────────────────────────

func TestGraphiteFingerprinter_Name(t *testing.T) {
	fp := &GraphiteFingerprinter{}
	assert.Equal(t, "graphite", fp.Name())
}

func TestGraphiteFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &GraphiteFingerprinter{}
	assert.Equal(t, "/version", fp.ProbeEndpoint())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestGraphiteFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 text/html → true",
			statusCode:  200,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "200 text/html charset → true",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 TEXT/HTML mixed case → true",
			statusCode:  200,
			contentType: "TEXT/HTML",
			want:        true,
		},
		{
			name:        "200 application/json → false",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "200 text/plain → false",
			statusCode:  200,
			contentType: "text/plain",
			want:        false,
		},
		{
			name:       "200 no content-type → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:        "404 text/html → false",
			statusCode:  404,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "500 text/html → false",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "302 text/html → false",
			statusCode:  302,
			contentType: "text/html",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GraphiteFingerprinter{}
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

// ── Fingerprint ──────────────────────────────────────────────────────────────

func TestGraphiteFingerprinter_Fingerprint(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantNil     bool
		wantVersion string
		wantCPE     string
	}{
		{
			name:        "valid 3-component version",
			body:        "1.1.10\n",
			wantVersion: "1.1.10",
			wantCPE:     "cpe:2.3:a:graphiteproject:graphite:1.1.10:*:*:*:*:*:*:*",
		},
		{
			name:        "valid 2-component version",
			body:        "1.1\n",
			wantVersion: "1.1",
			wantCPE:     "cpe:2.3:a:graphiteproject:graphite:1.1:*:*:*:*:*:*:*",
		},
		{
			name:        "version with leading/trailing whitespace",
			body:        "  1.5.0  \n",
			wantVersion: "1.5.0",
			wantCPE:     "cpe:2.3:a:graphiteproject:graphite:1.5.0:*:*:*:*:*:*:*",
		},
		{
			name:    "empty body",
			body:    "",
			wantNil: true,
		},
		{
			name:    "whitespace-only body",
			body:    "   \n",
			wantNil: true,
		},
		{
			name:    "HTML page body",
			body:    "<html><head><title>Not Graphite</title></head><body></body></html>",
			wantNil: true,
		},
		{
			name:    "JSON body",
			body:    `{"version": "1.1.10"}`,
			wantNil: true,
		},
		{
			name:    "version with trailing text",
			body:    "1.1.10abc",
			wantNil: true,
		},
		{
			name:    "version with leading text",
			body:    "V1.1.10",
			wantNil: true,
		},
		{
			name:    "body exactly 50 chars → rejected by length guard",
			body:    "12345678901234567890123456.12345678901234567890123",
			wantNil: true,
		},
		{
			name:        "body exactly 49 chars → passes length guard",
			body:        "1234567890123456789012345.12345678901234567890123",
			wantVersion: "1234567890123456789012345.12345678901234567890123",
			wantCPE:     "cpe:2.3:a:graphiteproject:graphite:1234567890123456789012345.12345678901234567890123:*:*:*:*:*:*:*",
		},
		{
			name:    "colon in body → rejected by regex before CPE guard",
			body:    "1:2.3",
			wantNil: true,
		},
		{
			name:    "asterisk in body → rejected by regex before CPE guard",
			body:    "1.2*3",
			wantNil: true,
		},
		{
			name:    "single number no dots",
			body:    "123",
			wantNil: true,
		},
		{
			name:    "four-component version",
			body:    "1.2.3.4",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GraphiteFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, "graphite", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.wantCPE)
			assert.Equal(t, "version_endpoint", result.Metadata["detection_method"])
			assert.Equal(t, "Graphite Project", result.Metadata["vendor"])
			assert.Equal(t, "Graphite", result.Metadata["product"])
		})
	}
}

func TestGraphiteFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &GraphiteFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	bigBody := []byte(strings.Repeat("x", 2*1024*1024+1))
	result, err := fp.Fingerprint(resp, bigBody)
	assert.Nil(t, result)
	assert.Nil(t, err)
}

// ── buildGraphiteCPE ─────────────────────────────────────────────────────────

func TestBuildGraphiteCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with version",
			version:  "1.1.10",
			expected: "cpe:2.3:a:graphiteproject:graphite:1.1.10:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version → wildcard",
			version:  "",
			expected: "cpe:2.3:a:graphiteproject:graphite:*:*:*:*:*:*:*:*",
		},
		{
			name:     "two-component version",
			version:  "1.5",
			expected: "cpe:2.3:a:graphiteproject:graphite:1.5:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildGraphiteCPE(tt.version))
		})
	}
}

// ── Integration: Match + Fingerprint ─────────────────────────────────────────

func TestGraphiteFingerprinter_Integration(t *testing.T) {
	fp := &GraphiteFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte("1.1.10\n"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "graphite", result.Technology)
	assert.Equal(t, "1.1.10", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:graphiteproject:graphite:1.1.10:*:*:*:*:*:*:*")
}

func TestGraphiteFingerprinter_Integration_NonGraphite(t *testing.T) {
	fp := &GraphiteFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte("<html><body>Hello</body></html>"))
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ── Severity / SecurityFindings ──────────────────────────────────────────────

func TestGraphiteFingerprinter_NoSeverityOrFindings(t *testing.T) {
	fp := &GraphiteFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte("1.1.10\n"))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "fingerprinter-only: Severity must be unset")
	assert.Nil(t, result.SecurityFindings, "fingerprinter-only: no SecurityFindings")
}
