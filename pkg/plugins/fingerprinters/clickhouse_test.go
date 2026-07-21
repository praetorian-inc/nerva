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

func TestClickHouseHTTPFingerprinter_Name(t *testing.T) {
	fp := &ClickHouseHTTPFingerprinter{}
	assert.Equal(t, "clickhouse-http", fp.Name())
}

func TestClickHouseHTTPFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ClickHouseHTTPFingerprinter{}
	assert.Equal(t, "/?query=SELECT+version()", fp.ProbeEndpoint())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestClickHouseHTTPFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		headers    map[string]string
		want       bool
	}{
		{
			name:       "200 with X-ClickHouse-Query-Id → true",
			statusCode: 200,
			headers:    map[string]string{"X-ClickHouse-Query-Id": "abc-123"},
			want:       true,
		},
		{
			name:       "200 with X-ClickHouse-Summary → true",
			statusCode: 200,
			headers:    map[string]string{"X-ClickHouse-Summary": "{}"},
			want:       true,
		},
		{
			name:       "403 with X-ClickHouse-Exception-Code → true",
			statusCode: 403,
			headers:    map[string]string{"X-ClickHouse-Exception-Code": "516"},
			want:       true,
		},
		{
			name:       "mixed-case header key → true",
			statusCode: 200,
			headers:    map[string]string{"x-clickhouse-server-display-name": "prod-ch-01"},
			want:       true,
		},
		{
			name:       "499 with header → true (upper bound)",
			statusCode: 499,
			headers:    map[string]string{"X-ClickHouse-Format": "TSV"},
			want:       true,
		},
		{
			name:       "200 without any ClickHouse header → false",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/plain"},
			want:       false,
		},
		{
			name:       "500 without header → false",
			statusCode: 500,
			headers:    map[string]string{},
			want:       false,
		},
		{
			name:       "500 with header → false (status out of range)",
			statusCode: 500,
			headers:    map[string]string{"X-ClickHouse-Exception-Code": "1"},
			want:       false,
		},
		{
			name:       "199 with header → false (status out of range)",
			statusCode: 199,
			headers:    map[string]string{"X-ClickHouse-Exception-Code": "1"},
			want:       false,
		},
		{
			name:       "header key present but not X-ClickHouse prefix → false",
			statusCode: 200,
			headers:    map[string]string{"X-Powered-By": "ClickHouse"},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ClickHouseHTTPFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint ──────────────────────────────────────────────────────────────

func TestClickHouseHTTPFingerprinter_Fingerprint(t *testing.T) {
	tests := []struct {
		name            string
		statusCode      int
		body            string
		wantVersion     string
		wantCPE         string
		wantDetectionBy string
	}{
		{
			name:            "200 with 4-component version",
			statusCode:      200,
			body:            "24.1.5.53\n",
			wantVersion:     "24.1.5.53",
			wantCPE:         "cpe:2.3:a:clickhouse:clickhouse:24.1.5.53:*:*:*:*:*:*:*",
			wantDetectionBy: "version_query",
		},
		{
			name:            "200 with 3-component version",
			statusCode:      200,
			body:            "24.1.5\n",
			wantVersion:     "24.1.5",
			wantCPE:         "cpe:2.3:a:clickhouse:clickhouse:24.1.5:*:*:*:*:*:*:*",
			wantDetectionBy: "version_query",
		},
		{
			name:            "200 version with leading/trailing whitespace",
			statusCode:      200,
			body:            "  24.1.5.53  \n",
			wantVersion:     "24.1.5.53",
			wantCPE:         "cpe:2.3:a:clickhouse:clickhouse:24.1.5.53:*:*:*:*:*:*:*",
			wantDetectionBy: "version_query",
		},
		{
			name:            "403 auth-required — detected, empty version",
			statusCode:      403,
			body:            "Code: 516. DB::Exception: default: Authentication failed",
			wantVersion:     "",
			wantCPE:         "cpe:2.3:a:clickhouse:clickhouse:*:*:*:*:*:*:*:*",
			wantDetectionBy: "x-clickhouse-header",
		},
		{
			name:            "200 with non-version body — detected, empty version",
			statusCode:      200,
			body:            "Code: 62. DB::Exception: Syntax error",
			wantVersion:     "",
			wantCPE:         "cpe:2.3:a:clickhouse:clickhouse:*:*:*:*:*:*:*:*",
			wantDetectionBy: "x-clickhouse-header",
		},
		{
			name:            "200 empty body — detected, empty version",
			statusCode:      200,
			body:            "",
			wantVersion:     "",
			wantCPE:         "cpe:2.3:a:clickhouse:clickhouse:*:*:*:*:*:*:*:*",
			wantDetectionBy: "x-clickhouse-header",
		},
		{
			name:            "200 version with trailing text rejected",
			statusCode:      200,
			body:            "24.1.5abc",
			wantVersion:     "",
			wantCPE:         "cpe:2.3:a:clickhouse:clickhouse:*:*:*:*:*:*:*:*",
			wantDetectionBy: "x-clickhouse-header",
		},
		{
			name:            "200 version with leading text rejected",
			statusCode:      200,
			body:            "V24.1.5",
			wantVersion:     "",
			wantCPE:         "cpe:2.3:a:clickhouse:clickhouse:*:*:*:*:*:*:*:*",
			wantDetectionBy: "x-clickhouse-header",
		},
		{
			name:            "200 two-component version rejected (below major.minor.patch)",
			statusCode:      200,
			body:            "24.1",
			wantVersion:     "",
			wantCPE:         "cpe:2.3:a:clickhouse:clickhouse:*:*:*:*:*:*:*:*",
			wantDetectionBy: "x-clickhouse-header",
		},
		{
			name:            "200 five-component version rejected",
			statusCode:      200,
			body:            "24.1.5.53.1",
			wantVersion:     "",
			wantCPE:         "cpe:2.3:a:clickhouse:clickhouse:*:*:*:*:*:*:*:*",
			wantDetectionBy: "x-clickhouse-header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ClickHouseHTTPFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			resp.Header.Set("X-ClickHouse-Query-Id", "abc-123")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "clickhouse-http", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.wantCPE)
			assert.Equal(t, tt.wantDetectionBy, result.Metadata["detection_method"])
			assert.Equal(t, "ClickHouse", result.Metadata["vendor"])
			assert.Equal(t, "ClickHouse", result.Metadata["product"])
		})
	}
}

func TestClickHouseHTTPFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &ClickHouseHTTPFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-ClickHouse-Query-Id", "abc-123")

	bigBody := []byte(strings.Repeat("2", 2*1024*1024+1))
	result, err := fp.Fingerprint(resp, bigBody)
	require.NoError(t, err)
	require.NotNil(t, result)
	// Still detected via header, but version extraction skipped due to cap.
	assert.Equal(t, "", result.Version)
	assert.Equal(t, "x-clickhouse-header", result.Metadata["detection_method"])
}

// ── buildClickHouseHTTPCPE ───────────────────────────────────────────────────

func TestBuildClickHouseHTTPCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with version",
			version:  "24.1.5.53",
			expected: "cpe:2.3:a:clickhouse:clickhouse:24.1.5.53:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version → wildcard",
			version:  "",
			expected: "cpe:2.3:a:clickhouse:clickhouse:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildClickHouseHTTPCPE(tt.version))
		})
	}
}

// ── Integration: Match + Fingerprint ─────────────────────────────────────────

func TestClickHouseHTTPFingerprinter_Integration_Unauthenticated(t *testing.T) {
	fp := &ClickHouseHTTPFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-ClickHouse-Query-Id", "abc-123")
	resp.Header.Set("X-ClickHouse-Summary", `{"read_rows":"0"}`)

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte("24.1.5.53\n"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "clickhouse-http", result.Technology)
	assert.Equal(t, "24.1.5.53", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:clickhouse:clickhouse:24.1.5.53:*:*:*:*:*:*:*")
}

func TestClickHouseHTTPFingerprinter_Integration_AuthRequired(t *testing.T) {
	fp := &ClickHouseHTTPFingerprinter{}

	resp := &http.Response{
		StatusCode: 403,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-ClickHouse-Exception-Code", "516")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte("Code: 516. DB::Exception: default: Authentication failed"))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "clickhouse-http", result.Technology)
	assert.Equal(t, "", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:clickhouse:clickhouse:*:*:*:*:*:*:*:*")
}

func TestClickHouseHTTPFingerprinter_Integration_NonClickHouse(t *testing.T) {
	fp := &ClickHouseHTTPFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	require.False(t, fp.Match(resp))
}

// ── Severity / SecurityFindings ──────────────────────────────────────────────

func TestClickHouseHTTPFingerprinter_NoSeverityOrFindings(t *testing.T) {
	fp := &ClickHouseHTTPFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-ClickHouse-Query-Id", "abc-123")

	result, err := fp.Fingerprint(resp, []byte("24.1.5.53\n"))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "fingerprinter-only: Severity must be unset")
	assert.Nil(t, result.SecurityFindings, "fingerprinter-only: no SecurityFindings")
}
