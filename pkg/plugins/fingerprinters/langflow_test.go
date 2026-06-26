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
	"bytes"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// makeLangflowResp builds a minimal *http.Response for Langflow tests.
// Set requestPath to a non-empty string to attach a Request with that URL path.
func makeLangflowResp(statusCode int, contentType, requestPath string) *http.Response {
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
	}
	if contentType != "" {
		resp.Header.Set("Content-Type", contentType)
	}
	if requestPath != "" {
		resp.Request = &http.Request{
			URL: &url.URL{Path: requestPath},
		}
	}
	return resp
}

// ── Name / ProbeEndpoint / ProbeAccept ───────────────────────────────────────

func TestLangflowFingerprinter_Name(t *testing.T) {
	fp := &LangflowFingerprinter{}
	assert.Equal(t, "langflow", fp.Name())
}

func TestLangflowFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &LangflowFingerprinter{}
	assert.Equal(t, "/api/v1/version", fp.ProbeEndpoint())
}

func TestLangflowFingerprinter_ProbeAccept(t *testing.T) {
	fp := &LangflowFingerprinter{}
	assert.Equal(t, "application/json", fp.ProbeAccept())
}

func TestLangflowHTMLFingerprinter_Name(t *testing.T) {
	fp := &LangflowHTMLFingerprinter{}
	assert.Equal(t, "langflow-html", fp.Name())
}

// ── Match: LangflowFingerprinter ─────────────────────────────────────────────

func TestLangflowFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		requestPath string
		want        bool
	}{
		{
			name:        "200 application/json returns true",
			statusCode:  200,
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "301 application/json returns true",
			statusCode:  301,
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "404 application/json returns true",
			statusCode:  404,
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "499 application/json returns true",
			statusCode:  499,
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "500 returns false",
			statusCode:  500,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "100 informational returns false",
			statusCode:  100,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "200 text/html without probe path returns false",
			statusCode:  200,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "200 probe path /api/v1/version returns true regardless of content-type",
			statusCode:  200,
			contentType: "text/plain",
			requestPath: "/api/v1/version",
			want:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &LangflowFingerprinter{}
			resp := makeLangflowResp(tt.statusCode, tt.contentType, tt.requestPath)
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Match: LangflowHTMLFingerprinter ─────────────────────────────────────────

func TestLangflowHTMLFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 text/html returns true",
			statusCode:  200,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "301 text/html returns true",
			statusCode:  301,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "404 text/html returns true",
			statusCode:  404,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "499 text/html returns true",
			statusCode:  499,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "500 text/html returns false",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "100 informational returns false",
			statusCode:  100,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "200 application/json returns false",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &LangflowHTMLFingerprinter{}
			resp := makeLangflowResp(tt.statusCode, tt.contentType, "")
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint: LangflowFingerprinter positive detection ────────────────────

func TestLangflowFingerprinter_Fingerprint_Positive(t *testing.T) {
	fp := &LangflowFingerprinter{}

	t.Run("standard Langflow response detects with version 1.6.0", func(t *testing.T) {
		resp := makeLangflowResp(200, "application/json", "/api/v1/version")
		body := []byte(`{"version":"1.6.0","main_version":"1.6.0","package":"Langflow"}`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "langflow", result.Technology)
		assert.Equal(t, "1.6.0", result.Version)
	})

	t.Run("Langflow Base package variant is detected", func(t *testing.T) {
		// langflowPackageMarker is `"Langflow` (no closing quote), so "Langflow Base"
		// contains that prefix and is detected as a Langflow instance.
		resp := makeLangflowResp(200, "application/json", "/api/v1/version")
		body := []byte(`{"version":"1.6.0","main_version":"1.6.0","package":"Langflow Base"}`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "langflow", result.Technology)
		assert.Equal(t, "1.6.0", result.Version)
	})

	t.Run("Langflow Nightly package variant is detected", func(t *testing.T) {
		// langflowPackageMarker is `"Langflow` (no closing quote), so "Langflow Nightly"
		// contains that prefix and is detected as a Langflow instance.
		resp := makeLangflowResp(200, "application/json", "/api/v1/version")
		body := []byte(`{"version":"1.7.0","main_version":"1.7.0","package":"Langflow Nightly"}`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "langflow", result.Technology)
		assert.Equal(t, "1.7.0", result.Version)
	})
}

// ── Fingerprint: LangflowHTMLFingerprinter positive detection ────────────────

func TestLangflowHTMLFingerprinter_Fingerprint_Positive(t *testing.T) {
	fp := &LangflowHTMLFingerprinter{}

	t.Run("exact title tag Langflow detects", func(t *testing.T) {
		resp := makeLangflowResp(200, "text/html", "")
		body := []byte(`<html><head><title>Langflow</title></head></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "langflow", result.Technology)
	})

	t.Run("title tag with surrounding whitespace detects", func(t *testing.T) {
		resp := makeLangflowResp(200, "text/html", "")
		body := []byte(`<html><head><title> Langflow </title></head></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "langflow", result.Technology)
	})
}

// ── Fingerprint: LangflowFingerprinter negative/rejection tests ──────────────

func TestLangflowFingerprinter_Fingerprint_Negative(t *testing.T) {
	fp := &LangflowFingerprinter{}

	tests := []struct {
		name        string
		statusCode  int
		body        []byte
		requestPath string
	}{
		{
			name:        "status 500 returns nil",
			statusCode:  500,
			requestPath: "/api/v1/version",
			body:        []byte(`{"version":"1.6.0","main_version":"1.6.0","package":"Langflow"}`),
		},
		{
			name:        "status 100 returns nil",
			statusCode:  100,
			requestPath: "/api/v1/version",
			body:        []byte(`{"version":"1.6.0","main_version":"1.6.0","package":"Langflow"}`),
		},
		{
			name:        "empty body returns nil",
			statusCode:  200,
			requestPath: "/api/v1/version",
			body:        []byte{},
		},
		{
			name:        "body larger than 2 MiB returns nil",
			statusCode:  200,
			requestPath: "/api/v1/version",
			body:        bytes.Repeat([]byte("a"), 2*1024*1024+1),
		},
		{
			name:        "wrong path returns nil",
			statusCode:  200,
			requestPath: "/api/v2/info",
			body:        []byte(`{"version":"1.6.0","main_version":"1.6.0","package":"Langflow"}`),
		},
		{
			name:        "body without Langflow marker returns nil",
			statusCode:  200,
			requestPath: "/api/v1/version",
			body:        []byte(`{"version":"1.0.0","status":"ok"}`),
		},
		{
			name:        "Flowise response without package field returns nil",
			statusCode:  200,
			requestPath: "/api/v1/version",
			body:        []byte(`{"version":"3.1.2"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeLangflowResp(tt.statusCode, "application/json", tt.requestPath)
			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ── Fingerprint: LangflowHTMLFingerprinter negative tests ────────────────────

func TestLangflowHTMLFingerprinter_Fingerprint_Negative(t *testing.T) {
	fp := &LangflowHTMLFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		body       []byte
	}{
		{
			name:       "status 500 returns nil",
			statusCode: 500,
			body:       []byte(`<html><head><title>Langflow</title></head></html>`),
		},
		{
			name:       "status 100 returns nil",
			statusCode: 100,
			body:       []byte(`<html><head><title>Langflow</title></head></html>`),
		},
		{
			name:       "empty body returns nil",
			statusCode: 200,
			body:       []byte{},
		},
		{
			name:       "body larger than 2 MiB returns nil",
			statusCode: 200,
			body:       bytes.Repeat([]byte("a"), 2*1024*1024+1),
		},
		{
			name:       "generic HTML without Langflow title returns nil",
			statusCode: 200,
			body:       []byte(`<html><head><title>Welcome to My App</title></head></html>`),
		},
		{
			name:       "Langflow in paragraph text but not title returns nil",
			statusCode: 200,
			body:       []byte(`<html><head><title>Dashboard</title></head><body><p>Powered by Langflow</p></body></html>`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeLangflowResp(tt.statusCode, "text/html", "")
			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ── Version extraction ────────────────────────────────────────────────────────

func TestExtractLangflowVersion(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{
			name: "main_version preferred over version field",
			body: []byte(`{"version":"1.5.0","main_version":"1.6.0","package":"Langflow"}`),
			want: "1.6.0",
		},
		{
			name: "only version field (no main_version) falls back to version",
			body: []byte(`{"version":"1.6.0","package":"Langflow"}`),
			want: "1.6.0",
		},
		{
			name: "both fields absent yields empty string",
			body: []byte(`{"package":"Langflow"}`),
			want: "",
		},
		{
			name: "invalid main_version falls back to version field",
			body: []byte(`{"version":"1.6.0","main_version":"invalid","package":"Langflow"}`),
			want: "1.6.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLangflowVersion(tt.body)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── CPE building ──────────────────────────────────────────────────────────────

func TestBuildLangflowCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "version 1.6.0 yields versioned CPE",
			version: "1.6.0",
			want:    "cpe:2.3:a:langflow:langflow:1.6.0:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version yields wildcard CPE",
			version: "",
			want:    "cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildLangflowCPE(tt.version))
		})
	}
}

// ── Severity tests ────────────────────────────────────────────────────────────

func TestLangflowFingerprinter_Fingerprint_Severity(t *testing.T) {
	fp := &LangflowFingerprinter{}
	resp := makeLangflowResp(200, "application/json", "/api/v1/version")
	body := []byte(`{"version":"1.6.0","main_version":"1.6.0","package":"Langflow"}`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, plugins.SeverityHigh, result.Severity)
}

func TestLangflowHTMLFingerprinter_Fingerprint_Severity(t *testing.T) {
	fp := &LangflowHTMLFingerprinter{}
	resp := makeLangflowResp(200, "text/html", "")
	body := []byte(`<html><head><title>Langflow</title></head></html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	// HTML detection carries no severity — exposure is lower confidence
	assert.Empty(t, result.Severity)
}

// ── Metadata tests ────────────────────────────────────────────────────────────

func TestLangflowFingerprinter_Fingerprint_Metadata(t *testing.T) {
	fp := &LangflowFingerprinter{}
	resp := makeLangflowResp(200, "application/json", "/api/v1/version")
	body := []byte(`{"version":"1.6.0","main_version":"1.6.0","package":"Langflow"}`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "Langflow", result.Metadata["vendor"])
	assert.Equal(t, "Langflow", result.Metadata["product"])
	assert.Equal(t, "active_probe", result.Metadata["detection_method"])
	assert.Equal(t, "/api/v1/version", result.Metadata["probe_path"])
}

func TestLangflowHTMLFingerprinter_Fingerprint_Metadata(t *testing.T) {
	fp := &LangflowHTMLFingerprinter{}
	resp := makeLangflowResp(200, "text/html", "")
	body := []byte(`<html><head><title>Langflow</title></head></html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "Langflow", result.Metadata["vendor"])
	assert.Equal(t, "Langflow", result.Metadata["product"])
	assert.Equal(t, "html_title", result.Metadata["detection_method"])
}

// ── Integration: Match + Fingerprint round-trip ───────────────────────────────

func TestLangflowFingerprinter_Integration(t *testing.T) {
	fp := &LangflowFingerprinter{}

	t.Run("active probe round-trip with version 1.6.0", func(t *testing.T) {
		resp := makeLangflowResp(200, "application/json", "/api/v1/version")
		body := []byte(`{"version":"1.6.0","main_version":"1.6.0","package":"Langflow"}`)

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "langflow", result.Technology)
		assert.Equal(t, "1.6.0", result.Version)
		assert.Equal(t, "cpe:2.3:a:langflow:langflow:1.6.0:*:*:*:*:*:*:*", result.CPEs[0])
		assert.Equal(t, plugins.SeverityHigh, result.Severity)
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
	})
}

func TestLangflowHTMLFingerprinter_Integration(t *testing.T) {
	fp := &LangflowHTMLFingerprinter{}

	t.Run("HTML title round-trip yields wildcard CPE and no severity", func(t *testing.T) {
		resp := makeLangflowResp(200, "text/html", "")
		body := []byte(`<!DOCTYPE html><html><head><title>Langflow</title></head><body></body></html>`)

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "langflow", result.Technology)
		assert.Equal(t, "", result.Version)
		assert.Equal(t, "cpe:2.3:a:langflow:langflow:*:*:*:*:*:*:*:*", result.CPEs[0])
		assert.Empty(t, result.Severity)
	})
}
