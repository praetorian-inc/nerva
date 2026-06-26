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

// makeFlowiseResp builds a minimal *http.Response for Flowise tests.
// Set requestPath to a non-empty string to attach a Request with that path.
func makeFlowiseResp(statusCode int, contentType, requestPath string) *http.Response {
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

func TestFlowiseFingerprinter_Name(t *testing.T) {
	fp := &FlowiseFingerprinter{}
	assert.Equal(t, "flowise", fp.Name())
}

func TestFlowiseFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &FlowiseFingerprinter{}
	assert.Equal(t, "/api/v1/version", fp.ProbeEndpoint())
}

func TestFlowiseFingerprinter_ProbeAccept(t *testing.T) {
	fp := &FlowiseFingerprinter{}
	assert.Equal(t, "application/json", fp.ProbeAccept())
}

func TestFlowiseHTMLFingerprinter_Name(t *testing.T) {
	fp := &FlowiseHTMLFingerprinter{}
	assert.Equal(t, "flowise-html", fp.Name())
}

// ── Match: FlowiseFingerprinter ──────────────────────────────────────────────

func TestFlowiseFingerprinter_Match(t *testing.T) {
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
			fp := &FlowiseFingerprinter{}
			resp := makeFlowiseResp(tt.statusCode, tt.contentType, tt.requestPath)
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Match: FlowiseHTMLFingerprinter ─────────────────────────────────────────

func TestFlowiseHTMLFingerprinter_Match(t *testing.T) {
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
			fp := &FlowiseHTMLFingerprinter{}
			resp := makeFlowiseResp(tt.statusCode, tt.contentType, "")
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint: FlowiseFingerprinter positive detection ─────────────────────

func TestFlowiseFingerprinter_Fingerprint_Positive(t *testing.T) {
	fp := &FlowiseFingerprinter{}

	t.Run("body version 3.1.2 at /api/v1/version detects with version", func(t *testing.T) {
		resp := makeFlowiseResp(200, "application/json", "/api/v1/version")
		body := []byte(`{"version":"3.1.2"}`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "flowise", result.Technology)
		assert.Equal(t, "3.1.2", result.Version)
	})

	t.Run("body version 2.0.0 at /api/v1/version detects with version 2.0.0", func(t *testing.T) {
		resp := makeFlowiseResp(200, "application/json", "/api/v1/version")
		body := []byte(`{"version":"2.0.0"}`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "2.0.0", result.Version)
	})
}

// ── Fingerprint: FlowiseHTMLFingerprinter positive detection ──────────────────

func TestFlowiseHTMLFingerprinter_Fingerprint_Positive(t *testing.T) {
	fp := &FlowiseHTMLFingerprinter{}

	t.Run("name before content attribute order detects FlowiseAI", func(t *testing.T) {
		resp := makeFlowiseResp(200, "text/html", "")
		body := []byte(`<html><head><meta name="author" content="FlowiseAI"></head></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "flowise", result.Technology)
	})

	t.Run("content before name attribute order (reversed) detects FlowiseAI", func(t *testing.T) {
		resp := makeFlowiseResp(200, "text/html", "")
		body := []byte(`<html><head><meta content="FlowiseAI" name="author"></head></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "flowise", result.Technology)
	})
}

// ── Fingerprint: FlowiseFingerprinter negative/rejection tests ───────────────

func TestFlowiseFingerprinter_Fingerprint_Negative(t *testing.T) {
	fp := &FlowiseFingerprinter{}

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
			body:        []byte(`{"version":"3.1.2"}`),
		},
		{
			name:        "status 100 returns nil",
			statusCode:  100,
			requestPath: "/api/v1/version",
			body:        []byte(`{"version":"3.1.2"}`),
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
			body:        []byte(`{"version":"3.1.2"}`),
		},
		{
			name:        "body containing package field (Langflow) returns nil",
			statusCode:  200,
			requestPath: "/api/v1/version",
			body:        []byte(`{"version":"1.6.0","package":"Langflow"}`),
		},
		{
			name:        "Langflow response returns nil",
			statusCode:  200,
			requestPath: "/api/v1/version",
			body:        []byte(`{"version":"1.6.0","main_version":"1.6.0","package":"Langflow"}`),
		},
		{
			name:        "body with no version field returns nil",
			statusCode:  200,
			requestPath: "/api/v1/version",
			body:        []byte(`{"status":"ok"}`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeFlowiseResp(tt.statusCode, "application/json", tt.requestPath)
			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ── Fingerprint: FlowiseHTMLFingerprinter negative tests ──────────────────────

func TestFlowiseHTMLFingerprinter_Fingerprint_Negative(t *testing.T) {
	fp := &FlowiseHTMLFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		body       []byte
	}{
		{
			name:       "status 500 returns nil",
			statusCode: 500,
			body:       []byte(`<html><head><meta name="author" content="FlowiseAI"></head></html>`),
		},
		{
			name:       "status 100 returns nil",
			statusCode: 100,
			body:       []byte(`<html><head><meta name="author" content="FlowiseAI"></head></html>`),
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
			name:       "generic HTML without FlowiseAI meta tag returns nil",
			statusCode: 200,
			body:       []byte(`<html><head><title>My App</title><meta name="author" content="SomeOtherCompany"></head></html>`),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := makeFlowiseResp(tt.statusCode, "text/html", "")
			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ── Version extraction ────────────────────────────────────────────────────────

func TestExtractFlowiseVersion(t *testing.T) {
	tests := []struct {
		name string
		body []byte
		want string
	}{
		{
			name: "valid semver 3.1.2",
			body: []byte(`{"version":"3.1.2"}`),
			want: "3.1.2",
		},
		{
			name: "missing version field yields empty string",
			body: []byte(`{"status":"ok"}`),
			want: "",
		},
		{
			name: "invalid version abc yields empty string",
			body: []byte(`{"version":"abc"}`),
			want: "",
		},
		{
			name: "pre-release 3.1.2-beta extracts base semver 3.1.2",
			body: []byte(`{"version":"3.1.2-beta"}`),
			want: "3.1.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFlowiseVersion(tt.body)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── CPE building ──────────────────────────────────────────────────────────────

func TestBuildFlowiseCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "version 3.1.2 yields versioned CPE",
			version: "3.1.2",
			want:    "cpe:2.3:a:flowiseai:flowise:3.1.2:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version yields wildcard CPE",
			version: "",
			want:    "cpe:2.3:a:flowiseai:flowise:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildFlowiseCPE(tt.version))
		})
	}
}

// ── Severity tests ────────────────────────────────────────────────────────────

func TestFlowiseFingerprinter_Fingerprint_Severity(t *testing.T) {
	fp := &FlowiseFingerprinter{}
	resp := makeFlowiseResp(200, "application/json", "/api/v1/version")
	body := []byte(`{"version":"3.1.2"}`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, plugins.SeverityHigh, result.Severity)
}

func TestFlowiseHTMLFingerprinter_Fingerprint_Severity(t *testing.T) {
	fp := &FlowiseHTMLFingerprinter{}
	resp := makeFlowiseResp(200, "text/html", "")
	body := []byte(`<html><head><meta name="author" content="FlowiseAI"></head></html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	// HTML detection carries no severity — exposure is lower confidence
	assert.Empty(t, result.Severity)
}

// ── Metadata tests ────────────────────────────────────────────────────────────

func TestFlowiseFingerprinter_Fingerprint_Metadata(t *testing.T) {
	fp := &FlowiseFingerprinter{}
	resp := makeFlowiseResp(200, "application/json", "/api/v1/version")
	body := []byte(`{"version":"3.1.2"}`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "FlowiseAI", result.Metadata["vendor"])
	assert.Equal(t, "Flowise", result.Metadata["product"])
	assert.Equal(t, "active_probe", result.Metadata["detection_method"])
	assert.Equal(t, "/api/v1/version", result.Metadata["probe_path"])
}

func TestFlowiseHTMLFingerprinter_Fingerprint_Metadata(t *testing.T) {
	fp := &FlowiseHTMLFingerprinter{}
	resp := makeFlowiseResp(200, "text/html", "")
	body := []byte(`<html><head><meta name="author" content="FlowiseAI"></head></html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "FlowiseAI", result.Metadata["vendor"])
	assert.Equal(t, "Flowise", result.Metadata["product"])
	assert.Equal(t, "html_meta_tag", result.Metadata["detection_method"])
}

// ── Integration: Match + Fingerprint round-trip ───────────────────────────────

func TestFlowiseFingerprinter_Integration(t *testing.T) {
	fp := &FlowiseFingerprinter{}

	t.Run("active probe round-trip with version 3.1.2", func(t *testing.T) {
		resp := makeFlowiseResp(200, "application/json", "/api/v1/version")
		body := []byte(`{"version":"3.1.2"}`)

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "flowise", result.Technology)
		assert.Equal(t, "3.1.2", result.Version)
		assert.Equal(t, "cpe:2.3:a:flowiseai:flowise:3.1.2:*:*:*:*:*:*:*", result.CPEs[0])
		assert.Equal(t, plugins.SeverityHigh, result.Severity)
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
	})
}

func TestFlowiseHTMLFingerprinter_Integration(t *testing.T) {
	fp := &FlowiseHTMLFingerprinter{}

	t.Run("HTML meta tag round-trip yields wildcard CPE and no severity", func(t *testing.T) {
		resp := makeFlowiseResp(200, "text/html", "")
		body := []byte(`<!DOCTYPE html><html><head><meta name="author" content="FlowiseAI"><title>Flowise</title></head><body></body></html>`)

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "flowise", result.Technology)
		assert.Equal(t, "", result.Version)
		assert.Equal(t, "cpe:2.3:a:flowiseai:flowise:*:*:*:*:*:*:*:*", result.CPEs[0])
		assert.Empty(t, result.Severity)
	})
}
