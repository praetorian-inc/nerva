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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Name / ProbeEndpoint / ProbeAccept ───────────────────────────────────────

func TestLiteLLMFingerprinter_Name(t *testing.T) {
	fp := &LiteLLMFingerprinter{}
	assert.Equal(t, "litellm", fp.Name())
}

func TestLiteLLMFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &LiteLLMFingerprinter{}
	assert.Equal(t, "/health/liveliness", fp.ProbeEndpoint())
}

func TestLiteLLMFingerprinter_ProbeAccept(t *testing.T) {
	fp := &LiteLLMFingerprinter{}
	assert.Equal(t, "*/*", fp.ProbeAccept())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestLiteLLMFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		headers     map[string]string
		want        bool
	}{
		{
			name:        "200 application/json returns true",
			statusCode:  200,
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "200 text/html returns true",
			statusCode:  200,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "200 text/plain returns true",
			statusCode:  200,
			contentType: "text/plain",
			want:        true,
		},
		{
			name:        "200 with X-Litellm-Version header returns true regardless of content-type",
			statusCode:  200,
			contentType: "application/octet-stream",
			headers:     map[string]string{"X-Litellm-Version": "1.55.8"},
			want:        true,
		},
		{
			name:        "200 application/octet-stream without x-litellm headers returns false",
			statusCode:  200,
			contentType: "application/octet-stream",
			want:        false,
		},
		{
			name:        "500 text/plain returns false",
			statusCode:  500,
			contentType: "text/plain",
			want:        false,
		},
		{
			name:        "100 informational returns false",
			statusCode:  100,
			contentType: "application/json",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &LiteLLMFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Signal 1: X-Litellm-* headers ────────────────────────────────────────────

func TestLiteLLMFingerprinter_Fingerprint_HeaderSignal(t *testing.T) {
	fp := &LiteLLMFingerprinter{}

	t.Run("X-Litellm-Version header present yields detected with version and response_header method", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("X-Litellm-Version", "1.55.8")

		result, err := fp.Fingerprint(resp, []byte("{}"))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "response_header", result.Metadata["detection_method"])
		assert.Equal(t, "1.55.8", result.Version)
	})

	t.Run("X-Litellm-Call-Id and X-Litellm-Model-Id without version yields detected with empty version", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("X-Litellm-Call-Id", "abc-123")
		resp.Header.Set("X-Litellm-Model-Id", "gpt-4")

		result, err := fp.Fingerprint(resp, []byte("{}"))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "response_header", result.Metadata["detection_method"])
		assert.Equal(t, "", result.Version)
	})

	t.Run("X-Litellm-Version with active probe path yields active_probe detection method", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/health/liveliness"},
			},
		}
		resp.Header.Set("X-Litellm-Version", "1.55.8")

		result, err := fp.Fingerprint(resp, []byte("I'm alive!"))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
	})

	t.Run("X-Litellm-Version with invalid version abc.def.ghi yields detected but empty version", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("X-Litellm-Version", "abc.def.ghi")

		result, err := fp.Fingerprint(resp, []byte("{}"))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "", result.Version)
	})

	t.Run("X-Litellm-Version 1.55.8-beta yields version extracted as 1.55.8 with pre-release stripped", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("X-Litellm-Version", "1.55.8-beta")

		result, err := fp.Fingerprint(resp, []byte("{}"))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "1.55.8", result.Version)
	})
}

// ── Signal 2: Liveliness response ────────────────────────────────────────────

func TestLiteLLMFingerprinter_Fingerprint_LivelinessSignal(t *testing.T) {
	fp := &LiteLLMFingerprinter{}

	t.Run("body I'm alive! with /health/liveliness path yields detected with active_probe method", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/health/liveliness"},
			},
		}

		result, err := fp.Fingerprint(resp, []byte("I'm alive!"))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
		assert.Equal(t, "/health/liveliness", result.Metadata["probe_path"])
	})

	t.Run("body I'm alive! without /health/liveliness path is NOT detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/"},
			},
		}

		result, err := fp.Fingerprint(resp, []byte("I'm alive!"))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("body OK with /health/liveliness path is NOT detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/health/liveliness"},
			},
		}

		result, err := fp.Fingerprint(resp, []byte("OK"))
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

// ── Signal 3: JSON field names ────────────────────────────────────────────────

func TestLiteLLMFingerprinter_Fingerprint_JSONSignal(t *testing.T) {
	fp := &LiteLLMFingerprinter{}

	t.Run("body contains litellm_params field yields detected with json_field method", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`{"litellm_params":{"model":"gpt-4","api_key":"sk-xxx"}}`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "json_field", result.Metadata["detection_method"])
	})

	t.Run("body contains owned_by:litellm-provider without space yields detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`{"data":[{"id":"gpt-4","owned_by":"litellm-provider"}]}`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "json_field", result.Metadata["detection_method"])
	})

	t.Run("body contains owned_by: litellm-provider with space yields detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`{"data":[{"id":"gpt-4","owned_by": "litellm-provider"}]}`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "json_field", result.Metadata["detection_method"])
	})

	t.Run("body contains owned_by:openai is NOT detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`{"data":[{"id":"gpt-4","owned_by":"openai"}]}`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

// ── Signal 4: HTML branding ───────────────────────────────────────────────────

func TestLiteLLMFingerprinter_Fingerprint_HTMLSignal(t *testing.T) {
	fp := &LiteLLMFingerprinter{}

	t.Run("title LiteLLM Admin Panel plus href=/ui/dashboard yields detected with html_branding method", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head><title>LiteLLM Admin Panel</title></head><body><a href="/ui/dashboard">Dashboard</a></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "html_branding", result.Metadata["detection_method"])
	})

	t.Run("title LiteLLM Admin Panel without /ui path is NOT detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head><title>LiteLLM Admin Panel</title></head><body><a href="/dashboard">Dashboard</a></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("title AI Blog with href=/ui/something is NOT detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head><title>AI Blog</title></head><body><a href="/ui/something">Link</a></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

// ── Negative cases ────────────────────────────────────────────────────────────

func TestLiteLLMFingerprinter_Fingerprint_NegativeCases(t *testing.T) {
	fp := &LiteLLMFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		body       []byte
		header     http.Header
	}{
		{
			name:       "generic JSON status ok returns nil",
			statusCode: 200,
			body:       []byte(`{"status":"ok"}`),
			header:     make(http.Header),
		},
		{
			name:       "generic HTML page returns nil",
			statusCode: 200,
			body:       []byte(`<html><head><title>Welcome</title></head><body><p>Hello world</p></body></html>`),
			header:     make(http.Header),
		},
		{
			name:       "prose mention of LiteLLM in body paragraph but not in title returns nil",
			statusCode: 200,
			body:       []byte(`<html><head><title>Blog Post</title></head><body><p>LiteLLM is a great tool for routing.</p></body></html>`),
			header:     make(http.Header),
		},
		{
			name:       "status 500 with X-Litellm-Version header returns nil",
			statusCode: 500,
			body:       []byte(`{"error":"internal server error"}`),
			header: func() http.Header {
				h := make(http.Header)
				h.Set("X-Litellm-Version", "1.55.8")
				return h
			}(),
		},
		{
			name:       "empty body returns nil",
			statusCode: 200,
			body:       []byte(``),
			header:     make(http.Header),
		},
		{
			name:       "body larger than 2 MiB returns nil",
			statusCode: 200,
			body:       []byte(strings.Repeat("a", 2*1024*1024+1)),
			header:     make(http.Header),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.header,
			}

			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ── CPE building ──────────────────────────────────────────────────────────────

func TestBuildLiteLLMCPE(t *testing.T) {
	t.Run("empty version yields wildcard CPE", func(t *testing.T) {
		assert.Equal(t, "cpe:2.3:a:berriai:litellm:*:*:*:*:*:*:*:*", buildLiteLLMCPE(""))
	})

	t.Run("version 1.55.8 yields versioned CPE", func(t *testing.T) {
		assert.Equal(t, "cpe:2.3:a:berriai:litellm:1.55.8:*:*:*:*:*:*:*", buildLiteLLMCPE("1.55.8"))
	})
}

// ── Integration: Match + Fingerprint round-trip ───────────────────────────────

func TestLiteLLMFingerprinter_Integration(t *testing.T) {
	fp := &LiteLLMFingerprinter{}

	t.Run("full response with X-Litellm-Version header and active probe path yields full metadata", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/health/liveliness"},
			},
		}
		resp.Header.Set("X-Litellm-Version", "1.55.8")
		resp.Header.Set("Content-Type", "text/plain")

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, []byte("I'm alive!"))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "litellm", result.Technology)
		assert.Equal(t, "BerriAI", result.Metadata["vendor"])
		assert.Equal(t, "LiteLLM", result.Metadata["product"])
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
		assert.Equal(t, "1.55.8", result.Version)
		assert.Equal(t, "/health/liveliness", result.Metadata["probe_path"])
		assert.NotEmpty(t, result.Metadata["litellm_headers"])
	})

	t.Run("JSON response with litellm_params field and no headers yields json_field detection", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "application/json")
		body := []byte(`{"litellm_params":{"model":"claude-3","api_key":"sk-xxx"},"data":[]}`)

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "litellm", result.Technology)
		assert.Equal(t, "json_field", result.Metadata["detection_method"])
	})
}
