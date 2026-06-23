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

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Name / ProbeEndpoint / ProbeAccept ───────────────────────────────────────

func TestAnythingLLMFingerprinter_Name(t *testing.T) {
	fp := &AnythingLLMFingerprinter{}
	assert.Equal(t, "anythingllm", fp.Name())
}

func TestAnythingLLMFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &AnythingLLMFingerprinter{}
	assert.Equal(t, "/api/utils/metrics", fp.ProbeEndpoint())
}

func TestAnythingLLMFingerprinter_ProbeAccept(t *testing.T) {
	fp := &AnythingLLMFingerprinter{}
	assert.Equal(t, "application/json", fp.ProbeAccept())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestAnythingLLMFingerprinter_Match(t *testing.T) {
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
			name:        "200 text/html returns false (not JSON)",
			statusCode:  200,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "200 text/plain returns false",
			statusCode:  200,
			contentType: "text/plain",
			want:        false,
		},
		{
			name:        "200 /api/utils/metrics path without Content-Type returns true (fast-path)",
			statusCode:  200,
			requestPath: "/api/utils/metrics",
			want:        true,
		},
		{
			name:        "200 application/octet-stream returns false",
			statusCode:  200,
			contentType: "application/octet-stream",
			want:        false,
		},
		{
			name:        "500 application/json returns false",
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AnythingLLMFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if tt.requestPath != "" {
				resp.Request = &http.Request{
					URL: &url.URL{Path: tt.requestPath},
				}
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Signal: metrics JSON ──────────────────────────────────────────────────────

// realisticMetricsBody is a representative /api/utils/metrics response body.
const realisticMetricsBody = `{"online":true,"version":"abc123def","mode":"multi-user","vectorDB":"lancedb","storage":{"free":50000000,"used":10000000,"total":60000000},"appVersion":"1.14.1"}`

func TestAnythingLLMFingerprinter_Fingerprint_MetricsSignal(t *testing.T) {
	fp := &AnythingLLMFingerprinter{}

	t.Run("full metrics JSON with vectorDB + appVersion + mode yields detected with all metadata", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/api/utils/metrics"},
			},
		}

		result, err := fp.Fingerprint(resp, []byte(realisticMetricsBody))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "1.14.1", result.Version)
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
		assert.Equal(t, "multi-user", result.Metadata["mode"])
		assert.Equal(t, "lancedb", result.Metadata["vector_db"])
		assert.Equal(t, "/api/utils/metrics", result.Metadata["probe_path"])
		assert.Equal(t, plugins.SeverityHigh, result.Severity)
	})

	t.Run("metrics JSON with vectorDB + mode but no appVersion yields detected with empty version", func(t *testing.T) {
		body := `{"online":true,"mode":"single-user","vectorDB":"chroma","storage":{}}`
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/api/utils/metrics"},
			},
		}

		result, err := fp.Fingerprint(resp, []byte(body))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "", result.Version)
		assert.Equal(t, "single-user", result.Metadata["mode"])
	})

	t.Run("metrics JSON with vectorDB + appVersion but no mode yields detected", func(t *testing.T) {
		body := `{"online":true,"vectorDB":"pinecone","appVersion":"1.12.0"}`
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/api/utils/metrics"},
			},
		}

		result, err := fp.Fingerprint(resp, []byte(body))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "1.12.0", result.Version)
		_, modePresent := result.Metadata["mode"]
		assert.False(t, modePresent, "mode key should not be present when not in body")
	})

	t.Run("metrics JSON with only vectorDB (no appVersion, no mode) yields nil (insufficient signal)", func(t *testing.T) {
		body := `{"online":true,"vectorDB":"weaviate"}`
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		result, err := fp.Fingerprint(resp, []byte(body))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("metrics JSON without vectorDB yields nil (missing required field)", func(t *testing.T) {
		body := `{"online":true,"mode":"multi-user","appVersion":"1.14.1"}`
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		result, err := fp.Fingerprint(resp, []byte(body))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("metrics JSON with path NOT /api/utils/metrics yields detected with detection_method json_field", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/other/path"},
			},
		}

		result, err := fp.Fingerprint(resp, []byte(realisticMetricsBody))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "json_field", result.Metadata["detection_method"])
		_, probePath := result.Metadata["probe_path"]
		assert.False(t, probePath, "probe_path should not be set for json_field detection")
		assert.Empty(t, result.Severity, "json_field detection should not have severity")
	})
}

// ── Version extraction edge cases ────────────────────────────────────────────

func TestAnythingLLMFingerprinter_Fingerprint_VersionExtraction(t *testing.T) {
	fp := &AnythingLLMFingerprinter{}

	makeResp := func() *http.Response {
		return &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
	}

	t.Run("appVersion 1.14.1 extracts to 1.14.1", func(t *testing.T) {
		body := `{"vectorDB":"lancedb","mode":"multi-user","appVersion":"1.14.1"}`
		result, err := fp.Fingerprint(makeResp(), []byte(body))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "1.14.1", result.Version)
	})

	t.Run("appVersion 2.0.0-beta extracts to 2.0.0 (leading triple only)", func(t *testing.T) {
		body := `{"vectorDB":"lancedb","mode":"multi-user","appVersion":"2.0.0-beta"}`
		result, err := fp.Fingerprint(makeResp(), []byte(body))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "2.0.0", result.Version)
	})

	t.Run("appVersion abc.def.ghi yields empty version (no digit match)", func(t *testing.T) {
		body := `{"vectorDB":"lancedb","mode":"multi-user","appVersion":"abc.def.ghi"}`
		result, err := fp.Fingerprint(makeResp(), []byte(body))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "", result.Version)
	})

	t.Run("appVersion null yields empty version", func(t *testing.T) {
		body := `{"vectorDB":"lancedb","mode":"multi-user","appVersion":null}`
		result, err := fp.Fingerprint(makeResp(), []byte(body))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "", result.Version)
	})

	t.Run("appVersion empty string yields empty version", func(t *testing.T) {
		body := `{"vectorDB":"lancedb","mode":"multi-user","appVersion":""}`
		result, err := fp.Fingerprint(makeResp(), []byte(body))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "", result.Version)
	})

	t.Run("no appVersion field yields empty version", func(t *testing.T) {
		body := `{"vectorDB":"lancedb","mode":"multi-user"}`
		result, err := fp.Fingerprint(makeResp(), []byte(body))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "", result.Version)
	})

	t.Run("version field with semver and no appVersion yields version from version field", func(t *testing.T) {
		body := `{"vectorDB":"lancedb","mode":"multi-user","version":"1.13.0"}`
		result, err := fp.Fingerprint(makeResp(), []byte(body))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "1.13.0", result.Version)
	})

	t.Run("appVersion takes priority over version field", func(t *testing.T) {
		body := `{"vectorDB":"lancedb","mode":"multi-user","appVersion":"1.14.1","version":"1.13.0"}`
		result, err := fp.Fingerprint(makeResp(), []byte(body))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "1.14.1", result.Version)
	})

	t.Run("version field with git SHA yields empty version", func(t *testing.T) {
		body := `{"vectorDB":"lancedb","mode":"multi-user","version":"abc123def"}`
		result, err := fp.Fingerprint(makeResp(), []byte(body))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "", result.Version)
	})
}

// ── Negative cases ────────────────────────────────────────────────────────────

func TestAnythingLLMFingerprinter_Fingerprint_NegativeCases(t *testing.T) {
	fp := &AnythingLLMFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		body       []byte
	}{
		{
			name:       "generic JSON status ok returns nil",
			statusCode: 200,
			body:       []byte(`{"status":"ok"}`),
		},
		{
			name:       "JSON with only mode field returns nil (no vectorDB)",
			statusCode: 200,
			body:       []byte(`{"mode":"multi-user"}`),
		},
		{
			name:       "status 500 with valid metrics body returns nil",
			statusCode: 500,
			body:       []byte(realisticMetricsBody),
		},
		{
			name:       "empty body returns nil",
			statusCode: 200,
			body:       []byte(``),
		},
		{
			name:       "body larger than 2 MiB returns nil",
			statusCode: 200,
			body:       []byte(strings.Repeat("a", 2*1024*1024+1)),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}

			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ── CPE building ──────────────────────────────────────────────────────────────

func TestBuildAnythingLLMCPE(t *testing.T) {
	t.Run("empty version yields wildcard CPE", func(t *testing.T) {
		assert.Equal(t, "cpe:2.3:a:mintplex-labs:anythingllm:*:*:*:*:*:*:*:*", buildAnythingLLMCPE(""))
	})

	t.Run("version 1.14.1 yields versioned CPE", func(t *testing.T) {
		assert.Equal(t, "cpe:2.3:a:mintplex-labs:anythingllm:1.14.1:*:*:*:*:*:*:*", buildAnythingLLMCPE("1.14.1"))
	})
}

// ── AnythingLLMHTMLFingerprinter: Name ───────────────────────────────────────

func TestAnythingLLMHTMLFingerprinter_Name(t *testing.T) {
	fp := &AnythingLLMHTMLFingerprinter{}
	assert.Equal(t, "anythingllm-html", fp.Name())
}

// ── AnythingLLMHTMLFingerprinter: Match ──────────────────────────────────────

func TestAnythingLLMHTMLFingerprinter_Match(t *testing.T) {
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
			name:        "200 application/json returns false",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "200 text/plain returns false",
			statusCode:  200,
			contentType: "text/plain",
			want:        false,
		},
		{
			name:        "500 text/html returns false",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "100 text/html returns false",
			statusCode:  100,
			contentType: "text/html",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AnythingLLMHTMLFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", tt.contentType)
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── AnythingLLMHTMLFingerprinter: Fingerprint title signal ───────────────────

func TestAnythingLLMHTMLFingerprinter_Fingerprint_TitleSignal(t *testing.T) {
	fp := &AnythingLLMHTMLFingerprinter{}

	makeResp := func(statusCode int) *http.Response {
		return &http.Response{
			StatusCode: statusCode,
			Header:     make(http.Header),
		}
	}

	t.Run("title with og:url yields detected with login_page detection_method and og_url true", func(t *testing.T) {
		body := []byte(`<html><head><title>AnythingLLM | Your personal LLM trained on anything</title><meta property="og:url" content="https://anythingllm.com"></head><body><div id="root" class="h-screen"></div></body></html>`)
		result, err := fp.Fingerprint(makeResp(200), body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "login_page", result.Metadata["detection_method"])
		assert.Equal(t, true, result.Metadata["og_url"])
		assert.Equal(t, "anythingllm", result.Technology)
		assert.Equal(t, "", result.Version)
	})

	t.Run("title AnythingLLM without og:url yields detected without og_url key in metadata", func(t *testing.T) {
		body := []byte(`<html><head><title>AnythingLLM</title></head><body><div id="root"></div></body></html>`)
		result, err := fp.Fingerprint(makeResp(200), body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "login_page", result.Metadata["detection_method"])
		_, ogURLPresent := result.Metadata["og_url"]
		assert.False(t, ogURLPresent, "og_url key should not be present when og:url meta tag is absent")
	})

	t.Run("title anythingllm lowercase yields detected (regex is case-insensitive)", func(t *testing.T) {
		body := []byte(`<html><head><title>anythingllm admin</title></head><body></body></html>`)
		result, err := fp.Fingerprint(makeResp(200), body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "login_page", result.Metadata["detection_method"])
	})

	t.Run("title My App with no AnythingLLM yields nil", func(t *testing.T) {
		body := []byte(`<html><head><title>My App</title></head><body></body></html>`)
		result, err := fp.Fingerprint(makeResp(200), body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("AnythingLLM in body paragraph but not in title yields nil", func(t *testing.T) {
		body := []byte(`<html><head><title>AI Blog</title></head><body><p>AnythingLLM is great</p></body></html>`)
		result, err := fp.Fingerprint(makeResp(200), body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("empty body yields nil", func(t *testing.T) {
		result, err := fp.Fingerprint(makeResp(200), []byte{})
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("body larger than 2 MiB yields nil", func(t *testing.T) {
		result, err := fp.Fingerprint(makeResp(200), []byte(strings.Repeat("a", 2*1024*1024+1)))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("status 500 with valid title yields nil", func(t *testing.T) {
		body := []byte(`<html><head><title>AnythingLLM | Your personal LLM trained on anything</title></head><body></body></html>`)
		result, err := fp.Fingerprint(makeResp(500), body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("blog post title mentioning AnythingLLM mid-title yields nil (not at title start)", func(t *testing.T) {
		body := []byte(`<html><head><title>Review of AnythingLLM</title></head><body></body></html>`)
		result, err := fp.Fingerprint(makeResp(200), body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("tutorial title mentioning AnythingLLM mid-title yields nil", func(t *testing.T) {
		body := []byte(`<html><head><title>How to use AnythingLLM for your business</title></head><body></body></html>`)
		result, err := fp.Fingerprint(makeResp(200), body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("title with reversed og:url attribute order yields detected with og_url true", func(t *testing.T) {
		body := []byte(`<html><head><title>AnythingLLM | Your personal LLM trained on anything</title><meta content="https://anythingllm.com" property="og:url"></head><body></body></html>`)
		result, err := fp.Fingerprint(makeResp(200), body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, true, result.Metadata["og_url"])
	})
}

// ── AnythingLLMHTMLFingerprinter: Integration Match + Fingerprint round-trip ─

func TestAnythingLLMHTMLFingerprinter_Integration(t *testing.T) {
	fp := &AnythingLLMHTMLFingerprinter{}

	t.Run("full realistic login page yields complete detection result", func(t *testing.T) {
		body := []byte(`<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><title>AnythingLLM | Your personal LLM trained on anything</title><meta property="og:url" content="https://anythingllm.com"><meta property="og:title" content="AnythingLLM | Your personal LLM trained on anything"><link rel="icon" href="/favicon.png"><link rel="manifest" href="/manifest.json"><script type="module" crossorigin src="/index.js"></script><link rel="stylesheet" href="/index.css"></head><body><div id="root" class="h-screen"></div></body></html>`)

		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/html")

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "anythingllm", result.Technology)
		assert.Equal(t, "", result.Version)
		assert.Equal(t, "login_page", result.Metadata["detection_method"])
		assert.Equal(t, "Mintplex Labs", result.Metadata["vendor"])
		assert.Equal(t, "AnythingLLM", result.Metadata["product"])
		assert.Equal(t, true, result.Metadata["og_url"])
		assert.NotEmpty(t, result.CPEs)
		assert.Contains(t, result.CPEs[0], "cpe:2.3:a:mintplex-labs:anythingllm:")
		assert.Empty(t, result.Severity, "HTML detection should not have severity")
	})
}

// ── Integration: Match + Fingerprint round-trip ───────────────────────────────

func TestAnythingLLMFingerprinter_Integration(t *testing.T) {
	fp := &AnythingLLMFingerprinter{}

	t.Run("full metrics response with active probe path yields complete detection result", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/api/utils/metrics"},
			},
		}
		resp.Header.Set("Content-Type", "application/json")

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, []byte(realisticMetricsBody))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "anythingllm", result.Technology)
		assert.Equal(t, "Mintplex Labs", result.Metadata["vendor"])
		assert.Equal(t, "AnythingLLM", result.Metadata["product"])
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
		assert.Equal(t, "1.14.1", result.Version)
		assert.Equal(t, "multi-user", result.Metadata["mode"])
		assert.Equal(t, "lancedb", result.Metadata["vector_db"])
		assert.Equal(t, "/api/utils/metrics", result.Metadata["probe_path"])
		assert.NotEmpty(t, result.CPEs)
		assert.Equal(t, "cpe:2.3:a:mintplex-labs:anythingllm:1.14.1:*:*:*:*:*:*:*", result.CPEs[0])
		assert.Equal(t, plugins.SeverityHigh, result.Severity)
	})
}
