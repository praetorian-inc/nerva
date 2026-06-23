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

const realisticDifyAPIBody = `{"welcome":"Dify OpenAPI","api_version":"v1","server_version":"1.14.2"}`

const realisticDifyHTML = `<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"/><meta name="viewport" content="width=device-width,initial-scale=1"/><meta name="theme-color" content="#1C64F2"/><meta name="apple-mobile-web-app-capable" content="yes"/><meta name="apple-mobile-web-app-title" content="Dify"/><link rel="manifest" href="/manifest.json"/><link rel="icon" type="image/png" sizes="32x32" href="/icon-192x192.png"/><title>Dify</title></head><body><div id="__next"></div></body></html>`

// ── Name / ProbeEndpoint / ProbeAccept ───────────────────────────────────────

func TestDifyFingerprinter_Name(t *testing.T) {
	fp := &DifyFingerprinter{}
	assert.Equal(t, "dify", fp.Name())
}

func TestDifyFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &DifyFingerprinter{}
	assert.Equal(t, "/v1/", fp.ProbeEndpoint())
}

func TestDifyFingerprinter_ProbeAccept(t *testing.T) {
	fp := &DifyFingerprinter{}
	assert.Equal(t, "application/json", fp.ProbeAccept())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestDifyFingerprinter_Match(t *testing.T) {
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
			name:        "200 with /v1/ path and no Content-Type returns true",
			statusCode:  200,
			requestPath: "/v1/",
			want:        true,
		},
		{
			name:        "200 text/html returns false",
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
			name:        "500 application/json returns false",
			statusCode:  500,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "100 application/json returns false",
			statusCode:  100,
			contentType: "application/json",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &DifyFingerprinter{}
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

// ── Fingerprint: Active Probe Signal ─────────────────────────────────────────

func TestDifyFingerprinter_Fingerprint_ActiveProbe(t *testing.T) {
	fp := &DifyFingerprinter{}

	t.Run("body with welcome marker and server_version with /v1/ path yields detected result", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/v1/"}},
		}

		result, err := fp.Fingerprint(resp, []byte(realisticDifyAPIBody))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
		assert.Equal(t, "1.14.2", result.Version)
	})

	t.Run("body with welcome marker but no server_version with /v1/ path yields detected with empty version", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/v1/"}},
		}
		body := []byte(`{"welcome":"Dify OpenAPI","api_version":"v1"}`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "", result.Version)
	})

	t.Run("body with welcome marker and server_version but path is / yields nil (path gate)", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/"}},
		}

		result, err := fp.Fingerprint(resp, []byte(realisticDifyAPIBody))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("body without Dify OpenAPI marker with /v1/ path yields nil (no marker)", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/v1/"}},
		}
		body := []byte(`{"welcome":"Some Other API"}`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("empty body with /v1/ path yields nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/v1/"}},
		}

		result, err := fp.Fingerprint(resp, []byte{})
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("body larger than 2 MiB with /v1/ path yields nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/v1/"}},
		}
		body := []byte(strings.Repeat("a", 2*1024*1024+1))

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("status 500 with correct body and /v1/ path yields nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 500,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/v1/"}},
		}

		result, err := fp.Fingerprint(resp, []byte(realisticDifyAPIBody))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("status 100 with correct body and /v1/ path yields nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 100,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/v1/"}},
		}

		result, err := fp.Fingerprint(resp, []byte(realisticDifyAPIBody))
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

// ── Version Extraction ────────────────────────────────────────────────────────

func TestDifyVersionExtraction(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "server_version 1.14.2 yields 1.14.2",
			body: `{"welcome":"Dify OpenAPI","api_version":"v1","server_version":"1.14.2"}`,
			want: "1.14.2",
		},
		{
			name: "server_version 0.1.0 yields 0.1.0",
			body: `{"server_version":"0.1.0"}`,
			want: "0.1.0",
		},
		{
			name: "server_version 1.14.2-beta yields 1.14.2 (extraction regex strips suffix)",
			body: `{"server_version":"1.14.2-beta"}`,
			want: "1.14.2",
		},
		{
			name: "server_version abc.def.ghi yields empty string (fails validation)",
			body: `{"server_version":"abc.def.ghi"}`,
			want: "",
		},
		{
			name: "server_version empty string yields empty string",
			body: `{"server_version":""}`,
			want: "",
		},
		{
			name: "no server_version field yields empty string",
			body: `{"welcome":"Dify OpenAPI","api_version":"v1"}`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractDifyVersion([]byte(tt.body))
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── DifyHTMLFingerprinter ─────────────────────────────────────────────────────

func TestDifyHTMLFingerprinter_Name(t *testing.T) {
	fp := &DifyHTMLFingerprinter{}
	assert.Equal(t, "dify-html", fp.Name())
}

func TestDifyHTMLFingerprinter_Match(t *testing.T) {
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
			fp := &DifyHTMLFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", tt.contentType)
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

func TestDifyHTMLFingerprinter_Fingerprint_MetaTag(t *testing.T) {
	fp := &DifyHTMLFingerprinter{}

	t.Run("standard Dify HTML with apple-mobile-web-app-title meta tag yields detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		result, err := fp.Fingerprint(resp, []byte(realisticDifyHTML))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "dify", result.Technology)
	})

	t.Run("reversed attribute order content before name yields detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<!DOCTYPE html><html><head><meta content="Dify" name="apple-mobile-web-app-title" /></head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "dify", result.Technology)
	})

	t.Run("HTML without the meta tag yields nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<!DOCTYPE html><html><head><title>Some App</title></head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("HTML with different apple-mobile-web-app-title value yields nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<!DOCTYPE html><html><head><meta name="apple-mobile-web-app-title" content="NotDify"/></head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("empty body yields nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		result, err := fp.Fingerprint(resp, []byte{})
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("body larger than 2 MiB yields nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(strings.Repeat("a", 2*1024*1024+1))

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

// ── Negative Cases ────────────────────────────────────────────────────────────

func TestDifyFingerprinter_Fingerprint_NegativeCases(t *testing.T) {
	fp := &DifyFingerprinter{}

	tests := []struct {
		name        string
		statusCode  int
		body        []byte
		requestPath string
	}{
		{
			name:        "generic JSON status ok with path / returns nil",
			statusCode:  200,
			body:        []byte(`{"status":"ok"}`),
			requestPath: "/",
		},
		{
			name:        "generic HTML with unrelated title returns nil",
			statusCode:  200,
			body:        []byte(`<html><head><title>Welcome</title></head><body><p>Hello world</p></body></html>`),
			requestPath: "/",
		},
		{
			name:        "HTML that mentions Dify in a paragraph but not in meta tag returns nil",
			statusCode:  200,
			body:        []byte(`<html><head><title>Blog Post</title></head><body><p>Dify is a great LLM platform.</p></body></html>`),
			requestPath: "/",
		},
		{
			name:        "status 500 with Dify OpenAPI body returns nil",
			statusCode:  500,
			body:        []byte(realisticDifyAPIBody),
			requestPath: "/v1/",
		},
		{
			name:        "empty body returns nil",
			statusCode:  200,
			body:        []byte(``),
			requestPath: "/v1/",
		},
		{
			name:        "body larger than 2 MiB returns nil",
			statusCode:  200,
			body:        []byte(strings.Repeat("a", 2*1024*1024+1)),
			requestPath: "/v1/",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
				Request:    &http.Request{URL: &url.URL{Path: tt.requestPath}},
			}

			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ── CPE Building ──────────────────────────────────────────────────────────────

func TestBuildDifyCPE(t *testing.T) {
	t.Run("empty version yields wildcard CPE", func(t *testing.T) {
		assert.Equal(t, "cpe:2.3:a:langgenius:dify:*:*:*:*:*:*:*:*", buildDifyCPE(""))
	})

	t.Run("version 1.14.2 yields versioned CPE", func(t *testing.T) {
		assert.Equal(t, "cpe:2.3:a:langgenius:dify:1.14.2:*:*:*:*:*:*:*", buildDifyCPE("1.14.2"))
	})
}

// ── Integration: Match + Fingerprint Round-Trip ───────────────────────────────

func TestDifyFingerprinter_Integration(t *testing.T) {
	fp := &DifyFingerprinter{}

	t.Run("full /v1/ response yields Match true and full Fingerprint result", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/v1/"}},
		}
		resp.Header.Set("Content-Type", "application/json")

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, []byte(realisticDifyAPIBody))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "dify", result.Technology)
		assert.Equal(t, "1.14.2", result.Version)
		assert.Equal(t, "LangGenius", result.Metadata["vendor"])
		assert.Equal(t, "Dify", result.Metadata["product"])
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
		assert.Equal(t, "/v1/", result.Metadata["probe_path"])
	})
}

func TestDifyHTMLFingerprinter_Integration(t *testing.T) {
	fp := &DifyHTMLFingerprinter{}

	t.Run("full HTML response yields Match true and Fingerprint result with html_meta_tag method", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/html")

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, []byte(realisticDifyHTML))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "dify", result.Technology)
		assert.Equal(t, "", result.Version)
		assert.Equal(t, "LangGenius", result.Metadata["vendor"])
		assert.Equal(t, "Dify", result.Metadata["product"])
		assert.Equal(t, "html_meta_tag", result.Metadata["detection_method"])
	})
}

// ── DifySetupFingerprinter: Name / ProbeEndpoint / ProbeAccept ───────────────

func TestDifySetupFingerprinter_Name(t *testing.T) {
	fp := &DifySetupFingerprinter{}
	assert.Equal(t, "dify-setup", fp.Name())
}

func TestDifySetupFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &DifySetupFingerprinter{}
	assert.Equal(t, "/console/api/setup", fp.ProbeEndpoint())
}

func TestDifySetupFingerprinter_ProbeAccept(t *testing.T) {
	fp := &DifySetupFingerprinter{}
	assert.Equal(t, "application/json", fp.ProbeAccept())
}

// ── DifySetupFingerprinter: Match ─────────────────────────────────────────────

func TestDifySetupFingerprinter_Match(t *testing.T) {
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
			name:        "200 with /console/api/setup path and no Content-Type returns true",
			statusCode:  200,
			requestPath: "/console/api/setup",
			want:        true,
		},
		{
			name:        "200 text/html returns false",
			statusCode:  200,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "500 application/json returns false",
			statusCode:  500,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "100 application/json returns false",
			statusCode:  100,
			contentType: "application/json",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &DifySetupFingerprinter{}
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

// ── DifySetupFingerprinter: Fingerprint ───────────────────────────────────────

func TestDifySetupFingerprinter_Fingerprint_SetupSignal(t *testing.T) {
	fp := &DifySetupFingerprinter{}

	t.Run("not_started step with /console/api/setup path yields detected result with SecurityFindings", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/console/api/setup"}},
		}

		result, err := fp.Fingerprint(resp, []byte(`{"step":"not_started","setup_at":null}`))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "not_started", result.Metadata["setup_step"])
		require.NotEmpty(t, result.SecurityFindings)
		assert.Equal(t, "dify-setup-not-started", result.SecurityFindings[0].ID)
	})

	t.Run("finished step with /console/api/setup path yields detected result with no SecurityFindings", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/console/api/setup"}},
		}

		result, err := fp.Fingerprint(resp, []byte(`{"step":"finished","setup_at":"2024-01-15T10:30:00.000Z"}`))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "finished", result.Metadata["setup_step"])
		assert.Empty(t, result.SecurityFindings)
	})

	t.Run("not_started step WITHOUT /console/api/setup path yields nil (path gate)", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/"}},
		}

		result, err := fp.Fingerprint(resp, []byte(`{"step":"not_started"}`))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("body without step field with /console/api/setup path yields nil (no step field)", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/console/api/setup"}},
		}

		result, err := fp.Fingerprint(resp, []byte(`{"status":"ok"}`))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("empty body with /console/api/setup path yields nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/console/api/setup"}},
		}

		result, err := fp.Fingerprint(resp, []byte{})
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("body larger than 2 MiB with /console/api/setup path yields nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/console/api/setup"}},
		}
		body := []byte(strings.Repeat("a", 2*1024*1024+1))

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("status 500 with correct body and /console/api/setup path yields nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 500,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/console/api/setup"}},
		}

		result, err := fp.Fingerprint(resp, []byte(`{"step":"not_started","setup_at":null}`))
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

// ── DifySetupFingerprinter: Severity ──────────────────────────────────────────

func TestDifySetupFingerprinter_Severity(t *testing.T) {
	t.Run("setup detection (step=finished) has empty severity", func(t *testing.T) {
		fp := &DifySetupFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/console/api/setup"}},
		}

		result, err := fp.Fingerprint(resp, []byte(`{"step":"finished","setup_at":"2024-01-15T10:30:00.000Z"}`))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, plugins.Severity(""), result.Severity)
	})

	t.Run("setup detection (step=not_started) has SeverityHigh and SecurityFindings[0].Severity == SeverityHigh", func(t *testing.T) {
		fp := &DifySetupFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/console/api/setup"}},
		}

		result, err := fp.Fingerprint(resp, []byte(`{"step":"not_started","setup_at":null}`))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, plugins.SeverityHigh, result.Severity)
		require.NotEmpty(t, result.SecurityFindings)
		assert.Equal(t, plugins.SeverityHigh, result.SecurityFindings[0].Severity)
	})
}

// ── DifySetupFingerprinter: Integration ───────────────────────────────────────

func TestDifySetupFingerprinter_Integration(t *testing.T) {
	fp := &DifySetupFingerprinter{}

	t.Run("full /console/api/setup response yields Match true and full Fingerprint result", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/console/api/setup"}},
		}
		resp.Header.Set("Content-Type", "application/json")

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, []byte(`{"step":"not_started","setup_at":null}`))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "dify-setup", result.Technology)
		assert.Equal(t, "LangGenius", result.Metadata["vendor"])
		assert.Equal(t, "Dify", result.Metadata["product"])
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
		assert.Equal(t, "/console/api/setup", result.Metadata["probe_path"])
		assert.Equal(t, "not_started", result.Metadata["setup_step"])
		require.NotEmpty(t, result.SecurityFindings)
	})
}

// ── Severity ──────────────────────────────────────────────────────────────────

func TestDifyFingerprinter_Severity(t *testing.T) {
	t.Run("active probe detection has SeverityHigh", func(t *testing.T) {
		fp := &DifyFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    &http.Request{URL: &url.URL{Path: "/v1/"}},
		}

		result, err := fp.Fingerprint(resp, []byte(realisticDifyAPIBody))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, plugins.SeverityHigh, result.Severity)
	})

	t.Run("HTML detection has zero-value severity", func(t *testing.T) {
		fp := &DifyHTMLFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}

		result, err := fp.Fingerprint(resp, []byte(realisticDifyHTML))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, plugins.Severity(""), result.Severity)
	})
}
