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

// realisticHealthBody is a real Langfuse health response at /api/public/health.
const realisticHealthBody = `{"status":"OK","version":"3.194.1"}`

// langfuseSignInHTML is a realistic Langfuse login page.
const langfuseSignInHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sign in | Langfuse</title>
</head>
<body>
<form method="post" action="/api/auth/signin">
<input type="email" name="email" />
<input type="password" name="password" />
<button type="submit">Sign in</button>
</form>
</body>
</html>`

// langfuseSignUpHTML is a realistic Langfuse sign-up page.
const langfuseSignUpHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sign up | Langfuse</title>
</head>
<body>
<form method="post" action="/api/auth/signup">
<input type="email" name="email" />
<button type="submit">Sign up</button>
</form>
</body>
</html>`

// ---------------------------------------------------------------------------
// LangfuseFingerprinter — Name / ProbeEndpoint / ProbeAccept
// ---------------------------------------------------------------------------

func TestLangfuseFingerprinter_Name(t *testing.T) {
	fp := &LangfuseFingerprinter{}
	assert.Equal(t, "langfuse", fp.Name())
}

func TestLangfuseFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &LangfuseFingerprinter{}
	assert.Equal(t, "/api/public/health", fp.ProbeEndpoint())
}

func TestLangfuseFingerprinter_ProbeAccept(t *testing.T) {
	fp := &LangfuseFingerprinter{}
	assert.Equal(t, "application/json", fp.ProbeAccept())
}

// ---------------------------------------------------------------------------
// LangfuseFingerprinter — Match
// ---------------------------------------------------------------------------

func TestLangfuseFingerprinter_Match(t *testing.T) {
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
			name:        "200 text/html returns false",
			statusCode:  200,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "200 /api/public/health path without Content-Type returns true (fast-path)",
			statusCode:  200,
			requestPath: "/api/public/health",
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
			fp := &LangfuseFingerprinter{}
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

// ---------------------------------------------------------------------------
// LangfuseFingerprinter — Fingerprint health signal
// ---------------------------------------------------------------------------

func TestLangfuseFingerprinter_Fingerprint_HealthSignal(t *testing.T) {
	fp := &LangfuseFingerprinter{}

	t.Run("full health JSON at /api/public/health yields detected with version, active_probe, SeverityHigh", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/api/public/health"},
			},
		}
		resp.Header.Set("Content-Type", "application/json")

		result, err := fp.Fingerprint(resp, []byte(realisticHealthBody))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "langfuse", result.Technology)
		assert.Equal(t, "3.194.1", result.Version)
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
		assert.Equal(t, plugins.SeverityHigh, result.Severity)
	})

	t.Run("health with Database not available status at /api/public/health yields detected with health_status", func(t *testing.T) {
		body := []byte(`{"status":"Database not available","version":"3.194.1"}`)
		resp := &http.Response{
			StatusCode: 503,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/api/public/health"},
			},
		}
		resp.Header.Set("Content-Type", "application/json")

		// Note: 503 is < 500 threshold but >= 500 — should reject
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result, "503 is a server error, should be rejected")
	})

	t.Run("health with unhealthy 200 response at /api/public/health yields detected with health_status", func(t *testing.T) {
		body := []byte(`{"status":"Database not available","version":"2.80.0"}`)
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/api/public/health"},
			},
		}

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "2.80.0", result.Version)
		assert.Equal(t, "Database not available", result.Metadata["health_status"])
	})

	t.Run("health JSON with version and status but NOT at /api/public/health yields nil (path required)", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/health"},
			},
		}

		result, err := fp.Fingerprint(resp, []byte(realisticHealthBody))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("health JSON with only status (no version) yields nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/api/public/health"},
			},
		}

		result, err := fp.Fingerprint(resp, []byte(`{"status":"OK"}`))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("health JSON with only version (no status) yields nil", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/api/public/health"},
			},
		}

		result, err := fp.Fingerprint(resp, []byte(`{"version":"3.194.1"}`))
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

// ---------------------------------------------------------------------------
// LangfuseFingerprinter — Version extraction
// ---------------------------------------------------------------------------

func TestLangfuseFingerprinter_Fingerprint_VersionExtraction(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    string
	}{
		{
			name: "version 3.194.1 extracted correctly",
			body: `{"status":"OK","version":"3.194.1"}`,
			want: "3.194.1",
		},
		{
			name: "version 2.0.0-beta pre-release stripped by capture group",
			body: `{"status":"OK","version":"2.0.0-beta"}`,
			want: "2.0.0",
		},
		{
			name: "version abc123 not semver yields empty",
			body: `{"status":"OK","version":"abc123"}`,
			want: "",
		},
		{
			name: "empty version field yields empty",
			body: `{"status":"OK","version":""}`,
			want: "",
		},
		{
			name: "version null yields empty",
			body: `{"status":"OK","version":null}`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractLangfuseVersion([]byte(tt.body))
			assert.Equal(t, tt.want, got)
		})
	}
}

// ---------------------------------------------------------------------------
// LangfuseFingerprinter — Negative cases
// ---------------------------------------------------------------------------

func TestLangfuseFingerprinter_Fingerprint_NegativeCases(t *testing.T) {
	fp := &LangfuseFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		body       []byte
		path       string
	}{
		{
			name:       "generic JSON status ok returns nil",
			statusCode: 200,
			body:       []byte(`{"status":"ok"}`),
			path:       "/api/public/health",
		},
		{
			name:       "generic JSON with health and version but no status key returns nil",
			statusCode: 200,
			body:       []byte(`{"health":"ok","version":"1.0.0"}`),
			path:       "/api/public/health",
		},
		{
			name:       "500 with valid health body returns nil",
			statusCode: 500,
			body:       []byte(realisticHealthBody),
			path:       "/api/public/health",
		},
		{
			name:       "empty body returns nil",
			statusCode: 200,
			body:       []byte(``),
			path:       "/api/public/health",
		},
		{
			name:       "body larger than 2 MiB returns nil",
			statusCode: 200,
			body:       []byte(strings.Repeat("a", 2*1024*1024+1)),
			path:       "/api/public/health",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
				Request: &http.Request{
					URL: &url.URL{Path: tt.path},
				},
			}

			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ---------------------------------------------------------------------------
// buildLangfuseCPE
// ---------------------------------------------------------------------------

func TestBuildLangfuseCPE(t *testing.T) {
	t.Run("empty version yields wildcard CPE", func(t *testing.T) {
		assert.Equal(t, "cpe:2.3:a:langfuse:langfuse:*:*:*:*:*:*:*:*", buildLangfuseCPE(""))
	})

	t.Run("version 3.194.1 yields versioned CPE", func(t *testing.T) {
		assert.Equal(t, "cpe:2.3:a:langfuse:langfuse:3.194.1:*:*:*:*:*:*:*", buildLangfuseCPE("3.194.1"))
	})
}

// ---------------------------------------------------------------------------
// LangfuseHTMLFingerprinter — Name
// ---------------------------------------------------------------------------

func TestLangfuseHTMLFingerprinter_Name(t *testing.T) {
	fp := &LangfuseHTMLFingerprinter{}
	assert.Equal(t, "langfuse-html", fp.Name())
}

// ---------------------------------------------------------------------------
// LangfuseHTMLFingerprinter — Match
// ---------------------------------------------------------------------------

func TestLangfuseHTMLFingerprinter_Match(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &LangfuseHTMLFingerprinter{}
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

// ---------------------------------------------------------------------------
// LangfuseHTMLFingerprinter — Fingerprint title signal
// ---------------------------------------------------------------------------

func TestLangfuseHTMLFingerprinter_Fingerprint_TitleSignal(t *testing.T) {
	fp := &LangfuseHTMLFingerprinter{}

	makeHTMLResp := func(status int) *http.Response {
		resp := &http.Response{
			StatusCode: status,
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/html")
		return resp
	}

	t.Run("Sign in | Langfuse title yields detected with login_page", func(t *testing.T) {
		result, err := fp.Fingerprint(makeHTMLResp(200), []byte(`<html><head><title>Sign in | Langfuse</title></head></html>`))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "login_page", result.Metadata["detection_method"])
		assert.Equal(t, "langfuse", result.Technology)
	})

	t.Run("Sign up | Langfuse title yields detected", func(t *testing.T) {
		result, err := fp.Fingerprint(makeHTMLResp(200), []byte(`<html><head><title>Sign up | Langfuse</title></head></html>`))
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("standalone Langfuse title yields detected", func(t *testing.T) {
		result, err := fp.Fingerprint(makeHTMLResp(200), []byte(`<html><head><title>Langfuse</title></head></html>`))
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("langfuse lowercase title yields detected (case-insensitive)", func(t *testing.T) {
		result, err := fp.Fingerprint(makeHTMLResp(200), []byte(`<html><head><title>langfuse</title></head></html>`))
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("Dashboard | Langfuse title (internal page) yields detected", func(t *testing.T) {
		result, err := fp.Fingerprint(makeHTMLResp(200), []byte(`<html><head><title>Dashboard | Langfuse</title></head></html>`))
		require.NoError(t, err)
		require.NotNil(t, result)
	})

	t.Run("Review of Langfuse blog title yields nil (no pipe separator)", func(t *testing.T) {
		result, err := fp.Fingerprint(makeHTMLResp(200), []byte(`<html><head><title>Review of Langfuse</title></head></html>`))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("How to use Langfuse tutorial title yields nil", func(t *testing.T) {
		result, err := fp.Fingerprint(makeHTMLResp(200), []byte(`<html><head><title>How to use Langfuse</title></head></html>`))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("My App title yields nil", func(t *testing.T) {
		result, err := fp.Fingerprint(makeHTMLResp(200), []byte(`<html><head><title>My App</title></head></html>`))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("Langfuse in body but not in title yields nil", func(t *testing.T) {
		body := []byte(`<html><head><title>Login</title></head><body><p>Powered by Langfuse</p></body></html>`)
		result, err := fp.Fingerprint(makeHTMLResp(200), body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("empty body yields nil", func(t *testing.T) {
		result, err := fp.Fingerprint(makeHTMLResp(200), []byte(``))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("body larger than 2 MiB yields nil", func(t *testing.T) {
		result, err := fp.Fingerprint(makeHTMLResp(200), []byte(strings.Repeat("a", 2*1024*1024+1)))
		require.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("status 500 with valid title yields nil", func(t *testing.T) {
		result, err := fp.Fingerprint(makeHTMLResp(500), []byte(`<html><head><title>Sign in | Langfuse</title></head></html>`))
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

// ---------------------------------------------------------------------------
// LangfuseHTMLFingerprinter — Integration
// ---------------------------------------------------------------------------

func TestLangfuseHTMLFingerprinter_Integration(t *testing.T) {
	fp := &LangfuseHTMLFingerprinter{}

	t.Run("full round-trip with realistic sign-in HTML", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, []byte(langfuseSignInHTML))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "langfuse", result.Technology)
		assert.Equal(t, "Langfuse", result.Metadata["vendor"])
		assert.Equal(t, "Langfuse", result.Metadata["product"])
		assert.Equal(t, "", result.Version)
		assert.Equal(t, "login_page", result.Metadata["detection_method"])
		assert.Equal(t, []string{"cpe:2.3:a:langfuse:langfuse:*:*:*:*:*:*:*:*"}, result.CPEs)
	})

	t.Run("full round-trip with realistic sign-up HTML", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/html")

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, []byte(langfuseSignUpHTML))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "langfuse", result.Technology)
	})
}

// ---------------------------------------------------------------------------
// LangfuseFingerprinter — Integration
// ---------------------------------------------------------------------------

func TestLangfuseFingerprinter_Integration(t *testing.T) {
	fp := &LangfuseFingerprinter{}

	t.Run("full round-trip with health response yields complete metadata", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/api/public/health"},
			},
		}
		resp.Header.Set("Content-Type", "application/json")

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, []byte(realisticHealthBody))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "langfuse", result.Technology)
		assert.Equal(t, "Langfuse", result.Metadata["vendor"])
		assert.Equal(t, "Langfuse", result.Metadata["product"])
		assert.Equal(t, "3.194.1", result.Version)
		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
		assert.Equal(t, "/api/public/health", result.Metadata["probe_path"])
		assert.Equal(t, "OK", result.Metadata["health_status"])
		assert.Equal(t, plugins.SeverityHigh, result.Severity)
		assert.Equal(t, []string{"cpe:2.3:a:langfuse:langfuse:3.194.1:*:*:*:*:*:*:*"}, result.CPEs)
	})
}
