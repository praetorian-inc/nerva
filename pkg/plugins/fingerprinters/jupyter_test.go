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

// ─── JupyterNotebookFingerprinter ───────────────────────────────────────────

func TestJupyterNotebookFingerprinter_Name(t *testing.T) {
	fp := &JupyterNotebookFingerprinter{}
	assert.Equal(t, "jupyter-notebook", fp.Name())
}

func TestJupyterNotebookFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &JupyterNotebookFingerprinter{}
	assert.Equal(t, "/api", fp.ProbeEndpoint())
}

func TestJupyterNotebookFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "matches application/json",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "matches application/json with charset",
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "does not match text/html",
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "does not match empty content type",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &JupyterNotebookFingerprinter{}
			resp := &http.Response{
				Header: http.Header{"Content-Type": []string{tt.contentType}},
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

func TestJupyterNotebookFingerprinter_Fingerprint(t *testing.T) {
	jsonResp := func() *http.Response {
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}
	}

	t.Run("positive: valid JSON version detected", func(t *testing.T) {
		fp := &JupyterNotebookFingerprinter{}
		// base_url provides the Jupyter-specific corroboration signal.
		body := []byte(`{"version": "6.4.12", "base_url": "/", "last_activity": "2023-01-01T00:00:00Z"}`)

		result, err := fp.Fingerprint(jsonResp(), body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "jupyter-notebook", result.Technology)
		assert.Equal(t, "6.4.12", result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:jupyter:notebook:6.4.12:*:*:*:*:*:*:*")
		assert.Equal(t, "notebook", result.Metadata["variant"])
		assert.Equal(t, "unknown", result.Metadata["auth_status"])
		assert.Equal(t, "6.4.12", result.Metadata["api_version"])
	})

	t.Run("positive: single-digit version", func(t *testing.T) {
		fp := &JupyterNotebookFingerprinter{}
		// base_url provides the Jupyter-specific corroboration signal.
		body := []byte(`{"version": "7", "base_url": "/"}`)

		result, err := fp.Fingerprint(jsonResp(), body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "7", result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:jupyter:notebook:7:*:*:*:*:*:*:*")
	})

	t.Run("positive: ws_url field provides corroboration", func(t *testing.T) {
		fp := &JupyterNotebookFingerprinter{}
		body := []byte(`{"version": "7.0.6", "ws_url": "ws://localhost:8888/"}`)

		result, err := fp.Fingerprint(jsonResp(), body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "7.0.6", result.Version)
	})

	t.Run("positive: Tornado Server header provides corroboration", func(t *testing.T) {
		fp := &JupyterNotebookFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
				"Server":       []string{"TornadoServer/6.4.1"},
			},
		}
		// No base_url or ws_url, but Server header confirms Tornado.
		body := []byte(`{"version": "7"}`)

		result, err := fp.Fingerprint(resp, body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "7", result.Version)
	})

	t.Run("positive: jupyter Server header provides corroboration", func(t *testing.T) {
		fp := &JupyterNotebookFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
				"Server":       []string{"jupyter/1.0"},
			},
		}
		body := []byte(`{"version": "6.5.0"}`)

		result, err := fp.Fingerprint(resp, body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "6.5.0", result.Version)
	})

	t.Run("negative: rejects generic API with version-only response", func(t *testing.T) {
		fp := &JupyterNotebookFingerprinter{}
		// Bare {"version":"1.0"} without base_url/ws_url or Tornado/Jupyter Server header.
		body := []byte(`{"version": "1.0"}`)

		result, err := fp.Fingerprint(jsonResp(), body)

		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("negative: generic JSON API without version field returns nil", func(t *testing.T) {
		fp := &JupyterNotebookFingerprinter{}
		body := []byte(`{"status": "ok", "message": "hello"}`)

		result, err := fp.Fingerprint(jsonResp(), body)

		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("negative: JSON with empty version field returns nil", func(t *testing.T) {
		fp := &JupyterNotebookFingerprinter{}
		body := []byte(`{"version": ""}`)

		result, err := fp.Fingerprint(jsonResp(), body)

		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("negative: invalid version string rejected, returns nil", func(t *testing.T) {
		fp := &JupyterNotebookFingerprinter{}
		// Version with non-numeric characters should be rejected.
		body := []byte(`{"version": "6.4.12-beta", "base_url": "/"}`)

		result, err := fp.Fingerprint(jsonResp(), body)

		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("negative: CPE injection in version is rejected", func(t *testing.T) {
		fp := &JupyterNotebookFingerprinter{}
		body := []byte(`{"version": "6.4.12:*:*:*:*:cpe:2.3:a:evil", "base_url": "/"}`)

		result, err := fp.Fingerprint(jsonResp(), body)

		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("negative: malformed JSON returns nil", func(t *testing.T) {
		fp := &JupyterNotebookFingerprinter{}
		body := []byte("not valid json {{}")

		result, err := fp.Fingerprint(jsonResp(), body)

		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("negative: empty body returns nil", func(t *testing.T) {
		fp := &JupyterNotebookFingerprinter{}

		result, err := fp.Fingerprint(jsonResp(), []byte{})

		assert.NoError(t, err)
		assert.Nil(t, result)
	})
}

// ─── JupyterHubFingerprinter ─────────────────────────────────────────────────

func TestJupyterHubFingerprinter_Name(t *testing.T) {
	fp := &JupyterHubFingerprinter{}
	assert.Equal(t, "jupyterhub", fp.Name())
}

func TestJupyterHubFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &JupyterHubFingerprinter{}
	assert.Equal(t, "/hub/login", fp.ProbeEndpoint())
}

func TestJupyterHubFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name          string
		contentType   string
		hubVersionHdr string
		want          bool
	}{
		{
			name:        "matches text/html",
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "matches text/html with charset",
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:          "matches when X-JupyterHub-Version header present",
			contentType:   "text/plain",
			hubVersionHdr: "3.1.0",
			want:          true,
		},
		{
			name:        "does not match application/json without hub header",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "does not match empty content type without hub header",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &JupyterHubFingerprinter{}
			header := http.Header{"Content-Type": []string{tt.contentType}}
			if tt.hubVersionHdr != "" {
				header.Set("X-JupyterHub-Version", tt.hubVersionHdr)
			}
			resp := &http.Response{Header: header}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

func TestJupyterHubFingerprinter_Fingerprint(t *testing.T) {
	htmlResp := func(extraHeaders map[string]string) *http.Response {
		h := http.Header{"Content-Type": []string{"text/html; charset=utf-8"}}
		for k, v := range extraHeaders {
			h.Set(k, v)
		}
		return &http.Response{StatusCode: 200, Header: h}
	}

	t.Run("positive: X-JupyterHub-Version header detected", func(t *testing.T) {
		fp := &JupyterHubFingerprinter{}
		resp := htmlResp(map[string]string{"X-JupyterHub-Version": "3.1.0"})
		body := []byte(`<html><head><title>JupyterHub</title></head></html>`)

		result, err := fp.Fingerprint(resp, body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "jupyterhub", result.Technology)
		assert.Equal(t, "3.1.0", result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:jupyter:jupyterhub:3.1.0:*:*:*:*:*:*:*")
		assert.Equal(t, "jupyterhub", result.Metadata["variant"])
		assert.Equal(t, "unknown", result.Metadata["auth_status"])
		assert.Equal(t, "header", result.Metadata["version_source"])
	})

	t.Run("positive: jupyterhub in HTML body (no header)", func(t *testing.T) {
		fp := &JupyterHubFingerprinter{}
		resp := htmlResp(nil)
		body := []byte(`<html><head><title>Sign in - JupyterHub</title></head><body>Please sign in to JupyterHub.</body></html>`)

		result, err := fp.Fingerprint(resp, body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "jupyterhub", result.Technology)
		assert.Equal(t, "", result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:jupyter:jupyterhub:*:*:*:*:*:*:*:*")
		assert.Equal(t, "html", result.Metadata["version_source"])
	})

	t.Run("positive: case-insensitive jupyterhub in HTML body", func(t *testing.T) {
		fp := &JupyterHubFingerprinter{}
		resp := htmlResp(nil)
		body := []byte(`<html><body>Welcome to JUPYTERHUB</body></html>`)

		result, err := fp.Fingerprint(resp, body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "jupyterhub", result.Technology)
	})

	t.Run("positive: header version takes precedence over HTML body", func(t *testing.T) {
		fp := &JupyterHubFingerprinter{}
		resp := htmlResp(map[string]string{"X-JupyterHub-Version": "4.0.1"})
		body := []byte(`<html><body>jupyterhub login page</body></html>`)

		result, err := fp.Fingerprint(resp, body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "4.0.1", result.Version)
		assert.Equal(t, "header", result.Metadata["version_source"])
	})

	t.Run("positive: header with invalid version format uses empty version", func(t *testing.T) {
		fp := &JupyterHubFingerprinter{}
		resp := htmlResp(map[string]string{"X-JupyterHub-Version": "3.1"})
		body := []byte(`<html><body>jupyterhub</body></html>`)

		result, err := fp.Fingerprint(resp, body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "", result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:jupyter:jupyterhub:*:*:*:*:*:*:*:*")
		assert.Equal(t, "header", result.Metadata["version_source"])
	})

	t.Run("negative: HTML without jupyterhub references returns nil", func(t *testing.T) {
		fp := &JupyterHubFingerprinter{}
		resp := htmlResp(nil)
		body := []byte(`<html><head><title>Sign In</title></head><body>Please log in.</body></html>`)

		result, err := fp.Fingerprint(resp, body)

		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("negative: empty body without header returns nil", func(t *testing.T) {
		fp := &JupyterHubFingerprinter{}
		resp := htmlResp(nil)

		result, err := fp.Fingerprint(resp, []byte{})

		assert.NoError(t, err)
		assert.Nil(t, result)
	})
}

// ─── JupyterLabFingerprinter ─────────────────────────────────────────────────

func TestJupyterLabFingerprinter_Name(t *testing.T) {
	fp := &JupyterLabFingerprinter{}
	assert.Equal(t, "jupyterlab", fp.Name())
}

func TestJupyterLabFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &JupyterLabFingerprinter{}
	assert.Equal(t, "/lab", fp.ProbeEndpoint())
}

func TestJupyterLabFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "matches text/html",
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "matches text/html with charset",
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "does not match application/json",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "does not match empty content type",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &JupyterLabFingerprinter{}
			resp := &http.Response{
				Header: http.Header{"Content-Type": []string{tt.contentType}},
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

func TestJupyterLabFingerprinter_Fingerprint(t *testing.T) {
	htmlResp := func() *http.Response {
		return &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
		}
	}

	t.Run("positive: JupyterLab title detected", func(t *testing.T) {
		fp := &JupyterLabFingerprinter{}
		body := []byte(`<!DOCTYPE html><html><head><title>JupyterLab</title></head><body></body></html>`)

		result, err := fp.Fingerprint(htmlResp(), body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "jupyterlab", result.Technology)
		assert.Equal(t, "", result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:jupyter:jupyterlab:*:*:*:*:*:*:*:*")
		assert.Equal(t, "jupyterlab", result.Metadata["variant"])
		assert.Equal(t, "unknown", result.Metadata["auth_status"])
	})

	t.Run("positive: case-insensitive JupyterLab title", func(t *testing.T) {
		fp := &JupyterLabFingerprinter{}
		body := []byte(`<html><head><title>jupyterlab</title></head></html>`)

		result, err := fp.Fingerprint(htmlResp(), body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "jupyterlab", result.Technology)
	})

	t.Run("positive: jupyterlab script reference in body", func(t *testing.T) {
		fp := &JupyterLabFingerprinter{}
		body := []byte(`<html><head><script src="/static/jupyterlab/main.js"></script></head></html>`)

		result, err := fp.Fingerprint(htmlResp(), body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "jupyterlab", result.Technology)
	})

	t.Run("positive: version extracted from app_version attribute", func(t *testing.T) {
		fp := &JupyterLabFingerprinter{}
		body := []byte(`<html><head><title>JupyterLab</title></head><body data-app_version="3.6.5"></body></html>`)

		result, err := fp.Fingerprint(htmlResp(), body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "3.6.5", result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:jupyter:jupyterlab:3.6.5:*:*:*:*:*:*:*")
		assert.Equal(t, "html_meta", result.Metadata["version_source"])
	})

	t.Run("positive: version extracted from jupyterlab JS variable", func(t *testing.T) {
		fp := &JupyterLabFingerprinter{}
		body := []byte(`<html><head><title>JupyterLab</title></head><body><script>var jupyterlab = "4.0.0";</script></body></html>`)

		result, err := fp.Fingerprint(htmlResp(), body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "4.0.0", result.Version)
	})

	t.Run("negative: HTML without JupyterLab title or script references returns nil", func(t *testing.T) {
		fp := &JupyterLabFingerprinter{}
		body := []byte(`<html><head><title>Apache Jupyter</title></head><body>Welcome</body></html>`)

		result, err := fp.Fingerprint(htmlResp(), body)

		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("negative: generic HTML login page returns nil", func(t *testing.T) {
		fp := &JupyterLabFingerprinter{}
		body := []byte(`<html><head><title>Login</title></head><body><form method="POST"></form></body></html>`)

		result, err := fp.Fingerprint(htmlResp(), body)

		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("negative: malformed HTML returns nil", func(t *testing.T) {
		fp := &JupyterLabFingerprinter{}
		body := []byte(`<<<<not html>>>>>`)

		result, err := fp.Fingerprint(htmlResp(), body)

		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("negative: empty body returns nil", func(t *testing.T) {
		fp := &JupyterLabFingerprinter{}

		result, err := fp.Fingerprint(htmlResp(), []byte{})

		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("rejects data-src attribute with jupyterlab reference", func(t *testing.T) {
		fp := &JupyterLabFingerprinter{}
		// No <title>JupyterLab</title> and data-src should not match script regex.
		body := []byte(`<html><head><title>Other App</title></head><body><script data-src="/static/jupyterlab/main.js"></script></body></html>`)

		result, err := fp.Fingerprint(htmlResp(), body)

		assert.NoError(t, err)
		assert.Nil(t, result)
	})

	t.Run("rejects version from non-jupyterlab identifier", func(t *testing.T) {
		fp := &JupyterLabFingerprinter{}
		// Title matches, but "notjupyterlab" should NOT trigger version extraction
		// because \b word boundary prevents matching mid-identifier.
		body := []byte(`<html><title>JupyterLab</title><script>var notjupyterlab = "3.6.5"</script></html>`)

		result, err := fp.Fingerprint(htmlResp(), body)

		require.NoError(t, err)
		require.NotNil(t, result) // Title matches — should detect JupyterLab
		assert.Equal(t, "", result.Version) // Version must NOT be extracted from notjupyterlab
	})

	t.Run("version with pre-release suffix: clean semver prefix is extracted", func(t *testing.T) {
		fp := &JupyterLabFingerprinter{}
		// The regex captures exactly \d+\.\d+\.\d+, so "3.6.5" is extracted from "3.6.5-rc1".
		body := []byte(`<html><head><title>JupyterLab</title></head><body data-jupyterlab="3.6.5-rc1"></body></html>`)

		result, err := fp.Fingerprint(htmlResp(), body)

		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "3.6.5", result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:jupyter:jupyterlab:3.6.5:*:*:*:*:*:*:*")
	})
}

// ─── Shared helpers ──────────────────────────────────────────────────────────

func TestBuildJupyterCPE(t *testing.T) {
	tests := []struct {
		name     string
		product  string
		version  string
		expected string
	}{
		{
			name:     "notebook with version",
			product:  "notebook",
			version:  "6.4.12",
			expected: "cpe:2.3:a:jupyter:notebook:6.4.12:*:*:*:*:*:*:*",
		},
		{
			name:     "notebook with empty version uses wildcard",
			product:  "notebook",
			version:  "",
			expected: "cpe:2.3:a:jupyter:notebook:*:*:*:*:*:*:*:*",
		},
		{
			name:     "jupyterhub with version",
			product:  "jupyterhub",
			version:  "3.1.0",
			expected: "cpe:2.3:a:jupyter:jupyterhub:3.1.0:*:*:*:*:*:*:*",
		},
		{
			name:     "jupyterlab with version",
			product:  "jupyterlab",
			version:  "4.0.0",
			expected: "cpe:2.3:a:jupyter:jupyterlab:4.0.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildJupyterCPE(tt.product, tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestSanitizeJupyterVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		pattern string // "notebook" or "hub"
		want    string
	}{
		{
			name:    "notebook: valid dotted version passes",
			version: "6.4.12",
			pattern: "notebook",
			want:    "6.4.12",
		},
		{
			name:    "notebook: single digit version passes",
			version: "7",
			pattern: "notebook",
			want:    "7",
		},
		{
			name:    "notebook: pre-release rejected",
			version: "6.4.12-beta",
			pattern: "notebook",
			want:    "",
		},
		{
			name:    "hub: valid three-part semver passes",
			version: "3.1.0",
			pattern: "hub",
			want:    "3.1.0",
		},
		{
			name:    "hub: two-part version rejected",
			version: "3.1",
			pattern: "hub",
			want:    "",
		},
		{
			name:    "hub: CPE injection rejected",
			version: "3.1.0:*:*:*:*:cpe:2.3",
			pattern: "hub",
			want:    "",
		},
		{
			name:    "empty string rejected",
			version: "",
			pattern: "notebook",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var pattern = jupyterNotebookVersionRegex
			if tt.pattern == "hub" {
				pattern = jupyterHubVersionRegex
			}
			got := sanitizeJupyterVersion(tt.version, pattern)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ─── Severity is never set ───────────────────────────────────────────────────

func TestJupyterFingerprinters_NoSeverity(t *testing.T) {
	t.Run("notebook severity is zero value", func(t *testing.T) {
		fp := &JupyterNotebookFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"application/json"}},
		}
		// base_url provides the Jupyter-specific corroboration signal.
		result, err := fp.Fingerprint(resp, []byte(`{"version":"6.4.0","base_url":"/"}`))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Zero(t, result.Severity)
	})

	t.Run("jupyterhub severity is zero value", func(t *testing.T) {
		fp := &JupyterHubFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type":         []string{"text/html"},
				"X-JupyterHub-Version": []string{"3.1.0"},
			},
		}
		result, err := fp.Fingerprint(resp, []byte(`<html><body>jupyterhub</body></html>`))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Zero(t, result.Severity)
	})

	t.Run("jupyterlab severity is zero value", func(t *testing.T) {
		fp := &JupyterLabFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header:     http.Header{"Content-Type": []string{"text/html"}},
		}
		result, err := fp.Fingerprint(resp, []byte(`<html><head><title>JupyterLab</title></head></html>`))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Zero(t, result.Severity)
	})
}
