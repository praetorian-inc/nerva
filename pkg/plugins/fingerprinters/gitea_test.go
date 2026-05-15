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
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGiteaFingerprinter_Name(t *testing.T) {
	fp := &GiteaFingerprinter{}
	assert.Equal(t, "gitea", fp.Name())
}

func TestGiteaFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &GiteaFingerprinter{}
	assert.Equal(t, "/api/v1/version", fp.ProbeEndpoint())
}

func TestGiteaFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		headers     map[string]string
		cookies     []string // Set-Cookie header values
		expected    bool
	}{
		{
			name:        "matches JSON content type (active path)",
			contentType: "application/json",
			expected:    true,
		},
		{
			name:        "matches JSON with charset (active path)",
			contentType: "application/json; charset=utf-8",
			expected:    true,
		},
		{
			name:        "matches i_like_gitea cookie (passive path)",
			contentType: "text/html",
			cookies:     []string{"i_like_gitea=abc123; Path=/; HttpOnly"},
			expected:    true,
		},
		{
			name:        "matches X-Gitea-Version header (passive path)",
			contentType: "text/html",
			headers:     map[string]string{"X-Gitea-Version": "1.21.0"},
			expected:    true,
		},
		{
			name:        "does not match HTML without Gitea markers",
			contentType: "text/html",
			expected:    false,
		},
		{
			name:        "does not match plain text",
			contentType: "text/plain",
			expected:    false,
		},
		{
			name:        "does not match empty content type",
			contentType: "",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GiteaFingerprinter{}
			resp := &http.Response{
				Header: http.Header{},
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}
			for _, c := range tt.cookies {
				resp.Header.Add("Set-Cookie", c)
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestGiteaFingerprinter_Fingerprint_ValidGitea(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		expectedTech    string
		expectedVersion string
		expectedCPE     string
		expectedRawVer  string
		expectedIsFork  bool
		expectedForkVer string
	}{
		{
			name:            "gitea 1.21.0",
			body:            `{"version":"1.21.0"}`,
			expectedTech:    "gitea",
			expectedVersion: "1.21.0",
			expectedCPE:     "cpe:2.3:a:gitea:gitea:1.21.0:*:*:*:*:*:*:*",
			expectedRawVer:  "1.21.0",
			expectedIsFork:  false,
		},
		{
			name:            "gitea v1.21.0 with v prefix",
			body:            `{"version":"v1.21.0"}`,
			expectedTech:    "gitea",
			expectedVersion: "1.21.0",
			expectedCPE:     "cpe:2.3:a:gitea:gitea:1.21.0:*:*:*:*:*:*:*",
			expectedRawVer:  "v1.21.0",
			expectedIsFork:  false,
		},
		{
			name:            "gitea 1.26.0 with dev suffix",
			body:            `{"version":"1.26.0+dev-489-gc9a038bc4e"}`,
			expectedTech:    "gitea",
			expectedVersion: "1.26.0",
			expectedCPE:     "cpe:2.3:a:gitea:gitea:1.26.0:*:*:*:*:*:*:*",
			expectedRawVer:  "1.26.0+dev-489-gc9a038bc4e",
			expectedIsFork:  false,
		},
		{
			name:            "codeberg fork version",
			body:            `{"version":"14.0.0-103-5e0b41b3+gitea-1.22.0"}`,
			expectedTech:    "gitea",
			expectedVersion: "1.22.0",
			expectedCPE:     "cpe:2.3:a:gitea:gitea:1.22.0:*:*:*:*:*:*:*",
			expectedRawVer:  "14.0.0-103-5e0b41b3+gitea-1.22.0",
			expectedIsFork:  true,
			expectedForkVer: "14.0.0",
		},
		{
			name:            "forgejo fork version",
			body:            `{"version":"7.0.0+gitea-1.21.0"}`,
			expectedTech:    "gitea",
			expectedVersion: "1.21.0",
			expectedCPE:     "cpe:2.3:a:gitea:gitea:1.21.0:*:*:*:*:*:*:*",
			expectedRawVer:  "7.0.0+gitea-1.21.0",
			expectedIsFork:  true,
			expectedForkVer: "7.0.0",
		},
		{
			name:            "gitea 1.20.5",
			body:            `{"version":"1.20.5"}`,
			expectedTech:    "gitea",
			expectedVersion: "1.20.5",
			expectedCPE:     "cpe:2.3:a:gitea:gitea:1.20.5:*:*:*:*:*:*:*",
			expectedRawVer:  "1.20.5",
			expectedIsFork:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GiteaFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
				Body: io.NopCloser(bytes.NewReader([]byte(tt.body))),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.expectedTech, result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.expectedCPE)

			// Check raw_version in metadata
			if tt.expectedRawVer != "" {
				assert.Equal(t, tt.expectedRawVer, result.Metadata["raw_version"])
			}

			// Check fork metadata
			if tt.expectedIsFork {
				assert.Equal(t, true, result.Metadata["is_fork"])
				assert.Equal(t, tt.expectedForkVer, result.Metadata["fork_version"])
			} else {
				// For non-forks, these fields should not be present
				_, hasFork := result.Metadata["is_fork"]
				assert.False(t, hasFork, "is_fork should not be present for non-fork versions")
			}
		})
	}
}

func TestGiteaFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &GiteaFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	body := []byte("not valid json")

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err) // Should return nil result, not error
}

func TestGiteaFingerprinter_Fingerprint_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing version field",
			body: `{"status": "ok"}`,
		},
		{
			name: "empty version field",
			body: `{"version":""}`,
		},
		{
			name: "invalid version format - no digits",
			body: `{"version":"invalid"}`,
		},
		{
			name: "invalid version format - only one digit",
			body: `{"version":"1"}`,
		},
		{
			name: "JSON with version but extra fields",
			body: `{"version":"1.0.0","message":"Welcome"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GiteaFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			assert.Nil(t, result)
			assert.Nil(t, err) // Should return nil result, not error
		})
	}
}

func TestGiteaFingerprinter_Fingerprint_CPEInjection(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "CPE injection attempt with colon",
			body: `{"version":"1.0.0:*:*"}`,
		},
		{
			name: "CPE injection with special characters",
			body: `{"version":"1.0.0;rm -rf /"}`,
		},
		{
			name: "command injection attempt",
			body: `{"version":"1.0.0$(whoami)"}`,
		},
		{
			name: "path traversal attempt",
			body: `{"version":"../../etc/passwd"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GiteaFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			// Should reject malicious versions
			assert.Nil(t, result)
			assert.Nil(t, err)
		})
	}
}

func TestGiteaFingerprinter_Fingerprint_NotGitea(t *testing.T) {
	fp := &GiteaFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	// Valid JSON but not Gitea format
	body := []byte(`{"status": "ok", "app": "other"}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestBuildGiteaCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "1.21.0",
			expected: "cpe:2.3:a:gitea:gitea:1.21.0:*:*:*:*:*:*:*",
		},
		{
			name:     "version with suffix",
			version:  "1.26.0",
			expected: "cpe:2.3:a:gitea:gitea:1.26.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:gitea:gitea:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildGiteaCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestGiteaFingerprinter_Fingerprint_PassiveHeader(t *testing.T) {
	tests := []struct {
		name            string
		headerVersion   string
		expectedVersion string
		expectNil       bool
	}{
		{
			name:            "X-Gitea-Version 1.21.0",
			headerVersion:   "1.21.0",
			expectedVersion: "1.21.0",
		},
		{
			name:            "X-Gitea-Version with v prefix",
			headerVersion:   "v1.22.3",
			expectedVersion: "1.22.3",
		},
		{
			name:            "X-Gitea-Version with dev suffix",
			headerVersion:   "1.26.0+dev-489-gc9a038bc4e",
			expectedVersion: "1.26.0",
		},
		{
			name:          "X-Gitea-Version with unsafe chars rejected",
			headerVersion: "1.0.0:*:*",
			expectNil:     true,
		},
		{
			name:          "X-Gitea-Version with invalid format rejected",
			headerVersion: "invalid",
			expectNil:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GiteaFingerprinter{}
			resp := &http.Response{
				Header: http.Header{},
			}
			resp.Header.Set("X-Gitea-Version", tt.headerVersion)
			resp.Header.Set("Content-Type", "text/html")

			result, err := fp.Fingerprint(resp, []byte("<html></html>"))
			require.NoError(t, err)

			if tt.expectNil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, "gitea", result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Equal(t, "header", result.Metadata["detection_path"])
			assert.Equal(t, tt.headerVersion, result.Metadata["raw_version"])
		})
	}
}

func TestGiteaFingerprinter_Fingerprint_PassiveCookie(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		expectedVersion string
	}{
		{
			name:            "cookie only, no version in body",
			body:            `<html data-theme="gitea-auto"><head></head><body></body></html>`,
			expectedVersion: "",
		},
		{
			name:            "cookie with CSS gitea version in body",
			body:            `<html><head><link rel="stylesheet" href="/assets/css/index.css?v=~gitea-1.22.0"></head></html>`,
			expectedVersion: "1.22.0",
		},
		{
			name:            "cookie with gitea version in CSS (no tilde)",
			body:            `<html><head><link rel="stylesheet" href="/assets/css/index.css?v=gitea-1.21.0"></head></html>`,
			expectedVersion: "1.21.0",
		},
		{
			name:            "cookie with CSS gitea version followed by extra chars",
			body:            `<html><head><link rel="stylesheet" href="/assets/css/index.css?v=gitea-1.22.0abc"></head></html>`,
			expectedVersion: "1.22.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GiteaFingerprinter{}
			resp := &http.Response{
				Header: http.Header{},
			}
			resp.Header.Set("Content-Type", "text/html")
			resp.Header.Add("Set-Cookie", "i_like_gitea=abc123; Path=/; HttpOnly")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "gitea", result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Equal(t, "cookie", result.Metadata["detection_path"])
		})
	}
}

func TestGiteaFingerprinter_Fingerprint_FalsePositiveRegression(t *testing.T) {
	// Regression test: generic JSON API returning {"version":"1.0.0"} at /
	// WITHOUT Gitea-specific markers should still match via JSON path (active path).
	// The false positive prevention happens at Match() level in the passive path:
	// without i_like_gitea cookie or X-Gitea-Version header, an HTML response
	// won't pass Match(), so Fingerprint() is never called for non-Gitea HTML responses.
	//
	// However, when Fingerprint() IS called with JSON (active path from /api/v1/version),
	// it correctly processes the JSON. This test verifies the JSON path still works
	// and that the cookie/header paths correctly reject non-Gitea responses.

	fp := &GiteaFingerprinter{}

	t.Run("JSON without Gitea markers still processes via JSON path", func(t *testing.T) {
		// This simulates the active path calling Fingerprint() with JSON
		resp := &http.Response{
			Header: http.Header{},
		}
		resp.Header.Set("Content-Type", "application/json")

		body := []byte(`{"version":"1.0.0"}`)
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		// JSON path still works — this is correct for the active probe
		require.NotNil(t, result)
		assert.Equal(t, "gitea", result.Technology)
		assert.Equal(t, "1.0.0", result.Version)
	})

	t.Run("JSON with extra fields rejected (false positive prevention)", func(t *testing.T) {
		resp := &http.Response{
			Header: http.Header{},
		}
		resp.Header.Set("Content-Type", "application/json")

		body := []byte(`{"message":"Welcome to Stewart Production Assistant","version":"1.0.0","docs":"/docs"}`)
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result, "multi-key JSON should be rejected to prevent false positives")
	})

	t.Run("HTML without Gitea cookie or header returns nil", func(t *testing.T) {
		// This verifies that if somehow Fingerprint() is called with HTML
		// without Gitea markers, it returns nil
		resp := &http.Response{
			Header: http.Header{},
		}
		resp.Header.Set("Content-Type", "text/html")

		body := []byte(`<html><body>{"version":"1.0.0"}</body></html>`)
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}

func TestHasGiteaCookie(t *testing.T) {
	tests := []struct {
		name    string
		cookies []string
		want    bool
	}{
		{
			name:    "has i_like_gitea cookie",
			cookies: []string{"i_like_gitea=abc123; Path=/; HttpOnly"},
			want:    true,
		},
		{
			name:    "has i_like_gitea among multiple cookies",
			cookies: []string{"session=xyz", "i_like_gitea=abc123; Path=/"},
			want:    true,
		},
		{
			name:    "no gitea cookie",
			cookies: []string{"session=xyz; Path=/"},
			want:    false,
		},
		{
			name:    "no cookies at all",
			cookies: nil,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: http.Header{},
			}
			for _, c := range tt.cookies {
				resp.Header.Add("Set-Cookie", c)
			}
			assert.Equal(t, tt.want, hasGiteaCookie(resp))
		})
	}
}

func TestGiteaFingerprinter_Integration(t *testing.T) {
	// Save and restore global state to prevent test pollution
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &GiteaFingerprinter{}
	Register(fp)

	t.Run("active path JSON", func(t *testing.T) {
		body := []byte(`{"version":"1.21.0"}`)
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"application/json"},
			},
			Body: io.NopCloser(bytes.NewReader(body)),
		}

		results := RunFingerprinters(resp, body)
		require.Len(t, results, 1)
		assert.Equal(t, "gitea", results[0].Technology)
		assert.Equal(t, "1.21.0", results[0].Version)
	})

	t.Run("passive path cookie", func(t *testing.T) {
		body := []byte(`<html data-theme="gitea-auto"><head></head><body></body></html>`)
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"text/html"},
				"Set-Cookie":   []string{"i_like_gitea=abc123; Path=/; HttpOnly"},
			},
		}

		results := RunFingerprinters(resp, body)
		require.Len(t, results, 1)
		assert.Equal(t, "gitea", results[0].Technology)
		assert.Equal(t, "cookie", results[0].Metadata["detection_path"])
	})

	t.Run("passive path header", func(t *testing.T) {
		body := []byte(`<html><body>Gitea</body></html>`)
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type":    []string{"text/html"},
				"X-Gitea-Version": []string{"1.22.0"},
			},
		}

		results := RunFingerprinters(resp, body)
		require.Len(t, results, 1)
		assert.Equal(t, "gitea", results[0].Technology)
		assert.Equal(t, "1.22.0", results[0].Version)
		assert.Equal(t, "header", results[0].Metadata["detection_path"])
	})

	t.Run("non-gitea HTML not matched", func(t *testing.T) {
		body := []byte(`<html><body>Not Gitea</body></html>`)
		resp := &http.Response{
			StatusCode: 200,
			Header: http.Header{
				"Content-Type": []string{"text/html"},
			},
		}

		results := RunFingerprinters(resp, body)
		assert.Len(t, results, 0)
	})
}
