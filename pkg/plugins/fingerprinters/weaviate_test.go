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

func TestWeaviateFingerprinter_Name(t *testing.T) {
	fp := &WeaviateFingerprinter{}
	assert.Equal(t, "weaviate", fp.Name())
}

func TestWeaviateFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &WeaviateFingerprinter{}
	assert.Equal(t, "/v1/meta", fp.ProbeEndpoint())
}

func TestWeaviateFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		expected    bool
	}{
		{
			name:        "matches JSON content type",
			contentType: "application/json",
			expected:    true,
		},
		{
			name:        "matches JSON with charset",
			contentType: "application/json; charset=utf-8",
			expected:    true,
		},
		{
			name:        "does not match HTML",
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
			fp := &WeaviateFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestWeaviateFingerprinter_Fingerprint_ValidWeaviate(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		expectedTech    string
		expectedVersion string
		expectedCPE     string
		expectedModules []string
		hasModules      bool
		expectedGitHash string
	}{
		{
			name: "Weaviate 1.24.1 with modules",
			body: `{
				"hostname": "http://[::]:8080",
				"modules": {
					"text2vec-openai": {
						"documentationHref": "https://platform.openai.com/docs/guides/embeddings",
						"name": "OpenAI"
					},
					"generative-openai": {
						"documentationHref": "https://platform.openai.com/docs/guides/generation",
						"name": "OpenAI"
					}
				},
				"version": "1.24.1",
				"gitHash": "abc123def"
			}`,
			expectedTech:    "weaviate",
			expectedVersion: "1.24.1",
			expectedCPE:     "cpe:2.3:a:weaviate:weaviate:1.24.1:*:*:*:*:*:*:*",
			expectedModules: []string{"generative-openai", "text2vec-openai"},
			hasModules:      true,
			expectedGitHash: "abc123def",
		},
		{
			name: "Weaviate 1.23.0 minimal (no modules)",
			body: `{
				"hostname": "http://[::]:8080",
				"modules": {},
				"version": "1.23.0"
			}`,
			expectedTech:    "weaviate",
			expectedVersion: "1.23.0",
			expectedCPE:     "cpe:2.3:a:weaviate:weaviate:1.23.0:*:*:*:*:*:*:*",
			expectedModules: nil,
			hasModules:      false,
			expectedGitHash: "",
		},
		{
			name: "Weaviate with rc suffix (1.25.0-rc1 cleaned to 1.25.0)",
			body: `{
				"hostname": "http://[::]:8080",
				"modules": {
					"text2vec-contextionary": {}
				},
				"version": "1.25.0-rc1",
				"gitHash": "ff00ff"
			}`,
			expectedTech:    "weaviate",
			expectedVersion: "1.25.0",
			expectedCPE:     "cpe:2.3:a:weaviate:weaviate:1.25.0:*:*:*:*:*:*:*",
			expectedModules: []string{"text2vec-contextionary"},
			hasModules:      true,
			expectedGitHash: "ff00ff",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &WeaviateFingerprinter{}
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

			// Hostname is always present in metadata
			assert.Equal(t, "http://[::]:8080", result.Metadata["hostname"])

			// Anonymous access is always noted
			assert.Equal(t, true, result.Metadata["anonymous_access"])

			if tt.hasModules {
				assert.Equal(t, tt.expectedModules, result.Metadata["modules"])
			} else {
				_, hasModulesKey := result.Metadata["modules"]
				assert.False(t, hasModulesKey, "modules key should not be present when no modules loaded")
			}

			// gitHash should only be present when non-empty
			if tt.expectedGitHash != "" {
				assert.Equal(t, tt.expectedGitHash, result.Metadata["git_hash"])
			} else {
				_, hasGitHash := result.Metadata["git_hash"]
				assert.False(t, hasGitHash, "gitHash key should not be present when empty")
			}
		})
	}
}

func TestWeaviateFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &WeaviateFingerprinter{}
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

func TestWeaviateFingerprinter_Fingerprint_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing hostname",
			body: `{
				"modules": {},
				"version": "1.24.1"
			}`,
		},
		{
			name: "missing version",
			body: `{
				"hostname": "http://[::]:8080",
				"modules": {}
			}`,
		},
		{
			name: "empty version",
			body: `{
				"hostname": "http://[::]:8080",
				"modules": {},
				"version": ""
			}`,
		},
		{
			name: "invalid version (not semver)",
			body: `{
				"hostname": "http://[::]:8080",
				"modules": {},
				"version": "unknown"
			}`,
		},
		{
			name: "hostname not a URL (generic API false positive)",
			body: `{"hostname": "prod-api-01", "version": "2.0.0", "service": "inventory"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &WeaviateFingerprinter{}
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

func TestWeaviateFingerprinter_Fingerprint_NotWeaviate(t *testing.T) {
	fp := &WeaviateFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	// Valid JSON with hostname and version but hostname is not a URL — not Weaviate
	body := []byte(`{"hostname": "my-server", "version": "1.0.0", "status": "ok"}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestBuildWeaviateCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "1.24.1",
			expected: "cpe:2.3:a:weaviate:weaviate:1.24.1:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:weaviate:weaviate:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildWeaviateCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestWeaviateFingerprinter_Integration(t *testing.T) {
	// Save and restore the global registry to avoid flaky parallel tests
	originalFingerprinters := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = originalFingerprinters })
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &WeaviateFingerprinter{}
	Register(fp)

	body := []byte(`{
		"hostname": "http://[::]:8080",
		"modules": {
			"text2vec-openai": {
				"documentationHref": "https://platform.openai.com/docs/guides/embeddings",
				"name": "OpenAI"
			},
			"generative-openai": {
				"documentationHref": "https://platform.openai.com/docs/guides/generation",
				"name": "OpenAI"
			}
		},
		"version": "1.24.1"
	}`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "weaviate", results[0].Technology)
	assert.Equal(t, "1.24.1", results[0].Version)
}
