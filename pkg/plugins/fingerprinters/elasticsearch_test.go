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

func TestElasticsearchFingerprinter_Name(t *testing.T) {
	fp := &ElasticsearchFingerprinter{}
	assert.Equal(t, "elasticsearch", fp.Name())
}

func TestElasticsearchFingerprinter_Match(t *testing.T) {
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
			fp := &ElasticsearchFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestElasticsearchFingerprinter_Fingerprint_ValidElasticsearch(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name: "Elasticsearch 8.11.3",
			body: `{
				"name" : "es-node",
				"cluster_name" : "elasticsearch",
				"cluster_uuid" : "abc-123",
				"version" : {
					"number" : "8.11.3",
					"build_flavor" : "default",
					"build_type" : "docker",
					"build_hash" : "hash123",
					"build_date" : "2023-11-15T00:00:00Z",
					"build_snapshot" : false,
					"lucene_version" : "9.8.0",
					"minimum_wire_compatibility_version" : "7.17.0",
					"minimum_index_compatibility_version" : "7.0.0"
				},
				"tagline" : "You Know, for Search"
			}`,
			expectedTech:    "elasticsearch",
			expectedVersion: "8.11.3",
			expectedCPE:     "cpe:2.3:a:elastic:elasticsearch:8.11.3:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"cluster_name":   "elasticsearch",
				"lucene_version": "9.8.0",
			},
		},
		{
			name: "Elasticsearch with SNAPSHOT version",
			body: `{
				"name" : "dev-node",
				"cluster_name" : "dev-cluster",
				"cluster_uuid" : "def-456",
				"version" : {
					"number" : "8.12.0-SNAPSHOT",
					"build_flavor" : "default",
					"build_type" : "docker",
					"build_hash" : "hash456",
					"build_date" : "2023-12-01T00:00:00Z",
					"build_snapshot" : true,
					"lucene_version" : "9.9.0"
				},
				"tagline" : "You Know, for Search"
			}`,
			expectedTech:    "elasticsearch",
			expectedVersion: "8.12.0",
			expectedCPE:     "cpe:2.3:a:elastic:elasticsearch:8.12.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"cluster_name":   "dev-cluster",
				"lucene_version": "9.9.0",
			},
		},
		{
			name: "Elasticsearch 7.17.0",
			body: `{
				"name" : "legacy-node",
				"cluster_name" : "prod-cluster",
				"cluster_uuid" : "ghi-789",
				"version" : {
					"number" : "7.17.0",
					"build_flavor" : "default",
					"build_type" : "rpm",
					"build_hash" : "hash789",
					"build_date" : "2022-01-28T00:00:00Z",
					"build_snapshot" : false,
					"lucene_version" : "8.11.1"
				},
				"tagline" : "You Know, for Search"
			}`,
			expectedTech:    "elasticsearch",
			expectedVersion: "7.17.0",
			expectedCPE:     "cpe:2.3:a:elastic:elasticsearch:7.17.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"cluster_name":   "prod-cluster",
				"lucene_version": "8.11.1",
			},
		},
		{
			name: "Elasticsearch without version (edge case)",
			body: `{
				"name" : "minimal-node",
				"cluster_name" : "test-cluster",
				"cluster_uuid" : "jkl-012",
				"version" : {
					"number" : ""
				},
				"tagline" : "You Know, for Search"
			}`,
			expectedTech:    "elasticsearch",
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"cluster_name":   "test-cluster",
				"lucene_version": "",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ElasticsearchFingerprinter{}
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

			for key, expectedValue := range tt.expectedMetadata {
				assert.Equal(t, expectedValue, result.Metadata[key], "metadata key: %s", key)
			}

		})
	}
}

func TestElasticsearchFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &ElasticsearchFingerprinter{}
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

func TestElasticsearchFingerprinter_Fingerprint_MissingFields(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing tagline",
			body: `{
				"name" : "es-node",
				"cluster_name" : "elasticsearch",
				"version" : {
					"number" : "8.11.3"
				}
			}`,
		},
		{
			name: "wrong tagline (OpenSearch)",
			body: `{
				"name" : "opensearch-node",
				"cluster_name" : "opensearch",
				"version" : {
					"number" : "2.11.0",
					"distribution" : "opensearch"
				},
				"tagline" : "The OpenSearch Project: https://opensearch.org/"
			}`,
		},
		{
			name: "empty tagline",
			body: `{
				"name" : "es-node",
				"cluster_name" : "elasticsearch",
				"version" : {
					"number" : "8.11.3"
				},
				"tagline" : ""
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ElasticsearchFingerprinter{}
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

func TestElasticsearchFingerprinter_Fingerprint_NotElasticsearch(t *testing.T) {
	fp := &ElasticsearchFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	// Valid JSON but not Elasticsearch format
	body := []byte(`{"status": "ok", "version": "1.0.0", "application": "custom-api"}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestBuildElasticsearchCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "8.11.3",
			expected: "cpe:2.3:a:elastic:elasticsearch:8.11.3:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:elastic:elasticsearch:*:*:*:*:*:*:*:*",
		},
		{
			name:     "version with SNAPSHOT cleaned",
			version:  "8.12.0",
			expected: "cpe:2.3:a:elastic:elasticsearch:8.12.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildElasticsearchCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestElasticsearchFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &ElasticsearchFingerprinter{}
	Register(fp)

	body := []byte(`{
		"name" : "es-node",
		"cluster_name" : "elasticsearch",
		"cluster_uuid" : "abc-123",
		"version" : {
			"number" : "8.11.3",
			"build_flavor" : "default",
			"lucene_version" : "9.8.0"
		},
		"tagline" : "You Know, for Search"
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
	assert.Equal(t, "elasticsearch", results[0].Technology)
	assert.Equal(t, "8.11.3", results[0].Version)
}
