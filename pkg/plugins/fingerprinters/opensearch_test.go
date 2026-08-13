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

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestOpenSearchFingerprinter_Name(t *testing.T) {
	fp := &OpenSearchFingerprinter{}
	assert.Equal(t, "opensearch", fp.Name())
}

func TestOpenSearchFingerprinter_Match(t *testing.T) {
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
			name:        "does not match empty content type",
			contentType: "",
			expected:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OpenSearchFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestOpenSearchFingerprinter_Fingerprint_Positive(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name: "OpenSearch 2.11.0 via distribution field",
			body: `{
				"name" : "opensearch-node",
				"cluster_name" : "opensearch-cluster",
				"cluster_uuid" : "abc-123",
				"version" : {
					"distribution" : "opensearch",
					"number" : "2.11.0",
					"build_type" : "tar",
					"build_hash" : "hash123",
					"build_date" : "2023-11-15T00:00:00Z",
					"build_snapshot" : false,
					"lucene_version" : "9.7.0",
					"minimum_wire_compatibility_version" : "7.10.0",
					"minimum_index_compatibility_version" : "7.0.0"
				},
				"tagline" : "The OpenSearch Project: https://opensearch.org/"
			}`,
			expectedVersion: "2.11.0",
			expectedCPE:     "cpe:2.3:a:amazon:opensearch:2.11.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"cluster_name":   "opensearch-cluster",
				"lucene_version": "9.7.0",
			},
		},
		{
			name: "OpenSearch 1.3.14 via distribution field",
			body: `{
				"name" : "opensearch-node-1",
				"cluster_name" : "opensearch-legacy",
				"cluster_uuid" : "def-456",
				"version" : {
					"distribution" : "opensearch",
					"number" : "1.3.14",
					"build_type" : "rpm",
					"build_hash" : "hash456",
					"build_snapshot" : false,
					"lucene_version" : "8.10.1"
				},
				"tagline" : "The OpenSearch Project: https://opensearch.org/"
			}`,
			expectedVersion: "1.3.14",
			expectedCPE:     "cpe:2.3:a:amazon:opensearch:1.3.14:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"cluster_name":   "opensearch-legacy",
				"lucene_version": "8.10.1",
			},
		},
		{
			name: "OpenSearch SNAPSHOT version cleaned",
			body: `{
				"name" : "opensearch-dev",
				"cluster_name" : "dev-cluster",
				"cluster_uuid" : "ghi-789",
				"version" : {
					"distribution" : "opensearch",
					"number" : "2.12.0-SNAPSHOT",
					"build_type" : "tar",
					"build_snapshot" : true,
					"lucene_version" : "9.9.0"
				},
				"tagline" : "The OpenSearch Project: https://opensearch.org/"
			}`,
			expectedVersion: "2.12.0",
			expectedCPE:     "cpe:2.3:a:amazon:opensearch:2.12.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"cluster_name":   "dev-cluster",
				"lucene_version": "9.9.0",
			},
		},
		{
			name: "OpenSearch without distribution field but with tagline fallback",
			body: `{
				"name" : "opensearch-legacy-node",
				"cluster_name" : "legacy-cluster",
				"cluster_uuid" : "jkl-012",
				"version" : {
					"number" : "1.0.0",
					"build_type" : "tar",
					"build_snapshot" : false,
					"lucene_version" : "8.7.0"
				},
				"tagline" : "The OpenSearch Project: https://opensearch.org/"
			}`,
			expectedVersion: "1.0.0",
			expectedCPE:     "cpe:2.3:a:amazon:opensearch:1.0.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"cluster_name":   "legacy-cluster",
				"lucene_version": "8.7.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OpenSearchFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "opensearch", result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.expectedCPE)
			assert.Equal(t, plugins.SeverityHigh, result.Severity)

			for key, expectedValue := range tt.expectedMetadata {
				assert.Equal(t, expectedValue, result.Metadata[key], "metadata key: %s", key)
			}
		})
	}
}

func TestOpenSearchFingerprinter_Fingerprint_Negative(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Elasticsearch response with 'You Know, for Search' tagline",
			body: `{
				"name" : "es-node",
				"cluster_name" : "elasticsearch",
				"cluster_uuid" : "abc-123",
				"version" : {
					"number" : "8.11.3",
					"build_flavor" : "default",
					"build_type" : "docker",
					"lucene_version" : "9.8.0"
				},
				"tagline" : "You Know, for Search"
			}`,
		},
		{
			name: "generic JSON unrelated to OpenSearch",
			body: `{"status": "ok", "version": "1.0.0", "application": "custom-api"}`,
		},
		{
			name: "invalid JSON",
			body: `not valid json`,
		},
		{
			name: "empty body",
			body: ``,
		},

	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OpenSearchFingerprinter{}
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

func TestBuildOpenSearchCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "2.11.0",
			expected: "cpe:2.3:a:amazon:opensearch:2.11.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:amazon:opensearch:*:*:*:*:*:*:*:*",
		},
		{
			name:     "legacy 1.x version",
			version:  "1.3.14",
			expected: "cpe:2.3:a:amazon:opensearch:1.3.14:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildOpenSearchCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}


func TestOpenSearchFingerprinter_CPEMetacharGuard(t *testing.T) {
	body := []byte(`{
		"name" : "evil-node",
		"cluster_name" : "evil",
		"version" : {
			"distribution" : "opensearch",
			"number" : "2.11.0:*:*"
		},
		"tagline" : "The OpenSearch Project: https://opensearch.org/"
	}`)

	fp := &OpenSearchFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result, "OpenSearch is still detected but version is stripped")
	assert.Equal(t, "", result.Version, "version with CPE metacharacters must be stripped")
	assert.Contains(t, result.CPEs, "cpe:2.3:a:amazon:opensearch:*:*:*:*:*:*:*:*")
}

func TestOpenSearchFingerprinter_KibanaCollisionRegression(t *testing.T) {
	// OpenSearch root JSON must NOT trigger the Kibana fingerprinter.
	// Regression test for P0: kibana.go hasAPISignal gate was too loose.
	body := []byte(`{
		"name" : "opensearch-node",
		"cluster_name" : "opensearch-cluster",
		"cluster_uuid" : "abc-123",
		"version" : {
			"distribution" : "opensearch",
			"number" : "2.11.0",
			"build_hash" : "hash123",
			"lucene_version" : "9.7.0"
		},
		"tagline" : "The OpenSearch Project: https://opensearch.org/"
	}`)

	kibanaFP := &KibanaFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	result, err := kibanaFP.Fingerprint(resp, body)
	assert.Nil(t, err)
	assert.Nil(t, result, "Kibana fingerprinter must NOT match OpenSearch root JSON")
}


func TestOpenSearchFingerprinter_ElasticsearchCollisionRegression(t *testing.T) {
	// Elasticsearch root JSON must NOT trigger the OpenSearch fingerprinter.
	body := []byte(`{
		"name" : "es-node",
		"cluster_name" : "elasticsearch",
		"cluster_uuid" : "abc-123",
		"version" : {
			"number" : "8.11.3",
			"build_flavor" : "default",
			"build_type" : "docker",
			"build_hash" : "hash123",
			"lucene_version" : "9.8.0"
		},
		"tagline" : "You Know, for Search"
	}`)

	fp := &OpenSearchFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	result, err := fp.Fingerprint(resp, body)
	assert.Nil(t, err)
	assert.Nil(t, result, "OpenSearch fingerprinter must NOT match Elasticsearch root JSON")
}

func TestOpenSearchFingerprinter_KibanaStatusCollisionRegression(t *testing.T) {
	// Kibana /api/status JSON must NOT trigger the OpenSearch fingerprinter.
	body := []byte(`{
		"name" : "kibana",
		"uuid" : "abc-123",
		"version" : {
			"number" : "8.12.0",
			"build_hash" : "hash123",
			"build_number" : 12345,
			"build_snapshot" : false
		},
		"status" : {
			"overall" : {
				"level" : "available"
			}
		}
	}`)

	fp := &OpenSearchFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	result, err := fp.Fingerprint(resp, body)
	assert.Nil(t, err)
	assert.Nil(t, result, "OpenSearch fingerprinter must NOT match Kibana status JSON")
}
