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

func TestCockroachDBFingerprinter_Name(t *testing.T) {
	fp := &CockroachDBFingerprinter{}
	assert.Equal(t, "cockroachdb", fp.Name())
}

func TestCockroachDBFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &CockroachDBFingerprinter{}
	assert.Equal(t, "/api/v2/nodes/", fp.ProbeEndpoint())
}

func TestCockroachDBFingerprinter_Match(t *testing.T) {
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
			fp := &CockroachDBFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestCockroachDBFingerprinter_Fingerprint_ValidCockroachDB(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name: "CockroachDB v26.1.0",
			body: `{
				"nodes": [
					{
						"node_id": 1,
						"ServerVersion": {
							"major": 26,
							"minor": 1,
							"patch": 0,
							"internal": 0
						},
						"build_tag": "v26.1.0"
					}
				]
			}`,
			expectedTech:    "cockroachdb",
			expectedVersion: "26.1.0",
			expectedCPE:     "cpe:2.3:a:cockroachdb:cockroachdb:26.1.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"node_count":    1,
				"raw_build_tag": "v26.1.0",
			},
		},
		{
			name: "CockroachDB v24.3.5 with multiple nodes",
			body: `{
				"nodes": [
					{
						"node_id": 1,
						"ServerVersion": {
							"major": 24,
							"minor": 3,
							"patch": 5,
							"internal": 0
						},
						"build_tag": "v24.3.5"
					},
					{
						"node_id": 2,
						"ServerVersion": {
							"major": 24,
							"minor": 3,
							"patch": 5,
							"internal": 0
						},
						"build_tag": "v24.3.5"
					}
				]
			}`,
			expectedTech:    "cockroachdb",
			expectedVersion: "24.3.5",
			expectedCPE:     "cpe:2.3:a:cockroachdb:cockroachdb:24.3.5:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"node_count":    2,
				"raw_build_tag": "v24.3.5",
			},
		},
		{
			name: "CockroachDB v23.2.10",
			body: `{
				"nodes": [
					{
						"node_id": 1,
						"ServerVersion": {
							"major": 23,
							"minor": 2,
							"patch": 10,
							"internal": 0
						},
						"build_tag": "v23.2.10"
					}
				]
			}`,
			expectedTech:    "cockroachdb",
			expectedVersion: "23.2.10",
			expectedCPE:     "cpe:2.3:a:cockroachdb:cockroachdb:23.2.10:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"node_count":    1,
				"raw_build_tag": "v23.2.10",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CockroachDBFingerprinter{}
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

func TestCockroachDBFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &CockroachDBFingerprinter{}
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

func TestCockroachDBFingerprinter_Fingerprint_EmptyNodesArray(t *testing.T) {
	fp := &CockroachDBFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	body := []byte(`{"nodes": []}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err) // Empty nodes array is not CockroachDB
}

func TestCockroachDBFingerprinter_Fingerprint_MissingNodes(t *testing.T) {
	fp := &CockroachDBFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	body := []byte(`{"status": "ok"}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestCockroachDBFingerprinter_Fingerprint_MissingBuildTag_FallbackToServerVersion(t *testing.T) {
	fp := &CockroachDBFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	body := []byte(`{
		"nodes": [
			{
				"node_id": 1,
				"ServerVersion": {
					"major": 26,
					"minor": 1,
					"patch": 0,
					"internal": 0
				}
			}
		]
	}`)

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "cockroachdb", result.Technology)
	assert.Equal(t, "26.1.0", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:cockroachdb:cockroachdb:26.1.0:*:*:*:*:*:*:*")
}

func TestCockroachDBFingerprinter_Fingerprint_NoVersionInfo(t *testing.T) {
	fp := &CockroachDBFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	// No build_tag and ServerVersion.Major is 0
	body := []byte(`{
		"nodes": [
			{
				"node_id": 1,
				"ServerVersion": {
					"major": 0,
					"minor": 0,
					"patch": 0,
					"internal": 0
				}
			}
		]
	}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err) // No version info available
}

func TestCockroachDBFingerprinter_Fingerprint_CPEInjectionPrevention(t *testing.T) {
	tests := []struct {
		name        string
		buildTag    string
		expectedCPE string
	}{
		{
			name:        "malicious injection attempt with colon",
			buildTag:    "v1.0:*:*:malicious",
			expectedCPE: "", // Should be rejected
		},
		{
			name:        "malicious injection with asterisk",
			buildTag:    "v1.0*malicious",
			expectedCPE: "", // Should be rejected
		},
		{
			name:        "SQL injection attempt",
			buildTag:    "v1.0'; DROP TABLE--",
			expectedCPE: "", // Should be rejected
		},
		{
			name:        "script injection",
			buildTag:    "v1.0<script>alert(1)</script>",
			expectedCPE: "", // Should be rejected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CockroachDBFingerprinter{}
			body := []byte(`{
				"nodes": [
					{
						"node_id": 1,
						"ServerVersion": {
							"major": 1,
							"minor": 0,
							"patch": 0,
							"internal": 0
						},
						"build_tag": "` + tt.buildTag + `"
					}
				]
			}`)
			resp := &http.Response{
				StatusCode: 200,
				Header: http.Header{
					"Content-Type": []string{"application/json"},
				},
			}

			result, err := fp.Fingerprint(resp, body)

			// Should return nil for invalid version formats
			assert.Nil(t, result)
			assert.Nil(t, err)
		})
	}
}

func TestBuildCockroachDBCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "26.1.0",
			expected: "cpe:2.3:a:cockroachdb:cockroachdb:26.1.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:cockroachdb:cockroachdb:*:*:*:*:*:*:*:*",
		},
		{
			name:     "patch version",
			version:  "24.3.5",
			expected: "cpe:2.3:a:cockroachdb:cockroachdb:24.3.5:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildCockroachDBCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCockroachDBFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &CockroachDBFingerprinter{}
	Register(fp)

	body := []byte(`{
		"nodes": [
			{
				"node_id": 1,
				"ServerVersion": {
					"major": 26,
					"minor": 1,
					"patch": 0,
					"internal": 0
				},
				"build_tag": "v26.1.0"
			}
		]
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
	assert.Equal(t, "cockroachdb", results[0].Technology)
	assert.Equal(t, "26.1.0", results[0].Version)
}
