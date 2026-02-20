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

func TestArangoDBFingerprinter_Name(t *testing.T) {
	fp := &ArangoDBFingerprinter{}
	assert.Equal(t, "arangodb", fp.Name())
}

func TestArangoDBFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ArangoDBFingerprinter{}
	assert.Equal(t, "/_api/version", fp.ProbeEndpoint())
}

func TestArangoDBFingerprinter_Match(t *testing.T) {
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
			fp := &ArangoDBFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestArangoDBFingerprinter_Fingerprint_ValidArangoDB(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name: "ArangoDB 3.11.0 community",
			body: `{
				"server": "arango",
				"version": "3.11.0",
				"license": "community"
			}`,
			expectedTech:    "arangodb",
			expectedVersion: "3.11.0",
			expectedCPE:     "cpe:2.3:a:arangodb:arangodb:3.11.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"license": "community",
			},
		},
		{
			name: "ArangoDB 3.11.7 enterprise",
			body: `{
				"server": "arango",
				"version": "3.11.7",
				"license": "enterprise"
			}`,
			expectedTech:    "arangodb",
			expectedVersion: "3.11.7",
			expectedCPE:     "cpe:2.3:a:arangodb:arangodb:3.11.7:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"license": "enterprise",
			},
		},
		{
			name: "ArangoDB 3.10.2 community",
			body: `{
				"server": "arango",
				"version": "3.10.2",
				"license": "community"
			}`,
			expectedTech:    "arangodb",
			expectedVersion: "3.10.2",
			expectedCPE:     "cpe:2.3:a:arangodb:arangodb:3.10.2:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"license": "community",
			},
		},
		{
			name: "ArangoDB without version (edge case)",
			body: `{
				"server": "arango",
				"version": "",
				"license": "community"
			}`,
			expectedTech:    "arangodb",
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:a:arangodb:arangodb:*:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"license": "community",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ArangoDBFingerprinter{}
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

func TestArangoDBFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &ArangoDBFingerprinter{}
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

func TestArangoDBFingerprinter_Fingerprint_InvalidServer(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing server field",
			body: `{
				"version": "3.11.0",
				"license": "community"
			}`,
		},
		{
			name: "wrong server field",
			body: `{
				"server": "not-arango",
				"version": "3.11.0",
				"license": "community"
			}`,
		},
		{
			name: "empty server field",
			body: `{
				"server": "",
				"version": "3.11.0",
				"license": "community"
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ArangoDBFingerprinter{}
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

func TestArangoDBFingerprinter_Fingerprint_MissingRequiredFields(t *testing.T) {
	fp := &ArangoDBFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	// Valid server but missing version
	body := []byte(`{
		"server": "arango"
	}`)

	result, err := fp.Fingerprint(resp, body)

	// Should still succeed with empty version
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "arangodb", result.Technology)
	assert.Equal(t, "", result.Version)
}

func TestArangoDBFingerprinter_Fingerprint_NotArangoDB(t *testing.T) {
	fp := &ArangoDBFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	// Valid JSON but not ArangoDB format
	body := []byte(`{"status": "ok", "version": "1.0.0", "application": "custom-api"}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestBuildArangoDBCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "3.11.0",
			expected: "cpe:2.3:a:arangodb:arangodb:3.11.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:arangodb:arangodb:*:*:*:*:*:*:*:*",
		},
		{
			name:     "version with patch",
			version:  "3.11.7",
			expected: "cpe:2.3:a:arangodb:arangodb:3.11.7:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildArangoDBCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestArangoDBFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &ArangoDBFingerprinter{}
	Register(fp)

	body := []byte(`{
		"server": "arango",
		"version": "3.11.0",
		"license": "community"
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
	assert.Equal(t, "arangodb", results[0].Technology)
	assert.Equal(t, "3.11.0", results[0].Version)
}
