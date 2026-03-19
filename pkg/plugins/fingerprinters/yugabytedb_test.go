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

// YugabyteDB Master Fingerprinter Tests

func TestYugabyteDBMasterFingerprinter_Name(t *testing.T) {
	fp := &YugabyteDBMasterFingerprinter{}
	assert.Equal(t, "yugabytedb-master", fp.Name())
}

func TestYugabyteDBMasterFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &YugabyteDBMasterFingerprinter{}
	assert.Equal(t, "/api/v1/version", fp.ProbeEndpoint())
}

func TestYugabyteDBMasterFingerprinter_Match(t *testing.T) {
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
			fp := &YugabyteDBMasterFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestYugabyteDBMasterFingerprinter_Fingerprint_ValidYugabyteDB(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name: "YugabyteDB Master v2.14.0.0-b94 community edition",
			body: `{
				"version_info": {
					"version_string": "2.14.0.0-b94",
					"edition": "ce",
					"version_major": "2",
					"version_minor": "14",
					"version_patch": "0",
					"build_number": "94"
				}
			}`,
			expectedTech:    "yugabytedb-master",
			expectedVersion: "2.14.0.0-b94",
			expectedCPE:     "cpe:2.3:a:yugabyte:yugabytedb:2.14.0.0-b94:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"edition":       "ce",
				"node_type":     "master",
				"version_major": "2",
				"version_minor": "14",
				"version_patch": "0",
				"build_number":  "94",
				"detection_method": "version_api",
			},
		},
		{
			name: "YugabyteDB Master v2.20.0.0 enterprise edition",
			body: `{
				"version_info": {
					"version_string": "2.20.0.0",
					"edition": "ee",
					"version_major": "2",
					"version_minor": "20",
					"version_patch": "0",
					"build_number": "0"
				}
			}`,
			expectedTech:    "yugabytedb-master",
			expectedVersion: "2.20.0.0",
			expectedCPE:     "cpe:2.3:a:yugabyte:yugabytedb:2.20.0.0:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"edition":       "ee",
				"node_type":     "master",
				"version_major": "2",
				"version_minor": "20",
				"version_patch": "0",
				"build_number":  "0",
				"detection_method": "version_api",
			},
		},
		{
			name: "YugabyteDB Master v2.18.1.0-b123",
			body: `{
				"version_info": {
					"version_string": "2.18.1.0-b123",
					"edition": "ce",
					"version_major": "2",
					"version_minor": "18",
					"version_patch": "1",
					"build_number": "123"
				}
			}`,
			expectedTech:    "yugabytedb-master",
			expectedVersion: "2.18.1.0-b123",
			expectedCPE:     "cpe:2.3:a:yugabyte:yugabytedb:2.18.1.0-b123:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"edition":       "ce",
				"node_type":     "master",
				"version_major": "2",
				"version_minor": "18",
				"version_patch": "1",
				"build_number":  "123",
				"detection_method": "version_api",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &YugabyteDBMasterFingerprinter{}
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

func TestYugabyteDBMasterFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &YugabyteDBMasterFingerprinter{}
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

func TestYugabyteDBMasterFingerprinter_Fingerprint_MissingVersionInfo(t *testing.T) {
	fp := &YugabyteDBMasterFingerprinter{}
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

func TestYugabyteDBMasterFingerprinter_Fingerprint_EmptyVersionString(t *testing.T) {
	fp := &YugabyteDBMasterFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	body := []byte(`{
		"version_info": {
			"version_string": "",
			"edition": "ce"
		}
	}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err) // Empty version string is not valid
}

func TestYugabyteDBMasterFingerprinter_Fingerprint_CPEInjectionPrevention(t *testing.T) {
	tests := []struct {
		name          string
		versionString string
		expectedCPE   string
	}{
		{
			name:          "malicious injection attempt with colon",
			versionString: "2.0:*:*:malicious",
			expectedCPE:   "", // Should be rejected
		},
		{
			name:          "malicious injection with asterisk",
			versionString: "2.0*malicious",
			expectedCPE:   "", // Should be rejected
		},
		{
			name:          "SQL injection attempt",
			versionString: "2.0'; DROP TABLE--",
			expectedCPE:   "", // Should be rejected
		},
		{
			name:          "script injection",
			versionString: "2.0<script>alert(1)</script>",
			expectedCPE:   "", // Should be rejected
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &YugabyteDBMasterFingerprinter{}
			body := []byte(`{
				"version_info": {
					"version_string": "` + tt.versionString + `",
					"edition": "ce"
				}
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

func TestBuildYugabyteDBCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version with build number",
			version:  "2.14.0.0-b94",
			expected: "cpe:2.3:a:yugabyte:yugabytedb:2.14.0.0-b94:*:*:*:*:*:*:*",
		},
		{
			name:     "version without build number",
			version:  "2.20.0.0",
			expected: "cpe:2.3:a:yugabyte:yugabytedb:2.20.0.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:yugabyte:yugabytedb:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildYugabyteDBCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

// YugabyteDB TServer Fingerprinter Tests

func TestYugabyteDBTServerFingerprinter_Name(t *testing.T) {
	fp := &YugabyteDBTServerFingerprinter{}
	assert.Equal(t, "yugabytedb-tserver", fp.Name())
}

func TestYugabyteDBTServerFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &YugabyteDBTServerFingerprinter{}
	assert.Equal(t, "/api/v1/version", fp.ProbeEndpoint())
}

func TestYugabyteDBTServerFingerprinter_Match(t *testing.T) {
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &YugabyteDBTServerFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestYugabyteDBTServerFingerprinter_Fingerprint_ValidYugabyteDB(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name: "YugabyteDB TServer v2.14.0.0-b94",
			body: `{
				"version_info": {
					"version_string": "2.14.0.0-b94",
					"edition": "ce",
					"version_major": "2",
					"version_minor": "14",
					"version_patch": "0",
					"build_number": "94"
				}
			}`,
			expectedTech:    "yugabytedb-tserver",
			expectedVersion: "2.14.0.0-b94",
			expectedCPE:     "cpe:2.3:a:yugabyte:yugabytedb:2.14.0.0-b94:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"edition":       "ce",
				"node_type":     "tserver",
				"version_major": "2",
				"version_minor": "14",
				"version_patch": "0",
				"build_number":  "94",
				"detection_method": "version_api",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &YugabyteDBTServerFingerprinter{}
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

func TestYugabyteDBTServerFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &YugabyteDBTServerFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	body := []byte("not valid json")

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestYugabyteDBMasterFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &YugabyteDBMasterFingerprinter{}
	Register(fp)

	body := []byte(`{
		"version_info": {
			"version_string": "2.14.0.0-b94",
			"edition": "ce",
			"version_major": "2",
			"version_minor": "14",
			"version_patch": "0",
			"build_number": "94"
		}
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
	assert.Equal(t, "yugabytedb-master", results[0].Technology)
	assert.Equal(t, "2.14.0.0-b94", results[0].Version)
}

func TestYugabyteDBTServerFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &YugabyteDBTServerFingerprinter{}
	Register(fp)

	body := []byte(`{
		"version_info": {
			"version_string": "2.14.0.0-b94",
			"edition": "ce",
			"version_major": "2",
			"version_minor": "14",
			"version_patch": "0",
			"build_number": "94"
		}
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
	assert.Equal(t, "yugabytedb-tserver", results[0].Technology)
	assert.Equal(t, "2.14.0.0-b94", results[0].Version)
}
