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

func TestChromaDBFingerprinter_Name(t *testing.T) {
	fp := &ChromaDBFingerprinter{}
	assert.Equal(t, "chromadb", fp.Name())
}

func TestChromaDBFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ChromaDBFingerprinter{}
	assert.Equal(t, "/api/v1/heartbeat", fp.ProbeEndpoint())
}

func TestChromaDBFingerprinter_Match(t *testing.T) {
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
			fp := &ChromaDBFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestChromaDBFingerprinter_Fingerprint_ValidChromaDB(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name:            "ChromaDB with nanosecond heartbeat",
			body:            `{"nanosecond heartbeat": 1735740123456789000}`,
			expectedTech:    "chromadb",
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:a:chroma:chromadb:*:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"heartbeat": int64(1735740123456789000),
			},
		},
		{
			name:            "ChromaDB with minimum valid nanosecond timestamp",
			body:            `{"nanosecond heartbeat": 1000000000000000000}`,
			expectedTech:    "chromadb",
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:a:chroma:chromadb:*:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"heartbeat": int64(1000000000000000000),
			},
		},
		{
			name:            "ChromaDB with high nanosecond timestamp",
			body:            `{"nanosecond heartbeat": 2000000000000000000}`,
			expectedTech:    "chromadb",
			expectedVersion: "",
			expectedCPE:     "cpe:2.3:a:chroma:chromadb:*:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"heartbeat": int64(2000000000000000000),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ChromaDBFingerprinter{}
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

func TestChromaDBFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &ChromaDBFingerprinter{}
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

func TestChromaDBFingerprinter_Fingerprint_MissingHeartbeat(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing nanosecond heartbeat field",
			body: `{"version": "1.4.0"}`,
		},
		{
			name: "empty response",
			body: `{}`,
		},
		{
			name: "wrong field name (no space)",
			body: `{"nanosecondheartbeat": 1735740123456789000}`,
		},
		{
			name: "wrong field name (different)",
			body: `{"heartbeat": 1735740123456789000}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ChromaDBFingerprinter{}
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

func TestChromaDBFingerprinter_Fingerprint_InvalidHeartbeat(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "heartbeat value too small (milliseconds)",
			body: `{"nanosecond heartbeat": 1735740123456}`,
		},
		{
			name: "heartbeat value too small (seconds)",
			body: `{"nanosecond heartbeat": 1735740123}`,
		},
		{
			name: "heartbeat value zero",
			body: `{"nanosecond heartbeat": 0}`,
		},
		{
			name: "heartbeat value negative",
			body: `{"nanosecond heartbeat": -1}`,
		},
		{
			name: "heartbeat value just below threshold",
			body: `{"nanosecond heartbeat": 999999999999999999}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ChromaDBFingerprinter{}
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

func TestChromaDBFingerprinter_Fingerprint_NotChromaDB(t *testing.T) {
	fp := &ChromaDBFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
	}

	// Valid JSON but not ChromaDB format
	body := []byte(`{"status": "ok", "version": "1.0.0"}`)

	result, err := fp.Fingerprint(resp, body)

	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestBuildChromaDBCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "1.4.0",
			expected: "cpe:2.3:a:chroma:chromadb:1.4.0:*:*:*:*:*:*:*",
		},
		{
			name:     "version 0.5.20",
			version:  "0.5.20",
			expected: "cpe:2.3:a:chroma:chromadb:0.5.20:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version",
			version:  "",
			expected: "cpe:2.3:a:chroma:chromadb:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildChromaDBCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestChromaDBFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &ChromaDBFingerprinter{}
	Register(fp)

	body := []byte(`{"nanosecond heartbeat": 1735740123456789000}`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "chromadb", results[0].Technology)
	assert.Equal(t, "", results[0].Version) // Version is empty in heartbeat-only response
}
