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

func TestPineconeFingerprinter_Name(t *testing.T) {
	fp := &PineconeFingerprinter{}
	assert.Equal(t, "pinecone", fp.Name())
}

func TestPineconeFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		statusCode  int
		expected    bool
	}{
		{
			name:        "matches all responses regardless of content type",
			contentType: "application/json",
			statusCode:  401,
			expected:    true,
		},
		{
			name:        "matches HTML content type",
			contentType: "text/html",
			statusCode:  401,
			expected:    true,
		},
		{
			name:        "matches empty content type",
			contentType: "",
			statusCode:  401,
			expected:    true,
		},
		{
			name:        "matches 200 OK",
			contentType: "application/json",
			statusCode:  200,
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PineconeFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestPineconeFingerprinter_Fingerprint_ValidPinecone(t *testing.T) {
	tests := []struct {
		name             string
		headers          map[string]string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedMetadata map[string]any
	}{
		{
			name: "PRIMARY detection - X-Pinecone-Api-Version header",
			headers: map[string]string{
				"X-Pinecone-Api-Version": "2025-01",
			},
			expectedTech:    "pinecone",
			expectedVersion: "*",
			expectedCPE:     "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"api_version": "2025-01",
			},
		},
		{
			name: "SECONDARY detection - X-Pinecone-Auth-Rejected-Reason header",
			headers: map[string]string{
				"X-Pinecone-Auth-Rejected-Reason": "missing api key",
			},
			expectedTech:     "pinecone",
			expectedVersion:  "*",
			expectedCPE:      "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{},
		},
		{
			name: "Both headers present - PRIMARY takes precedence",
			headers: map[string]string{
				"X-Pinecone-Api-Version":          "2024-12",
				"X-Pinecone-Auth-Rejected-Reason": "invalid credentials",
			},
			expectedTech:    "pinecone",
			expectedVersion: "*",
			expectedCPE:     "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*",
			expectedMetadata: map[string]any{
				"api_version": "2024-12",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PineconeFingerprinter{}

			// Build response with headers
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}

			resp := &http.Response{
				StatusCode: 401,
				Header:     header,
				Body:       io.NopCloser(bytes.NewReader([]byte(""))),
			}

			result, err := fp.Fingerprint(resp, []byte(""))

			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.expectedTech, result.Technology)
			assert.Equal(t, tt.expectedVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.expectedCPE)

			// Check metadata
			if apiVersion, ok := tt.expectedMetadata["api_version"]; ok {
				assert.Equal(t, apiVersion, result.Metadata["api_version"], "metadata key: api_version")
			}
		})
	}
}

func TestPineconeFingerprinter_Fingerprint_NotPinecone(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
	}{
		{
			name: "no Pinecone headers",
			headers: map[string]string{
				"Content-Type": "application/json",
				"Server":       "nginx",
			},
		},
		{
			name: "empty headers",
			headers: map[string]string{},
		},
		{
			name: "similar but incorrect headers",
			headers: map[string]string{
				"X-Api-Version": "1.0",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PineconeFingerprinter{}

			// Build response with headers
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}

			resp := &http.Response{
				StatusCode: 401,
				Header:     header,
			}

			result, err := fp.Fingerprint(resp, []byte(""))

			assert.Nil(t, result)
			assert.Nil(t, err)
		})
	}
}

func TestBuildPineconeCPE(t *testing.T) {
	// Pinecone CPE always uses wildcard version
	result := buildPineconeCPE()
	assert.Equal(t, "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*", result)
}

func TestPineconeFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register
	fp := &PineconeFingerprinter{}
	Register(fp)

	// Test with PRIMARY detection header
	header := http.Header{}
	header.Set("X-Pinecone-Api-Version", "2025-01")

	resp := &http.Response{
		StatusCode: 401,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader([]byte(""))),
	}

	results := RunFingerprinters(resp, []byte(""))

	require.Len(t, results, 1)
	assert.Equal(t, "pinecone", results[0].Technology)
	assert.Equal(t, "*", results[0].Version)
	assert.Contains(t, results[0].CPEs, "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*")
}
