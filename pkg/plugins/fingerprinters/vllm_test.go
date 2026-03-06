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

func TestVLLMFingerprinter_Name(t *testing.T) {
	fp := &VLLMFingerprinter{}
	assert.Equal(t, "vllm", fp.Name())
}

func TestVLLMFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &VLLMFingerprinter{}
	assert.Equal(t, "/v1/models", fp.ProbeEndpoint())
}

func TestVLLMFingerprinter_Match(t *testing.T) {
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
			fp := &VLLMFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestVLLMFingerprinter_Fingerprint_ValidVLLM(t *testing.T) {
	maxLen := 4096
	tests := []struct {
		name             string
		body             string
		expectedTech     string
		expectedVersion  string
		expectedCPE      string
		expectedModels   []string
		expectedCount    int
		expectedMaxModel *int
	}{
		{
			name: "single model with owned_by vllm and max_model_len",
			body: `{
				"object": "list",
				"data": [
					{
						"id": "meta-llama/Llama-2-7b-chat-hf",
						"object": "model",
						"owned_by": "vllm",
						"max_model_len": 4096
					}
				]
			}`,
			expectedTech:     "vllm",
			expectedVersion:  "",
			expectedCPE:      "cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*",
			expectedModels:   []string{"meta-llama/Llama-2-7b-chat-hf"},
			expectedCount:    1,
			expectedMaxModel: &maxLen,
		},
		{
			name: "multiple models",
			body: `{
				"object": "list",
				"data": [
					{
						"id": "meta-llama/Llama-2-7b-chat-hf",
						"object": "model",
						"owned_by": "vllm",
						"max_model_len": 4096
					},
					{
						"id": "mistralai/Mistral-7B-v0.1",
						"object": "model",
						"owned_by": "vllm"
					}
				]
			}`,
			expectedTech:     "vllm",
			expectedVersion:  "",
			expectedCPE:      "cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*",
			expectedModels:   []string{"meta-llama/Llama-2-7b-chat-hf", "mistralai/Mistral-7B-v0.1"},
			expectedCount:    2,
			expectedMaxModel: &maxLen,
		},
		{
			name: "model without max_model_len field",
			body: `{
				"object": "list",
				"data": [
					{
						"id": "gpt2",
						"object": "model",
						"owned_by": "vllm"
					}
				]
			}`,
			expectedTech:     "vllm",
			expectedVersion:  "",
			expectedCPE:      "cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*",
			expectedModels:   []string{"gpt2"},
			expectedCount:    1,
			expectedMaxModel: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &VLLMFingerprinter{}
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

			assert.Equal(t, tt.expectedCount, result.Metadata["modelCount"])
			assert.Equal(t, true, result.Metadata["anonymousAccess"])
			assert.Equal(t, tt.expectedModels, result.Metadata["models"])

			if tt.expectedMaxModel != nil {
				assert.Equal(t, tt.expectedMaxModel, result.Metadata["maxModelLen"])
			} else {
				_, hasMaxModelLen := result.Metadata["maxModelLen"]
				assert.False(t, hasMaxModelLen, "maxModelLen key should not be present when field is absent")
			}
		})
	}
}

func TestVLLMFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &VLLMFingerprinter{}
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

func TestVLLMFingerprinter_Fingerprint_NotVLLM(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "empty data array",
			body: `{"object": "list", "data": []}`,
		},
		{
			name: "missing object field",
			body: `{
				"data": [
					{
						"id": "gpt-4",
						"object": "model",
						"owned_by": "openai"
					}
				]
			}`,
		},
		{
			name: "owned_by is not vllm (openai)",
			body: `{
				"object": "list",
				"data": [
					{
						"id": "gpt-4",
						"object": "model",
						"owned_by": "openai"
					}
				]
			}`,
		},
		{
			name: "owned_by is not vllm (system)",
			body: `{
				"object": "list",
				"data": [
					{
						"id": "text-davinci-003",
						"object": "model",
						"owned_by": "system"
					}
				]
			}`,
		},
		{
			name: "valid JSON but completely different structure",
			body: `{"status": "ok", "models": ["gpt-4"], "version": "1.0.0"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &VLLMFingerprinter{}
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

func TestBuildVLLMCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "0.4.2",
			expected: "cpe:2.3:a:vllm:vllm:0.4.2:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version uses wildcard",
			version:  "",
			expected: "cpe:2.3:a:vllm:vllm:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildVLLMCPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestVLLMFingerprinter_Integration(t *testing.T) {
	// Save and restore the global registry to avoid flaky parallel tests
	originalFingerprinters := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = originalFingerprinters })
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &VLLMFingerprinter{}
	Register(fp)

	body := []byte(`{
		"object": "list",
		"data": [
			{
				"id": "meta-llama/Llama-2-7b-chat-hf",
				"object": "model",
				"owned_by": "vllm",
				"max_model_len": 4096
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
	assert.Equal(t, "vllm", results[0].Technology)
	assert.Equal(t, "", results[0].Version)
}
