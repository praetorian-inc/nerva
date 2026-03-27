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

func TestLocalAIFingerprinter_Name(t *testing.T) {
	fp := &LocalAIFingerprinter{}
	assert.Equal(t, "localai", fp.Name())
}

func TestLocalAIFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &LocalAIFingerprinter{}
	assert.Equal(t, "/system", fp.ProbeEndpoint())
}

func TestLocalAIFingerprinter_Match(t *testing.T) {
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
			fp := &LocalAIFingerprinter{}
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestLocalAIFingerprinter_Fingerprint_ValidLocalAI(t *testing.T) {
	tests := []struct {
		name                 string
		body                 string
		expectedTech         string
		expectedVersion      string
		expectedCPE          string
		expectedBackends     []string
		expectedModelCount   int
		expectedLoadedModels []string
	}{
		{
			name: "backends with loaded models",
			body: `{
				"backends": ["llama-cpp", "stablediffusion"],
				"loaded_models": [{"id": "ggml-gpt4all-j"}]
			}`,
			expectedTech:         "localai",
			expectedVersion:      "",
			expectedCPE:          "cpe:2.3:a:localai:localai:*:*:*:*:*:*:*:*",
			expectedBackends:     []string{"llama-cpp", "stablediffusion"},
			expectedModelCount:   1,
			expectedLoadedModels: []string{"ggml-gpt4all-j"},
		},
		{
			name: "backends with no loaded models (empty loaded_models array)",
			body: `{
				"backends": ["llama-cpp"],
				"loaded_models": []
			}`,
			expectedTech:         "localai",
			expectedVersion:      "",
			expectedCPE:          "cpe:2.3:a:localai:localai:*:*:*:*:*:*:*:*",
			expectedBackends:     []string{"llama-cpp"},
			expectedModelCount:   0,
			expectedLoadedModels: nil,
		},
		{
			name: "multiple backends and multiple models",
			body: `{
				"backends": ["llama-cpp", "stablediffusion", "whisper", "bark"],
				"loaded_models": [
					{"id": "ggml-gpt4all-j"},
					{"id": "stablediffusion"},
					{"id": "whisper-en"}
				]
			}`,
			expectedTech:         "localai",
			expectedVersion:      "",
			expectedCPE:          "cpe:2.3:a:localai:localai:*:*:*:*:*:*:*:*",
			expectedBackends:     []string{"llama-cpp", "stablediffusion", "whisper", "bark"},
			expectedModelCount:   3,
			expectedLoadedModels: []string{"ggml-gpt4all-j", "stablediffusion", "whisper-en"},
		},
		{
			name: "empty backends with loaded models",
			body: `{"backends": [], "loaded_models": [{"id": "model1"}]}`,
			expectedTech:         "localai",
			expectedVersion:      "",
			expectedCPE:          "cpe:2.3:a:localai:localai:*:*:*:*:*:*:*:*",
			expectedBackends:     []string{},
			expectedModelCount:   1,
			expectedLoadedModels: []string{"model1"},
		},
		{
			name: "extra unknown fields present alongside required fields",
			body: `{"backends": ["llama-cpp"], "loaded_models": [], "version": "2.0.0", "extra": true}`,
			expectedTech:         "localai",
			expectedVersion:      "",
			expectedCPE:          "cpe:2.3:a:localai:localai:*:*:*:*:*:*:*:*",
			expectedBackends:     []string{"llama-cpp"},
			expectedModelCount:   0,
			expectedLoadedModels: nil,
		},
		{
			name: "single backend no models",
			body: `{"backends": ["llama-cpp"], "loaded_models": []}`,
			expectedTech:         "localai",
			expectedVersion:      "",
			expectedCPE:          "cpe:2.3:a:localai:localai:*:*:*:*:*:*:*:*",
			expectedBackends:     []string{"llama-cpp"},
			expectedModelCount:   0,
			expectedLoadedModels: nil,
		},
		{
			name: "backends is null instead of array",
			body: `{"backends": null, "loaded_models": []}`,
			expectedTech:         "localai",
			expectedVersion:      "",
			expectedCPE:          "cpe:2.3:a:localai:localai:*:*:*:*:*:*:*:*",
			expectedBackends:     nil,
			expectedModelCount:   0,
			expectedLoadedModels: nil,
		},
		{
			name: "loaded_models is null instead of array",
			body: `{"backends": [], "loaded_models": null}`,
			expectedTech:         "localai",
			expectedVersion:      "",
			expectedCPE:          "cpe:2.3:a:localai:localai:*:*:*:*:*:*:*:*",
			expectedBackends:     []string{},
			expectedModelCount:   0,
			expectedLoadedModels: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &LocalAIFingerprinter{}
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

			assert.Equal(t, tt.expectedBackends, result.Metadata["backends"])
			assert.Equal(t, tt.expectedModelCount, result.Metadata["loaded_model_count"])
			assert.Equal(t, true, result.Metadata["anonymous_access"])

			if tt.expectedLoadedModels != nil {
				assert.Equal(t, tt.expectedLoadedModels, result.Metadata["loaded_models"])
			} else {
				_, hasLoadedModels := result.Metadata["loaded_models"]
				assert.False(t, hasLoadedModels, "loadedModels key should not be present when no models are loaded")
			}
		})
	}
}

func TestLocalAIFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	fp := &LocalAIFingerprinter{}
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

func TestLocalAIFingerprinter_Fingerprint_NotLocalAI(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "missing backends key",
			body: `{"loaded_models": [{"id": "some-model"}]}`,
		},
		{
			name: "missing loaded_models key",
			body: `{"backends": ["llama-cpp"]}`,
		},
		{
			name: "valid JSON but completely different structure (vLLM /v1/models response)",
			body: `{
				"object": "list",
				"data": [
					{
						"id": "meta-llama/Llama-2-7b-chat-hf",
						"object": "model",
						"owned_by": "vllm"
					}
				]
			}`,
		},
		{
			name: "empty JSON object",
			body: `{}`,
		},
		{
			name: "backends is string not array",
			body: `{"backends": "llama-cpp", "loaded_models": []}`,
		},
		{
			name: "extra fields present (should still not match if missing required)",
			body: `{"status": "ok", "version": "1.0.0"}`,
		},
		{
			name: "OpenAI API response format",
			body: `{"object": "list", "data": [{"id": "gpt-4", "object": "model", "owned_by": "openai"}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &LocalAIFingerprinter{}
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

func TestBuildLocalAICPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "normal version",
			version:  "1.40.0",
			expected: "cpe:2.3:a:localai:localai:1.40.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version uses wildcard",
			version:  "",
			expected: "cpe:2.3:a:localai:localai:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildLocalAICPE(tt.version)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestLocalAIFingerprinter_Integration(t *testing.T) {
	// Save and restore the global registry to avoid flaky parallel tests
	originalFingerprinters := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = originalFingerprinters })
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &LocalAIFingerprinter{}
	Register(fp)

	body := []byte(`{
		"backends": ["llama-cpp", "stablediffusion"],
		"loaded_models": [{"id": "ggml-gpt4all-j"}]
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
	assert.Equal(t, "localai", results[0].Technology)
	assert.Equal(t, "", results[0].Version)
}

func TestLocalAIFingerprinter_Fingerprint_LargePayload(t *testing.T) {
	fp := &LocalAIFingerprinter{}

	// Build a response with 20 backends and 50 models
	backendsJSON := `["llama-cpp","stablediffusion","whisper","bark","rwkv","bert-embeddings","falcon","mpt","gpt4all-j","dolly","gpt2","gptj","gptneox","mptq","codegen","replit","starcoder","bloom","opt","t5"]`
	modelsJSON := `[` +
		`{"id":"model-00"},{"id":"model-01"},{"id":"model-02"},{"id":"model-03"},{"id":"model-04"},` +
		`{"id":"model-05"},{"id":"model-06"},{"id":"model-07"},{"id":"model-08"},{"id":"model-09"},` +
		`{"id":"model-10"},{"id":"model-11"},{"id":"model-12"},{"id":"model-13"},{"id":"model-14"},` +
		`{"id":"model-15"},{"id":"model-16"},{"id":"model-17"},{"id":"model-18"},{"id":"model-19"},` +
		`{"id":"model-20"},{"id":"model-21"},{"id":"model-22"},{"id":"model-23"},{"id":"model-24"},` +
		`{"id":"model-25"},{"id":"model-26"},{"id":"model-27"},{"id":"model-28"},{"id":"model-29"},` +
		`{"id":"model-30"},{"id":"model-31"},{"id":"model-32"},{"id":"model-33"},{"id":"model-34"},` +
		`{"id":"model-35"},{"id":"model-36"},{"id":"model-37"},{"id":"model-38"},{"id":"model-39"},` +
		`{"id":"model-40"},{"id":"model-41"},{"id":"model-42"},{"id":"model-43"},{"id":"model-44"},` +
		`{"id":"model-45"},{"id":"model-46"},{"id":"model-47"},{"id":"model-48"},{"id":"model-49"}` +
		`]`
	body := []byte(`{"backends":` + backendsJSON + `,"loaded_models":` + modelsJSON + `}`)

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"application/json"},
		},
		Body: io.NopCloser(bytes.NewReader(body)),
	}

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "localai", result.Technology)
	assert.Equal(t, "", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:localai:localai:*:*:*:*:*:*:*:*")

	backends, ok := result.Metadata["backends"].([]string)
	require.True(t, ok, "backends metadata should be a []string")
	assert.Len(t, backends, 20)

	assert.Equal(t, 50, result.Metadata["loaded_model_count"])

	loadedModels, ok := result.Metadata["loaded_models"].([]string)
	require.True(t, ok, "loadedModels metadata should be a []string")
	assert.Len(t, loadedModels, 50)
	assert.Equal(t, "model-00", loadedModels[0])
	assert.Equal(t, "model-49", loadedModels[49])
}
