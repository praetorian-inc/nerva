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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// VLLMFingerprinter detects vLLM inference server via /v1/models endpoint
type VLLMFingerprinter struct{}

// vllmModelsResponse represents the JSON response from vLLM /v1/models endpoint
type vllmModelsResponse struct {
	Object string      `json:"object"`
	Data   []vllmModel `json:"data"`
}

// vllmModel represents a single model entry in the vLLM models list
type vllmModel struct {
	ID          string `json:"id"`
	Object      string `json:"object"`
	OwnedBy     string `json:"owned_by"`
	MaxModelLen *int   `json:"max_model_len,omitempty"`
}

func init() {
	Register(&VLLMFingerprinter{})
}

func (f *VLLMFingerprinter) Name() string {
	return "vllm"
}

func (f *VLLMFingerprinter) ProbeEndpoint() string {
	return "/v1/models"
}

func (f *VLLMFingerprinter) Match(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func (f *VLLMFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Parse JSON response
	var models vllmModelsResponse
	if err := json.Unmarshal(body, &models); err != nil {
		return nil, nil // Not valid JSON, not vLLM format
	}

	// Validate: object must be "list" and data must be non-empty
	if models.Object != "list" || len(models.Data) == 0 {
		return nil, nil
	}

	// Check at least one model has owned_by == "vllm" (vLLM discriminator)
	hasVLLMModel := false
	for _, model := range models.Data {
		if model.OwnedBy == "vllm" {
			hasVLLMModel = true
			break
		}
	}
	if !hasVLLMModel {
		return nil, nil
	}

	// Collect model IDs
	modelIDs := make([]string, 0, len(models.Data))
	for _, model := range models.Data {
		modelIDs = append(modelIDs, model.ID)
	}

	metadata := map[string]any{
		"modelCount":      len(models.Data),
		"anonymousAccess": true,
		"models":          modelIDs,
	}

	// Extract max_model_len from first model if present (vLLM-specific field)
	if models.Data[0].MaxModelLen != nil {
		metadata["maxModelLen"] = models.Data[0].MaxModelLen
	}

	// vLLM does not expose version in /v1/models — use wildcard CPE
	return &FingerprintResult{
		Technology: "vllm",
		Version:    "",
		CPEs:       []string{buildVLLMCPE("")},
		Metadata:   metadata,
	}, nil
}

// buildVLLMCPE generates a CPE (Common Platform Enumeration) string for vLLM.
// CPE format: cpe:2.3:a:vllm:vllm:{version}:*:*:*:*:*:*:*
//
// vLLM does not expose version via /v1/models, so version is always "*".
func buildVLLMCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:vllm:vllm:%s:*:*:*:*:*:*:*", version)
}
