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

// LocalAIFingerprinter detects LocalAI self-hosted inference server via /system endpoint
type LocalAIFingerprinter struct{}

// localAISystemResponse represents the JSON response from LocalAI /system endpoint
type localAISystemResponse struct {
	Backends []string        `json:"backends"`
	Models   []localAIModel  `json:"loaded_models"`
}

// localAIModel represents a single loaded model entry in the LocalAI system response
type localAIModel struct {
	ID string `json:"id"`
}

func init() {
	Register(&LocalAIFingerprinter{})
}

func (f *LocalAIFingerprinter) Name() string {
	return "localai"
}

func (f *LocalAIFingerprinter) ProbeEndpoint() string {
	return "/system"
}

func (f *LocalAIFingerprinter) Match(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func (f *LocalAIFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Parse JSON response
	var sysInfo localAISystemResponse
	if err := json.Unmarshal(body, &sysInfo); err != nil {
		return nil, nil // Not valid JSON, not LocalAI format
	}

	// Validate: both "backends" and "loaded_models" keys must be present as JSON arrays.
	// We use a raw map to detect key presence (empty arrays are valid LocalAI responses).
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil
	}

	_, hasBackends := raw["backends"]
	_, hasLoadedModels := raw["loaded_models"]
	if !hasBackends || !hasLoadedModels {
		return nil, nil
	}

	// Collect loaded model IDs
	modelIDs := make([]string, 0, len(sysInfo.Models))
	for _, model := range sysInfo.Models {
		modelIDs = append(modelIDs, model.ID)
	}

	metadata := map[string]any{
		"backends":         sysInfo.Backends,
		"loaded_model_count": len(sysInfo.Models),
		"anonymous_access":  true,
	}
	if len(modelIDs) > 0 {
		metadata["loaded_models"] = modelIDs
	}

	// LocalAI /system does not expose version — use wildcard CPE
	return &FingerprintResult{
		Technology: "localai",
		Version:    "",
		CPEs:       []string{buildLocalAICPE("")},
		Metadata:   metadata,
	}, nil
}

// buildLocalAICPE generates a CPE (Common Platform Enumeration) string for LocalAI.
// CPE format: cpe:2.3:a:localai:localai:{version}:*:*:*:*:*:*:*
//
// LocalAI /system does not expose version, so version is always "*".
func buildLocalAICPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:localai:localai:%s:*:*:*:*:*:*:*", version)
}
