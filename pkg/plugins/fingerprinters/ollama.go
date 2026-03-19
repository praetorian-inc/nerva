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

/*
Package fingerprinters provides HTTP fingerprinting for Ollama LLM inference servers.

# Detection Strategy

Ollama is an open-source LLM inference server that allows running large language
models locally. Exposed instances represent security concerns due to:
  - Unrestricted access to AI model inference capabilities
  - Potential for prompt injection and model abuse
  - Resource consumption through GPU/CPU intensive operations
  - Possible exposure of custom or fine-tuned models
  - Lack of authentication in default configurations

Detection uses a multi-endpoint approach:
1. Primary: Query /api/version endpoint (returns version information)
2. Fallback: Query /api/tags endpoint (returns model listing)
3. Match: Check for Content-Type: application/json header

# API Response Formats

The /api/version endpoint returns JSON:

	{
	  "version": "0.5.1"
	}

The /api/tags endpoint returns JSON with model information:

	{
	  "models": [
	    {
	      "name": "llama3.2:latest",
	      "model": "llama3.2:latest",
	      "size": 2019393189,
	      "digest": "sha256:...",
	      "details": {
	        "family": "llama",
	        "parameter_size": "3.2B",
	        "quantization_level": "Q4_K_M"
	      }
	    }
	  ]
	}

Format breakdown:
  - version: Ollama version string (primary detection)
  - models: Array of loaded models (fallback detection)
  - name: Model identifier with tag
  - size: Model size in bytes
  - details: Model metadata (optional)

# Port Configuration

Ollama typically runs on:
  - 11434: Default Ollama HTTP API port
  - Custom ports: Configurable via environment variables

# Security Concerns

Exposed Ollama instances allow:
  - Arbitrary prompt execution without authentication
  - Model inference abuse (compute resource consumption)
  - Information disclosure about loaded models
  - Potential data exfiltration through model responses
  - Model manipulation if write access is exposed

# Example Usage

	fp := &OllamaFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s\n", result.Technology, result.Version)
			if modelCount, ok := result.Metadata["model_count"].(int); ok {
				fmt.Printf("Models loaded: %d\n", modelCount)
			}
		}
	}
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// OllamaFingerprinter detects Ollama LLM inference server instances
type OllamaFingerprinter struct{}

// ollamaVersionResponse represents the JSON structure from /api/version
type ollamaVersionResponse struct {
	Version string `json:"version"`
}

// ollamaTagsResponse represents the JSON structure from /api/tags
type ollamaTagsResponse struct {
	Models []ollamaModel `json:"models"`
}

// ollamaModel represents a single model in the tags response
type ollamaModel struct {
	Name   string                 `json:"name"`
	Model  string                 `json:"model"`
	Size   int64                  `json:"size"`
	Digest string                 `json:"digest"`
	Details map[string]interface{} `json:"details"`
}

// ollamaVersionRegex validates Ollama version format for CPE safety.
// Accepts: 0.5.1, 1.0.0, etc. (strict semantic versioning with exactly 3 components)
// Rejects: pre-release versions (0.5.1-rc1), build metadata (0.5.1+build), and
// any special characters that could enable CPE injection attacks.
// This strict validation prioritizes security over completeness.
var ollamaVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&OllamaFingerprinter{})
}

func (f *OllamaFingerprinter) Name() string {
	return "ollama"
}

func (f *OllamaFingerprinter) ProbeEndpoint() string {
	return "/api/version"
}

func (f *OllamaFingerprinter) Match(resp *http.Response) bool {
	// Check for Content-Type: application/json header
	// Ollama API returns JSON responses
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func (f *OllamaFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Try to parse as version response first (primary endpoint)
	var versionResp ollamaVersionResponse
	if err := json.Unmarshal(body, &versionResp); err == nil && versionResp.Version != "" {
		// Validate version format to prevent CPE injection
		if !ollamaVersionRegex.MatchString(versionResp.Version) {
			return nil, nil
		}

		return &FingerprintResult{
			Technology: "ollama",
			Version:    versionResp.Version,
			CPEs:       []string{buildOllamaCPE(versionResp.Version)},
			Metadata:   map[string]any{},
		}, nil
	}

	// Fallback: try to parse as tags response (secondary endpoint)
	var tagsResp ollamaTagsResponse
	if err := json.Unmarshal(body, &tagsResp); err != nil {
		return nil, nil // Not valid Ollama format
	}

	// Validate it's actually Ollama by checking models field exists
	// Even if empty, the field should be present
	if tagsResp.Models == nil {
		return nil, nil
	}

	// Build metadata with model information
	metadata := map[string]any{
		"model_count": len(tagsResp.Models),
	}

	// Extract model names
	if len(tagsResp.Models) > 0 {
		modelNames := make([]string, 0, len(tagsResp.Models))
		for _, model := range tagsResp.Models {
			if model.Name != "" {
				modelNames = append(modelNames, model.Name)
			}
		}
		if len(modelNames) > 0 {
			metadata["models"] = modelNames
		}
	}

	return &FingerprintResult{
		Technology: "ollama",
		Version:    "", // Tags endpoint doesn't include version
		CPEs:       []string{buildOllamaCPE("")},
		Metadata:   metadata,
	}, nil
}

func buildOllamaCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:ollama:ollama:%s:*:*:*:*:*:*:*", version)
}
