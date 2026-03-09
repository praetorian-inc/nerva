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
Package fingerprinters provides HTTP fingerprinting for NVIDIA Triton Inference Server.

# Detection Strategy

Triton is NVIDIA's production ML inference server. Exposed instances represent
security concerns:
  - Model theft - download proprietary ML models
  - Inference abuse - unauthorized compute usage
  - Infrastructure reconnaissance - reveals ML stack details

Detection uses active probing:
  - Active: Query /v2 metadata endpoint (no authentication required)
  - Response must contain JSON with "name" field equal to "triton"

# API Response Format

The /v2 endpoint returns JSON without authentication:

	{
	  "name": "triton",
	  "version": "2.42.0",
	  "extensions": ["classification", "sequence", ...]
	}

# Port Configuration

Triton typically runs on:
  - 8000: Default HTTP API port
  - 8001: gRPC port
  - 8002: Metrics port
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// TritonFingerprinter detects NVIDIA Triton Inference Server via /v2 metadata endpoint
type TritonFingerprinter struct{}

// tritonMetadataResponse represents the JSON structure from /v2
type tritonMetadataResponse struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Extensions []string `json:"extensions"`
}

// tritonVersionRegex validates Triton version format
// Accepts: 2.42.0 (standard semver), 2.42.0-rc1 (pre-release)
var tritonVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(-[a-zA-Z0-9._-]+)?$`)

func init() {
	Register(&TritonFingerprinter{})
}

func (f *TritonFingerprinter) Name() string {
	return "triton"
}

func (f *TritonFingerprinter) ProbeEndpoint() string {
	return "/v2"
}

func (f *TritonFingerprinter) Match(resp *http.Response) bool {
	// Pre-filter: require JSON content type and 200 status
	if resp.StatusCode != 200 {
		return false
	}
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *TritonFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var meta tritonMetadataResponse
	if err := json.Unmarshal(body, &meta); err != nil {
		return nil, nil // Not valid JSON
	}

	// Key validation: name must be "triton"
	if meta.Name != "triton" {
		return nil, nil
	}

	// Validate version format to prevent CPE injection
	version := meta.Version
	if version != "" && !tritonVersionRegex.MatchString(version) {
		version = "" // Invalid format, use wildcard in CPE
	}

	// Build metadata
	metadata := map[string]any{}
	if len(meta.Extensions) > 0 {
		metadata["extensions"] = meta.Extensions
	}

	return &FingerprintResult{
		Technology: "triton",
		Version:    version,
		CPEs:       []string{buildTritonCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildTritonCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:nvidia:triton_inference_server:%s:*:*:*:*:*:*:*", version)
}
