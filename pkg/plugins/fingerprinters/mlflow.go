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
Package fingerprinters provides HTTP fingerprinting for MLflow.

# Detection Strategy

MLflow is an open-source ML platform for managing the machine learning lifecycle.
Exposed instances represent a security concern due to:
  - Access to experiment runs, model artifacts, and training metadata
  - Potential exposure of proprietary ML models and datasets
  - Artifact storage endpoints that may expose cloud credentials
  - Often deployed without authentication in internal environments

Detection uses two active fingerprinters:
 1. MLflowFingerprinter: Queries /api/2.0/mlflow/experiments/search?max_results=10 for experiment enumeration
 2. MLflowVersionFingerprinter: Queries /version for version extraction

# API Response Format

The /api/2.0/mlflow/experiments/search?max_results=10 endpoint returns JSON without authentication:

	{
	  "experiments": [
	    {
	      "experiment_id": "0",
	      "name": "Default",
	      "artifact_location": "mlflow-artifacts:/0",
	      "lifecycle_stage": "active"
	    }
	  ]
	}

The /version endpoint returns a plain text version string:

	2.3.0

or with surrounding quotes:

	"2.3.0"

# Port Configuration

MLflow typically runs on:
  - 5000: Default MLflow UI and REST API port
  - 443:  HTTPS in production deployments

# Example Usage

	fp := &MLflowFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s with %d experiments\n",
				result.Technology, result.Metadata["experiment_count"])
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

// MLflowFingerprinter detects MLflow instances via /api/2.0/mlflow/experiments/search
type MLflowFingerprinter struct{}

// MLflowVersionFingerprinter extracts the MLflow version via /version
type MLflowVersionFingerprinter struct{}

// mlflowExperimentsResponse represents the JSON structure from /api/2.0/mlflow/experiments/search
type mlflowExperimentsResponse struct {
	Experiments []mlflowExperiment `json:"experiments"`
}

// mlflowExperiment represents a single experiment entry
type mlflowExperiment struct {
	ExperimentID     string `json:"experiment_id"`
	Name             string `json:"name"`
	ArtifactLocation string `json:"artifact_location"`
	LifecycleStage   string `json:"lifecycle_stage"`
}

// mlflowVersionRegex validates MLflow version format.
// Accepts: 2.3.0, 2.12.1, 2.3.0rc1, 2.3.0.dev0
var mlflowVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+([a-zA-Z0-9._-]*)?$`)

func init() {
	Register(&MLflowFingerprinter{})
	Register(&MLflowVersionFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *MLflowFingerprinter) Name() string {
	return "mlflow"
}

// ProbeEndpoint returns the endpoint to probe for experiment search.
func (f *MLflowFingerprinter) ProbeEndpoint() string {
	return "/api/2.0/mlflow/experiments/search?max_results=10"
}

// Match returns true if the response Content-Type indicates JSON.
func (f *MLflowFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

// Fingerprint parses the experiments list response and extracts metadata.
func (f *MLflowFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var experiments mlflowExperimentsResponse
	if err := json.Unmarshal(body, &experiments); err != nil {
		return nil, nil // Not MLflow format
	}

	// The experiments key must be present (even if empty list).
	// json.Unmarshal sets nil slice when key is absent; a JSON null also decodes to nil.
	// We use a sentinel to distinguish: re-check raw JSON for key presence.
	if !mlflowHasExperimentsKey(body) {
		return nil, nil
	}

	names := make([]string, 0, len(experiments.Experiments))
	for _, exp := range experiments.Experiments {
		names = append(names, exp.Name)
	}

	metadata := map[string]any{
		"experiment_count": len(experiments.Experiments),
		"experiment_names": names,
	}

	return &FingerprintResult{
		Technology: "mlflow",
		CPEs:       []string{buildMLflowCPE("")},
		Metadata:   metadata,
	}, nil
}

// mlflowHasExperimentsKey checks that the raw JSON contains the "experiments" key
// with a non-null value. This distinguishes between an absent key and a null value.
func mlflowHasExperimentsKey(body []byte) bool {
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return false
	}
	val, ok := raw["experiments"]
	if !ok {
		return false
	}
	return string(val) != "null"
}

// Name returns the fingerprinter identifier.
func (f *MLflowVersionFingerprinter) Name() string {
	return "mlflow-version"
}

// ProbeEndpoint returns the version endpoint.
func (f *MLflowVersionFingerprinter) ProbeEndpoint() string {
	return "/version"
}

// Match returns true if the response Content-Type indicates text or JSON.
func (f *MLflowVersionFingerprinter) Match(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "text/") || strings.Contains(ct, "application/json")
}

// Fingerprint parses the plain text version string from /version.
func (f *MLflowVersionFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	raw := strings.TrimSpace(string(body))

	// Strip surrounding quotes if present (e.g., `"2.3.0"` -> `2.3.0`)
	raw = strings.Trim(raw, `"`)

	if !mlflowVersionRegex.MatchString(raw) {
		return nil, nil
	}

	metadata := map[string]any{
		"version_source": "/version",
	}

	return &FingerprintResult{
		Technology: "mlflow",
		Version:    raw,
		CPEs:       []string{buildMLflowCPE(raw)},
		Metadata:   metadata,
	}, nil
}

// buildMLflowCPE constructs a CPE 2.3 string for MLflow.
func buildMLflowCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:mlflow:mlflow:%s:*:*:*:*:*:*:*", version)
}
