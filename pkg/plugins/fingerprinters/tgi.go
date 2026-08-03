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
Package fingerprinters provides HTTP fingerprinting for HuggingFace Text
Generation Inference (TGI) LLM serving instances.

# What We Detect

  - TGI /info endpoint via GET /info — confirmed by the "router" field
    containing "text-generation-router", the Cargo package name embedded at
    build time via env!("CARGO_PKG_NAME"), a value unique to TGI.
  - TGI /metrics endpoint via GET /metrics — confirmed by two or more
    distinct Prometheus metric names prefixed with "tgi_", a naming
    convention unique to TGI's metrics exporter.

# What We Do NOT Detect

  - TGI instances deployed behind reverse proxies that strip or rewrite the
    "router" field in /info responses, or that block both /info and
    /metrics entirely.
  - TGI instances behind an authentication layer that returns a non-200
    status, or a non-JSON/non-text body, for unauthenticated requests to
    /info or /metrics.

# Active Probe Safety

Both probes issue a plain GET with no request body: GET /info retrieves
read-only server and model metadata, and GET /metrics retrieves read-only
Prometheus metrics. Neither triggers inference, mutates server state, nor
transmits authentication material.

# CPE

cpe:2.3:a:huggingface:text_generation_inference:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TGIInfoFingerprinter detects HuggingFace Text Generation Inference (TGI)
// via the /info endpoint, extracting version and model metadata.
type TGIInfoFingerprinter struct{}

// TGIMetricsFingerprinter detects TGI via its Prometheus /metrics endpoint.
// It does not extract version or model information.
type TGIMetricsFingerprinter struct{}

// tgiInfoResponse represents the JSON structure from /info.
type tgiInfoResponse struct {
	ModelID     string `json:"model_id"`
	ModelSHA    string `json:"model_sha"`
	Router      string `json:"router"`
	Version     string `json:"version"`
	DockerLabel string `json:"docker_label"`
}

// tgiVersionRegex validates TGI version format for CPE safety.
// Accepts: 2.0.2, 1.0.0, etc. (strict semantic versioning with exactly 3 components)
// Rejects: pre-release versions (2.0.2-rc1), build metadata, and any special
// characters that could enable CPE injection attacks.
var tgiVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// tgiMetricPattern matches a Prometheus metric name prefixed with "tgi_" at
// the start of a (trimmed) metrics line.
var tgiMetricPattern = regexp.MustCompile(`^tgi_[a-zA-Z0-9_]+`)

// tgiMaxBodySize caps the response body size accepted by the TGI
// fingerprinters to avoid unbounded memory use.
const tgiMaxBodySize = 2 * 1024 * 1024

func init() {
	Register(&TGIInfoFingerprinter{})
	Register(&TGIMetricsFingerprinter{})
}

// --- TGIInfoFingerprinter ---

func (f *TGIInfoFingerprinter) Name() string {
	return "tgi"
}

func (f *TGIInfoFingerprinter) ProbeEndpoint() string {
	return "/info"
}

func (f *TGIInfoFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode != http.StatusOK {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "application/json")
}

func (f *TGIInfoFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if len(body) > tgiMaxBodySize {
		return nil, nil
	}

	var info tgiInfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, nil
	}

	// Definitive marker: the "router" field is unique to TGI and always
	// contains "text-generation-router" (the Cargo package name embedded via
	// env!("CARGO_PKG_NAME")).
	if !strings.Contains(info.Router, "text-generation-router") {
		return nil, nil
	}

	version := info.Version
	if !tgiVersionRegex.MatchString(version) {
		version = ""
	}
	// Defense-in-depth: unreachable given the anchored regex above, but
	// retained in case the regex is loosened in a future edit.
	if strings.ContainsAny(version, ":*?") {
		version = ""
	}

	metadata := map[string]any{}
	if info.ModelID != "" {
		metadata["model_id"] = info.ModelID
	}
	if info.ModelSHA != "" {
		metadata["model_sha"] = info.ModelSHA
	}
	if info.DockerLabel != "" {
		metadata["docker_label"] = info.DockerLabel
	}

	return &FingerprintResult{
		Technology:       "tgi",
		Version:          version,
		CPEs:             []string{buildTGICPE(version)},
		Metadata:         metadata,
		Severity:         plugins.SeverityHigh,
		SecurityFindings: []plugins.SecurityFinding{tgiUnauthFinding("TGI /info endpoint accessible without authentication")},
	}, nil
}

// --- TGIMetricsFingerprinter ---

// Name is distinct from TGIInfoFingerprinter's ("tgi_metrics" vs "tgi") because
// the registry (GetProbeEndpoints/GetFingerprinterByName) keys on Name(), not
// Technology. Two fingerprinters sharing a Name() would collide: only one
// probe endpoint would survive in GetProbeEndpoints() and GetFingerprinterByName
// would always resolve to whichever fingerprinter registered first, breaking
// active probing for the other. Technology remains "tgi" for both so results
// are reported under the same technology in output.
func (f *TGIMetricsFingerprinter) Name() string {
	return "tgi_metrics"
}

func (f *TGIMetricsFingerprinter) ProbeEndpoint() string {
	return "/metrics"
}

func (f *TGIMetricsFingerprinter) ProbeAccept() string {
	return "text/plain"
}

func (f *TGIMetricsFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode != http.StatusOK {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/plain")
}

func (f *TGIMetricsFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if len(body) > tgiMaxBodySize {
		return nil, nil
	}

	if len(tgiMetricNames(body)) < 2 {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "tgi",
		CPEs:       []string{buildTGICPE("")},
	}, nil
}

// tgiMetricNames returns the set of distinct Prometheus metric names
// prefixed with "tgi_" found in body. Comment lines (# HELP / # TYPE) are
// skipped; only actual metric sample lines are counted.
func tgiMetricNames(body []byte) map[string]bool {
	names := make(map[string]bool)
	for _, line := range strings.Split(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if m := tgiMetricPattern.FindString(line); m != "" {
			names[m] = true
		}
	}
	return names
}

// --- Shared helpers ---

func tgiUnauthFinding(evidence string) plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "tgi-unauthenticated-api",
		Severity:    plugins.SeverityHigh,
		Description: "TGI API accessible without authentication; allows arbitrary model inference, model enumeration, and resource abuse",
		Evidence:    evidence,
	}
}

func buildTGICPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:huggingface:text_generation_inference:%s:*:*:*:*:*:*:*", version)
}
