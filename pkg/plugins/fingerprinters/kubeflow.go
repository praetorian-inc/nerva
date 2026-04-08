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

// KubeflowFingerprinter detects Kubeflow Central Dashboard instances via HTTP.
//
// Detection Strategy:
// Kubeflow is an open-source machine learning platform for Kubernetes that
// provides a multi-user environment for ML workflows. Exposed instances
// represent a security concern due to:
//   - Access to ML pipelines, models, and training data
//   - Multi-tenant namespace isolation that may be misconfigured
//   - Often deployed inside Kubernetes clusters with broad service access
//   - Potential lateral movement via in-cluster service accounts
//
// Detection uses two signals:
//  1. Passive: Root "/" returns HTML with <title>Kubeflow Central Dashboard</title>
//  2. Active: Probe "/api/workgroup/env-info" returns JSON:
//     {
//       "user": "user@example.com",
//       "platform": {
//         "provider": "gcp",
//         "providerName": "Google Cloud",
//         "buildVersion": "1.8.0",
//         "buildId": "abc123"
//       },
//       "namespaces": [
//         {"user": "user@example.com", "namespace": "kubeflow-user", "role": "contributor", "owner": "user@example.com"}
//       ]
//     }
//
// Version Notes:
// Version is extracted from platform.buildVersion when present.
//
// Port Configuration:
// Kubeflow Central Dashboard typically runs on:
//   - 80/443: Production deployments via Istio ingress gateway or Kubernetes Service
//   - 8082: Default container port (Central Dashboard)
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// KubeflowFingerprinter detects Kubeflow Central Dashboard instances
type KubeflowFingerprinter struct{}

// kubeflowPlatformInfo represents the nested platform object in the env-info response
type kubeflowPlatformInfo struct {
	Provider     string `json:"provider"`
	ProviderName string `json:"providerName"`
	BuildVersion string `json:"buildVersion"`
	BuildId      string `json:"buildId"`
}

// kubeflowEnvInfo from the /api/workgroup/env-info endpoint
type kubeflowEnvInfo struct {
	Platform   kubeflowPlatformInfo `json:"platform"`
	User       string               `json:"user"`
	Namespaces []kubeflowNamespace  `json:"namespaces"`
}

// kubeflowNamespace represents a namespace entry in the env-info response
type kubeflowNamespace struct {
	User      string `json:"user"`
	Namespace string `json:"namespace"`
	Role      string `json:"role"`
	Owner     string `json:"owner"`
}

// kubeflowTitleRegex matches the Kubeflow Central Dashboard title case-insensitively
var kubeflowTitleRegex = regexp.MustCompile(`(?i)<title>\s*Kubeflow\s+Central\s+Dashboard\s*</title>`)

// kubeflowVersionRegex validates version strings for CPE safety (digits and dots only)
var kubeflowVersionRegex = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)*$`)

func init() {
	Register(&KubeflowFingerprinter{})
}

func (f *KubeflowFingerprinter) Name() string {
	return "kubeflow"
}

func (f *KubeflowFingerprinter) ProbeEndpoint() string {
	return "/api/workgroup/env-info"
}

// Match returns true for both text/html and application/json responses.
// HTML is matched for the passive root "/" signal.
// JSON is matched for the active probe "/api/workgroup/env-info" signal,
// because the http.go probe path also calls Match() on the probe response.
func (f *KubeflowFingerprinter) Match(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "text/html") || strings.Contains(contentType, "application/json")
}

// Fingerprint routes detection to HTML or JSON logic based on content type.
func (f *KubeflowFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	contentType := resp.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/json") {
		return f.fingerprintJSON(body)
	}
	return f.fingerprintHTML(body)
}

// fingerprintHTML detects Kubeflow from the root "/" HTML response.
func (f *KubeflowFingerprinter) fingerprintHTML(body []byte) (*FingerprintResult, error) {
	if !kubeflowTitleRegex.Match(body) {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "kubeflow",
		Version:    "",
		CPEs:       []string{buildKubeflowCPE("")},
		Metadata:   map[string]any{},
	}, nil
}

// fingerprintJSON detects Kubeflow from the /api/workgroup/env-info JSON response.
func (f *KubeflowFingerprinter) fingerprintJSON(body []byte) (*FingerprintResult, error) {
	var info kubeflowEnvInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, nil
	}

	// user must be non-empty
	if info.User == "" {
		return nil, nil
	}

	// namespaces key must exist in raw JSON (json.Unmarshal silently initializes
	// nil slices for missing fields, so we check the raw JSON explicitly)
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, nil
	}
	if _, ok := raw["namespaces"]; !ok {
		return nil, nil
	}

	version := info.Platform.BuildVersion
	if !kubeflowVersionRegex.MatchString(version) {
		version = ""
	}

	metadata := map[string]any{
		"user": info.User,
	}
	if info.Platform.Provider != "" {
		metadata["provider"] = info.Platform.Provider
	}
	if info.Platform.ProviderName != "" {
		metadata["provider_name"] = info.Platform.ProviderName
	}
	if len(info.Namespaces) > 0 {
		metadata["namespace_count"] = len(info.Namespaces)
	}

	return &FingerprintResult{
		Technology: "kubeflow",
		Version:    version,
		CPEs:       []string{buildKubeflowCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildKubeflowCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:kubeflow:kubeflow:%s:*:*:*:*:*:*:*", version)
}
