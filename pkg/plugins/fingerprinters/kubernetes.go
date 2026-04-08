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

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// KubernetesFingerprinter detects Kubernetes API servers via /version endpoint
type KubernetesFingerprinter struct{}

// k8sVersionResponse from the /version endpoint
type k8sVersionResponse struct {
	Major        string `json:"major"`
	Minor        string `json:"minor"`
	GitVersion   string `json:"gitVersion"`
	GitCommit    string `json:"gitCommit"`
	GitTreeState string `json:"gitTreeState"`
	BuildDate    string `json:"buildDate"`
	GoVersion    string `json:"goVersion"`
	Compiler     string `json:"compiler"`
	Platform     string `json:"platform"`
}

func init() {
	Register(&KubernetesFingerprinter{})
}

func (f *KubernetesFingerprinter) Name() string {
	return "kubernetes"
}

func (f *KubernetesFingerprinter) ProbeEndpoint() string {
	return "/version"
}

func (f *KubernetesFingerprinter) Match(resp *http.Response) bool {
	// K8s API typically returns JSON
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func (f *KubernetesFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Try to parse as k8s version response
	var version k8sVersionResponse
	if err := json.Unmarshal(body, &version); err != nil {
		return nil, nil // Not k8s format
	}

	// Validate it's actually Kubernetes by checking required fields
	if version.GitVersion == "" || version.Platform == "" {
		return nil, nil
	}

	// Validate gitTreeState — real K8s API servers use clean/dirty/archive
	validGitTreeStates := map[string]bool{"clean": true, "dirty": true, "archive": true}
	if !validGitTreeStates[version.GitTreeState] {
		return nil, nil
	}

	// GitVersion format: "v1.29.0" - strip the "v" prefix for CPE
	versionStr := strings.TrimPrefix(version.GitVersion, "v")

	// Handle suffixes (k3s, gke, etc.) - extract base version
	// Examples: v1.28.3+k3s1 -> 1.28.3, v1.27.8-gke.1067004 -> 1.27.8
	versionStr = strings.Split(versionStr, "+")[0]
	versionStr = strings.Split(versionStr, "-")[0]

	return &FingerprintResult{
		Technology: "kubernetes",
		Version:    versionStr,
		CPEs:       []string{buildK8sCPE(versionStr)},
		Metadata: map[string]any{
			"platform":   version.Platform,
			"go_version": version.GoVersion,
			"git_commit": version.GitCommit,
		},
		Severity: plugins.SeverityHigh,
	}, nil
}

func buildK8sCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:kubernetes:kubernetes:%s:*:*:*:*:*:*:*", version)
}
