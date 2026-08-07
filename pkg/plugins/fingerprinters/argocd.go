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
Package fingerprinters provides HTTP fingerprinting for Argo CD.

# What We Detect

Argo CD instances via two independent signals, either of which is sufficient
for detection:

  - ArgoCDAPIFingerprinter: probes /api/version, which returns JSON
    containing a Version field alongside at least one of KsonnetVersion,
    KustomizeVersion, or HelmVersion — fields unique to Argo CD's version
    endpoint that distinguish it from generic Go JSON APIs.
  - ArgoCDLoginFingerprinter: probes /login, the Argo CD UI's login page,
    and detects the "Argo CD" page title in the returned HTML.

# What We Do NOT Detect

  - Argo CD instances that have disabled or moved the /api/version and
    /login endpoints
  - A version number from the /login page — the Argo CD UI is a single-page
    application and does not expose a version in its HTML

# CPE Format

cpe:2.3:a:argoproj:argo_cd:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// argoCDMaxBodySize caps the response body read by both ArgoCD fingerprinters
// to prevent excessive memory consumption from oversized responses.
const argoCDMaxBodySize = 1 << 20

// Package-level precompiled regexes.
var (
	// argoCDVersionRegex validates that an extracted version is safe to embed
	// in a CPE. Accepts strict MAJOR.MINOR.PATCH semver only, e.g. "2.9.3".
	argoCDVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

	// argoCDLoginTitleRegex matches <title>Argo CD</title>, case-insensitive,
	// tolerant of title attributes and surrounding whitespace.
	argoCDLoginTitleRegex = regexp.MustCompile(`(?i)<title[^>]*>\s*Argo CD\s*</title>`)
)

// ArgoCDAPIFingerprinter detects Argo CD via the /api/version endpoint.
type ArgoCDAPIFingerprinter struct{}

// ArgoCDLoginFingerprinter detects Argo CD via the /login page title.
type ArgoCDLoginFingerprinter struct{}

type argoCDVersionResponse struct {
	Version          string `json:"Version"`
	BuildDate        string `json:"BuildDate"`
	GitCommit        string `json:"GitCommit"`
	GoVersion        string `json:"GoVersion"`
	Platform         string `json:"Platform"`
	KsonnetVersion   string `json:"KsonnetVersion"`
	KustomizeVersion string `json:"KustomizeVersion"`
	HelmVersion      string `json:"HelmVersion"`
}

func init() {
	Register(&ArgoCDAPIFingerprinter{})
	Register(&ArgoCDLoginFingerprinter{})
}

// --- ArgoCDAPIFingerprinter ---

func (f *ArgoCDAPIFingerprinter) Name() string { return "argocd" }

func (f *ArgoCDAPIFingerprinter) ProbeEndpoint() string { return "/api/version" }

func (f *ArgoCDAPIFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode != http.StatusOK {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "application/json")
}

func (f *ArgoCDAPIFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if len(body) > argoCDMaxBodySize {
		body = body[:argoCDMaxBodySize]
	}

	var vResp argoCDVersionResponse
	if err := json.Unmarshal(body, &vResp); err != nil {
		return nil, nil
	}

	if vResp.Version == "" {
		return nil, nil
	}
	if vResp.KsonnetVersion == "" && vResp.KustomizeVersion == "" && vResp.HelmVersion == "" {
		return nil, nil
	}

	version := extractArgoCDVersion(vResp.Version)

	metadata := map[string]any{
		"raw_version": vResp.Version,
	}
	if vResp.BuildDate != "" {
		metadata["build_date"] = vResp.BuildDate
	}
	if vResp.GitCommit != "" {
		metadata["git_commit"] = vResp.GitCommit
	}
	if vResp.GoVersion != "" {
		metadata["go_version"] = vResp.GoVersion
	}
	if vResp.Platform != "" {
		metadata["platform"] = vResp.Platform
	}
	if vResp.KsonnetVersion != "" {
		metadata["ksonnet_version"] = vResp.KsonnetVersion
	}
	if vResp.KustomizeVersion != "" {
		metadata["kustomize_version"] = vResp.KustomizeVersion
	}
	if vResp.HelmVersion != "" {
		metadata["helm_version"] = vResp.HelmVersion
	}

	return &FingerprintResult{
		Technology: "argocd",
		Version:    version,
		CPEs:       []string{buildArgoCDCPE(version)},
		Metadata:   metadata,
	}, nil
}

// --- ArgoCDLoginFingerprinter ---

func (f *ArgoCDLoginFingerprinter) Name() string { return "argocd-login" }

func (f *ArgoCDLoginFingerprinter) ProbeEndpoint() string { return "/login" }

func (f *ArgoCDLoginFingerprinter) ProbeAccept() string { return "text/html" }

func (f *ArgoCDLoginFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode > 499 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

func (f *ArgoCDLoginFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if len(body) > argoCDMaxBodySize {
		body = body[:argoCDMaxBodySize]
	}

	if !argoCDLoginTitleRegex.Match(body) {
		return nil, nil
	}

	// No CPE is emitted here. The login page carries no version, so this
	// fingerprinter could only ever produce a wildcard CPE. The HTTP engine
	// concatenates CPEs from all matching fingerprinters without reconciling
	// them, so a wildcard alongside the precise CPE from /api/version would
	// match every argo_cd CVE regardless of version and make a fully patched
	// instance correlate as vulnerable. Technology and detection_method still
	// record the login signal.
	return &FingerprintResult{
		Technology: "argocd-login",
		Version:    "",
		Metadata: map[string]any{
			"detection_method": "login_title",
		},
	}, nil
}

// --- Shared helpers ---

// extractArgoCDVersion strips a leading "v" prefix and a "+build" suffix from
// the raw Argo CD Version field (e.g. "v2.9.3+6eba5be" -> "2.9.3"), then
// validates the result against strict MAJOR.MINOR.PATCH semver and guards
// against CPE metacharacters. Returns "" if the raw value cannot be reduced
// to a safe, valid version string.
func extractArgoCDVersion(raw string) string {
	version := strings.TrimPrefix(raw, "v")
	if idx := strings.Index(version, "+"); idx != -1 {
		version = version[:idx]
	}

	if !argoCDVersionRegex.MatchString(version) {
		return ""
	}

	return version
}

// buildArgoCDCPE constructs a CPE 2.3 string for Argo CD.
// When version is empty, a wildcard CPE is emitted to support asset inventory.
func buildArgoCDCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:argoproj:argo_cd:%s:*:*:*:*:*:*:*", version)
}
