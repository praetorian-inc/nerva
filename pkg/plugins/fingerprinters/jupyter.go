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
Package fingerprinters provides HTTP fingerprinting for Jupyter Notebook, JupyterHub, and JupyterLab.

# Detection Strategy

Three fingerprinters are registered:

  - JupyterNotebookFingerprinter (Active): probes /api for the Jupyter Notebook
    REST API, validates the version field in the JSON response.

  - JupyterHubFingerprinter (Active): probes /hub/login for JupyterHub login page.
    Primary signal is the X-JupyterHub-Version header (definitive). Secondary
    signal is "jupyterhub" in the HTML body.

  - JupyterLabFingerprinter (Active): probes /lab for JupyterLab. Requires
    <title>JupyterLab</title> (case-insensitive) and/or jupyterlab references
    in script/CSS paths. Version extracted via app_version/jupyterlab pattern.

# CPE Format

  - Notebook:   cpe:2.3:a:jupyter:notebook:{version}:*:*:*:*:*:*:*
  - JupyterHub: cpe:2.3:a:jupyter:jupyterhub:{version}:*:*:*:*:*:*:*
  - JupyterLab: cpe:2.3:a:jupyter:jupyterlab:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Package-level precompiled regexes.
var (
	// jupyterNotebookVersionRegex validates Notebook API version strings (digits and dots only).
	jupyterNotebookVersionRegex = regexp.MustCompile(`^\d+(\.\d+)*$`)

	// jupyterHubVersionRegex validates JupyterHub version strings (three-part semver).
	jupyterHubVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

	// jupyterLabTitleRegex matches <title>JupyterLab</title> case-insensitively.
	jupyterLabTitleRegex = regexp.MustCompile(`(?i)<title[^>]*>\s*JupyterLab\s*</title>`)

	// jupyterLabScriptRegex matches jupyterlab references in script/CSS paths.
	jupyterLabScriptRegex = regexp.MustCompile(`(?i)(?:src|href)=['""][^'"]*jupyterlab[^'"]*['"]`)

	// jupyterLabVersionRegex extracts version from app_version or jupyterlab JS attributes.
	// Matches patterns like: data-app_version="3.6.5", jupyterlab: "4.0.0", var jupyterlab = "4.0.0"
	jupyterLabVersionRegex = regexp.MustCompile(`(?i)(?:app_?version|jupyterlab)['":\s=]+(\d+\.\d+\.\d+)`)
)

// jupyterNotebookAPIResponse represents the minimal JSON structure of the Jupyter Notebook /api endpoint.
type jupyterNotebookAPIResponse struct {
	Version string `json:"version"`
}

// JupyterNotebookFingerprinter detects Jupyter Notebook via the /api endpoint.
type JupyterNotebookFingerprinter struct{}

// JupyterHubFingerprinter detects JupyterHub via the /hub/login endpoint.
type JupyterHubFingerprinter struct{}

// JupyterLabFingerprinter detects JupyterLab via the /lab endpoint.
type JupyterLabFingerprinter struct{}

func init() {
	Register(&JupyterNotebookFingerprinter{})
	Register(&JupyterHubFingerprinter{})
	Register(&JupyterLabFingerprinter{})
}

// buildJupyterCPE generates a CPE 2.3 string for a Jupyter product.
func buildJupyterCPE(product, version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:jupyter:%s:%s:*:*:*:*:*:*:*", product, v)
}

// sanitizeJupyterVersion returns the version if it matches the provided regex,
// or empty string on validation failure.
func sanitizeJupyterVersion(version string, pattern *regexp.Regexp) string {
	if pattern.MatchString(version) {
		return version
	}
	return ""
}

// --- JupyterNotebookFingerprinter ---

func (f *JupyterNotebookFingerprinter) Name() string { return "jupyter-notebook" }

func (f *JupyterNotebookFingerprinter) ProbeEndpoint() string { return "/api" }

func (f *JupyterNotebookFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *JupyterNotebookFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var apiResp jupyterNotebookAPIResponse
	if err := json.Unmarshal(body, &apiResp); err != nil {
		return nil, nil
	}

	if apiResp.Version == "" {
		return nil, nil
	}

	version := sanitizeJupyterVersion(apiResp.Version, jupyterNotebookVersionRegex)
	if version == "" {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "jupyter-notebook",
		Version:    version,
		CPEs:       []string{buildJupyterCPE("notebook", version)},
		Metadata: map[string]any{
			"variant":     "notebook",
			"auth_status": "unknown",
			"api_version": apiResp.Version,
		},
	}, nil
}

// --- JupyterHubFingerprinter ---

func (f *JupyterHubFingerprinter) Name() string { return "jupyterhub" }

func (f *JupyterHubFingerprinter) ProbeEndpoint() string { return "/hub/login" }

func (f *JupyterHubFingerprinter) Match(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")
	hubHeader := resp.Header.Get("X-JupyterHub-Version")
	return strings.Contains(ct, "text/html") || hubHeader != ""
}

func (f *JupyterHubFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Primary signal: X-JupyterHub-Version header is definitive.
	headerVersion := resp.Header.Get("X-JupyterHub-Version")
	if headerVersion != "" {
		version := sanitizeJupyterVersion(headerVersion, jupyterHubVersionRegex)
		return &FingerprintResult{
			Technology: "jupyterhub",
			Version:    version,
			CPEs:       []string{buildJupyterCPE("jupyterhub", version)},
			Metadata: map[string]any{
				"variant":        "jupyterhub",
				"auth_status":    "unknown",
				"version_source": "header",
			},
		}, nil
	}

	// Secondary signal: HTML body contains "jupyterhub" (case-insensitive).
	if !strings.Contains(strings.ToLower(string(body)), "jupyterhub") {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "jupyterhub",
		Version:    "",
		CPEs:       []string{buildJupyterCPE("jupyterhub", "")},
		Metadata: map[string]any{
			"variant":        "jupyterhub",
			"auth_status":    "unknown",
			"version_source": "html",
		},
	}, nil
}

// --- JupyterLabFingerprinter ---

func (f *JupyterLabFingerprinter) Name() string { return "jupyterlab" }

func (f *JupyterLabFingerprinter) ProbeEndpoint() string { return "/lab" }

func (f *JupyterLabFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "text/html")
}

func (f *JupyterLabFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	hasTitle := jupyterLabTitleRegex.Match(body)
	hasScriptRef := jupyterLabScriptRegex.Match(body)

	if !hasTitle && !hasScriptRef {
		return nil, nil
	}

	// Extract version from app_version or jupyterlab JS attributes.
	version := ""
	versionSource := ""
	if matches := jupyterLabVersionRegex.FindSubmatch(body); len(matches) >= 2 {
		candidate := string(matches[1])
		version = sanitizeJupyterVersion(candidate, jupyterHubVersionRegex)
		if version != "" {
			versionSource = "html"
		}
	}

	metadata := map[string]any{
		"variant":     "jupyterlab",
		"auth_status": "unknown",
	}
	if versionSource != "" {
		metadata["version_source"] = versionSource
	}

	return &FingerprintResult{
		Technology: "jupyterlab",
		Version:    version,
		CPEs:       []string{buildJupyterCPE("jupyterlab", version)},
		Metadata:   metadata,
	}, nil
}
