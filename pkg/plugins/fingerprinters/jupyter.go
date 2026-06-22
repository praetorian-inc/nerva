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
    REST API, validates the version field in the JSON response. Requires
    corroboration: either Jupyter-specific JSON fields (base_url, ws_url) or
    a Tornado/Jupyter Server header to avoid false-positives on generic APIs.

  - JupyterHubFingerprinter (Active): probes /hub/login for JupyterHub login page.
    Primary signal is the X-Jupyterhub-Version header (definitive). Secondary
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

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// Package-level precompiled regexes.
var (
	// jupyterNotebookVersionRegex validates Notebook API version strings (digits and dots only).
	jupyterNotebookVersionRegex = regexp.MustCompile(`^\d+(\.\d+)*$`)

	// jupyterHubSignupFormRegex matches a <form> tag with an action attribute containing "signup".
	jupyterHubSignupFormRegex = regexp.MustCompile(`(?i)<form\b[^>]*\saction\s*=\s*["'][^"']*signup`)

	// jupyterHubVersionRegex validates JupyterHub version strings (three-part semver).
	jupyterHubVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

	// jupyterLabTitleRegex matches <title>JupyterLab</title> case-insensitively.
	jupyterLabTitleRegex = regexp.MustCompile(`(?i)<title[^>]*>\s*JupyterLab\s*</title>`)

	// jupyterLabScriptRegex matches jupyterlab references in script/CSS paths.
	// Uses [^-\w] instead of \b because \b fires between '-' and a word character,
	// so \b would match data-src= (the '-' before 's' is non-word, triggering \b).
	// [^-\w] explicitly excludes attribute prefixes like data-src= and ng-src=.
	jupyterLabScriptRegex = regexp.MustCompile(`(?i)(?:^|[^-\w])(?:src|href)=['""][^'"]*jupyterlab[^'"]*['"]`)

	// jupyterLabVersionRegex extracts version from app_version or jupyterlab JS attributes.
	// Matches patterns like: data-app_version="3.6.5", jupyterlab: "4.0.0", var jupyterlab = "4.0.0"
	jupyterLabVersionRegex = regexp.MustCompile(`(?i)\b(?:app_?version|jupyterlab)['":\s=]+(\d+\.\d+\.\d+)`)

	// jupyterHubBodyRegex matches "jupyterhub" case-insensitively in HTML body.
	jupyterHubBodyRegex = regexp.MustCompile(`(?i)jupyterhub`)
)

// jupyterNotebookAPIResponse represents the minimal JSON structure of the Jupyter Notebook /api endpoint.
type jupyterNotebookAPIResponse struct {
	Version string `json:"version"`
	BaseURL string `json:"base_url"`
	WsURL   string `json:"ws_url"`
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
	Register(&JupyterNotebookMisconfigFingerprinter{})
	Register(&JupyterHubMisconfigFingerprinter{})
	Register(&JupyterHubSignupFingerprinter{})
	Register(&JupyterLabMisconfigFingerprinter{})
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

	// Require corroboration: Jupyter-specific JSON fields or Server header.
	// Bare {"version":"N"} at /api is too generic without additional signals.
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	hasJupyterServer := strings.Contains(serverHeader, "tornado") || strings.Contains(serverHeader, "jupyter")
	hasJupyterFields := apiResp.BaseURL != "" || apiResp.WsURL != ""
	if !hasJupyterServer && !hasJupyterFields {
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
	hubHeader := resp.Header.Get("X-Jupyterhub-Version")
	return strings.Contains(ct, "text/html") || hubHeader != ""
}

func (f *JupyterHubFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Primary signal: X-Jupyterhub-Version header is definitive.
	headerVersion := resp.Header.Get("X-Jupyterhub-Version")
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
	if !jupyterHubBodyRegex.Match(body) {
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
			// Determine source based on what matched before the version.
			fullMatch := strings.ToLower(string(matches[0]))
			if strings.Contains(fullMatch, "app") {
				versionSource = "html_meta"
			} else {
				versionSource = "html_regex"
			}
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

// --- JupyterNotebookMisconfigFingerprinter ---

// JupyterNotebookMisconfigFingerprinter detects unauthenticated access to
// the Jupyter Notebook kernels API at /api/kernels. A 200 response with a
// JSON array indicates the kernel list is accessible without authentication.
type JupyterNotebookMisconfigFingerprinter struct{}

func (f *JupyterNotebookMisconfigFingerprinter) Name() string { return "jupyter-notebook-misconfig" }

func (f *JupyterNotebookMisconfigFingerprinter) ProbeEndpoint() string { return "/api/kernels" }

func (f *JupyterNotebookMisconfigFingerprinter) Match(resp *http.Response) bool {
	return resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *JupyterNotebookMisconfigFingerprinter) Fingerprint(_ *http.Response, body []byte) (*FingerprintResult, error) {
	var kernels []json.RawMessage
	if err := json.Unmarshal(body, &kernels); err != nil {
		return nil, nil
	}
	if kernels == nil {
		return nil, nil
	}
	if len(kernels) == 0 {
		return nil, nil
	}
	var first struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	if err := json.Unmarshal(kernels[0], &first); err != nil || (first.ID == "" && first.Name == "") {
		return nil, nil
	}
	return &FingerprintResult{
		Technology: "jupyter-notebook",
		Severity:   plugins.SeverityCritical,
	}, nil
}

// --- JupyterHubMisconfigFingerprinter ---

// JupyterHubMisconfigFingerprinter detects unauthenticated access to the
// JupyterHub users API at /hub/api/users. A 200 response with a JSON array
// of user objects confirms the admin API is accessible without authentication.
type JupyterHubMisconfigFingerprinter struct{}

func (f *JupyterHubMisconfigFingerprinter) Name() string { return "jupyterhub-misconfig" }

func (f *JupyterHubMisconfigFingerprinter) ProbeEndpoint() string { return "/hub/api/users" }

func (f *JupyterHubMisconfigFingerprinter) Match(resp *http.Response) bool {
	return resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *JupyterHubMisconfigFingerprinter) Fingerprint(_ *http.Response, body []byte) (*FingerprintResult, error) {
	var users []json.RawMessage
	if err := json.Unmarshal(body, &users); err != nil || users == nil {
		return nil, nil
	}
	if len(users) == 0 {
		return nil, nil
	}
	var first struct {
		Name  string `json:"name"`
		Admin *bool  `json:"admin"`
	}
	if err := json.Unmarshal(users[0], &first); err != nil || first.Name == "" {
		return nil, nil
	}
	return &FingerprintResult{
		Technology: "jupyterhub",
		Severity:   plugins.SeverityCritical,
	}, nil
}

// --- JupyterHubSignupFingerprinter ---

// JupyterHubSignupFingerprinter detects open user registration on JupyterHub
// at /hub/signup. Both a jupyterhub body reference and a signup form action
// must be present to avoid false positives from login page redirects.
type JupyterHubSignupFingerprinter struct{}

func (f *JupyterHubSignupFingerprinter) Name() string { return "jupyterhub-signup" }

func (f *JupyterHubSignupFingerprinter) ProbeEndpoint() string { return "/hub/signup" }

func (f *JupyterHubSignupFingerprinter) ProbeAccept() string { return "text/html" }

func (f *JupyterHubSignupFingerprinter) Match(resp *http.Response) bool {
	return resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "text/html")
}

func (f *JupyterHubSignupFingerprinter) Fingerprint(_ *http.Response, body []byte) (*FingerprintResult, error) {
	if !jupyterHubBodyRegex.Match(body) || !jupyterHubSignupFormRegex.Match(body) {
		return nil, nil
	}
	return &FingerprintResult{
		Technology: "jupyterhub-registration",
		Severity:   plugins.SeverityMedium,
	}, nil
}

// --- JupyterLabMisconfigFingerprinter ---

// JupyterLabMisconfigFingerprinter detects unauthenticated access to the
// JupyterLab settings API at /lab/api/settings. A 200 response with at
// least one key prefixed "@jupyterlab" confirms unauthenticated access.
type JupyterLabMisconfigFingerprinter struct{}

func (f *JupyterLabMisconfigFingerprinter) Name() string { return "jupyterlab-misconfig" }

func (f *JupyterLabMisconfigFingerprinter) ProbeEndpoint() string { return "/lab/api/settings" }

func (f *JupyterLabMisconfigFingerprinter) Match(resp *http.Response) bool {
	return resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *JupyterLabMisconfigFingerprinter) Fingerprint(_ *http.Response, body []byte) (*FingerprintResult, error) {
	var payload struct {
		Settings []struct {
			ID string `json:"id"`
		} `json:"settings"`
	}
	if err := json.Unmarshal(body, &payload); err != nil {
		return nil, nil
	}
	for _, s := range payload.Settings {
		if strings.HasPrefix(s.ID, "@jupyterlab/") {
			return &FingerprintResult{
				Technology: "jupyterlab",
				Severity:   plugins.SeverityCritical,
			}, nil
		}
	}
	return nil, nil
}
