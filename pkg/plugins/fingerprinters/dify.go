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
Package fingerprinters provides HTTP fingerprinting for Dify instances.

# What We Detect

  - Dify instances via the unauthenticated /v1/ API endpoint which returns
    a JSON response containing "Dify OpenAPI" and the server_version field.
  - Dify web UI via the distinctive apple-mobile-web-app-title meta tag
    with content "Dify" present in all Dify pages.
  - Dify setup status via the unauthenticated /console/api/setup endpoint
    which returns the instance configuration state. Unconfigured instances
    (step "not_started") are flagged as a security finding.

# What We Do NOT Detect

  - Dify instances behind reverse proxies that rewrite or block the /v1/
    API path and strip distinctive HTML meta tags.
  - Dify API consumers or SDK integrations that do not expose the Dify
    web interface or API root.

# Security Context

Exposed Dify instances are high-severity findings because the platform
manages LLM API keys for connected providers, knowledge bases containing
potentially sensitive documents, and workflow configurations. The
/console/api/ admin endpoints may expose additional attack surface.

# Active Probe Safety

The active probe issues a plain GET /v1/ with no request body and Accept
header set to application/json. This is a read-only API root that returns
a static JSON welcome message. No write operations are performed.

The /console/api/setup probe issues a plain GET with Accept: application/json.
This is a read-only endpoint that returns the setup state. No write operations
are performed.

# CPE

cpe:2.3:a:langgenius:dify:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// difyVersionExtractRe extracts a semver version from the server_version JSON field.
// Intentionally loose to capture the version value; strict validation follows.
var difyVersionExtractRe = regexp.MustCompile(`"server_version"\s*:\s*"(\d+\.\d+\.\d+)`)

// difyVersionValidateRe is the anchored second-stage CPE validation gate.
// Accepts only pure three-component numeric semver strings.
var difyVersionValidateRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// difyMetaAppTitleRe matches the apple-mobile-web-app-title meta tag with content "Dify"
// in either attribute order (name before content, or content before name).
var difyMetaAppTitleRe = regexp.MustCompile(`(?i)<meta\s[^>]*(?:name\s*=\s*["']apple-mobile-web-app-title["'][^>]*content\s*=\s*["']Dify["']|content\s*=\s*["']Dify["'][^>]*name\s*=\s*["']apple-mobile-web-app-title["'])`)

// difyOpenAPIMarker is the unique JSON welcome string present in all Dify /v1/ responses.
var difyOpenAPIMarker = []byte(`"Dify OpenAPI"`)

// difySetupStepRe extracts the setup step value from the /console/api/setup JSON response.
var difySetupStepRe = regexp.MustCompile(`"step"\s*:\s*"(not_started|finished)"`)

// DifyFingerprinter detects Dify instances via the unauthenticated /v1/ API endpoint.
// Implements ActiveHTTPFingerprinter + AcceptHeaderProvider.
type DifyFingerprinter struct{}

// DifyHTMLFingerprinter detects Dify instances via the apple-mobile-web-app-title HTML meta tag.
// Implements HTTPFingerprinter only (passive detection).
type DifyHTMLFingerprinter struct{}

// DifySetupFingerprinter detects Dify instances via the unauthenticated /console/api/setup endpoint.
// Unconfigured instances (step "not_started") are flagged as a high-severity security finding.
// Implements ActiveHTTPFingerprinter + AcceptHeaderProvider.
type DifySetupFingerprinter struct{}

func init() {
	Register(&DifyFingerprinter{})
	Register(&DifyHTMLFingerprinter{})
	Register(&DifySetupFingerprinter{})
}

// --- DifyFingerprinter (active probe) ---

func (f *DifyFingerprinter) Name() string {
	return "dify"
}

func (f *DifyFingerprinter) ProbeEndpoint() string {
	return "/v1/"
}

func (f *DifyFingerprinter) ProbeAccept() string {
	return "application/json"
}

// Match returns true when the response is a candidate for active Dify detection.
//
// Fast-path: the /v1/ probe path always matches on success. Otherwise accepts
// application/json content-type responses. 5xx and sub-200 responses are rejected.
func (f *DifyFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	if resp.Request != nil && resp.Request.URL != nil &&
		resp.Request.URL.Path == "/v1/" {
		return true
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "application/json")
}

// Fingerprint performs full Dify detection via the /v1/ API endpoint.
//
// Gate: rejects status < 200 or >= 500, bodies larger than 2 MiB, and empty bodies.
// Requires both the "Dify OpenAPI" marker in the body and that the request path
// is /v1/ to avoid false positives on unrelated JSON responses.
func (f *DifyFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	if len(body) == 0 {
		return nil, nil
	}

	if resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.Path != "/v1/" {
		return nil, nil
	}

	if !bytes.Contains(body, difyOpenAPIMarker) {
		return nil, nil
	}

	version := extractDifyVersion(body)

	metadata := map[string]any{
		"vendor":           "LangGenius",
		"product":          "Dify",
		"detection_method": "active_probe",
		"probe_path":       "/v1/",
	}
	if version != "" {
		metadata["version"] = version
	}

	return &FingerprintResult{
		Technology: "dify",
		Version:    version,
		CPEs:       []string{buildDifyCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityHigh,
	}, nil
}

// --- DifyHTMLFingerprinter (passive HTML detection) ---

func (f *DifyHTMLFingerprinter) Name() string {
	return "dify-html"
}

// Match returns true when the response is a candidate for HTML-based Dify detection.
//
// Accepts text/html content-type responses. 5xx and sub-200 responses are rejected.
func (f *DifyHTMLFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint detects Dify via the apple-mobile-web-app-title meta tag present
// in all Dify Next.js pages.
//
// Gate: rejects status < 200 or >= 500, bodies larger than 2 MiB, and empty bodies.
// Version is not available from HTML; CPE is emitted with a wildcard version.
func (f *DifyHTMLFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	if len(body) == 0 {
		return nil, nil
	}

	if !difyMetaAppTitleRe.Match(body) {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "dify",
		Version:    "",
		CPEs:       []string{buildDifyCPE("")},
		Metadata: map[string]any{
			"vendor":           "LangGenius",
			"product":          "Dify",
			"detection_method": "html_meta_tag",
		},
	}, nil
}

// --- DifySetupFingerprinter (active probe) ---

func (f *DifySetupFingerprinter) Name() string {
	return "dify-setup"
}

func (f *DifySetupFingerprinter) ProbeEndpoint() string {
	return "/console/api/setup"
}

func (f *DifySetupFingerprinter) ProbeAccept() string {
	return "application/json"
}

// Match returns true when the response is a candidate for Dify setup detection.
//
// Fast-path: the /console/api/setup probe path always matches on success. Otherwise
// accepts application/json content-type responses. 5xx and sub-200 responses are rejected.
func (f *DifySetupFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	if resp.Request != nil && resp.Request.URL != nil &&
		resp.Request.URL.Path == "/console/api/setup" {
		return true
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "application/json")
}

// Fingerprint detects the Dify instance setup state via the /console/api/setup endpoint.
//
// Gate: rejects status < 200 or >= 500, bodies larger than 2 MiB, and empty bodies.
// Requires the request path to be /console/api/setup to avoid false positives.
// Unconfigured instances (step "not_started") are reported as a high-severity finding.
func (f *DifySetupFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	if len(body) == 0 {
		return nil, nil
	}

	if resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.Path != "/console/api/setup" {
		return nil, nil
	}

	m := difySetupStepRe.FindSubmatch(body)
	if len(m) < 2 {
		return nil, nil
	}

	step := string(m[1])

	result := &FingerprintResult{
		Technology: "dify-setup",
		Version:    "",
		CPEs:       []string{buildDifyCPE("")},
		Metadata: map[string]any{
			"vendor":           "LangGenius",
			"product":          "Dify",
			"detection_method": "active_probe",
			"probe_path":       "/console/api/setup",
			"setup_step":       step,
		},
	}

	if step == "not_started" {
		result.Severity = plugins.SeverityHigh
		result.SecurityFindings = []plugins.SecurityFinding{{
			ID:          "dify-setup-not-started",
			Severity:    plugins.SeverityHigh,
			Description: "The Dify instance has not completed initial setup. An attacker could initialize the admin account and gain full control of the platform.",
			Evidence:    `GET /console/api/setup returned {"step": "not_started"}`,
		}}
	}

	return result, nil
}

// --- Helper functions ---

// extractDifyVersion extracts and validates the server_version from the /v1/ JSON body.
// Uses two-stage validation: loose extraction regex followed by anchored format check.
// Returns "" when no valid semver version is found.
func extractDifyVersion(body []byte) string {
	m := difyVersionExtractRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	v := string(m[1])
	if !difyVersionValidateRe.MatchString(v) {
		return ""
	}
	return v
}

// buildDifyCPE constructs a CPE 2.3 string for Dify.
// When version is empty, a wildcard "*" is emitted to support asset inventory
// without version data.
func buildDifyCPE(version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:langgenius:dify:%s:*:*:*:*:*:*:*", v)
}
