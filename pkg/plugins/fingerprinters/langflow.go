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
Package fingerprinters provides HTTP fingerprinting for Langflow instances.

# What We Detect

  - Langflow instances via the unauthenticated /api/v1/version endpoint which
    returns a JSON response containing the "package":"Langflow" field along with
    version and main_version fields. This is the definitive active probe.

  - Langflow web UI pages via the distinctive <title>Langflow</title> tag present
    in all Langflow React frontend pages.

# What We Do NOT Detect

  - Langflow instances behind reverse proxies that rewrite or block the
    /api/v1/version path and strip identifying HTML title tags.

  - Langflow API consumers or SDK integrations that do not expose the Langflow
    web interface or version endpoint.

# Security Context

Exposed Langflow instances are high-severity findings because the platform
manages LLM API keys for connected providers, custom AI flow configurations,
and workflow automations. Unauthenticated access to the API enables enumeration
of flows, components, and potentially the execution of arbitrary LLM workflows.

# Active Probe Safety

The active probe issues a plain GET /api/v1/version with no request body and
Accept header set to application/json. This is a read-only informational endpoint
that returns a static JSON version object. No write operations are performed.

# CPE

cpe:2.3:a:langflow:langflow:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// langflowMainVersionExtractRe extracts a semver version from the main_version JSON field.
// Intentionally loose to capture the version value; strict validation follows.
var langflowMainVersionExtractRe = regexp.MustCompile(`"main_version"\s*:\s*"(\d+\.\d+\.\d+)`)

// langflowVersionExtractRe extracts a semver version from the version JSON field.
// Used as a fallback when main_version is absent or invalid.
var langflowVersionExtractRe = regexp.MustCompile(`"version"\s*:\s*"(\d+\.\d+\.\d+)`)

// langflowVersionValidateRe is the anchored second-stage CPE validation gate.
// Accepts only pure three-component numeric semver strings.
var langflowVersionValidateRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// langflowTitleRe matches <title>Langflow</title> in Langflow frontend HTML pages.
// Allows optional whitespace around the product name and is case-insensitive.
var langflowTitleRe = regexp.MustCompile(`(?i)<title>\s*Langflow\s*</title>`)

// langflowPackageFieldRe matches the "package" key-value pair present in all
// Langflow /api/v1/version responses, anchoring detection to the JSON field name
// rather than the value alone. The trailing quote is intentionally omitted so that
// all Langflow package name variants are matched: "Langflow", "Langflow Base",
// "Langflow Nightly", "Langflow Base Nightly", etc.
var langflowPackageFieldRe = regexp.MustCompile(`"package"\s*:\s*"Langflow`)

// LangflowFingerprinter detects Langflow instances via the unauthenticated /api/v1/version endpoint.
// Implements ActiveHTTPFingerprinter + AcceptHeaderProvider.
type LangflowFingerprinter struct{}

// LangflowHTMLFingerprinter detects Langflow instances via the <title>Langflow</title> HTML tag.
// Implements HTTPFingerprinter only (passive detection).
type LangflowHTMLFingerprinter struct{}

func init() {
	Register(&LangflowFingerprinter{})
	Register(&LangflowHTMLFingerprinter{})
}

// --- LangflowFingerprinter (active probe) ---

func (f *LangflowFingerprinter) Name() string {
	return "langflow"
}

func (f *LangflowFingerprinter) ProbeEndpoint() string {
	return "/api/v1/version"
}

func (f *LangflowFingerprinter) ProbeAccept() string {
	return "application/json"
}

// Match returns true when the response is a candidate for active Langflow detection.
//
// Fast-path: the /api/v1/version probe path always matches on success. Otherwise
// accepts application/json content-type responses. 5xx and sub-200 responses are
// rejected.
func (f *LangflowFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	if resp.Request != nil && resp.Request.URL != nil &&
		resp.Request.URL.Path == "/api/v1/version" {
		return true
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "application/json")
}

// Fingerprint performs full Langflow detection via the /api/v1/version endpoint.
//
// Gate: rejects status < 200 or >= 500, bodies larger than 2 MiB, and empty bodies.
// Requires the "Langflow" package marker in the body and that the request path is
// /api/v1/version to avoid false positives on unrelated JSON responses.
// Version extraction prefers the main_version field (clean semver) over the version
// field which may carry pre-release suffixes.
func (f *LangflowFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	if len(body) == 0 {
		return nil, nil
	}

	if resp.Request == nil || resp.Request.URL == nil || resp.Request.URL.Path != "/api/v1/version" {
		return nil, nil
	}

	if !langflowPackageFieldRe.Match(body) {
		return nil, nil
	}

	version := extractLangflowVersion(body)

	metadata := map[string]any{
		"vendor":           "Langflow",
		"product":          "Langflow",
		"detection_method": "active_probe",
		"probe_path":       "/api/v1/version",
	}
	if version != "" {
		metadata["version"] = version
	}

	return &FingerprintResult{
		Technology: "langflow",
		Version:    version,
		CPEs:       []string{buildLangflowCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityHigh,
	}, nil
}

// --- LangflowHTMLFingerprinter (passive HTML detection) ---

func (f *LangflowHTMLFingerprinter) Name() string {
	return "langflow-html"
}

// Match returns true when the response is a candidate for HTML-based Langflow detection.
//
// Accepts text/html content-type responses. 5xx and sub-200 responses are rejected.
func (f *LangflowHTMLFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint detects Langflow via the <title>Langflow</title> tag present in all
// Langflow React frontend pages.
//
// Gate: rejects status < 200 or >= 500, bodies larger than 2 MiB, and empty bodies.
// Version is not available from HTML; CPE is emitted with a wildcard version.
func (f *LangflowHTMLFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	if len(body) == 0 {
		return nil, nil
	}

	if !langflowTitleRe.Match(body) {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "langflow",
		Version:    "",
		CPEs:       []string{buildLangflowCPE("")},
		Metadata: map[string]any{
			"vendor":           "Langflow",
			"product":          "Langflow",
			"detection_method": "html_title",
		},
	}, nil
}

// --- Helper functions ---

// extractLangflowVersion extracts and validates the version from the /api/v1/version
// JSON body using two-stage validation.
//
// Stage 1 prefers the main_version field (clean semver with no pre-release suffix).
// Stage 2 falls back to the version field when main_version is absent or invalid.
// Both stages apply the anchored langflowVersionValidateRe before accepting a value.
// Returns "" when no valid semver version is found.
func extractLangflowVersion(body []byte) string {
	if m := langflowMainVersionExtractRe.FindSubmatch(body); len(m) >= 2 {
		v := string(m[1])
		if langflowVersionValidateRe.MatchString(v) {
			return v
		}
	}

	if m := langflowVersionExtractRe.FindSubmatch(body); len(m) >= 2 {
		v := string(m[1])
		if langflowVersionValidateRe.MatchString(v) {
			return v
		}
	}

	return ""
}

// buildLangflowCPE constructs a CPE 2.3 string for Langflow.
// When version is empty, a wildcard "*" is emitted to support asset inventory
// without version data.
func buildLangflowCPE(version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:langflow:langflow:%s:*:*:*:*:*:*:*", v)
}
