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
Package fingerprinters provides HTTP fingerprinting for Langfuse instances.

# What We Detect

  - Langfuse server instances via the unauthenticated /api/public/health
    endpoint. This endpoint returns a JSON object with "status" and "version"
    fields. Detection requires the response to come from the /api/public/health
    path and contain both fields.

  - Langfuse login/signup pages via the distinctive <title> tag pattern
    "... | Langfuse". This passive signal detects instances where the root
    page redirects to the authentication flow.

# What We Do NOT Detect

  - Langfuse Cloud instances at cloud.langfuse.com (not self-hosted).

  - Langfuse instances behind reverse proxies that both block /api/public/health
    AND rewrite the HTML pages to remove Langfuse branding.

# Security Context

Exposed Langfuse instances are high-severity findings. The platform stores
API keys for LLM providers (OpenAI, Anthropic, Google, Cohere, and others),
full conversation histories and prompt templates, user PII captured in
traced LLM interactions, and evaluation/scoring data. Self-hosted instances
may be deployed without authentication, allowing unauthorized access to all
stored data and configuration.

No specific CVEs are catalogued against Langfuse at this time; however,
the exposure class mirrors credential-theft and data-exfiltration risk seen
in other AI infrastructure that stores provider keys and sensitive data.

# Active Probe Safety

The active probe issues a plain GET /api/public/health with Accept:
application/json and no request body. The health endpoint is a read-only
status check. No write operations are performed and no authentication
material is transmitted.

# CPE

cpe:2.3:a:langfuse:langfuse:{version}:*:*:*:*:*:*:*
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

// langfuseTitleRe matches Langfuse page titles. Requires either:
//   - Title is exactly "Langfuse" (with optional whitespace)
//   - Title ends with "| Langfuse" (the pattern used across all Langfuse pages)
//
// This avoids false positives from blog posts like "Review of Langfuse".
var langfuseTitleRe = regexp.MustCompile(`(?i)<title[^>]*>(?:\s*Langfuse\s*|[^<]*\|\s*Langfuse\s*)</title>`)

// langfuseVersionExtractRe extracts a semver triple from the "version" JSON field.
var langfuseVersionExtractRe = regexp.MustCompile(`"version"\s*:\s*"(\d+\.\d+\.\d+)`)

// langfuseVersionValidateRe is the anchored second-stage CPE validation gate.
var langfuseVersionValidateRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// langfuseStatusRe extracts the "status" JSON field value.
var langfuseStatusRe = regexp.MustCompile(`"status"\s*:\s*"([^"]{1,64})"`)

// LangfuseFingerprinter detects Langfuse instances via the unauthenticated
// /api/public/health endpoint.
// Implements ActiveHTTPFingerprinter + AcceptHeaderProvider.
type LangfuseFingerprinter struct{}

// LangfuseHTMLFingerprinter detects Langfuse instances passively via
// the distinctive <title> tag pattern on login and signup pages.
type LangfuseHTMLFingerprinter struct{}

func init() {
	Register(&LangfuseFingerprinter{})
	Register(&LangfuseHTMLFingerprinter{})
}

// --- LangfuseFingerprinter ---

// Name returns the fingerprinter identifier.
func (f *LangfuseFingerprinter) Name() string {
	return "langfuse"
}

// ProbeEndpoint returns the Langfuse health check path.
// A GET to /api/public/health returns JSON with "status" and "version" fields.
// The endpoint requires no authentication.
func (f *LangfuseFingerprinter) ProbeEndpoint() string {
	return "/api/public/health"
}

// ProbeAccept returns the Accept header for the active probe.
func (f *LangfuseFingerprinter) ProbeAccept() string {
	return "application/json"
}

// Match returns true when the response is a candidate for Langfuse active probe detection.
//
// Fast-path: path == "/api/public/health" always matches (probe response).
// Fallback: Content-Type contains "application/json".
// 5xx and sub-200 responses are rejected immediately.
func (f *LangfuseFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Fast-path: active probe response from /api/public/health always matches.
	if resp.Request != nil && resp.Request.URL != nil &&
		resp.Request.URL.Path == "/api/public/health" {
		return true
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "application/json")
}

// Fingerprint performs full Langfuse active probe detection and metadata extraction.
//
// Gate: rejects status < 200 or >= 500 and bodies larger than 2 MiB.
//
// Detection requires BOTH of the following:
//  1. Body contains both "version" and "status" JSON keys.
//  2. Response path is exactly "/api/public/health".
//
// If both conditions are met, the instance is detected with detection_method
// "active_probe" and SeverityHigh.
func (f *LangfuseFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: 2 MiB body cap.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Signal: body must contain BOTH "version" AND "status" JSON keys.
	if !bytes.Contains(body, []byte(`"version"`)) || !bytes.Contains(body, []byte(`"status"`)) {
		return nil, nil
	}

	// Path check: must be exactly /api/public/health.
	if resp.Request == nil || resp.Request.URL == nil ||
		resp.Request.URL.Path != "/api/public/health" {
		return nil, nil
	}

	// --- Extract version and status ---

	version := extractLangfuseVersion(body)
	healthStatus := ""
	if m := langfuseStatusRe.FindSubmatch(body); len(m) >= 2 {
		healthStatus = string(m[1])
	}

	// --- Metadata ---

	metadata := map[string]any{
		"vendor":           "Langfuse",
		"product":          "Langfuse",
		"detection_method": "active_probe",
		"probe_path":       "/api/public/health",
	}
	if healthStatus != "" {
		metadata["health_status"] = healthStatus
	}

	return &FingerprintResult{
		Technology: "langfuse",
		Version:    version,
		CPEs:       []string{buildLangfuseCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityHigh,
	}, nil
}

// --- LangfuseHTMLFingerprinter ---

// Name returns the fingerprinter identifier.
func (f *LangfuseHTMLFingerprinter) Name() string {
	return "langfuse-html"
}

// Match returns true when the response may be a Langfuse HTML page.
// Requires status in [200, 500) and Content-Type containing "text/html".
func (f *LangfuseHTMLFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs passive Langfuse detection via the HTML <title> tag.
//
// Gate: rejects status < 200 or >= 500 and bodies larger than 2 MiB.
//
// Detection requires:
//   - Title is exactly "Langfuse" OR title ends with "| Langfuse".
//
// No version is extracted (not available from HTML).
// No severity is set (informational finding).
func (f *LangfuseHTMLFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: 2 MiB body cap.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Signal: title must match the Langfuse pattern.
	if !langfuseTitleRe.Match(body) {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "langfuse",
		Version:    "",
		CPEs:       []string{buildLangfuseCPE("")},
		Metadata: map[string]any{
			"vendor":           "Langfuse",
			"product":          "Langfuse",
			"detection_method": "login_page",
		},
	}, nil
}

// --- Shared helpers ---

// extractLangfuseVersion extracts and validates the Langfuse version from the
// health endpoint JSON body. Uses a two-stage approach: first extract a candidate
// via langfuseVersionExtractRe, then validate with langfuseVersionValidateRe.
// Returns "" when no valid semver version is found.
func extractLangfuseVersion(body []byte) string {
	m := langfuseVersionExtractRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	candidate := string(m[1])
	if !langfuseVersionValidateRe.MatchString(candidate) {
		return ""
	}
	return candidate
}

// buildLangfuseCPE constructs a CPE 2.3 string for Langfuse.
// When version is empty, a wildcard "*" is emitted to support asset inventory
// without version data.
func buildLangfuseCPE(version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:langfuse:langfuse:%s:*:*:*:*:*:*:*", v)
}
