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
Package fingerprinters provides HTTP fingerprinting for AnythingLLM instances.

# What We Detect

  - AnythingLLM server instances via the unauthenticated /api/utils/metrics
    endpoint. This endpoint returns a JSON object containing application
    metrics including "vectorDB", "appVersion", and "mode" fields that are
    distinctive to AnythingLLM. Detection requires both "vectorDB" and at
    least one of "appVersion" or "mode" to be present in the response body.

  - AnythingLLM login page HTML via the distinctive <title> tag containing
    "AnythingLLM". This passive signal detects instances where the root page
    is accessible even if the /api/utils/metrics endpoint is blocked.

# What We Do NOT Detect

  - AnythingLLM instances deployed behind reverse proxies that both block
    /api/utils/metrics AND rewrite the HTML login page to remove AnythingLLM
    branding.

  - AnythingLLM Desktop (Electron-based single-user app); it does not expose
    the metrics endpoint on a network-accessible HTTP server in default
    configuration.

# Security Context

Exposed AnythingLLM instances are high-severity findings. The application
stores API keys for LLM providers (OpenAI, Anthropic, Gemini, and others)
and embedding services used to build the vector database. Uploaded documents
constitute proprietary organizational data; vector database contents expose
document embeddings derived from that data. Multi-user server mode is often
deployed without strong authentication requirements, allowing unauthorized
users to access workspaces, documents, and chat history. Agent mode enables
execution of arbitrary tools and code on the server, significantly expanding
the blast radius of unauthorized access.

No specific CVEs are catalogued against AnythingLLM at this time; however,
the exposure class mirrors credential-theft and data-exfiltration risk seen
in other AI infrastructure that stores provider keys and ingested documents.

# Active Probe Safety

The active probe issues a plain GET /api/utils/metrics with Accept:
application/json and no request body. The metrics endpoint is a read-only
informational endpoint that returns application state. No write operations
are performed and no authentication material is transmitted.

# CPE

cpe:2.3:a:mintplex-labs:anythingllm:{version}:*:*:*:*:*:*:*
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

// anythingLLMTitleRe matches the distinctive AnythingLLM page title.
// Requires "AnythingLLM" at the start of the title (only optional whitespace
// before it) to avoid false positives from blog posts like "Review of AnythingLLM".
var anythingLLMTitleRe = regexp.MustCompile(`(?i)<title[^>]*>\s*AnythingLLM[^<]*</title>`)

// anythingLLMOGRe matches the AnythingLLM OpenGraph URL meta tag.
// This is a corroborating signal — the og:url pointing to anythingllm.com.
// Uses alternation to handle both attribute orderings (property before content,
// or content before property), since HTML attributes may appear in any order.
var anythingLLMOGRe = regexp.MustCompile(`(?i)<meta\s[^>]*(?:property\s*=\s*["']og:url["'][^>]*content\s*=\s*["'][^"']*anythingllm\.com[^"']*["']|content\s*=\s*["'][^"']*anythingllm\.com[^"']*["'][^>]*property\s*=\s*["']og:url["'])`)

// anythingLLMVersionExtractRe extracts the leading semver triple from the
// "appVersion" JSON field. Capturing only the three-component numeric prefix
// avoids pre-release or build-metadata suffixes that would fail CPE validation.
var anythingLLMVersionExtractRe = regexp.MustCompile(`"appVersion"\s*:\s*"(\d+\.\d+\.\d+)`)

// anythingLLMVersionFieldRe extracts a semver triple from the "version" JSON
// field. Some AnythingLLM deployments report a clean semver under "version"
// rather than "appVersion". This is used as a fallback after appVersion fails.
// The regex matches the literal `"version"` (quote before 'v'), which is
// distinct from `"appVersion"` (quote before 'a'), so no collision occurs.
var anythingLLMVersionFieldRe = regexp.MustCompile(`"version"\s*:\s*"(\d+\.\d+\.\d+)`)

// anythingLLMVersionValidateRe is the anchored second-stage CPE validation gate.
// Accepts only pure semver strings (three numeric components, nothing else).
// Rejects pre-release suffixes, build metadata, and any CPE metacharacters.
var anythingLLMVersionValidateRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// anythingLLMModeRe extracts the "mode" field value from the metrics JSON.
// AnythingLLM reports "multi-user" or "single-user" to indicate deployment type.
var anythingLLMModeRe = regexp.MustCompile(`"mode"\s*:\s*"([^"]{1,32})"`)

// anythingLLMVectorDBRe extracts the "vectorDB" field value from the metrics JSON.
// Example values include "lancedb", "pinecone", "chroma", "weaviate".
var anythingLLMVectorDBRe = regexp.MustCompile(`"vectorDB"\s*:\s*"([^"]{1,64})"`)

// AnythingLLMFingerprinter detects AnythingLLM server instances.
// Implements ActiveHTTPFingerprinter + AcceptHeaderProvider.
type AnythingLLMFingerprinter struct{}

func init() {
	Register(&AnythingLLMFingerprinter{})
	Register(&AnythingLLMHTMLFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *AnythingLLMFingerprinter) Name() string {
	return "anythingllm"
}

// ProbeEndpoint returns the AnythingLLM metrics endpoint path.
// A plain GET to /api/utils/metrics returns JSON with vectorDB, appVersion,
// and mode fields. No write operations are performed.
func (f *AnythingLLMFingerprinter) ProbeEndpoint() string {
	return "/api/utils/metrics"
}

// ProbeAccept returns the Accept header for the active probe.
func (f *AnythingLLMFingerprinter) ProbeAccept() string {
	return "application/json"
}

// Match returns true when the response is a candidate for AnythingLLM detection.
//
// Fast-path: active probe responses from /api/utils/metrics always match.
// Fallback: responses with Content-Type containing "application/json" match.
//
// Status codes below 200 or 5xx are rejected immediately.
func (f *AnythingLLMFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Fast-path: active probe response from /api/utils/metrics always matches.
	if resp.Request != nil && resp.Request.URL != nil &&
		resp.Request.URL.Path == "/api/utils/metrics" {
		return true
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "application/json") {
		return true
	}

	return false
}

// Fingerprint performs full AnythingLLM detection and metadata extraction.
//
// Gate: rejects status < 200 or >= 500 and bodies larger than 2 MiB.
//
// Detection signal (metrics JSON):
//   - Body contains "vectorDB" AND at least one of ("appVersion" OR "mode").
//     This combination is distinctive to AnythingLLM's /api/utils/metrics
//     response and is not expected to appear in unrelated JSON APIs.
//
// If the signal does not fire, Fingerprint returns nil.
func (f *AnythingLLMFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: 2 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Signal 1 (metrics JSON): body contains "vectorDB" AND at least one of
	// "appVersion" or "mode". Use bytes.Contains to avoid allocating a string.
	hasVectorDB := bytes.Contains(body, []byte(`"vectorDB"`))
	hasAppVersion := bytes.Contains(body, []byte(`"appVersion"`))
	hasMode := bytes.Contains(body, []byte(`"mode"`))

	if !hasVectorDB || (!hasAppVersion && !hasMode) {
		return nil, nil
	}

	// Determine detection method.
	detectionMethod := "json_field"
	if resp.Request != nil && resp.Request.URL != nil &&
		resp.Request.URL.Path == "/api/utils/metrics" {
		detectionMethod = "active_probe"
	}

	// Extract version from appVersion field.
	version := extractAnythingLLMVersion(body)

	// Extract mode and vectorDB from the metrics JSON.
	mode := extractAnythingLLMField(anythingLLMModeRe, body)
	vectorDB := extractAnythingLLMField(anythingLLMVectorDBRe, body)

	// Build metadata map.
	metadata := map[string]any{
		"vendor":           "Mintplex Labs",
		"product":          "AnythingLLM",
		"detection_method": detectionMethod,
	}

	if detectionMethod == "active_probe" {
		metadata["probe_path"] = resp.Request.URL.Path
	}

	if version != "" {
		metadata["version"] = version
	}

	if mode != "" {
		metadata["mode"] = mode
	}

	if vectorDB != "" {
		metadata["vector_db"] = vectorDB
	}

	result := &FingerprintResult{
		Technology: "anythingllm",
		Version:    version,
		CPEs:       []string{buildAnythingLLMCPE(version)},
		Metadata:   metadata,
	}

	if detectionMethod == "active_probe" {
		result.Severity = plugins.SeverityHigh
	}

	return result, nil
}

// extractAnythingLLMVersion extracts and validates the AnythingLLM version from
// the metrics JSON body. Uses a two-stage approach: the extract regex captures
// the leading semver triple, and the validate regex confirms it is pure digits
// before CPE emission. Returns "" when no valid semver version is found.
//
// The function tries "appVersion" first (the canonical field). If that is absent
// or not a valid semver triple, it falls back to the "version" field, which some
// deployments populate with a clean semver string instead of a git SHA.
func extractAnythingLLMVersion(body []byte) string {
	// Try appVersion first (the canonical field).
	m := anythingLLMVersionExtractRe.FindSubmatch(body)
	if len(m) < 2 {
		// Fall back to "version" field (some deployments report semver here).
		m = anythingLLMVersionFieldRe.FindSubmatch(body)
	}
	if len(m) < 2 {
		return ""
	}
	raw := string(m[1])
	if !anythingLLMVersionValidateRe.MatchString(raw) {
		return ""
	}
	return raw
}

// extractAnythingLLMField extracts a single captured string from the metrics
// JSON body using the given compiled regex. Returns "" when no match is found.
func extractAnythingLLMField(re *regexp.Regexp, body []byte) string {
	m := re.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return string(m[1])
}

// buildAnythingLLMCPE constructs a CPE 2.3 string for AnythingLLM.
// Vendor "mintplex-labs" is used to match NVD convention. When version is
// empty, a wildcard "*" is emitted to support asset inventory without version
// data.
func buildAnythingLLMCPE(version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:mintplex-labs:anythingllm:%s:*:*:*:*:*:*:*", v)
}

// --- AnythingLLMHTMLFingerprinter ---

// AnythingLLMHTMLFingerprinter detects AnythingLLM from the HTML login page
// served at the root. It is a passive-only fingerprinter (HTTPFingerprinter only)
// and complements AnythingLLMFingerprinter for deployments where the metrics
// endpoint is blocked.
type AnythingLLMHTMLFingerprinter struct{}

// Name returns the fingerprinter identifier.
func (f *AnythingLLMHTMLFingerprinter) Name() string {
	return "anythingllm-html"
}

// Match returns true when the response is a candidate for HTML-based AnythingLLM detection.
//
// Rejects status codes below 200 or 5xx. Content-Type must contain "text/html".
func (f *AnythingLLMHTMLFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint detects AnythingLLM from the HTML login page.
//
// Gate: rejects status < 200 or >= 500 and bodies larger than 2 MiB.
//
// Detection signal:
//   - HTML <title> contains "AnythingLLM" (via anythingLLMTitleRe). This is a
//     standalone signal because the title "AnythingLLM | Your personal LLM
//     trained on anything" is highly distinctive and unique to this product.
//
// If the title signal does not fire, Fingerprint returns nil.
// When the corroborating og:url meta tag pointing to anythingllm.com is also
// present, metadata["og_url"] is set to true for additional confidence.
func (f *AnythingLLMHTMLFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: 2 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Signal: distinctive <title> containing "AnythingLLM".
	if !anythingLLMTitleRe.Match(body) {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":           "Mintplex Labs",
		"product":          "AnythingLLM",
		"detection_method": "login_page",
	}

	// Corroborating signal: og:url pointing to anythingllm.com.
	if anythingLLMOGRe.Match(body) {
		metadata["og_url"] = true
	}

	return &FingerprintResult{
		Technology: "anythingllm",
		Version:    "",
		CPEs:       []string{buildAnythingLLMCPE("")},
		Metadata:   metadata,
	}, nil
}
