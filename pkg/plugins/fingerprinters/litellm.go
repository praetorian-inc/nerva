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
Package fingerprinters provides HTTP fingerprinting for LiteLLM Proxy instances.

# What We Detect

  - LiteLLM Proxy instances via proprietary X-Litellm-* response headers.
    Any response header whose name starts with "X-Litellm-" (case-insensitive)
    is a standalone signal. The X-Litellm-Version header additionally enables
    version extraction.

  - LiteLLM liveliness endpoint: when the active probe to /health/liveliness
    returns exactly the plain-text string "I'm alive!", the instance is
    confirmed. This is the definitive active-probe signal.

  - LiteLLM-specific JSON field name prefixes embedded in API responses.
    Field names beginning with "litellm_" (e.g., litellm_params,
    litellm_version, litellm_budget_table) are unique to LiteLLM and
    constitute a standalone signal. The model list marker
    "owned_by":"litellm" (with or without a space after the colon) is
    also matched.

  - LiteLLM admin UI HTML: an HTML <title> tag containing "litellm"
    combined with a "/ui" path reference in a src or href attribute.
    Both sub-signals must fire together.

# What We Do NOT Detect

  - LiteLLM Proxy instances deployed behind reverse proxies that strip all
    X-Litellm-* headers and serve a custom HTML front-end without LiteLLM
    branding.

  - LiteLLM SDK usage inside application code (not proxy mode); the SDK does
    not expose an HTTP server with these markers.

  - OpenAI-compatible proxies (LiteLLM-compatible but not LiteLLM itself)
    that mimic the /models list but omit "owned_by":"litellm".

# Security Context

Exposed LiteLLM Proxy instances are high-severity findings because the proxy
stores and forwards API keys for every connected LLM provider (OpenAI,
Anthropic, Google, Cohere, Mistral, and 100+ others). Unauthenticated access
to the proxy may allow arbitrary requests billed to the operator's provider
accounts and can expose provider API keys through configuration endpoints.

No specific CVEs are publicly catalogued against LiteLLM Proxy at this time;
however, the exposure class mirrors credential-theft risk seen in other
credential-holding infrastructure.

# Active Probe Safety

The active probe issues a plain GET /health/liveliness with no request body
and Accept header set to accept any content type. The liveliness endpoint is a read-only health check that
returns a plain-text "I'm alive!" string. No write operations are performed.

# CPE

cpe:2.3:a:berriai:litellm:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// litellmVersionExtractRe extracts a semver-like version string from the
// X-Litellm-Version header. Matches the first dotted-numeric prefix such as
// "1.40.10" in "1.40.10-stable". The extraction regex is intentionally loose;
// the second-stage anchored regex enforces strict format before CPE emission.
var litellmVersionExtractRe = regexp.MustCompile(`^\d+\.\d+\.\d+`)

// litellmVersionValidateRe is the anchored second-stage CPE validation gate.
// Accepts only pure semver strings (three numeric components, nothing else).
// Rejects pre-release suffixes, build metadata, and any CPE metacharacters.
var litellmVersionValidateRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// litellmTitleRe matches LiteLLM branding in an HTML <title> tag.
// The <title> element is a structural self-identification marker.
// Case-insensitive to match "LiteLLM", "litellm", "LITELLM", etc.
var litellmTitleRe = regexp.MustCompile(`(?i)<title[^>]*>[^<]*litellm[^<]*</title>`)

// litellmUIPathRe matches a "/ui" path reference in a src or href attribute.
// LiteLLM's admin dashboard is served under /ui; its presence together with
// the title-tag signal confirms the LiteLLM web front-end.
var litellmUIPathRe = regexp.MustCompile(`(?i)(?:href|src)=["'][^"']*/ui[/"']`)

// LiteLLMFingerprinter detects LiteLLM Proxy instances.
// Implements ActiveHTTPFingerprinter + AcceptHeaderProvider.
type LiteLLMFingerprinter struct{}

func init() {
	Register(&LiteLLMFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *LiteLLMFingerprinter) Name() string {
	return "litellm"
}

// ProbeEndpoint returns the LiteLLM liveliness health check path.
// A plain GET to /health/liveliness returns "I'm alive!" as text/plain
// when the proxy is running. No write operations are performed.
func (f *LiteLLMFingerprinter) ProbeEndpoint() string {
	return "/health/liveliness"
}

// ProbeAccept returns the Accept header for the active probe.
// The /health/liveliness endpoint returns plain text, not JSON.
func (f *LiteLLMFingerprinter) ProbeAccept() string {
	return "*/*"
}

// Match returns true when the response is a candidate for LiteLLM detection.
//
// Fast-path signals that warrant a body scan:
//   - Any response header name starts with "X-Litellm-" (case-insensitive)
//   - Content-Type is application/json, text/html, or text/plain
//
// 5xx responses and responses below 200 are rejected immediately.
func (f *LiteLLMFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Fast-path: any X-Litellm-* response header is a definitive marker.
	for k := range resp.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-litellm-") {
			return true
		}
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "application/json") ||
		strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "text/plain") {
		return true
	}

	return false
}

// Fingerprint performs full LiteLLM detection and metadata extraction.
//
// Gate: rejects status < 200 or >= 500 and bodies larger than 2 MiB.
//
// Detection signals (priority order):
//  1. X-Litellm-* response headers (standalone) — "active_probe" when the
//     response came from /health/*, otherwise "response_header".
//  2. /health/liveliness plain-text body == "I'm alive!" (standalone) — "active_probe".
//  3. JSON body containing "litellm_" key prefix or "owned_by":"litellm" — "json_field".
//  4. HTML <title> containing "litellm" AND a "/ui" href/src reference — "html_branding".
//
// At least one signal must fire, or Fingerprint returns nil.
func (f *LiteLLMFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: 2 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Determine whether this response came from the active probe path.
	isActiveProbe := false
	if resp.Request != nil && resp.Request.URL != nil {
		isActiveProbe = strings.HasPrefix(resp.Request.URL.Path, "/health/")
	}

	// --- Signal 1: X-Litellm-* response headers ---

	var litellmHeaders []string
	for k := range resp.Header {
		if strings.HasPrefix(strings.ToLower(k), "x-litellm-") {
			litellmHeaders = append(litellmHeaders, k)
		}
	}
	hasHeaderSignal := len(litellmHeaders) > 0

	// --- Signal 2: /health/liveliness "I'm alive!" plain-text response ---

	hasLivelinessSignal := false
	if resp.Request != nil && resp.Request.URL != nil &&
		strings.Contains(resp.Request.URL.Path, "/health/liveliness") {
		if strings.TrimSpace(string(body)) == "I'm alive!" {
			hasLivelinessSignal = true
		}
	}

	// --- Signal 3: LiteLLM-specific JSON field name prefix ---

	hasJSONSignal := strings.Contains(string(body), `"litellm_`) ||
		strings.Contains(string(body), `"owned_by":"litellm`) ||
		strings.Contains(string(body), `"owned_by": "litellm`)

	// --- Signal 4: HTML branding in title + /ui path reference ---

	hasHTMLSignal := litellmTitleRe.Match(body) && litellmUIPathRe.Match(body)

	// At least one signal must fire.
	if !hasHeaderSignal && !hasLivelinessSignal && !hasJSONSignal && !hasHTMLSignal {
		return nil, nil
	}

	// --- Version extraction ---

	version := extractLiteLLMVersion(resp)

	// --- Detection method (priority: active_probe > response_header > json_field > html_branding) ---

	var detectionMethod string
	switch {
	case hasHeaderSignal && isActiveProbe:
		detectionMethod = "active_probe"
	case hasLivelinessSignal:
		detectionMethod = "active_probe"
	case hasHeaderSignal:
		detectionMethod = "response_header"
	case hasJSONSignal:
		detectionMethod = "json_field"
	default:
		detectionMethod = "html_branding"
	}

	// --- Metadata ---

	metadata := map[string]any{
		"vendor":           "BerriAI",
		"product":          "LiteLLM",
		"detection_method": detectionMethod,
	}

	if isActiveProbe || hasLivelinessSignal {
		metadata["probe_path"] = "/health/liveliness"
	}

	if version != "" {
		metadata["version"] = version
	}

	if len(litellmHeaders) > 0 {
		metadata["litellm_headers"] = litellmHeaders
	}

	return &FingerprintResult{
		Technology: "litellm",
		Version:    version,
		CPEs:       []string{buildLiteLLMCPE(version)},
		Metadata:   metadata,
	}, nil
}

// extractLiteLLMVersion extracts and validates the LiteLLM version from the
// X-Litellm-Version response header. Uses sanitizeHTTPHeaderValue to defang
// the raw header value before processing. Returns "" when no valid semver
// version is found.
func extractLiteLLMVersion(resp *http.Response) string {
	raw := resp.Header.Get("X-Litellm-Version")
	if raw == "" {
		return ""
	}
	sanitized := sanitizeHTTPHeaderValue(raw)
	m := litellmVersionExtractRe.FindString(sanitized)
	if m == "" {
		return ""
	}
	if !litellmVersionValidateRe.MatchString(m) {
		return ""
	}
	return m
}

// buildLiteLLMCPE constructs a CPE 2.3 string for LiteLLM Proxy.
// Vendor "berriai" is the NVD convention for BerriAI. When version is empty,
// a wildcard "*" is emitted to support asset inventory without version data.
func buildLiteLLMCPE(version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:berriai:litellm:%s:*:*:*:*:*:*:*", v)
}
