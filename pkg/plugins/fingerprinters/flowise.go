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
Package fingerprinters provides HTTP fingerprinting for Flowise, an open-source
low-code platform for building LLM-powered applications and chatflows.

# What We Detect

  - Flowise instances via the unauthenticated /api/v1/version endpoint.
    A JSON response containing a "version" field without a "package" field
    confirms Flowise. The "package" field exclusion distinguishes Flowise from
    Langflow, which exposes the same path and returns {"package":"Langflow",...}.

  - Flowise instances via the <meta name="author" content="FlowiseAI"> tag
    embedded in the React SPA's index.html. This tag is present in all Flowise
    UI builds and does not require authentication to observe.

# What We Do NOT Detect

  - Flowise deployments behind reverse proxies that block /api/v1/version and
    strip the HTML meta author tag from responses.

  - Langflow instances, which share the /api/v1/version path but include
    {"package":"Langflow"} in the response body. The "package" exclusion check
    prevents false-positive Flowise detections on Langflow deployments.

  - Flowise instances that have customized their HTML template to remove the
    FlowiseAI author meta tag.

# Security Context

Exposed Flowise instances are high-severity findings because Flowise orchestrates
LLM workflows that may include stored credentials, API keys for external LLM
providers (OpenAI, Anthropic, Azure OpenAI, etc.), and database connection strings
stored in chatflow configurations. Unauthenticated access to the API can expose
these secrets and allow arbitrary chatflow execution. Default Flowise deployments
do not require authentication on the API.

# Active Probe Safety

The active probe issues a plain GET /api/v1/version with Accept:
application/json. This is a read-only, idempotent endpoint that returns the
installed version string. No write operations are performed, no chatflows are
triggered, and no credentials are accessed.

# CPE

cpe:2.3:a:flowiseai:flowise:{version}:*:*:*:*:*:*:*
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

// flowiseVersionExtractRe is the first-stage loose extraction regex.
// Matches the version value from a JSON body containing `"version":"1.2.3"`.
// The extraction regex is intentionally loose; the anchored second-stage
// regex enforces strict semver format before CPE emission.
var flowiseVersionExtractRe = regexp.MustCompile(`"version"\s*:\s*"(\d+\.\d+\.\d+)`)

// flowiseVersionValidateRe is the anchored second-stage CPE validation gate.
// Accepts only pure semver strings (three numeric dot-separated components).
// Rejects pre-release suffixes, build metadata, and any CPE metacharacters.
var flowiseVersionValidateRe = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// flowiseHTMLAuthorRe matches the FlowiseAI author meta tag in HTML bodies.
// Handles both attribute orders:
//   - <meta name="author" content="FlowiseAI" ...>
//   - <meta content="FlowiseAI" name="author" ...>
//
// The outer [^>]{0,300} bounds prevent catastrophic backtracking on malformed HTML.
var flowiseHTMLAuthorRe = regexp.MustCompile(
	`(?i)<meta[^>]{0,300}(?:name=["']author["'][^>]{0,200}content=["']FlowiseAI["']|content=["']FlowiseAI["'][^>]{0,200}name=["']author["'])[^>]{0,100}>`,
)

// flowiseVersionMarker is the byte slice used for fast-path body scanning
// before invoking the extraction regex. Avoids regex cost on non-Flowise JSON.
var flowiseVersionMarker = []byte(`"version"`)

// flowisePackageMarker is the Langflow exclusion marker. Langflow returns
// {"package":"Langflow",...} on the same /api/v1/version path as Flowise.
// Rejecting bodies that contain this marker prevents false-positive Flowise
// detections on Langflow deployments.
var flowisePackageMarker = []byte(`"package"`)

// flowiseGiteaHashMarker is the Gitea exclusion marker. Gitea's /api/v1/version
// returns {"version":"1.x.y","git_hash":"..."} on the same path as Flowise.
// Rejecting bodies that contain this field prevents false-positive Flowise
// detections on Gitea deployments.
var flowiseGiteaHashMarker = []byte(`"git_hash"`)

// FlowiseFingerprinter detects Flowise instances via the /api/v1/version endpoint.
// Implements ActiveHTTPFingerprinter + AcceptHeaderProvider.
type FlowiseFingerprinter struct{}

// FlowiseHTMLFingerprinter detects Flowise instances via the HTML meta author tag.
// Implements HTTPFingerprinter (passive only — no active probe).
type FlowiseHTMLFingerprinter struct{}

func init() {
	Register(&FlowiseFingerprinter{})
	Register(&FlowiseHTMLFingerprinter{})
}

// --- FlowiseFingerprinter ---

// Name returns the fingerprinter identifier.
func (f *FlowiseFingerprinter) Name() string {
	return "flowise"
}

// ProbeEndpoint returns the Flowise version API path.
// A plain GET to /api/v1/version returns {"version":"<semver>"} without
// authentication on default Flowise deployments.
func (f *FlowiseFingerprinter) ProbeEndpoint() string {
	return "/api/v1/version"
}

// ProbeAccept returns the Accept header for the active probe.
// The /api/v1/version endpoint returns application/json.
func (f *FlowiseFingerprinter) ProbeAccept() string {
	return "application/json"
}

// Match returns true when the response is a candidate for Flowise detection.
//
// Fast-path: the active probe response from /api/v1/version always matches.
// Otherwise, application/json Content-Type is required to proceed to body scan.
//
// 5xx responses are rejected immediately; responses below 200 are also rejected.
func (f *FlowiseFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Fast-path: active probe path is an immediate match candidate.
	if resp.Request != nil && resp.Request.URL != nil &&
		resp.Request.URL.Path == "/api/v1/version" {
		return true
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "application/json")
}

// Fingerprint performs full Flowise detection and extracts technology information.
//
// Gates: status < 200 or >= 500, body > 2 MiB, empty body.
//
// Detection requires all of the following conditions:
//  1. Response came from /api/v1/version (path check).
//  2. Body contains the "version" JSON key (marker check).
//  3. Body does NOT contain the "package" JSON key (Langflow exclusion).
//  4. The extracted version passes two-stage semver validation.
func (f *FlowiseFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: 2 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Gate 3: empty body cannot contain a version field.
	if len(body) == 0 {
		return nil, nil
	}

	// Path check: only match responses from the version endpoint.
	if resp.Request == nil || resp.Request.URL == nil ||
		resp.Request.URL.Path != "/api/v1/version" {
		return nil, nil
	}

	// Marker check: body must contain the "version" JSON key.
	if !bytes.Contains(body, flowiseVersionMarker) {
		return nil, nil
	}

	// Langflow exclusion: reject bodies containing the "package" key.
	// Langflow returns {"package":"Langflow",...} on the same endpoint.
	if bytes.Contains(body, flowisePackageMarker) {
		return nil, nil
	}

	// Gitea exclusion: Gitea's /api/v1/version returns the same JSON shape.
	// Check body marker (some versions include "git_hash") and header.
	if bytes.Contains(body, flowiseGiteaHashMarker) {
		return nil, nil
	}
	if resp.Header.Get("X-Gitea-Version") != "" {
		return nil, nil
	}

	// Version extraction with two-stage validation.
	// Reject bodies where the version value is not a valid semver string
	// (e.g. {"version":"dev"}). A wildcard-CPE result on a generic JSON API
	// that happens to serve /api/v1/version would be a false positive.
	version := extractFlowiseVersion(body)
	if version == "" {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":           "FlowiseAI",
		"product":          "Flowise",
		"detection_method": "active_probe",
		"probe_path":       "/api/v1/version",
	}

	return &FingerprintResult{
		Technology: "flowise",
		Version:    version,
		CPEs:       []string{buildFlowiseCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityHigh,
	}, nil
}

// --- FlowiseHTMLFingerprinter ---

// Name returns the fingerprinter identifier.
func (f *FlowiseHTMLFingerprinter) Name() string {
	return "flowise-html"
}

// Match returns true when the response is a candidate for HTML meta tag detection.
//
// Requires status 200–499 and a text/html Content-Type. 5xx responses are rejected.
func (f *FlowiseHTMLFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs passive Flowise detection via the HTML meta author tag.
//
// Gates: status < 200 or >= 500, body > 2 MiB, empty body.
//
// Detection requires a <meta name="author" content="FlowiseAI"> tag in the body.
// Both attribute orders (name-before-content and content-before-name) are matched,
// case-insensitively. No version is extracted from HTML; a wildcard CPE is emitted.
func (f *FlowiseHTMLFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: 2 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Gate 3: empty body cannot contain an HTML meta tag.
	if len(body) == 0 {
		return nil, nil
	}

	// Match the FlowiseAI author meta tag.
	if !flowiseHTMLAuthorRe.Match(body) {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":           "FlowiseAI",
		"product":          "Flowise",
		"detection_method": "html_meta_tag",
	}

	return &FingerprintResult{
		Technology: "flowise",
		Version:    "",
		CPEs:       []string{buildFlowiseCPE("")},
		Metadata:   metadata,
	}, nil
}

// --- Shared helpers ---

// extractFlowiseVersion performs two-stage version extraction from a Flowise
// /api/v1/version JSON body. Stage 1 applies the loose extraction regex to
// capture the candidate string; stage 2 applies the anchored validation regex
// to reject non-semver or CPE-unsafe values. Returns "" when no valid version
// is found.
func extractFlowiseVersion(body []byte) string {
	m := flowiseVersionExtractRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	v := string(m[1])
	if !flowiseVersionValidateRe.MatchString(v) {
		return ""
	}
	return v
}

// buildFlowiseCPE constructs a CPE 2.3 string for Flowise.
// The NVD vendor is "flowiseai" and the product is "flowise".
// When version is empty, a wildcard "*" is emitted to support asset inventory
// without version data (e.g., HTML-only detection).
func buildFlowiseCPE(version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:flowiseai:flowise:%s:*:*:*:*:*:*:*", v)
}
