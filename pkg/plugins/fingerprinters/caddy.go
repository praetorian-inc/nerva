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
Package fingerprinters provides HTTP fingerprinting for Caddy web server.

# What We Detect

  - Caddy v2+ (Go-based, automatic HTTPS web server)

# What We Do NOT Detect

  - Caddy v1 (legacy, different codebase, reached end-of-life)
  - Other Go web servers that do not identify as Caddy

# Security Context

The primary security concern is admin API exposure. Caddy v2 ships with a
local-only admin API on port 2019 by default. When this API is exposed to
external networks, any client can read and write the full server configuration
via plain HTTP — no authentication required by default. This allows an attacker
to redirect traffic, add TLS certificates, or disable HTTPS entirely.

No specific CVE applies; the risk is misconfiguration rather than a
vulnerability in the product itself.

# Active Probe Safety

The active probe issues a plain GET /config/ with no request body. This is a
read-only operation: it retrieves the current Caddy configuration as JSON but
makes no modifications. The admin API's write operations (PUT, POST, DELETE,
PATCH) are not used.

# CPE

cpe:2.3:a:caddyserver:caddy:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// CaddyFingerprinter detects Caddy v2+ web server instances.
type CaddyFingerprinter struct{}

// caddyServerVersionRegex extracts the version from the Server header.
// Matches: "Caddy/v2.7.6", "Caddy 2.7.6", "Caddy/2.7"
// The (?i) flag makes the initial "Caddy" match case-insensitive.
// Bounded: 2–4 dotted digit groups to prevent runaway matching.
var caddyServerVersionRegex = regexp.MustCompile(
	`(?i)Caddy[/ ]*v?([0-9]+(?:\.[0-9]+){1,3})`,
)

// caddyVersionValidateRegex is the anchored validation gate applied after
// version extraction. Rejects values like "2.7.6-beta", "2.7.6:*:", ".1", "..".
var caddyVersionValidateRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}$`)

// caddyAdminAPIRegex detects a Caddy admin API response body. The /config/
// endpoint returns a JSON object with top-level keys such as "apps", "admin",
// and "logging". Matching "apps" followed by a colon and opening brace is a
// strong signal because this key does not appear in generic JSON responses.
var caddyAdminAPIRegex = regexp.MustCompile(`"apps"\s*:\s*\{`)

// caddyTLSConfigRegex detects TLS configuration in the Caddy admin API response.
// When the "apps" object contains a "tls" key with an object value, Caddy has
// explicit TLS/automatic HTTPS configuration active.
var caddyTLSConfigRegex = regexp.MustCompile(`"tls"\s*:\s*\{`)

func init() {
	Register(&CaddyFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *CaddyFingerprinter) Name() string {
	return "caddy"
}

// ProbeEndpoint returns the admin API probe path. A plain GET to /config/
// retrieves the full Caddy configuration as JSON when the admin API is
// exposed. No write operations are performed.
func (f *CaddyFingerprinter) ProbeEndpoint() string {
	return "/config/"
}

// ProbeAccept returns the Accept header for the active probe.
// The Caddy admin API returns application/json.
func (f *CaddyFingerprinter) ProbeAccept() string {
	return "application/json"
}

// Match returns true when the response is a candidate for Caddy detection.
//
// Fast path: Server header contains "caddy" (case-insensitive) — immediate
// match because this is a definitive signal.
//
// Body-scan candidates: text/html responses (Caddy error pages) and
// application/json responses (admin API). Responses with unrelated
// Content-Type values are not worth scanning.
//
// 5xx responses are rejected: server errors do not provide usable fingerprint
// data and indicate something is already wrong on the server side.
// Responses below 200 (informational) are also rejected.
func (f *CaddyFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Header-based fast-path.
	if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "caddy") {
		return true
	}

	// Body-scan candidate: text/html (error pages) or application/json (admin API).
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/json") {
		return true
	}

	return false
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection requires at least one definitive signal:
//   - Server header starting with "caddy" (case-insensitive) — PRIMARY
//   - Admin API JSON body (contains "apps":{} structure) — SECONDARY
//
// Body brand token ("caddy" in body + corroborating marker) is a TERTIARY
// signal that must be paired with at least one of the above to fire.
// "Caddy" is a common English word (golf caddy, caddy shack, etc.) so body-only
// detection without a corroborating signal would produce too many false positives.
//
// Version extraction priority:
//  1. Server header regex (most reliable)
//  2. Body text (admin API or brand)
//  3. Empty → wildcard CPE
//
// Admin API exposure: when the /config/ endpoint returns a Caddy config JSON
// object, the admin API is accessible from the scanning perspective. This is
// reported as admin_api_exposed=true in metadata with SeverityHigh.
func (f *CaddyFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: internal 2 MiB body cap — defense-in-depth above the engine's
	// 10 MiB io.LimitReader. A Caddy admin API response or error page is
	// well under 2 MiB; larger bodies are almost certainly not Caddy.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Gate 3: CPE-injection defense — reject bodies containing ":*:".
	// Attacker-controlled bodies could attempt to inject CPE metacharacters
	// via the version string.
	if strings.Contains(string(body), ":*:") {
		return nil, nil
	}

	serverHeader := resp.Header.Get("Server")
	serverLower := strings.ToLower(serverHeader)
	bodyLower := strings.ToLower(string(body))

	// --- Signal detection ---

	// PRIMARY: Server header starts with "caddy" or equals "caddy".
	hasServerHeaderSignal := strings.HasPrefix(serverLower, "caddy") || serverLower == "caddy"

	// SECONDARY: Admin API JSON body contains Caddy config structure.
	hasAdminAPISignal := isCaddyAdminAPI(body)

	// TERTIARY: Body contains "caddy" + corroborating marker.
	hasBodyBrand := strings.Contains(bodyLower, "caddy") &&
		(strings.Contains(bodyLower, "caddyserver") ||
			strings.Contains(bodyLower, "powered by caddy"))

	// At least one definitive signal must be present.
	// Body brand token alone is not sufficient.
	if !hasServerHeaderSignal && !hasAdminAPISignal {
		return nil, nil
	}

	// Determine if this response came from the active probe (/config/).
	isActiveProbe := false
	if resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/config/") {
			isActiveProbe = true
		}
	}

	// Determine detection method.
	var detectionMethod string
	switch {
	case isActiveProbe && hasAdminAPISignal:
		detectionMethod = "active_probe"
	case hasAdminAPISignal:
		detectionMethod = "admin_api"
	case hasServerHeaderSignal && hasBodyBrand:
		detectionMethod = "body"
	default:
		detectionMethod = "server_header"
	}

	version := extractCaddyVersion(resp, body)

	// Build metadata — only include keys with non-empty / non-false values (YAGNI).
	metadata := map[string]any{
		"vendor":           "caddyserver",
		"product":          "Caddy",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	// Report admin API exposure only when we actually checked for it.
	if hasAdminAPISignal || isActiveProbe {
		metadata["admin_api_exposed"] = hasAdminAPISignal
	}
	if isActiveProbe {
		metadata["probe_path"] = "/config/"
	}
	if serverHeader != "" {
		metadata["server_header"] = sanitizeCaddyHeaderValue(serverHeader)
	}

	// Auto-HTTPS detection: check admin API config and response scheme.
	if autoHTTPS := detectCaddyAutoHTTPS(resp, body, hasAdminAPISignal); autoHTTPS {
		metadata["auto_https"] = true
	}

	result := &FingerprintResult{
		Technology: "caddy",
		Version:    version,
		CPEs:       []string{buildCaddyCPE(version)},
		Metadata:   metadata,
	}

	// Exposed admin API is a high-severity misconfiguration finding.
	if hasAdminAPISignal {
		result.Severity = plugins.SeverityHigh
	}

	return result, nil
}

// extractCaddyVersion tries the Server header first then the response body,
// applying two-stage validation before returning. Returns empty string if no
// valid version is found.
func extractCaddyVersion(resp *http.Response, body []byte) string {
	// Priority 1: Server header (most reliable when Caddy includes version).
	if m := caddyServerVersionRegex.FindSubmatch([]byte(resp.Header.Get("Server"))); len(m) >= 2 {
		if v := string(m[1]); caddyVersionValidateRegex.MatchString(v) {
			return v
		}
	}

	// Priority 2: Body (admin API response or branded page may include version).
	if m := caddyServerVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); caddyVersionValidateRegex.MatchString(v) {
			return v
		}
	}

	return ""
}

// sanitizeCaddyHeaderValue strips control characters and limits length to
// prevent log injection or oversized metadata values from attacker-controlled
// headers. Uses rune-aware truncation at 256 bytes.
func sanitizeCaddyHeaderValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7F {
			b.WriteRune(r)
			if b.Len() >= 256 {
				break
			}
		}
	}
	return b.String()
}

// buildCaddyCPE constructs a CPE 2.3 string for Caddy web server.
// NVD vendor/product: caddyserver:caddy.
// When version is empty, a wildcard CPE is emitted.
func buildCaddyCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:caddyserver:caddy:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:caddyserver:caddy:%s:*:*:*:*:*:*:*", version)
}

// isCaddyAdminAPI reports whether body looks like a Caddy admin API JSON
// response. The /config/ endpoint returns a JSON object with a top-level
// "apps" key containing a nested object. This is a strong distinguishing
// signal because no other common web service returns this exact structure.
func isCaddyAdminAPI(body []byte) bool {
	return caddyAdminAPIRegex.Match(body)
}

// detectCaddyAutoHTTPS determines whether automatic HTTPS appears to be enabled.
// Detection sources (in priority order):
//  1. Admin API body: presence of "tls" key in the apps config JSON
//  2. Admin API body: HTTPS listener (":443") in server configuration
//  3. Response scheme: request was served over HTTPS
//
// Returns true if any signal indicates HTTPS is active, false otherwise.
// This is best-effort: Caddy enables auto-HTTPS by default for public domains
// even without explicit TLS configuration.
func detectCaddyAutoHTTPS(resp *http.Response, body []byte, hasAdminAPISignal bool) bool {
	// From admin API config: explicit TLS configuration.
	if hasAdminAPISignal && caddyTLSConfigRegex.Match(body) {
		return true
	}

	// From admin API config: HTTPS listener on port 443.
	if hasAdminAPISignal && strings.Contains(string(body), ":443") {
		return true
	}

	// From response: served over HTTPS.
	if resp.Request != nil && resp.Request.URL != nil && resp.Request.URL.Scheme == "https" {
		return true
	}

	return false
}
