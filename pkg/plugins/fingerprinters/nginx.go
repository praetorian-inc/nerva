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
Package fingerprinters provides HTTP fingerprinting for Nginx web server and
related products.

# What We Detect

  - Nginx web server (all versions)
  - OpenResty (Nginx-based platform for Lua scripting)
  - Nginx UI management interface (exposes configuration and RCE risk)

# What We Do NOT Detect

  - Tengine (Nginx fork by Alibaba; a separate fingerprinter exists for it)
  - Angie (Nginx fork with different CPE taxonomy)
  - CloudFlare-Nginx (CDN variant serving traffic on behalf of F5; different context)

# Security Context

Nginx UI (CVE-2024-31016) exposes a full web-based management interface that
allows unauthenticated or weakly-authenticated users to read and modify the
server configuration, upload files, and potentially achieve remote code
execution. An exposed Nginx UI represents a full server takeover risk.

Beyond the management interface, Nginx version disclosure (via the Server
header or default error pages) maps directly to known CVE sets. Nginx holds
roughly 43% of the web server market, making it a high-value target.

# Active Probe Safety

The active probe issues a plain GET /api/ with no request body. This is a
read-only operation that retrieves metadata from the Nginx UI management API
when the interface is exposed. No write operations are performed.

# CPEs

Nginx:      cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*
OpenResty:  cpe:2.3:a:openresty:openresty:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// NginxFingerprinter detects Nginx web server, OpenResty, and Nginx UI instances.
type NginxFingerprinter struct{}

// nginxServerVersionRegex extracts the version from the Server header.
// Matches: "nginx/1.25.3", "openresty/1.21.4.1", "NGINX/1.24.0".
// The (?i) flag makes the prefix match case-insensitive.
// Bounded: 2–4 dotted digit groups to prevent runaway matching.
var nginxServerVersionRegex = regexp.MustCompile(
	`(?i)(?:nginx|openresty)/([0-9]+(?:\.[0-9]+){1,3})`,
)

// nginxVersionValidateRegex is the anchored validation gate applied after
// version extraction. Rejects values like "1.25.3-beta", "1.25.3:*:", ".1", "..".
var nginxVersionValidateRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,3}$`)

// nginxUIRegex detects Nginx UI markers in the response body. The Nginx UI
// login page, API responses, and asset references all contain these tokens.
var nginxUIRegex = regexp.MustCompile(`(?i)nginx[\s_-]*ui`)

// nginxErrorPageRegex detects the default Nginx error page. The error page
// contains a centered footer with the server name, optionally including the
// version: <center>nginx</center> or <center>nginx/1.25.3</center>.
var nginxErrorPageRegex = regexp.MustCompile(`(?i)<center>\s*nginx(?:/[0-9.]+)?\s*</center>`)

func init() {
	Register(&NginxFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *NginxFingerprinter) Name() string {
	return "nginx"
}

// ProbeEndpoint returns the Nginx UI management API probe path. A plain GET
// to /api/ retrieves metadata from the Nginx UI when the interface is exposed.
// No write operations are performed.
func (f *NginxFingerprinter) ProbeEndpoint() string {
	return "/api/"
}

// ProbeAccept returns the Accept header for the active probe.
// Nginx UI's /api/ endpoint returns application/json.
func (f *NginxFingerprinter) ProbeAccept() string {
	return "application/json"
}

// Match returns true when the response is a candidate for Nginx detection.
//
// Fast path: Server header starts with "nginx" or "openresty" (case-insensitive)
// — immediate match because this is a definitive signal. Tengine responses are
// explicitly excluded here to avoid conflicts with TengineFingerprinter.
//
// Body-scan candidates: text/html responses (Nginx error pages) and
// application/json responses (Nginx UI API). Responses with unrelated
// Content-Type values are not worth scanning.
//
// 5xx responses are rejected: server errors do not provide usable fingerprint
// data. Responses below 200 (informational) are also rejected.
func (f *NginxFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Header-based fast-path — exclude Tengine to avoid conflicts.
	serverLower := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverLower, "tengine") {
		// Handled by TengineFingerprinter — do not match.
	} else if strings.HasPrefix(serverLower, "nginx") || strings.HasPrefix(serverLower, "openresty") {
		return true
	}

	// Body-scan candidate: text/html (error pages) or application/json (Nginx UI API).
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/json") {
		return true
	}

	return false
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection requires at least one definitive signal:
//   - Server header starting with "nginx" or "openresty" (not "tengine") — PRIMARY
//   - Default Nginx error page body pattern — SECONDARY
//   - Nginx UI markers in body — TERTIARY
//
// Version extraction priority:
//  1. Server header regex (most reliable)
//  2. Error page body (version in <center>nginx/X.Y.Z</center>)
//  3. Empty → wildcard CPE
//
// Nginx UI exposure: when the /api/ endpoint or any body contains Nginx UI
// markers, nginx_ui_exposed=true is reported with SeverityHigh due to the
// RCE risk described in CVE-2024-31016.
func (f *NginxFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: internal 2 MiB body cap — defense-in-depth above the engine's
	// limit. A Nginx error page or API response is well under 2 MiB.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	serverHeader := resp.Header.Get("Server")
	serverLower := strings.ToLower(serverHeader)

	// --- Signal detection ---

	// PRIMARY: Server header starts with "nginx" or "openresty" (not "tengine").
	hasServerHeaderSignal := !strings.Contains(serverLower, "tengine") &&
		(strings.HasPrefix(serverLower, "nginx") || strings.HasPrefix(serverLower, "openresty"))

	// SECONDARY: Default Nginx error page body pattern.
	hasErrorPageSignal := isNginxErrorPage(body)

	// TERTIARY: Nginx UI markers in body.
	hasNginxUISignal := isNginxUI(body)

	// At least one definitive signal must be present.
	if !hasServerHeaderSignal && !hasErrorPageSignal && !hasNginxUISignal {
		return nil, nil
	}

	// Variant detection.
	variant := "nginx"
	if isOpenResty(serverHeader) {
		variant = "openresty"
	}

	// Determine if this response came from the active probe (/api/).
	isActiveProbe := false
	if resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/api/") {
			isActiveProbe = true
		}
	}

	// Determine detection method.
	var detectionMethods []string
	if hasServerHeaderSignal {
		detectionMethods = append(detectionMethods, "server_header")
	}
	if hasErrorPageSignal {
		detectionMethods = append(detectionMethods, "error_page")
	}
	if hasNginxUISignal {
		if isActiveProbe {
			detectionMethods = append(detectionMethods, "active_probe")
		} else {
			detectionMethods = append(detectionMethods, "nginx_ui")
		}
	}
	detectionMethod := strings.Join(detectionMethods, ",")

	version := extractNginxVersion(serverHeader, body)
	// Defense-in-depth: discard version if it somehow contains CPE metacharacters.
	// The extraction regex only captures digits and dots, so this should never trigger.
	if strings.ContainsAny(version, ":*") {
		version = ""
	}

	// Build metadata — only include keys with non-empty / non-false values (YAGNI).
	vendor := "F5"
	product := "Nginx"
	if variant == "openresty" {
		vendor = "OpenResty"
		product = "OpenResty"
	}

	metadata := map[string]any{
		"vendor":           vendor,
		"product":          product,
		"variant":          variant,
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if hasNginxUISignal {
		metadata["nginx_ui_exposed"] = true
	}
	if isActiveProbe && hasNginxUISignal {
		metadata["probe_path"] = "/api/"
	}
	if serverHeader != "" {
		metadata["server_header"] = sanitizeHTTPHeaderValue(serverHeader)
	}

	result := &FingerprintResult{
		Technology: "nginx",
		Version:    version,
		CPEs:       []string{buildNginxCPE(version, variant == "openresty")},
		Metadata:   metadata,
	}

	// Exposed Nginx UI is a high-severity misconfiguration/RCE risk (CVE-2024-31016).
	if hasNginxUISignal {
		result.Severity = plugins.SeverityHigh
	}

	return result, nil
}

// extractNginxVersion tries the Server header first then the error page body,
// applying two-stage validation before returning. Returns empty string if no
// valid version is found.
func extractNginxVersion(serverHeader string, body []byte) string {
	// Priority 1: Server header (most reliable when Nginx includes version).
	if m := nginxServerVersionRegex.FindSubmatch([]byte(serverHeader)); len(m) >= 2 {
		if v := string(m[1]); nginxVersionValidateRegex.MatchString(v) {
			return v
		}
	}

	// Priority 2: Error page body — <center>nginx/X.Y.Z</center> pattern.
	if m := nginxServerVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); nginxVersionValidateRegex.MatchString(v) {
			return v
		}
	}

	return ""
}

// isOpenResty reports whether the Server header indicates OpenResty.
func isOpenResty(serverHeader string) bool {
	return strings.HasPrefix(strings.ToLower(serverHeader), "openresty")
}

// isNginxUI reports whether the body contains Nginx UI management interface markers.
// These markers appear in the Nginx UI login page, API responses, and asset references.
func isNginxUI(body []byte) bool {
	return nginxUIRegex.Match(body)
}

// isNginxErrorPage reports whether the body matches the default Nginx error page
// pattern: <center>nginx</center> or <center>nginx/X.Y.Z</center>.
func isNginxErrorPage(body []byte) bool {
	return nginxErrorPageRegex.Match(body)
}

// buildNginxCPE constructs a CPE 2.3 string for Nginx or OpenResty.
// Nginx CPE: cpe:2.3:a:f5:nginx:{version}:*:*:*:*:*:*:*
// OpenResty CPE: cpe:2.3:a:openresty:openresty:{version}:*:*:*:*:*:*:*
// When version is empty, a wildcard CPE is emitted.
func buildNginxCPE(version string, openResty bool) string {
	v := version
	if v == "" {
		v = "*"
	}
	if openResty {
		return fmt.Sprintf("cpe:2.3:a:openresty:openresty:%s:*:*:*:*:*:*:*", v)
	}
	return fmt.Sprintf("cpe:2.3:a:f5:nginx:%s:*:*:*:*:*:*:*", v)
}
