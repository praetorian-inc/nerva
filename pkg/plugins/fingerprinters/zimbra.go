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
Package fingerprinters provides HTTP fingerprinting for Zimbra Collaboration Suite.

# What We Detect

  - Zimbra Collaboration Suite (Server) — community and network editions
    detected via the standard unauthenticated login page at /zimbra/.

# What We Do NOT Detect

  - Zimbra Cloud / Synacor-hosted variants that may not expose /zimbra/.
  - Branded Zimbra OEM deployments that remove standard Zimbra branding.

# CVE Context

  - CVE-2022-27925 + CVE-2022-37042 — chained for pre-auth RCE against
    Zimbra 8.8.15 and 9.0 before July 2022 patches (CISA Advisory AA22-228A).
  - CVE-2025-68645 — PHP remote file inclusion affecting Zimbra <= 10.x,
    added to CISA KEV in 2025. Active exploitation observed in the wild.

# Active Probe Safety

The active probe issues a plain GET /zimbra/ with no query string and no request
body. /zimbra/ is the standard unauthenticated login entry point for all Zimbra
server deployments. The probe is safe to run against any target.

# CPE

cpe:2.3:a:zimbra:collaboration:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// ZimbraFingerprinter detects Zimbra Collaboration Suite server instances.
type ZimbraFingerprinter struct{}

// zimbraCacheBusterVersionRegex extracts the version from the zimbraCacheBusterVersion
// JavaScript variable. Example: var zimbraCacheBusterVersion = "8.8.15_GA_4179";
// The regex stops at the first non-version character after the digits, so only
// the dotted version portion is captured.
var zimbraCacheBusterVersionRegex = regexp.MustCompile(
	`zimbraCacheBusterVersion\s*=\s*["']?(\d+\.\d+\.\d+)`,
)

// zimbraScriptVersionRegex extracts the version from a script src URL with a
// Zimbra path and a ?v= version parameter.
// Example: /zimbra/css/skin.css?v=8.8.15_GA_4179
var zimbraScriptVersionRegex = regexp.MustCompile(
	`(?i)/zimbra/[^"']*\?v=(\d+\.\d+\.\d+)`,
)

// zimbraClientVersionRegex extracts the version from a CLIENT_VERSION declaration.
// Example: CLIENT_VERSION = "8.8.15"
var zimbraClientVersionRegex = regexp.MustCompile(
	`CLIENT_VERSION[^"]*"(\d+\.\d+\.\d+)`,
)

// zimbraVersionValidateRegex is the two-stage validation gate. Anchored ^…$ to
// reject partial matches; allows 2–5 dotted digit groups.
var zimbraVersionValidateRegex = regexp.MustCompile(
	`^[0-9]+(?:\.[0-9]+){1,4}$`,
)

func init() {
	Register(&ZimbraFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *ZimbraFingerprinter) Name() string {
	return "zimbra"
}

// ProbeEndpoint returns the active probe path. /zimbra/ is the standard
// unauthenticated login entry point for all Zimbra server deployments.
func (f *ZimbraFingerprinter) ProbeEndpoint() string {
	return "/zimbra/"
}

// Match returns true when the response is potentially a Zimbra login page.
// A Zimbra-specific cookie (ZM_TEST or ZM_AUTH_TOKEN) in Set-Cookie headers
// is treated as a definitive signal regardless of Content-Type.
// A text/html Content-Type with a status in 200–499 is treated as a
// candidate for body-driven detection.
func (f *ZimbraFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Zimbra-specific cookie is a definitive match signal.
	if hasZimbraCookie(resp) {
		return true
	}

	// text/html content may contain Zimbra branding.
	if strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection requires at least one definitive signal:
//  1. Body (lowercased) contains "zimbra web client" OR body contains both
//     "zimbra" and a login form indicator (os_username, loginForm, ZLoginForm).
//  2. A Set-Cookie header contains ZM_TEST (Zimbra-specific cookie).
//  3. Body contains a Zimbra-specific JS reference: "zimbramail", "zmsetting",
//     or "zimbracachebusterversion" (all case-insensitive).
//
// Version extraction priority:
//  1. zimbraCacheBusterVersion JS variable
//  2. Script src with Zimbra path and ?v= version parameter
//  3. CLIENT_VERSION pattern
func (f *ZimbraFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: internal 2 MiB body cap — a legitimate Zimbra login page is <200 KiB;
	// bodies >2 MiB are almost certainly not Zimbra and would waste regex time.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Gate 3: CPE-injection defense — reject bodies containing `:*:`.
	if strings.Contains(string(body), ":*:") {
		return nil, nil
	}

	bodyLower := strings.ToLower(string(body))

	// Evaluate definitive signals.
	hasLoginBranding := strings.Contains(bodyLower, "zimbra web client")
	hasZimbraAndLoginForm := strings.Contains(bodyLower, "zimbra") &&
		(strings.Contains(bodyLower, "os_username") ||
			strings.Contains(bodyLower, "loginform") ||
			strings.Contains(bodyLower, "zloginform"))
	hasCookieSignal := hasZimbraCookie(resp)
	hasJSRef := strings.Contains(bodyLower, "zimbramail") ||
		strings.Contains(bodyLower, "zmsetting") ||
		strings.Contains(bodyLower, "zimbracachebusterversion")

	if !hasLoginBranding && !hasZimbraAndLoginForm && !hasCookieSignal && !hasJSRef {
		return nil, nil
	}

	// Determine detection method.
	detectionMethod := "body"
	if hasCookieSignal && !hasLoginBranding && !hasZimbraAndLoginForm && !hasJSRef {
		detectionMethod = "cookie"
	}

	// Check for active probe.
	isActiveProbe := false
	if resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/zimbra/") {
			isActiveProbe = true
			if detectionMethod == "body" {
				detectionMethod = "active_probe"
			}
		}
	}

	version := extractZimbraVersion(body)

	metadata := map[string]any{
		"vendor":           "Zimbra",
		"product":          "Collaboration",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if isActiveProbe {
		metadata["probe_path"] = "/zimbra/"
	}
	if hasCookieSignal {
		metadata["zm_cookies"] = true
	}

	return &FingerprintResult{
		Technology: "zimbra",
		Version:    version,
		CPEs:       []string{buildZimbraCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityHigh,
	}, nil
}

// extractZimbraVersion tries the three version sources in priority order and
// applies two-stage validation before returning. Returns empty string if no
// valid version is found.
func extractZimbraVersion(body []byte) string {
	// Priority 1: zimbraCacheBusterVersion JS variable.
	if m := zimbraCacheBusterVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); zimbraVersionValidateRegex.MatchString(v) {
			return v
		}
	}

	// Priority 2: script src with Zimbra path and ?v= version parameter.
	if m := zimbraScriptVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); zimbraVersionValidateRegex.MatchString(v) {
			return v
		}
	}

	// Priority 3: CLIENT_VERSION pattern.
	if m := zimbraClientVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); zimbraVersionValidateRegex.MatchString(v) {
			return v
		}
	}

	return ""
}

// hasZimbraCookie returns true if any Set-Cookie header value contains
// ZM_TEST or ZM_AUTH_TOKEN (case-insensitive).
func hasZimbraCookie(resp *http.Response) bool {
	for _, cookie := range resp.Header["Set-Cookie"] {
		upper := strings.ToUpper(cookie)
		if strings.Contains(upper, "ZM_TEST") || strings.Contains(upper, "ZM_AUTH_TOKEN") {
			return true
		}
	}
	return false
}

// sanitizeZimbraHeaderValue strips control characters and limits length to
// prevent log injection or oversized metadata values from attacker-controlled headers.
func sanitizeZimbraHeaderValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7F {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if len(result) > 256 {
		result = result[:256]
	}
	return result
}

// buildZimbraCPE constructs a CPE 2.3 string for Zimbra Collaboration Suite.
// When version is empty, a wildcard CPE is emitted.
func buildZimbraCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:zimbra:collaboration:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:zimbra:collaboration:%s:*:*:*:*:*:*:*", version)
}
