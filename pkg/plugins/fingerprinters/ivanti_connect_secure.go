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
Package fingerprinters provides HTTP fingerprinting for Ivanti Connect Secure.

# What We Detect

  - Ivanti Connect Secure (formerly Pulse Secure) VPN login portals via the
    distinctive /dana-na/ URL path prefix, which is unique to this product family.
    The active probe targets /dana-na/auth/url_default/welcome.cgi.

  - Structural HTML markers that appear exclusively on Ivanti/Pulse Secure portals:
    the /dana-na/css/ds CSS path and the frmLogin form structure with login.cgi action.

  - DS-prefixed cookies set in the response (DSID, DSSignInURL, DSBrowserID,
    DSLastAccess, DSSIGNIN, DSPREAUTH). Two or more distinct DS-prefixed cookie names
    in a single response is a strong, standalone signal.

  - Corroborated title branding: "Ivanti" or "Pulse Secure" in the HTML <title> tag
    combined with any /dana-na/ or /dana/ path reference in the body.

  - Realm names from the authentication realm selector, if present in the login form.

  - Product variant is always reported as "Connect Secure" because the /dana-na/
    path structure detected by this fingerprinter is specific to that product.

# What We Do NOT Detect

  - Ivanti Connect Secure instances hidden behind reverse proxies that rewrite all
    /dana-na/ paths and suppress identifying HTML and cookies.

  - Ivanti Policy Secure or Ivanti Neurons for ZTA, which are related products but
    serve different login pages without the /dana-na/ path structure.

  - The version number: it is not exposed on the unauthenticated login portal.
    The CPE uses a wildcard version component.

# Security Context

Ivanti Connect Secure is a high-value VPN appliance target. It has been exploited
actively in the wild, with multiple critical vulnerabilities disclosed:

  - CVE-2023-46805 (authentication bypass, CVSS 8.2) — allows unauthenticated access
    to restricted resources via path traversal in the web component.
  - CVE-2024-21887 (command injection, CVSS 9.1) — allows authenticated administrators
    to inject OS commands via crafted requests. Chained with CVE-2023-46805 for RCE.
  - CVE-2025-22457 (stack-based buffer overflow, CVSS 9.0) — allows unauthenticated
    remote code execution via a malformed HTTP response. Exploited in the wild by
    state-sponsored threat actors before patch availability.

The login page being internet-accessible is the normal operational state for a VPN
appliance, so no severity elevation is applied by this fingerprinter. However, the
presence of an Ivanti Connect Secure portal is significant context for downstream
vulnerability assessment.

# Active Probe Safety

The active probe issues a plain GET /dana-na/auth/url_default/welcome.cgi with
Accept: text/html. This is the standard VPN login page endpoint, publicly accessible
by design. No authentication is required and no write operations are performed.

# CPE

cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// danaCSSRegex matches the distinctive Ivanti/Pulse Secure CSS path in HTML.
// The CSS file appears as /dana-na/css/ds.css or /dana-na/css/ds_<hash>.css.
var danaCSSRegex = regexp.MustCompile(`(?i)/dana-na/css/ds[._]`)

// danaLoginFormRegex matches the Ivanti login form structure.
// Requires both name="frmLogin" AND an action containing login.cgi in the same
// <form> tag to avoid false positives from unrelated forms with similar names.
var danaLoginFormRegex = regexp.MustCompile(`(?i)<form[^>]*(?:name\s*=\s*["']frmLogin["'][^>]*action\s*=\s*["'][^"']*login\.cgi[^"']*["']|action\s*=\s*["'][^"']*login\.cgi[^"']*["'][^>]*name\s*=\s*["']frmLogin["'])[^>]*>`)

// ivantiTitleRegex matches Ivanti or Pulse Secure branding in the HTML title.
var ivantiTitleRegex = regexp.MustCompile(`(?i)<title[^>]*>[^<]*(?:ivanti|pulse\s+secure)[^<]*</title>`)

// danaPathRegex matches any /dana-na/ or /dana/ path reference in HTML.
var danaPathRegex = regexp.MustCompile(`(?i)/dana(?:-na)?/`)

// realmSelectRegex matches the realm <select> element and captures its inner content.
// Only options within this specific select are extracted as realm names.
var realmSelectRegex = regexp.MustCompile(`(?is)<select[^>]*name\s*=\s*["']realm["'][^>]*>(.*?)</select>`)

// realmOptionRegex extracts realm names from <option> elements in the realm select.
var realmOptionRegex = regexp.MustCompile(`(?i)<option[^>]*value\s*=\s*["']([^"']{1,64})["'][^>]*>`)

// IvantiConnectSecureFingerprinter detects Ivanti Connect Secure (formerly Pulse
// Secure) VPN login portals via /dana-na/ structural markers, DS-prefixed session
// cookies, and corroborated title branding.
type IvantiConnectSecureFingerprinter struct{}

func init() {
	Register(&IvantiConnectSecureFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *IvantiConnectSecureFingerprinter) Name() string {
	return "ivanti-connect-secure"
}

// ProbeEndpoint returns the Ivanti Connect Secure VPN login page path.
// This is the standard welcome/login page endpoint, publicly accessible by design.
func (f *IvantiConnectSecureFingerprinter) ProbeEndpoint() string {
	return "/dana-na/auth/url_default/welcome.cgi"
}

// ProbeAccept returns the Accept header for the active probe.
func (f *IvantiConnectSecureFingerprinter) ProbeAccept() string {
	return "text/html"
}

// Match returns true when the response is a candidate for Ivanti Connect Secure detection.
//
// Fast path: any DS-prefixed cookie present in Set-Cookie headers is a strong signal.
//
// Body-scan candidates: text/html responses that may contain login page structure.
//
// Responses below 200 (informational) and 5xx (server error) are rejected.
func (f *IvantiConnectSecureFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// DS-prefixed cookies are a strong signal.
	for _, cookie := range resp.Header["Set-Cookie"] {
		if strings.HasPrefix(strings.ToUpper(strings.TrimSpace(cookie)), "DS") {
			return true
		}
	}

	// HTML content may contain login page or branding.
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection signals:
//  1. Structural HTML markers (standalone): body contains /dana-na/css/ds path or
//     frmLogin form structure — both are unique to Ivanti/Pulse Secure.
//  2. DS-prefixed cookies (standalone when 2+): two or more distinct DS-prefixed
//     cookie names (DSID, DSSignInURL, DSBrowserID, DSLastAccess, DSSIGNIN, DSPREAUTH).
//  3. Corroborated branding: "Ivanti" or "Pulse Secure" in <title> AND any /dana-na/
//     or /dana/ path reference in the body.
//
// At least one of these must fire or nil is returned.
//
// Version is not exposed on the unauthenticated login page; CPE uses wildcard.
//
// Detection method values: "active_probe", "login_page", "response_cookie", "title_branding".
func (f *IvantiConnectSecureFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: 2 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// --- Signal detection ---

	// Signal 1: structural HTML markers unique to Ivanti/Pulse Secure.
	hasLoginPageStructure := danaCSSRegex.Match(body) || danaLoginFormRegex.Match(body)

	// Signal 2: DS-prefixed cookies — require 2+ distinct names to avoid
	// false positives from a single DSID cookie that could appear elsewhere.
	dsCookieNames, hasDSCookies := countDSCookies(resp)

	// Signal 3: corroborated branding — brand in title AND dana path in body.
	hasBranding := ivantiTitleRegex.Match(body) && danaPathRegex.Match(body)

	// At least one signal must fire.
	if !hasLoginPageStructure && !hasDSCookies && !hasBranding {
		return nil, nil
	}

	// --- Active probe detection ---

	isActiveProbe := false
	if resp.Request != nil && resp.Request.URL != nil {
		p := strings.ToLower(resp.Request.URL.Path)
		isActiveProbe = strings.HasPrefix(p, "/dana-na/auth/")
	}

	// --- Detection method ---

	var detectionMethod string
	switch {
	case hasLoginPageStructure && isActiveProbe:
		detectionMethod = "active_probe"
	case hasLoginPageStructure:
		detectionMethod = "login_page"
	case hasDSCookies:
		detectionMethod = "response_cookie"
	default:
		detectionMethod = "title_branding"
	}

	// --- Metadata ---

	metadata := map[string]any{
		"vendor":           "Ivanti",
		"product":          "Connect Secure",
		"detection_method": detectionMethod,
	}

	if isActiveProbe {
		metadata["probe_path"] = "/dana-na/auth/url_default/welcome.cgi"
	}

	if hasDSCookies {
		metadata["ds_cookies"] = dsCookieNames
	}

	// Extract realm names if the body contains a realm selector.
	if realms := extractRealms(body); len(realms) > 0 {
		metadata["realms"] = realms
	}

	// Detect legacy Pulse Secure branding.
	bodyLower := strings.ToLower(string(body))
	if strings.Contains(bodyLower, "pulse secure") || strings.Contains(bodyLower, "pulse connect secure") {
		metadata["legacy_branding"] = "Pulse Secure"
	}

	metadata["product_variant"] = "Connect Secure"

	return &FingerprintResult{
		Technology: "ivanti-connect-secure",
		Version:    "",
		CPEs:       []string{buildIvantiConnectSecureCPE("")},
		Metadata:   metadata,
	}, nil
}

// countDSCookies inspects the Set-Cookie response headers and returns the
// distinct DS-prefixed cookie names found, plus a bool indicating whether
// two or more distinct names were present. A single DS cookie is insufficient
// as a standalone signal; two or more is considered definitive.
func countDSCookies(resp *http.Response) ([]string, bool) {
	seen := make(map[string]struct{})
	for _, raw := range resp.Header["Set-Cookie"] {
		// Cookie name is the portion before the first '=' or ';'.
		name := raw
		if idx := strings.IndexAny(raw, "=;"); idx >= 0 {
			name = raw[:idx]
		}
		name = strings.TrimSpace(name)
		if strings.HasPrefix(strings.ToUpper(name), "DS") && name != "" {
			seen[name] = struct{}{}
		}
	}
	if len(seen) < 2 {
		return nil, false
	}
	names := make([]string, 0, len(seen))
	for n := range seen {
		names = append(names, n)
	}
	return names, true
}

// extractRealms returns realm names from the login form's realm <select> element.
// It first locates the <select> element with name="realm" (or name='realm'), then
// extracts <option> values only from within that element to avoid capturing options
// from unrelated dropdowns (language, timezone, etc.).
// Returns at most 32 realm names, each bounded to 64 characters by the extraction regex.
func extractRealms(body []byte) []string {
	m := realmSelectRegex.FindSubmatch(body)
	if len(m) < 2 {
		return nil
	}
	selectContent := m[1]
	matches := realmOptionRegex.FindAllSubmatch(selectContent, 32)
	if len(matches) == 0 {
		return nil
	}
	realms := make([]string, 0, len(matches))
	for _, match := range matches {
		if len(match) >= 2 {
			v := strings.TrimSpace(string(match[1]))
			if v != "" {
				realms = append(realms, v)
			}
		}
	}
	return realms
}

// buildIvantiConnectSecureCPE constructs a CPE 2.3 string for Ivanti Connect Secure.
// When version is empty, a wildcard CPE is emitted to support asset inventory.
func buildIvantiConnectSecureCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:ivanti:connect_secure:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:ivanti:connect_secure:%s:*:*:*:*:*:*:*", version)
}
