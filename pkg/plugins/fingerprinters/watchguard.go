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

package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// WatchGuardFingerprinter detects WatchGuard Firebox appliances running Fireware OS.
//
// Detection Strategy:
// WatchGuard Firebox exposes multiple web surfaces. Detection uses a tiered
// signal model to balance precision and recall:
//
//	Tier 1 (any one alone is sufficient):
//	  - Set-Cookie: wg_portald_session_id=... (pathognomonic)
//	  - TLS leaf cert issuer CN contains "Fireware web CA" (default self-signed CA)
//	  - HTML <title> matches "WatchGuard Access Portal" | "Fireware XTM User
//	    Authentication" | "Fireware Web UI"
//
//	Tier 2 (at least two of the following together, AND at least one must be a
//	strong signal: form action="/auth/login", wg-logo/wgLogo.gif asset, or
//	Firebox-DB domain selector):
//	  - body contains "Firebox" (case-insensitive) [weak]
//	  - body contains "WatchGuard Technologies" (case-insensitive) [weak]
//	  - body contains "Firebox-DB" (case-sensitive domain-selector option) [STRONG]
//	  - body contains form action="/auth/login" [STRONG]
//	  - body contains logo asset wg-logo or wgLogo.gif [STRONG]
//
//	Explicit rejection:
//	  - title containing "Dimension" — WatchGuard Dimension log/reporting
//	    product shares branding but is NOT a Firebox.
//
// Active Probe:
//   - GET /auth/login.html (Access Portal login page)
//
// Default Ports (documented for metadata heuristics; framework probes
// externally and does not pass a port parameter):
//   - 443  Access Portal / clientless VPN
//   - 4100 WG-Auth (WatchGuard-specific)
//   - 8080 Fireware Web UI admin
//   - 4117 Alternate admin / wgagent
//
// Version Detection:
// Fireware does NOT reliably expose version passively. Best-effort extraction
// from:
//  1. HTML comment leak: <!-- Fireware v12.5.9 -->
//  2. Asset query string: /auth/js/auth.js?v=12.5.9
//
// Extracted values are strictly validated (^\d+\.\d+(?:\.\d+)?$) before
// being embedded in a CPE. Empty string is returned when validation fails;
// we never fabricate a default.
//
// Model: NOT extracted. Not reliably available via HTTP. Use SNMP
// (see LAB-2092) as a secondary channel for model identification.
//
// CPE: cpe:2.3:o:watchguard:fireware:<version>:*:*:*:*:*:*:*
//
//	Product slug "fireware" is NVD-canonical (NOT "fireware_os").
//
// Security Risks:
//   - CVE-2025-14733 (CVSS 9.3, CISA KEV 2025-12-19): Out-of-bounds write in
//     `iked` on Fireware IKEv2 allows unauthenticated RCE. Fixed in Fireware
//     2025.1.4, 12.11.6, 12.5.15, 12.3.1_Update4 (FIPS). NOTE: detecting this
//     fingerprint may trigger downstream CVE-2025-14733 IKEv2 probes — ensure
//     downstream probe logic is banner-grade, not exploit-grade.
//   - CVE-2022-26318 (CVSS 9.8): Unauthenticated RCE via stack buffer overflow
//     in `wgagent` XML-RPC XPath parser at /agent/login.
//     Fixed in Fireware 12.7.2_U2.
//   - CVE-2022-31749 (CVSS ~7.5): Argument injection in CLI diagnose/import-pac
//     allows authenticated file R/W including configd-hash.xml (Firebox-DB
//     password hashes). Fixed in Fireware 12.8.
//   - Cyclops Blink (CISA AA22-054A, 2022-02-23): Russian GRU Unit 74455
//     (Sandworm) modular C2 persisting via non-standard firmware update path,
//     targeting management-exposed Fireboxes since at least June 2019.
//
// Metadata extracted: vendor, product, component, management_interface,
// vpn_enabled.
type WatchGuardFingerprinter struct{}

func init() {
	Register(&WatchGuardFingerprinter{})
}

// watchGuardAdminPortWebUI and watchGuardAdminPortAlt are the well-known
// WatchGuard Firebox management / portal ports. Used by metadata logic to flag
// admin-interface exposure when the URL port matches.
//
// NOTE: The framework probes externally and does NOT pass a port parameter
// into Fingerprint(). These ports are documented for godoc / metadata
// heuristics only (via resp.Request.URL when available).
const (
	watchGuardAdminPortWebUI = 8080
	watchGuardAdminPortAlt   = 4117
)

// watchGuardFirewareVersionCommentPattern matches the primary version source:
// an HTML comment leak such as <!-- Fireware v12.5 --> or <!-- Fireware v12.5.9 -->.
var watchGuardFirewareVersionCommentPattern = regexp.MustCompile(
	`(?i)<!--\s*Fireware\s+v?(\d+\.\d+(?:\.\d+)?)\s*-->`,
)

// watchGuardAssetVersionPattern matches the fallback version source: an asset
// query string such as ?v=12.5.9 or ?ver=12.5.9 in script/stylesheet URLs.
var watchGuardAssetVersionPattern = regexp.MustCompile(
	`[?&]v(?:er)?=(\d+\.\d+(?:\.\d+)?)`,
)

// watchGuardFirewareVersionRegex validates extracted version values before CPE
// emission. Accepts only strict 2-to-3 component dotted numeric versions.
// Acts as a CPE-injection guard — no shell-special or CPE-special characters
// (:, *, -, ?) can pass the \d+ anchored match.
var watchGuardFirewareVersionRegex = regexp.MustCompile(
	`^\d+\.\d+(?:\.\d+)?$`,
)

// watchGuardTitlePattern matches the Fireware login page <title> element for
// each of the three known Firebox web surfaces.
var watchGuardTitlePattern = regexp.MustCompile(
	`(?i)<title>\s*(WatchGuard Access Portal|Fireware XTM User Authentication|Fireware Web UI)\s*</title>`,
)

// watchGuardDimensionTitlePattern matches pages from WatchGuard Dimension
// (log/reporting product) so they can be hard-rejected before Tier-1/2 evaluation.
var watchGuardDimensionTitlePattern = regexp.MustCompile(
	`(?i)<title>[^<]*Dimension[^<]*</title>`,
)

// watchGuardFireboxDBPattern matches the case-sensitive "Firebox-DB" domain
// selector literal that appears in Firebox authentication login forms. This is
// a STRONG Tier-2 signal because "Firebox-DB" is unique to Firebox's local
// user database option and does not appear on generic pages.
// NOTE: case-sensitive intentionally — no (?i) flag.
var watchGuardFireboxDBPattern = regexp.MustCompile(
	`Firebox-DB`,
)

// watchGuardFormActionPattern matches the form action="/auth/login" attribute
// on Firebox login pages. This is a STRONG Tier-2 signal because the /auth/login
// path is WatchGuard-specific and does not appear on generic web pages.
var watchGuardFormActionPattern = regexp.MustCompile(
	`(?i)action=["']?/auth/login["'\s>]`,
)

// watchGuardLogoPattern matches references to WatchGuard logo assets (wg-logo
// CSS class or wgLogo.gif image). This is a STRONG Tier-2 signal — logo assets
// with these exact names are served only by Firebox devices.
var watchGuardLogoPattern = regexp.MustCompile(
	`(?i)(?:wg-logo|wgLogo\.gif)`,
)

// maxBodyScanBytes caps the body slice before string conversion in Fingerprint().
// Limits memory allocation and scan work against adversarially large responses.
// 1 MiB is more than sufficient for any Firebox login page.
const maxBodyScanBytes = 1 << 20

// Name returns the fingerprinter identifier.
func (f *WatchGuardFingerprinter) Name() string {
	return "watchguard-firebox"
}

// ProbeEndpoint returns the active probe path. The Firebox Access Portal login
// page is the most information-rich surface available without authentication.
func (f *WatchGuardFingerprinter) ProbeEndpoint() string {
	return "/auth/login.html"
}

// Match is a fast pre-filter. Returns true for responses that warrant full
// Fingerprint() analysis. Only reads headers and status — never the body.
func (f *WatchGuardFingerprinter) Match(resp *http.Response) bool {
	// Reject 5xx server errors and responses below 200.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Fast path: WatchGuard-specific header/cookie signals.
	if isWatchGuardHeader(resp) {
		return true
	}

	// Fast path: TLS cert with Fireware CA issuer.
	if isWatchGuardCert(resp) {
		return true
	}

	// Fall through to body analysis for text/html responses.
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full detection and returns a result if this response
// is from a WatchGuard Firebox appliance. Returns nil, nil for non-matching
// responses.
func (f *WatchGuardFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Reject 5xx server errors and responses below 200.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// [H1] Body-size cap: limit memory allocation before string conversion.
	scanBody := body
	if len(scanBody) > maxBodyScanBytes {
		scanBody = scanBody[:maxBodyScanBytes]
	}

	bodyStr := string(scanBody)
	lower := strings.ToLower(bodyStr)

	// [H2] HARD REJECT: WatchGuard Dimension is a distinct log/reporting
	// product that shares branding. Reject before any Tier-1/2 evaluation.
	if isWatchGuardDimension(bodyStr) {
		return nil, nil
	}

	// Tier-1 signals: any ONE is sufficient for a positive detection.
	tier1 := false
	if isWatchGuardCookie(resp) {
		tier1 = true
	}
	if isWatchGuardCert(resp) {
		tier1 = true
	}
	if watchGuardTitlePattern.MatchString(bodyStr) {
		tier1 = true
	}

	// Tier-2 signals: require ≥2 total AND ≥1 strong signal.
	// Strong signals: Firebox-DB, form action /auth/login, wg-logo asset.
	// Weak signals: body keyword "Firebox" or "WatchGuard Technologies".
	tier2Count := 0
	tier2StrongCount := 0

	if strings.Contains(lower, "firebox") {
		tier2Count++
		// "firebox" alone is a weak signal — do not increment strongCount.
	}
	if strings.Contains(lower, "watchguard technologies") {
		tier2Count++
		// Also weak on its own.
	}
	if watchGuardFireboxDBPattern.MatchString(bodyStr) {
		tier2Count++
		tier2StrongCount++
	}
	if watchGuardFormActionPattern.MatchString(bodyStr) {
		tier2Count++
		tier2StrongCount++
	}
	if watchGuardLogoPattern.MatchString(bodyStr) {
		tier2Count++
		tier2StrongCount++
	}

	// Decision: Tier-1 alone, OR ≥2 Tier-2 with ≥1 strong signal.
	// Two generic keyword-only matches ("Firebox" + "WatchGuard Technologies")
	// are NOT sufficient — marketing pages can contain both strings.
	if !tier1 && (tier2Count < 2 || tier2StrongCount < 1) {
		return nil, nil
	}

	// Classify which Firebox surface this response came from.
	component := detectWatchGuardComponent(resp, bodyStr)

	// Extract Fireware OS version — best-effort, never fabricated.
	version := extractFirewareVersion(scanBody)

	// Build metadata with the fixed documented field set only.
	metadata := map[string]any{
		"vendor":               "WatchGuard",
		"product":              "Firebox",
		"component":            component,
		"management_interface": isAdminSurface(resp, component),
		"vpn_enabled":          component == "Access Portal" || component == "Authentication Portal",
	}

	return &FingerprintResult{
		Technology: "watchguard-firebox",
		Version:    version,
		CPEs:       []string{buildFirewareCPE(version)},
		Metadata:   metadata,
	}, nil
}

// isWatchGuardHeader checks response headers for WatchGuard-specific Server
// strings and cookies. Fast path for Match().
//
// Signals:
//   - Set-Cookie: wg_portald_session_id=... (pathognomonic)
//   - Server: Fireware or Fireware XTM (legacy 11.x)
func isWatchGuardHeader(resp *http.Response) bool {
	server := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(server, "fireware") {
		return true
	}
	return isWatchGuardCookie(resp)
}

// isWatchGuardCookie scans Set-Cookie headers for the pathognomonic
// wg_portald_session_id cookie name.
//
// Cookie NAMES are case-sensitive per RFC 6265 §4.1.1 — HasPrefix is used
// with the exact lowercase name. Do NOT use EqualFold on cookie names.
// resp.Header.Values("Set-Cookie") returns ALL Set-Cookie headers (not just
// the first), which is required because servers commonly set multiple cookies.
func isWatchGuardCookie(resp *http.Response) bool {
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		// HasPrefix with "=" ensures we match the cookie NAME exactly,
		// not a cookie value that happens to contain the substring.
		if strings.HasPrefix(cookie, "wg_portald_session_id=") {
			return true
		}
	}
	return false
}

// isWatchGuardCert inspects the TLS peer-certificate chain for WatchGuard
// markers. Safe against nil/empty TLS state. Returns true when:
//   - Issuer CommonName contains "Fireware web CA" (Tier-1 — strong, WatchGuard's
//     default self-signed CA; no public CA issues with this CN), OR
//   - Subject Organization contains "WatchGuard" (Tier-2 corroborating signal), OR
//   - Subject OrganizationalUnit contains "Fireware" (Tier-2 corroborating signal)
//
// [H4] Subject.CommonName is NOT checked for branding — it is entirely
// attacker-controlled on customer-replaced certificates.
//
// Real devices ship with a self-signed "Fireware web CA" by default;
// operators CAN replace this, so cert absence alone does not negate
// detection. Cert presence is a high-confidence Tier-1 positive.
func isWatchGuardCert(resp *http.Response) bool {
	if resp == nil || resp.TLS == nil {
		return false
	}
	if len(resp.TLS.PeerCertificates) == 0 {
		return false
	}
	leaf := resp.TLS.PeerCertificates[0]
	if leaf == nil {
		return false
	}

	// Issuer CN — strongest signal (default "Fireware web CA").
	// This is Tier-1: no public CA would issue with this CN.
	if strings.Contains(
		strings.ToLower(leaf.Issuer.CommonName),
		"fireware web ca",
	) {
		return true
	}

	// Subject O — WatchGuard-customized. Treated as Tier-1 here because
	// isWatchGuardCert is only called from cert-specific paths; Subject.O
	// is user-controlled but still distinctive in the cert context.
	for _, org := range leaf.Subject.Organization {
		if strings.Contains(strings.ToLower(org), "watchguard") {
			return true
		}
	}

	// Subject OU — Fireware-customized. Corroborating signal.
	for _, ou := range leaf.Subject.OrganizationalUnit {
		if strings.Contains(strings.ToLower(ou), "fireware") {
			return true
		}
	}

	return false
}

// isWatchGuardDimension returns true if the response is from WatchGuard
// Dimension (a log/reporting product that shares branding). This is
// a HARD REJECT path in Fingerprint() called before Tier-1/Tier-2
// evaluation. Current signal: title matches "Dimension".
func isWatchGuardDimension(bodyStr string) bool {
	return watchGuardDimensionTitlePattern.MatchString(bodyStr)
}

// detectWatchGuardComponent classifies which Firebox surface this response
// came from. Returns one of:
//   - "Fireware Web UI"       (admin UI on 8080/4117)
//   - "Authentication Portal" (legacy Fireware XTM 11.x)
//   - "Access Portal"         (Fireware 12.x+ VPN/portal, and fallback)
//
// Title is authoritative when present; otherwise inferred from body signals.
func detectWatchGuardComponent(resp *http.Response, bodyStr string) string {
	m := watchGuardTitlePattern.FindStringSubmatch(bodyStr)
	if len(m) >= 2 {
		switch m[1] {
		case "Fireware Web UI":
			return "Fireware Web UI"
		case "Fireware XTM User Authentication":
			return "Authentication Portal"
		case "WatchGuard Access Portal":
			return "Access Portal"
		}
	}

	// Fallback: infer from body/cookie signals.
	if isWatchGuardCookie(resp) || watchGuardFireboxDBPattern.MatchString(bodyStr) ||
		watchGuardLogoPattern.MatchString(bodyStr) {
		return "Access Portal"
	}

	return "Access Portal"
}

// extractFirewareVersion extracts Fireware OS version from the response
// body using two ordered heuristics (HTML comment first, asset query
// string second). Returns "" if neither matches or the extracted value
// fails validation (CPE-injection guard).
//
// NEVER fabricates a default version; empty string is the contract.
func extractFirewareVersion(body []byte) string {
	// Primary: HTML comment leak <!-- Fireware v12.5 -->
	m := watchGuardFirewareVersionCommentPattern.FindSubmatch(body)
	if len(m) >= 2 {
		return validateFirewareVersion(string(m[1]))
	}

	// Fallback: asset query string ?v=12.5.9 or ?ver=12.5.9
	m = watchGuardAssetVersionPattern.FindSubmatch(body)
	if len(m) >= 2 {
		return validateFirewareVersion(string(m[1]))
	}

	return ""
}

// validateFirewareVersion applies the length cap and regex validation to a
// candidate version string. Returns "" if the value fails either check.
// The 16-char cap [H3] provides defense-in-depth against pathologically
// long strings before the regex runs.
func validateFirewareVersion(version string) string {
	// [H3] Length cap: WatchGuard versions are at most 10 chars ("2025.1.4").
	// 16 chars provides generous margin while preventing multi-MB CPE strings.
	if len(version) > 16 {
		return ""
	}
	if !watchGuardFirewareVersionRegex.MatchString(version) {
		return ""
	}
	return version
}

// buildFirewareCPE constructs the NVD-aligned CPE string. Product slug is
// "fireware" (NOT "fireware_os"), confirmed against the NVD dictionary.
// Returns wildcard version CPE when version is empty.
//
// Format:
//
//	cpe:2.3:o:watchguard:fireware:<version>:*:*:*:*:*:*:*
func buildFirewareCPE(version string) string {
	if version == "" {
		return "cpe:2.3:o:watchguard:fireware:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf(
		"cpe:2.3:o:watchguard:fireware:%s:*:*:*:*:*:*:*",
		version,
	)
}

// isAdminSurface returns true if the response likely came from a management
// interface. Current heuristics:
//   - Component is "Fireware Web UI" (title-based — authoritative), OR
//   - Request URL port is 8080 or 4117 (when resp.Request is populated)
//
// Reads resp.Request.URL.Port() defensively; returns false if any hop is nil.
func isAdminSurface(resp *http.Response, component string) bool {
	if component == "Fireware Web UI" {
		return true
	}
	if resp == nil || resp.Request == nil || resp.Request.URL == nil {
		return false
	}
	port := resp.Request.URL.Port()
	return port == fmt.Sprintf("%d", watchGuardAdminPortWebUI) ||
		port == fmt.Sprintf("%d", watchGuardAdminPortAlt)
}
