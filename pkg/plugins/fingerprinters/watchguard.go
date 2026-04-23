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
	"crypto/x509"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// WatchGuardFingerprinter detects WatchGuard Firebox appliances running Fireware OS.
//
// Detection Strategy:
// Tiered signal model:
//
//	Tier 1 (any one alone is sufficient):
//	  - Set-Cookie: wg_portald_session_id=... (pathognomonic)
//	  - TLS leaf cert Issuer.CN contains "Fireware web CA" (default self-signed CA)
//	  - HTML <title> matches "WatchGuard Access Portal" | "Fireware XTM User
//	    Authentication" | "Fireware Web UI"
//
//	Tier 2 (≥2 total AND ≥1 strong):
//	  - body "Firebox" (weak) / "WatchGuard Technologies" (weak)
//	  - body "Firebox-DB" selector [STRONG] / form action="/auth/login" [STRONG]
//	  - wg-logo or wgLogo.gif asset [STRONG]
//	  - TLS leaf cert Subject.O/OU [STRONG — cert-level, but operator-controlled]
//
//	[H4] Only Issuer.CN is Tier-1; Subject.O/OU are operator-controlled on
//	customer-replaced certs and are capped at Tier-2 strong to prevent spoofing.
//
//	Explicit rejection: title containing "Dimension" (WatchGuard log/reporting
//	product — shares branding, is NOT a Firebox).
//
// Active Probe: GET /auth/login.html (Access Portal login; most signal-rich surface).
//
// Version Detection: HTML comment <!-- Fireware v12.5.9 --> first; fallback to
// asset query string ?v=12.5.9. Validated as ^\d+\.\d+(?:\.\d+)?$ before CPE
// embedding; empty string returned when absent — never fabricated.
//
// CPE: cpe:2.3:o:watchguard:fireware:<version>:*:*:*:*:*:*:*
// ("fireware" is NVD-canonical, not "fireware_os")
//
// Security Risks:
//   - CVE-2025-14733 (CVSS 9.3, CISA KEV 2025-12-19): OOB write in iked
//     (IKEv2) → unauthenticated RCE. Fixed in 2025.1.4, 12.11.6, 12.5.15.
//   - CVE-2022-26318 (CVSS 9.8): Unauthenticated RCE via stack overflow in
//     wgagent XML-RPC at /agent/login. Fixed in 12.7.2_U2.
//   - CVE-2022-31749 (CVSS ~7.5): CLI argument injection → config file R/W.
//     Fixed in 12.8.
//   - Cyclops Blink (CISA AA22-054A): GRU/Sandworm C2 via management-exposed
//     Fireboxes since ≥2019.
//
// Metadata: vendor, product, component, management_interface, vpn_enabled.
type WatchGuardFingerprinter struct{}

func init() {
	Register(&WatchGuardFingerprinter{})
}

// watchGuardFirewareVersionCommentPattern matches HTML comment version leaks:
// <!-- Fireware v12.5 --> or <!-- Fireware v12.5.9 -->
var watchGuardFirewareVersionCommentPattern = regexp.MustCompile(
	`(?i)<!--\s*Fireware\s+v?(\d+\.\d+(?:\.\d+)?)\s*-->`,
)

// watchGuardAssetVersionPattern matches fallback version source: ?v=12.5.9 or ?ver=12.5.9
var watchGuardAssetVersionPattern = regexp.MustCompile(
	`[?&]v(?:er)?=(\d+\.\d+(?:\.\d+)?)`,
)

// watchGuardFirewareVersionRegex validates candidate versions before CPE emission.
// Acts as a CPE-injection guard — anchored \d+ rejects shell/CPE-special characters.
var watchGuardFirewareVersionRegex = regexp.MustCompile(
	`^\d+\.\d+(?:\.\d+)?$`,
)

// watchGuardTitlePattern matches the three known Firebox web surface titles.
var watchGuardTitlePattern = regexp.MustCompile(
	`(?i)<title>\s*(WatchGuard Access Portal|Fireware XTM User Authentication|Fireware Web UI)\s*</title>`,
)

// watchGuardDimensionTitlePattern matches WatchGuard Dimension (log/reporting product)
// for hard rejection before Tier-1/2 evaluation.
var watchGuardDimensionTitlePattern = regexp.MustCompile(
	`(?i)<title>[^<]*Dimension[^<]*</title>`,
)

// watchGuardFireboxDBPattern matches the case-sensitive "Firebox-DB" domain selector
// literal. STRONG Tier-2 signal — unique to Firebox local user database option.
// NOTE: no (?i) flag; case-sensitive intentionally.
var watchGuardFireboxDBPattern = regexp.MustCompile(
	`Firebox-DB`,
)

// watchGuardFormActionPattern matches form action="/auth/login". STRONG Tier-2 signal.
var watchGuardFormActionPattern = regexp.MustCompile(
	`(?i)action=["']?/auth/login["'\s>]`,
)

// watchGuardLogoPattern matches WatchGuard logo assets. STRONG Tier-2 signal.
var watchGuardLogoPattern = regexp.MustCompile(
	`(?i)(?:wg-logo|wgLogo\.gif)`,
)

// maxBodyScanBytes caps the body slice before scanning. 1 MiB is more than
// sufficient for any Firebox login page; guards against adversarially large responses.
const maxBodyScanBytes = 1 << 20

// Name returns the fingerprinter identifier.
func (f *WatchGuardFingerprinter) Name() string {
	return "watchguard-firebox"
}

// ProbeEndpoint returns the active probe path.
func (f *WatchGuardFingerprinter) ProbeEndpoint() string {
	return "/auth/login.html"
}

// Match is a fast pre-filter. Returns true for responses that warrant full
// Fingerprint() analysis. Only reads headers and status — never the body.
func (f *WatchGuardFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	if isWatchGuardHeader(resp) {
		return true
	}
	if f.isWatchGuardCertIssuer(resp) {
		return true
	}
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		return true
	}
	return false
}

// Fingerprint performs full detection and returns a result if this response
// is from a WatchGuard Firebox appliance. Returns nil, nil for non-matching responses.
func (f *WatchGuardFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
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

	// [H2] HARD REJECT: Dimension is a distinct log/reporting product.
	if watchGuardDimensionTitlePattern.MatchString(bodyStr) {
		return nil, nil
	}

	// Tier-1: any one is sufficient.
	tier1 := isWatchGuardCookie(resp) || f.isWatchGuardCertIssuer(resp) || watchGuardTitlePattern.MatchString(bodyStr)

	// Tier-2: ≥2 total AND ≥1 strong.
	// [H4] Subject.O/OU are operator-controlled; they contribute as Tier-2 strong
	// (cert-level match is more specific than a body keyword) but are NOT Tier-1.
	tier2Count, tier2StrongCount := 0, 0
	if strings.Contains(lower, "firebox") {
		tier2Count++ // weak
	}
	if strings.Contains(lower, "watchguard technologies") {
		tier2Count++ // weak
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
	if f.isWatchGuardCertSubject(resp) {
		tier2Count++
		tier2StrongCount++
	}

	// Two generic keyword-only matches are NOT sufficient — marketing pages can
	// contain both strings.
	if !tier1 && (tier2Count < 2 || tier2StrongCount < 1) {
		return nil, nil
	}

	component := detectWatchGuardComponent(resp, bodyStr)
	version := extractFirewareVersion(scanBody)

	// Inline admin-surface check: Fireware Web UI title is authoritative;
	// ports 8080 and 4117 are the documented WatchGuard management ports.
	isAdmin := component == "Fireware Web UI"
	if !isAdmin && resp != nil && resp.Request != nil && resp.Request.URL != nil {
		port := resp.Request.URL.Port()
		isAdmin = port == "8080" || port == "4117"
	}

	metadata := map[string]any{
		"vendor":               "WatchGuard",
		"product":              "Firebox",
		"component":            component,
		"management_interface": isAdmin,
		"vpn_enabled":          component == "Access Portal" || component == "Authentication Portal",
	}

	return &FingerprintResult{
		Technology: "watchguard-firebox",
		Version:    version,
		CPEs:       []string{buildFirewareCPE(version)},
		Metadata:   metadata,
	}, nil
}

// isWatchGuardHeader checks response headers for WatchGuard-specific Server strings
// and the pathognomonic wg_portald_session_id cookie. Fast path for Match().
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
// Cookie names are case-sensitive per RFC 6265 §4.1.1. resp.Header.Values returns
// ALL Set-Cookie headers, which is required because servers commonly set multiple.
func isWatchGuardCookie(resp *http.Response) bool {
	for _, cookie := range resp.Header.Values("Set-Cookie") {
		// HasPrefix with "=" matches the cookie NAME exactly, not a value substring.
		if strings.HasPrefix(cookie, "wg_portald_session_id=") {
			return true
		}
	}
	return false
}

// getWatchGuardLeafCert returns the leaf certificate from resp.TLS, applying
// a 4-layer nil guard. Returns nil if any layer is absent.
func getWatchGuardLeafCert(resp *http.Response) *x509.Certificate {
	if resp == nil || resp.TLS == nil {
		return nil
	}
	if len(resp.TLS.PeerCertificates) == 0 {
		return nil
	}
	return resp.TLS.PeerCertificates[0]
}

// isWatchGuardCertIssuer returns true iff the leaf cert's Issuer.CommonName
// contains "Fireware web CA" — WatchGuard's self-signed default CA.
//
// Tier-1 signal: no public CA would issue with that exact CN. A customer-replaced
// cert carries a public CA issuer that is NOT "Fireware web CA", so absence is
// not diagnostic, but presence is near-conclusive.
//
// [H4] Subject.CN is NOT checked — entirely attacker-controlled on replaced certs.
func (f *WatchGuardFingerprinter) isWatchGuardCertIssuer(resp *http.Response) bool {
	leaf := getWatchGuardLeafCert(resp)
	if leaf == nil {
		return false
	}
	return strings.Contains(
		strings.ToLower(leaf.Issuer.CommonName),
		"fireware web ca",
	)
}

// isWatchGuardCertSubject returns true iff Subject.Organization contains
// "WatchGuard" or Subject.OrganizationalUnit contains "Fireware".
//
// These fields are operator-controlled on customer-replaced certs — Tier-2
// STRONG corroborating signal only. A malicious operator can craft Subject fields;
// the ≥2/≥1-strong gate prevents false-positive classification from spoofing alone.
func (f *WatchGuardFingerprinter) isWatchGuardCertSubject(resp *http.Response) bool {
	leaf := getWatchGuardLeafCert(resp)
	if leaf == nil {
		return false
	}
	for _, org := range leaf.Subject.Organization {
		if strings.Contains(strings.ToLower(org), "watchguard") {
			return true
		}
	}
	for _, ou := range leaf.Subject.OrganizationalUnit {
		if strings.Contains(strings.ToLower(ou), "fireware") {
			return true
		}
	}
	return false
}

// detectWatchGuardComponent classifies the Firebox surface. Returns one of:
// "Fireware Web UI", "Authentication Portal", or "Access Portal" (default).
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
	return "Access Portal"
}

// extractFirewareVersion extracts Fireware OS version from the response body.
// Tries HTML comment first, then asset query string. Returns "" if neither
// matches or validation fails — never fabricates a default.
func extractFirewareVersion(body []byte) string {
	m := watchGuardFirewareVersionCommentPattern.FindSubmatch(body)
	if len(m) >= 2 {
		return validateFirewareVersion(string(m[1]))
	}
	m = watchGuardAssetVersionPattern.FindSubmatch(body)
	if len(m) >= 2 {
		return validateFirewareVersion(string(m[1]))
	}
	return ""
}

// validateFirewareVersion applies a length cap and regex validation.
// Returns "" if either check fails.
// [H3] 16-char cap provides defense-in-depth before the regex runs
// (WatchGuard versions are at most 10 chars, e.g. "2025.1.4").
func validateFirewareVersion(version string) string {
	if len(version) > 16 {
		return ""
	}
	if !watchGuardFirewareVersionRegex.MatchString(version) {
		return ""
	}
	return version
}

// buildFirewareCPE constructs the NVD-aligned CPE string.
// Product slug is "fireware" (NOT "fireware_os"), confirmed against the NVD dictionary.
func buildFirewareCPE(version string) string {
	if version == "" {
		return "cpe:2.3:o:watchguard:fireware:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf(
		"cpe:2.3:o:watchguard:fireware:%s:*:*:*:*:*:*:*",
		version,
	)
}
