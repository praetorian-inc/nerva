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
Package fingerprinters provides HTTP fingerprinting for Progress MOVEit Transfer.
Also detects MOVEit Transfer SFTP from the SSH version-exchange banner
(`SSH-2.0-MOVEit Transfer SFTP`) via FingerprintMOVEitSSHBanner — used by the
SSH service plugin to enrich port-22 results with the same MOVEit CPE.

# What We Detect

MOVEit Transfer (formerly Ipswitch MOVEit, now Progress MOVEit) is an enterprise
managed file transfer (MFT) product. This fingerprinter targets the HTTP/HTTPS
web interface.

# Detection Strategy

Primary signal (DMZCookieTest cookie, checked first):
  - Cookie name "DMZCookieTest" with value containing "ifyoucanreadthisyourbrowsersupportscookies"
    — this string is unique to MOVEit Transfer and matches 13,000+ Shodan results (§3.3).
    When matched, detection_method is "dmz_cookie". No body markers required.

Secondary signals (body markers, require ≥1 to match):
  - "stylesheet_moveit", "moveit.transfer", "moveitpopup", "moveitdmz_form",
    "moveit transfer sign on" — all checked case-insensitively.

siLock cookie prefix (§3.7):
  - Cookies with names starting "siLock" (e.g. siLockCSRFToken, siLockLongTermInstID)
    are a heritage MOVEit identifier. Present in metadata as silock_cookie_present=true
    when found. Alone (without DMZCookieTest or body markers) a siLock cookie is
    insufficient for detection.

# Active Probe

ProbeEndpoint() returns "/human.aspx". This is a plain GET request with no
query string or body. CVE-2023-34362 exploitation required POST with SQL
injection parameters — our GET is benign on all axes.

# Version Extraction (passive, major-only)

Version is inferred from the documentation year in links of the form:
  docs.ipswitch.com/MOVEit/Transfer<YEAR>/Help/

Year-to-major-version mapping (corrected per research §3.9):

| Doc URL Year | Internal Major Version |
|-------------|----------------------|
| 2019        | 11                   |
| 2020        | 12                   |
| 2021        | 13                   |
| 2022        | 14                   |
| 2023        | 15                   |
| 2024        | 16                   |

Minor/patch extraction is intentionally NOT implemented. Determining minor/patch
would require an active POST to /MOVEitisapi/MOVEitisapi.dll?action=capa, which
is out of scope for this ticket and would increase active probe surface area.

Validated as ^[0-9]{1,2}$ (major only, 1-2 digits).

# CPE

cpe:2.3:a:progress:moveit_transfer:<version>:*:*:*:*:*:*:*

# CVE Context

  - CVE-2024-5806 (CVSS 9.1): Authentication bypass in SFTP module. Allows
    unauthenticated users to impersonate any user. Do NOT probe SFTP endpoints.
  - CVE-2023-34362 (Cl0p MOVEit mass-exploitation SQLi): Unauthenticated SQL
    injection in /human.aspx POST handler. Historical context only — our probe
    is a GET request only and does NOT replicate the exploit POST parameters.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// MOVEitFingerprinter detects Progress MOVEit Transfer MFT instances.
type MOVEitFingerprinter struct{}

// moveitDocYearRegex extracts the documentation year from the body.
// Example: "docs.ipswitch.com/MOVEit/Transfer2023/Help/" → "2023"
var moveitDocYearRegex = regexp.MustCompile(
	`docs\.ipswitch\.com/MOVEit/Transfer([0-9]{4})/Help/`,
)

// moveitVersionValidateRegex validates major-only version strings (1–2 digits).
var moveitVersionValidateRegex = regexp.MustCompile(
	`^[0-9]{1,2}$`,
)

// moveitDocYearToMajorVersion maps documentation link years to product major versions.
// Source: MOVEit release history and NVD CPE records (research §3.9).
// 2021 maps to 13 (not 12) and 2024 maps to 16 (not 15) — corrected from initial
// implementation which had both values wrong.
// Minor/patch extraction is intentionally NOT implemented — see package doc.
var moveitDocYearToMajorVersion = map[string]string{
	"2019": "11",
	"2020": "12",
	"2021": "13",
	"2022": "14",
	"2023": "15",
	"2024": "16",
}

// moveitBodyMarkers lists the case-folded body signals for MOVEit Transfer.
// Any one is sufficient for detection (when DMZCookieTest is absent).
var moveitBodyMarkers = []string{
	"stylesheet_moveit",
	"moveit.transfer",
	"moveitpopup",
	"moveitdmz_form",
	"moveit transfer sign on",
}

func init() {
	Register(&MOVEitFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *MOVEitFingerprinter) Name() string {
	return "moveit"
}

// ProbeEndpoint returns "/human.aspx" — the documented unauthenticated login page.
// This is a safe plain GET that does not approach the CVE-2023-34362 exploit surface
// (which required POST with SQL injection parameters).
func (f *MOVEitFingerprinter) ProbeEndpoint() string {
	return "/human.aspx"
}

// Match returns true when the response status is in the 200–499 range (inclusive).
// 5xx responses are rejected as they provide no usable fingerprint data.
func (f *MOVEitFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return true
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection priority:
//  1. DMZCookieTest cookie with value "ifyoucanreadthisyourbrowsersupportscookies" — alone sufficient.
//  2. At least one body marker — alone sufficient.
//
// siLock-prefixed cookies are noted in metadata when found.
func (f *MOVEitFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: internal 2 MiB body cap.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Gate 3: CPE-injection defense (fail-closed).
	// The version validator below is anchored to digits-and-dots, so no
	// untrusted byte can reach the CPE format string today. This body-level
	// check is a belt-and-braces guard against future regressions in the
	// version extractors. Trade-off: an operator who controls the response
	// body can suppress detection by embedding ":*:" (e.g. in an HTML
	// comment); we accept that false-negative as preferable to a CPE-format
	// injection regression.
	if strings.Contains(string(body), ":*:") {
		return nil, nil
	}

	cookies := resp.Cookies()
	hasDMZCookie := moveitHasDMZCookieTest(cookies)
	hasSiLock := moveitHasSiLockCookie(cookies)

	bodyLower := strings.ToLower(string(body))
	hasBodyMarker := moveitHasBodyMarker(bodyLower)

	// Neither primary cookie nor body markers found — no detection.
	if !hasDMZCookie && !hasBodyMarker {
		// siLock alone is insufficient without DMZCookieTest or body markers.
		return nil, nil
	}

	// Determine detection method and probe path.
	detectionMethod := "body"
	probePath := ""
	if resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/human.aspx") {
			probePath = "/human.aspx"
			detectionMethod = "active_probe"
		}
	}
	if hasDMZCookie {
		// DMZCookieTest is the strongest signal and overrides everything except
		// active_probe is still set below when applicable.
		detectionMethod = "dmz_cookie"
		// When probing via active probe AND DMZCookieTest is present, the active
		// probe is what triggered the response, but the cookie is the signal.
		// Per the brief, active_probe takes priority for detection_method, but
		// dmz_cookie_present should still be tracked.
		if probePath != "" {
			detectionMethod = "active_probe"
		}
	}

	// Extract version from documentation year link.
	version, docYear := extractMOVEitVersion(body)

	metadata := map[string]any{
		"vendor":           "Progress",
		"product":          "MOVEit Transfer",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if probePath != "" {
		metadata["probe_path"] = probePath
	}
	if docYear != "" {
		metadata["doc_year"] = docYear
	}
	if hasDMZCookie {
		metadata["dmz_cookie_present"] = true
	}
	if hasSiLock {
		metadata["silock_cookie_present"] = true
	}

	return &FingerprintResult{
		Technology: "moveit",
		Version:    version,
		CPEs:       []string{buildMOVEitCPE(version)},
		Metadata:   metadata,
	}, nil
}

// moveitHasDMZCookieTest returns true when a cookie named "DMZCookieTest" is present
// with a value containing "ifyoucanreadthisyourbrowsersupportscookies".
// This is the strongest and most unique MOVEit signal (§3.3).
func moveitHasDMZCookieTest(cookies []*http.Cookie) bool {
	for _, c := range cookies {
		if c.Name == "DMZCookieTest" &&
			strings.Contains(c.Value, "ifyoucanreadthisyourbrowsersupportscookies") {
			return true
		}
	}
	return false
}

// moveitHasSiLockCookie returns true when any cookie has a name starting with "siLock".
// The siLock prefix is a heritage MOVEit identifier from the Ipswitch era (§3.7).
func moveitHasSiLockCookie(cookies []*http.Cookie) bool {
	for _, c := range cookies {
		if strings.HasPrefix(c.Name, "siLock") {
			return true
		}
	}
	return false
}

// moveitHasBodyMarker returns true if the lowercased body contains at least one
// of the pathognomonic MOVEit Transfer body markers.
func moveitHasBodyMarker(bodyLower string) bool {
	for _, marker := range moveitBodyMarkers {
		if strings.Contains(bodyLower, marker) {
			return true
		}
	}
	return false
}

// extractMOVEitVersion extracts the major version and documentation year from the body.
// Returns ("", "") if no documentation year link is found or the year is not in the
// known mapping. Minor/patch extraction is intentionally NOT implemented.
func extractMOVEitVersion(body []byte) (version, docYear string) {
	m := moveitDocYearRegex.FindSubmatch(body)
	if len(m) < 2 {
		return "", ""
	}
	year := string(m[1])
	major, ok := moveitDocYearToMajorVersion[year]
	if !ok {
		return "", year
	}
	if !moveitVersionValidateRegex.MatchString(major) {
		return "", year
	}
	return major, year
}

// moveitSSHBannerRegex matches the MOVEit Transfer SFTP version-string banner
// per RFC 4253 §4.2 ("SSH-protoversion-softwareversion").
//
// Real example: "SSH-2.0-MOVEit Transfer SFTP\r\n"
// Captured group 1 is the SSH protocol version (e.g. "2.0") — NOT the MOVEit
// product version. Product version cannot be derived from this banner; obtain
// it via /MOVEitisapi/MOVEitisapi.dll?action=capa (out of scope for nerva).
//
// nmap-service-probes carries the same matcher form. Trailing CR/LF tolerated;
// anchored to prevent partial-line spoofing inside multi-line server banners.
var moveitSSHBannerRegex = regexp.MustCompile(
	`^SSH-([0-9]+\.[0-9]+)-MOVEit Transfer SFTP\s*$`,
)

// FingerprintMOVEitSSHBanner detects Progress MOVEit Transfer SFTP from a
// connection banner. Returns nil for non-matching banners so callers can
// distinguish "not MOVEit" from a hard error.
//
// The function only inspects the version-exchange line and does not perform
// any active probing. It is safe to call on any SSH banner; the regex anchor
// rejects partial matches.
func FingerprintMOVEitSSHBanner(banner string) *FingerprintResult {
	trimmed := strings.TrimRight(banner, "\r\n")
	if len(trimmed) > 256 {
		// SSH version-exchange lines are bounded at 255 bytes per RFC 4253 §4.2.
		// Reject obviously oversized inputs.
		return nil
	}
	m := moveitSSHBannerRegex.FindStringSubmatch(trimmed)
	if m == nil {
		return nil
	}
	return &FingerprintResult{
		Technology: "moveit",
		Version:    "",
		CPEs:       []string{buildMOVEitCPE("")},
		Metadata: map[string]any{
			"vendor":               "Progress",
			"product":              "MOVEit Transfer SFTP",
			"detection_method":     "ssh_banner",
			"ssh_protocol_version": m[1],
			"banner":               sanitizeHTTPHeaderValue(trimmed),
		},
	}
}

// buildMOVEitCPE constructs the NVD-canonical CPE 2.3 string for MOVEit Transfer.
// NVD vendor: progress, product: moveit_transfer.
// When version is empty, a wildcard CPE is emitted.
func buildMOVEitCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:progress:moveit_transfer:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:progress:moveit_transfer:%s:*:*:*:*:*:*:*", version)
}
