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
Package fingerprinters provides HTTP fingerprinting for Fortra GoAnywhere MFT
(Managed File Transfer).

# What We Detect

  - GoAnywhere MFT: enterprise managed file transfer software by Fortra
    (formerly HelpSystems/Linoma Software). The admin web interface is typically
    served on ports 8000 and 8001 under the /goanywhere/ context path.

# What We Do NOT Detect

  - GoAnywhere Gateway: a separate reverse-proxy component with a different
    installation footprint and no branded login page.
  - GoAnywhere Agent: the agent-side component; no web UI.

# CVE Context

  - CVE-2023-0669 (Five Eyes AA24-317A Top 15, CISA KEV): pre-auth remote code
    execution via a deserialization vulnerability in the License Response
    Servlet. Mass-exploited by the Cl0p ransomware group.
  - CVE-2024-0204 (CVSS 9.8, CISA KEV): authentication bypass in the
    GoAnywhere admin portal. Our active probe issues a plain GET /goanywhere/
    with no POST body and no exploit-specific query parameters. This probe does
    NOT constitute exploitation of either CVE.

# Detection Strategy

Detection relies on brand tokens in the response body. At least one of the
following must be present:

  - The lowercased body contains "goanywhere" (brand token present in page
    source, error pages, meta tags, and asset paths).
  - A <title> element (case-insensitive) contains "goanywhere".

Header-based detection (via Server header) is NOT used because GoAnywhere MFT
typically runs behind a Java application server (Tomcat) that emits a generic
"Apache-Coyote/1.1" or similar Server header unrelated to the product.

# Version Extraction

Two regex patterns are tried in priority order:

 1. GoAnywhere product string with version:
    "GoAnywhere MFT v7.1.3" or "GoAnywhere MFT 7.1.3"
 2. Generic "Version: 7.1.3" or "Version 7.1.3" fallback (common in admin
    UI footer labels like "Version 7.4.1").

# CPE

cpe:2.3:a:fortra:goanywhere_managed_file_transfer:{version}:*:*:*:*:*:*:*

NVD vendor changed from "linoma" to "fortra" after Fortra's acquisition of
HelpSystems / Linoma Software. "fortra" is the current NVD-canonical vendor
for GoAnywhere MFT.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// GoAnywhereFingerprinter detects Fortra GoAnywhere MFT admin portal instances.
type GoAnywhereFingerprinter struct{}

// goanywhereVersionRegex extracts the version from GoAnywhere product strings.
// Examples: "GoAnywhere MFT v7.1.3", "GoAnywhere MFT 7.1.3", "GoAnywhere v7.4.1".
// The [^<]{0,50}? non-greedy bounded quantifier prevents runaway matching on
// large HTML bodies that lack the version string.
var goanywhereVersionRegex = regexp.MustCompile(
	`(?i)GoAnywhere[^<]{0,50}?v?(\d+\.\d+\.\d+)`,
)

// goanywhereGenericVersionRegex is a fallback pattern for version strings
// that appear in generic "Version: 7.4.1" or "Version 7.4.1" labels,
// commonly found in admin UI footers.
var goanywhereGenericVersionRegex = regexp.MustCompile(
	`(?i)version[:\s]+(\d+\.\d+\.\d+)`,
)

// goanywhereVersionValidateRegex is the second-stage version validator.
// Anchored ^…$ to reject partial matches; only digits and dots allowed.
// Accepts: "7.4.1", "7.4.1.2", "10.0.1.0".
// Rejects: "7.4.1-beta", "7.4.1:*:", ".1", "..".
var goanywhereVersionValidateRegex = regexp.MustCompile(
	`^[0-9]+(?:\.[0-9]+){1,4}$`,
)

// goanywhereTitleRegex matches a <title> element whose text content includes
// "goanywhere" (case-insensitive). [^<]* prevents crossing tag boundaries.
var goanywhereTitleRegex = regexp.MustCompile(
	`(?i)<title[^>]*>[^<]*goanywhere[^<]*</title>`,
)

func init() {
	Register(&GoAnywhereFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *GoAnywhereFingerprinter) Name() string {
	return "goanywhere"
}

// ProbeEndpoint returns the active probe path for the GoAnywhere admin portal.
// The /goanywhere/ context root is the canonical path for the MFT admin UI.
func (f *GoAnywhereFingerprinter) ProbeEndpoint() string {
	return "/goanywhere/"
}

// Match returns true when the response status is in the 200–499 range (inclusive)
// and the Content-Type header indicates an HTML response.
//
// 5xx responses are rejected: a server error does not provide usable fingerprint
// data. Responses in 200–499 that are not HTML (e.g., JSON APIs, images) are
// excluded to avoid unnecessary body parsing overhead.
func (f *GoAnywhereFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html")
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection requires at least one brand signal in the response body:
//   - The lowercased body contains "goanywhere".
//   - A <title> element (case-insensitive) contains "goanywhere".
//
// If neither signal is present, nil is returned (not a GoAnywhere instance).
//
// Version extraction priority:
//  1. GoAnywhere product string with version (e.g., "GoAnywhere MFT v7.1.3").
//  2. Generic "Version: 7.4.1" or "Version 7.4.1" footer label.
//  3. Empty (wildcard CPE emitted).
func (f *GoAnywhereFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: internal 2 MiB body cap — defense-in-depth above the engine's
	// io.LimitReader. A legitimate GoAnywhere login page is well under 1 MiB;
	// bodies >2 MiB are almost certainly not GoAnywhere and waste regex time.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	bodyLower := strings.ToLower(string(body))

	// Gate 3: CPE-injection defense — reject bodies containing `:*:`.
	// An attacker-controlled response could attempt to inject CPE metacharacters
	// via a crafted version string embedded in the page.
	if strings.Contains(bodyLower, ":*:") {
		return nil, nil
	}

	// Brand-token detection: at least one signal must be present.
	hasBrandInBody := strings.Contains(bodyLower, "goanywhere")
	hasBrandInTitle := goanywhereTitleRegex.Match(body)

	if !hasBrandInBody && !hasBrandInTitle {
		return nil, nil
	}

	// Determine detection method.
	detectionMethod := "body"
	if resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/goanywhere/") {
			detectionMethod = "active_probe"
		}
	}

	version := extractGoAnywhereVersion(body)

	metadata := map[string]any{
		"vendor":           "Fortra",
		"product":          "GoAnywhere MFT",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if detectionMethod == "active_probe" {
		metadata["probe_path"] = "/goanywhere/"
	}

	return &FingerprintResult{
		Technology: "goanywhere",
		Version:    version,
		CPEs:       []string{buildGoAnywhereCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityHigh,
	}, nil
}

// extractGoAnywhereVersion tries the two version sources in priority order and
// applies two-stage validation before returning. Returns empty string if no
// valid version is found.
func extractGoAnywhereVersion(body []byte) string {
	// Priority 1: GoAnywhere product string (e.g., "GoAnywhere MFT v7.1.3").
	if m := goanywhereVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); goanywhereVersionValidateRegex.MatchString(v) {
			return v
		}
	}

	// Priority 2: Generic version label (e.g., "Version: 7.4.1" in page footer).
	if m := goanywhereGenericVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); goanywhereVersionValidateRegex.MatchString(v) {
			return v
		}
	}

	return ""
}

// buildGoAnywhereCPE constructs a CPE 2.3 string for Fortra GoAnywhere MFT.
// NVD vendor: "fortra" (updated from "linoma" after the acquisition).
// NVD product: "goanywhere_managed_file_transfer".
// When version is empty, a wildcard CPE is emitted.
func buildGoAnywhereCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:fortra:goanywhere_managed_file_transfer:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:fortra:goanywhere_managed_file_transfer:%s:*:*:*:*:*:*:*", version)
}
