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
Package fingerprinters provides HTTP fingerprinting for Samsung MagicINFO 9 Server.

# What We Detect

  - Samsung MagicINFO 9 Server via the /MagicInfo/ path and Server header
  - MagicINFO Premium and Lite editions (from Server header)
  - Version extraction from Server header and body content

# What We Do NOT Detect

  - MagicINFO deployments behind reverse proxies that strip the Server header
    and /MagicInfo/ path references
  - Non-HTTP MagicINFO protocols or embedded device interfaces
  - Oracle WebLogic on port 7001 (common false-positive target — detection
    requires explicit MagicINFO markers, not just the port)

# Security Context

Samsung MagicINFO 9 Server is a digital signage content management platform.
Exposed MagicINFO instances have been associated with CVE-2024-7399 (unauthenticated
RCE via file upload) and other critical vulnerabilities. Identifying exposed
instances supports asset inventory and patch prioritization.

This fingerprinter performs detection only; it does not assess authentication
state or execute any write operations against the target.

# Active Probe Safety

The active probe issues a plain GET /MagicInfo/ with no request body. This is
a read-only request for the application root; no write operations are performed.

# CPE

cpe:2.3:a:samsung:magicinfo_9_server:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// SamsungMagicINFOFingerprinter detects Samsung MagicINFO 9 Server instances
// via the Server response header and HTML body markers.
type SamsungMagicINFOFingerprinter struct{}

// magicInfoVersionBodyRegex extracts build-number versions from HTML body context.
// MagicINFO uses dotted build numbers such as "21.1050" and "21.1052".
// The word boundary (\b) before the keyword prevents spurious matches like
// "aversion=1.5" from triggering version extraction.
var magicInfoVersionBodyRegex = regexp.MustCompile(
	`(?i)\b(?:version|ver)\s*[=:"\s]+(\d+\.\d+)`,
)

// magicInfoServerVersionRegex extracts a build-number version from the Server header.
// Matches a trailing token like "MagicInfo Premium Server/21.1050".
// The gap between "MagicInfo" and the slash is capped at 20 characters to prevent
// matching through unrelated server components such as "Apache-Coyote/1.1", where
// the unbounded [^/]* would consume " Server Apache-Coyote" and then capture "1.1"
// as if it were a MagicINFO version.
var magicInfoServerVersionRegex = regexp.MustCompile(
	`(?i)MagicInfo[^/]{0,20}/(\d+\.\d+)`,
)

// magicInfoVersionValidateRegex is the anchored second-stage validation gate.
// Accepts exactly two dot-separated numeric components: "21.1050", "9.0".
var magicInfoVersionValidateRegex = regexp.MustCompile(`^\d+\.\d+$`)

// magicInfoEditionRegex extracts the edition keyword from the Server header.
// Matches "Premium" or "Lite" as standalone words (case-insensitive).
var magicInfoEditionRegex = regexp.MustCompile(`(?i)\b(Premium|Lite)\b`)

// magicInfoTitleRegex matches a MagicINFO-branded <title> tag.
// Anchored to the title element to avoid matching prose mentions.
var magicInfoTitleRegex = regexp.MustCompile(
	`(?i)<title[^>]{0,100}>[^<]{0,200}magicinfo[^<]{0,200}</title>`,
)

// magicInfoBodyBrandRegex matches the canonical "MagicINFO" or "magicinfo" brand
// in the body (not just the /MagicInfo/ path).
// Word boundaries prevent matching "magicinfo" inside URL path segments like
// "/MagicInfo/" echoed in error pages (note: \b matches between "/" and "M"
// since "/" is not a word character, so path-echo false positives must be
// addressed at the corroboration level — see Fingerprint for the title requirement).
var magicInfoBodyBrandRegex = regexp.MustCompile(`(?i)\bmagicinfo\b`)

const magicInfoVersionMaxLen = 20

func init() {
	Register(&SamsungMagicINFOFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *SamsungMagicINFOFingerprinter) Name() string {
	return "samsung-magicinfo"
}

// ProbeEndpoint returns the MagicINFO application root path.
func (f *SamsungMagicINFOFingerprinter) ProbeEndpoint() string {
	return "/MagicInfo/"
}

// ProbeAccept returns the Accept header for the active probe.
func (f *SamsungMagicINFOFingerprinter) ProbeAccept() string {
	return "text/html"
}

// Match returns true when the response is a candidate for MagicINFO detection.
//
// Accept conditions (status 200-499):
//   - Server header contains "MagicInfo" (case-insensitive) — sufficient alone
//   - Content-Type is text/html
//
// 5xx responses are always rejected.
func (f *SamsungMagicINFOFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Server header containing "MagicInfo" is a standalone signal.
	if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "magicinfo") {
		return true
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection signals:
//  1. Standalone signal: Server header contains "MagicInfo" — confirmed without body analysis.
//     The body cap does NOT gate this path; a large response with a MagicInfo Server header
//     is still detected.
//  2. Corroborated signal: body contains MagicINFO brand AND a MagicINFO-branded <title>
//     element. The title requirement prevents false positives from error pages that echo
//     the /MagicInfo/ path or mention "Samsung" incidentally.
//
// At least one signal set must fire for detection to succeed.
func (f *SamsungMagicINFOFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter — reject 5xx.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	serverHeader := resp.Header.Get("Server")
	serverLower := strings.ToLower(serverHeader)

	// Standalone signal: Server header contains "MagicInfo".
	// This signal is evaluated before the body cap so that valid MagicINFO servers
	// with large response bodies are not silently rejected.
	hasServerSignal := strings.Contains(serverLower, "magicinfo")

	// Gate 2: 1 MiB body cap — only applies when the server-header signal is absent.
	// When the server header already confirms MagicINFO, body analysis is skipped.
	if !hasServerSignal && len(body) > 1*1024*1024 {
		return nil, nil
	}

	// --- Signal detection ---

	// Corroborated signal: body brand + MagicINFO-branded <title> element.
	// Requiring the title (a strong structural HTML marker) prevents error pages
	// that echo "/MagicInfo/" or mention "Samsung" from triggering a false positive.
	hasBodyBrand := magicInfoBodyBrandRegex.Match(body)
	hasTitleRef := magicInfoTitleRegex.Match(body)
	hasCorroboratedSignal := hasBodyBrand && hasTitleRef

	if !hasServerSignal && !hasCorroboratedSignal {
		return nil, nil
	}

	// --- Version extraction ---

	version := extractMagicINFOVersion(serverHeader, body)

	// --- Edition detection ---

	edition := ""
	if serverHeader != "" {
		if m := magicInfoEditionRegex.FindStringSubmatch(serverHeader); len(m) >= 2 {
			edition = m[1]
		}
	}

	// --- Metadata ---

	metadata := map[string]any{
		"vendor":  "Samsung",
		"product": "MagicINFO 9 Server",
	}
	if edition != "" {
		metadata["edition"] = edition
	}

	return &FingerprintResult{
		Technology: "samsung-magicinfo",
		Version:    version,
		CPEs:       []string{buildMagicINFOCPE(version)},
		Metadata:   metadata,
	}, nil
}

// extractMagicINFOVersion extracts a build-number version from the Server header
// and body. Three-layer validation: length cap → regex → first valid match.
//
// Priority: Server header version suffix first, then body keyword context.
func extractMagicINFOVersion(serverHeader string, body []byte) string {
	// Priority 1: Server header version suffix.
	if serverHeader != "" {
		if m := magicInfoServerVersionRegex.FindStringSubmatch(serverHeader); len(m) >= 2 {
			v := m[1]
			if len(v) <= magicInfoVersionMaxLen &&
				!strings.ContainsAny(v, ":*?") &&
				magicInfoVersionValidateRegex.MatchString(v) {
				return v
			}
		}
	}

	// Priority 2: body keyword context (version=/Version=/ver=).
	matches := magicInfoVersionBodyRegex.FindAllSubmatch(body, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		v := string(m[1])
		if len(v) > magicInfoVersionMaxLen {
			continue
		}
		if strings.ContainsAny(v, ":*?") {
			continue
		}
		if magicInfoVersionValidateRegex.MatchString(v) {
			return v
		}
	}

	return ""
}

// buildMagicINFOCPE constructs a CPE 2.3 string for Samsung MagicINFO 9 Server.
// When version is empty, a wildcard CPE is emitted for asset inventory.
// Explicit guard rejects any version string containing CPE metacharacters.
func buildMagicINFOCPE(version string) string {
	if strings.ContainsAny(version, ":*?") {
		version = ""
	}
	if version == "" {
		return "cpe:2.3:a:samsung:magicinfo_9_server:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:samsung:magicinfo_9_server:%s:*:*:*:*:*:*:*", version)
}
