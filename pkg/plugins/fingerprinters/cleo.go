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
Package fingerprinters provides HTTP fingerprinting for Cleo Managed File Transfer products.

# What We Detect

  - Cleo Harmony — enterprise MFT platform
  - Cleo VLTrader — mid-tier MFT platform
  - Cleo LexiCom — desktop MFT client platform

All three products share a common server codebase (VersaLex engine) and emit the same
`Server: Cleo <Variant>/<version> (<OS string>)` HTTP response header format.

# Detection Strategy

Primary (Tier-1, any one sufficient):
  - `Server: Cleo {Harmony|VLTrader|LexiCom}/<version>` — vendor-emitted, pathognomonic.
    The OS suffix `(Windows Server 2019)` / `(Linux)` etc. is tolerated; version still
    extracts cleanly because the regex capture stops before the space.
  - `WWW-Authenticate: Basic realm="Cleo Harmony"` (or VLTrader/LexiCom) — returned on a
    401 response from the /server endpoint. Realm-derived detections carry no version.

Body+Server corroboration (Tier-2):
  - When Server header AND a body marker both match, detection_method is set to
    "body+server_header" for higher confidence.
  - Body markers (§1.6): `VersaLex Web Portal`, `mftportal`, `VLPortal`.
  - Single body markers without a server header or realm signal do NOT cause detection.
  - Existing body-only path: title or body text contains exact product name (`Cleo Harmony`
    etc.). When exactly one brand string matches with no server header, detection fires.
    When ≥2 of the new weaker body markers also match, detection_method reflects the
    stronger combined evidence.

# Active Probe

ProbeEndpoint() returns "/Synchronization" — the cluster-node sync endpoint targeted by
CVE-2024-50623 and CVE-2024-55956. An unauthenticated GET here always returns the Server
header. Per the Metasploit module, this is the canonical fingerprinting endpoint.

Neither this probe nor any code in this package sends the VLSync: header required to
approach the CVE-2024-50623/55956 exploit surface. Safe plain GET.

# CPE (NVD canonical per product)

  - Harmony:  cpe:2.3:a:cleo:harmony:<version>:*:*:*:*:*:*:*
  - VLTrader: cpe:2.3:a:cleo:vltrader:<version>:*:*:*:*:*:*:*
  - LexiCom:  cpe:2.3:a:cleo:lexicom:<version>:*:*:*:*:*:*:*

# CVE Context

  - CVE-2024-50623 (CVSS 9.8): Unrestricted file upload → RCE via autorun directory.
    Exploited by Cl0p ransomware (December 2024). Do NOT probe the autorun endpoint.
  - CVE-2024-55956 (CVSS 9.8): Follow-on unrestricted file write bypass — exploited
    actively in the wild via the same Cl0p campaign.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// CleoFingerprinter detects Cleo Harmony, VLTrader, and LexiCom MFT instances.
type CleoFingerprinter struct{}

// cleoVariants lists the three supported Cleo product names exactly as they appear
// in the Server header and page title.
var cleoVariants = []string{"Harmony", "VLTrader", "LexiCom"}

// cleoServerHeaderRegex extracts variant and version from the Server header.
// Example: "Cleo Harmony/5.8.0.21 (Linux)" → ["Harmony", "5.8.0.21"]
// The OS suffix "(Windows Server 2019)" is tolerated — the capture group stops at the
// space before "(" because [0-9.] does not match a space.
// Bounded: 2–4 dotted digit groups; guards against adversarial input.
var cleoServerHeaderRegex = regexp.MustCompile(
	`Cleo (Harmony|VLTrader|LexiCom)/([0-9]+(?:\.[0-9]+){1,3})`,
)

// cleoWWWAuthRegex matches the realm value in a WWW-Authenticate header for Cleo products.
// Example: `WWW-Authenticate: Basic realm="Cleo VLTrader"` → "VLTrader"
var cleoWWWAuthRegex = regexp.MustCompile(
	`(?i)realm="Cleo (Harmony|VLTrader|LexiCom)"`,
)

// cleoVersionValidateRegex is the two-stage validation gate applied after
// version extraction. Anchored ^…$ rejects partial matches.
var cleoVersionValidateRegex = regexp.MustCompile(
	`^[0-9]+(?:\.[0-9]+){1,3}$`,
)

// cleoWeakBodyMarkers are secondary body markers that corroborate detection but are
// insufficient alone. They must be combined with a Server header signal or with ≥2
// matching markers alongside the brand string.
var cleoWeakBodyMarkers = []string{"versalex web portal", "mftportal", "vlportal"}

func init() {
	Register(&CleoFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *CleoFingerprinter) Name() string {
	return "cleo"
}

// ProbeEndpoint returns "/Synchronization" — the cluster-node sync endpoint.
// An unauthenticated GET always returns the Server header. This is the endpoint
// targeted by both CVE-2024-50623 and CVE-2024-55956, and the endpoint the
// Metasploit module probes. We do NOT send the VLSync: header, so this is a safe
// plain GET that does not approach the exploit surface.
func (f *CleoFingerprinter) ProbeEndpoint() string {
	return "/Synchronization"
}

// Match returns true when the response status is in the 200–499 range (inclusive).
// 5xx responses are rejected as they provide no usable fingerprint data.
func (f *CleoFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return true
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection priority:
//  1. Server header: `Cleo {Harmony|VLTrader|LexiCom}/<version>` — Tier-1, sufficient alone.
//     OS suffix (e.g. "(Linux)") is tolerated; version still extracts cleanly.
//  2. WWW-Authenticate: realm="Cleo Harmony" (or VLTrader/LexiCom) — Tier-1 fallback,
//     no version (realm contains no version string).
//  3. Body: title or body text contains exact product name — sufficient alone.
//     When Server header AND a body marker also match, method is "body+server_header".
func (f *CleoFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: internal 2 MiB body cap.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Gate 3: CPE-injection defense.
	if strings.Contains(string(body), ":*:") {
		return nil, nil
	}

	serverHeader := resp.Header.Get("Server")
	bodyLower := strings.ToLower(string(body))

	// Attempt Tier-1: Server header match.
	variant, version, detectionMethod := extractCleoFromServerHeader(serverHeader)

	// If server header matched, check for body marker corroboration (upgrades detection_method).
	if variant != "" && hasCleoWeakBodyMarker(bodyLower) {
		detectionMethod = "body+server_header"
	}

	// Attempt Tier-1 fallback: WWW-Authenticate realm.
	if variant == "" {
		variant, detectionMethod = extractCleoFromWWWAuthenticate(resp.Header)
		// version remains "" — realm does not contain a version string
	}

	// Attempt Tier-2: body match (title or body text contains exact product brand string).
	if variant == "" {
		variant = extractCleoVariantFromBody(body)
		if variant != "" {
			detectionMethod = "body"
		}
	}

	// Nothing matched.
	if variant == "" {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":           "Cleo",
		"product":          variant,
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if serverHeader != "" {
		metadata["server_header"] = sanitizeCleoHeaderValue(serverHeader)
	}

	return &FingerprintResult{
		Technology: "cleo",
		Version:    version,
		CPEs:       []string{buildCleoCPE(variant, version)},
		Metadata:   metadata,
	}, nil
}

// extractCleoFromServerHeader parses the Server header for a Cleo brand string.
// Returns (variant, version, detectionMethod) or ("", "", "") if not matched.
func extractCleoFromServerHeader(serverHeader string) (variant, version, detectionMethod string) {
	if serverHeader == "" {
		return "", "", ""
	}
	m := cleoServerHeaderRegex.FindStringSubmatch(serverHeader)
	if len(m) < 3 {
		return "", "", ""
	}
	v := m[2]
	if !cleoVersionValidateRegex.MatchString(v) {
		v = ""
	}
	return m[1], v, "server_header"
}

// extractCleoFromWWWAuthenticate checks the WWW-Authenticate header values for a
// Cleo realm string. Returns (variant, "www_authenticate") or ("", "") if not matched.
// Realm-derived detections carry no version information.
func extractCleoFromWWWAuthenticate(header http.Header) (variant, detectionMethod string) {
	for _, v := range header.Values("WWW-Authenticate") {
		if m := cleoWWWAuthRegex.FindStringSubmatch(v); len(m) >= 2 {
			// m[1] is the variant captured from the header; normalise to canonical casing.
			return canonicalCleoVariant(m[1]), "www_authenticate"
		}
	}
	return "", ""
}

// canonicalCleoVariant returns the canonical casing for a Cleo variant name matched
// case-insensitively from the WWW-Authenticate realm.
func canonicalCleoVariant(raw string) string {
	switch strings.ToLower(raw) {
	case "harmony":
		return "Harmony"
	case "vltrader":
		return "VLTrader"
	case "lexicom":
		return "LexiCom"
	default:
		return raw
	}
}

// hasCleoWeakBodyMarker returns true if the lowercased body contains at least one
// of the weaker Cleo-specific body markers (§1.6).
func hasCleoWeakBodyMarker(bodyLower string) bool {
	for _, marker := range cleoWeakBodyMarkers {
		if strings.Contains(bodyLower, marker) {
			return true
		}
	}
	return false
}

// extractCleoVariantFromBody scans the lowercased body for exact Cleo product brand strings.
// Returns the matched variant name (e.g. "Harmony") or "" if none found.
// Checks title tag first (preferred), then broader body text.
func extractCleoVariantFromBody(body []byte) string {
	bodyLower := strings.ToLower(string(body))
	for _, variant := range cleoVariants {
		needle := "cleo " + strings.ToLower(variant)
		if strings.Contains(bodyLower, needle) {
			return variant
		}
	}
	return ""
}

// sanitizeCleoHeaderValue strips control characters and limits length to 256 chars
// to prevent log injection from attacker-controlled headers.
func sanitizeCleoHeaderValue(s string) string {
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

// buildCleoCPE constructs the NVD-canonical CPE 2.3 string for the given Cleo product.
// NVD product slugs: harmony, vltrader, lexicom (lowercase of the variant).
// When version is empty, a wildcard CPE is emitted.
func buildCleoCPE(variant, version string) string {
	product := strings.ToLower(variant)
	if version == "" {
		return fmt.Sprintf("cpe:2.3:a:cleo:%s:*:*:*:*:*:*:*:*", product)
	}
	return fmt.Sprintf("cpe:2.3:a:cleo:%s:%s:*:*:*:*:*:*:*", product, version)
}
