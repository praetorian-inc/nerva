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
Package fingerprinters provides HTTP fingerprinting for Adobe ColdFusion
application server.

# What We Detect

  - Adobe ColdFusion via the /CFIDE/administrator/ admin endpoint (active probe)
  - Adobe ColdFusion via X-Powered-By: ColdFusion or Server: ColdFusion headers (passive)
  - Adobe ColdFusion via body tokens referencing "coldfusion" combined with "cfide",
    ".cfm", or "adobe" (body detection)

# What We Do NOT Detect

  - Lucee (open-source CFML engine) — different product, separate CPE; Lucee sets
    "Lucee" in headers and does not expose /CFIDE/administrator/.
  - BlueDragon (New Atlanta) — defunct product not encountered in practice.

# CVE Context

  - CVE-2023-29300 (CVSS 9.8, CISA KEV): Deserialization of untrusted data allows
    unauthenticated RCE. Affects ColdFusion 2018 ≤ Update 16, 2021 ≤ Update 6,
    2023 GA.
  - CVE-2023-38203 (CVSS 9.8, CISA KEV): Deserialization RCE, closely related
    exploitation chain. Same affected versions.
    Our probe is a plain GET /CFIDE/administrator/ — it does not trigger
    deserialization paths (which require POST with crafted AMF or WDDX payloads).

# Active Probe Safety

The active probe issues a plain GET /CFIDE/administrator/ with no query string
and no request body. CVE-2023-29300 and CVE-2023-38203 exploit paths require
POST with crafted deserialization payloads. This probe is safe to run against
any target, including unpatched instances.

# Version Extraction Priority

 1. X-Powered-By header value (e.g., "ColdFusion/2023.0.1") — most explicit
 2. Body text containing "ColdFusion <year>" or "Version: <x.y.z>" patterns

# CPE

cpe:2.3:a:adobe:coldfusion:{version}:*:*:*:*:*:*:*
Wildcard CPE emitted when version is unavailable.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// ColdFusionFingerprinter detects Adobe ColdFusion application server instances.
type ColdFusionFingerprinter struct{}

// coldfusionPoweredByVersionRegex extracts the version from the X-Powered-By header.
// Example: "ColdFusion/2023.0.1" or "ColdFusion 2023".
// Bounded: 1–5 dotted digit groups; handles both slash and space separators.
var coldfusionPoweredByVersionRegex = regexp.MustCompile(
	`(?i)ColdFusion[/ ]*(\d+(?:\.\d+){0,4})`,
)

// coldfusionBodyVersionRegex extracts the version from body text.
// Matches patterns like "ColdFusion 2023", "ColdFusion 2023.0.6", "ColdFusion 2021".
// Space-separated: "ColdFusion <version>".
var coldfusionBodyVersionRegex = regexp.MustCompile(
	`(?i)ColdFusion\s+(\d+(?:\.\d+){0,4})`,
)

// coldfusionVersionValidateRegex is the two-stage anchored validation gate.
// Accepts a single integer (e.g., "2023") or dotted notation (e.g., "2023.0.1").
// Rejects partial matches, semver qualifiers, and CPE metacharacters.
var coldfusionVersionValidateRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,4}$`)

func init() {
	Register(&ColdFusionFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *ColdFusionFingerprinter) Name() string {
	return "coldfusion"
}

// ProbeEndpoint returns the active probe path. The /CFIDE/administrator/ endpoint
// is the canonical ColdFusion administrator interface. A plain GET to this path
// does not trigger CVE-2023-29300 or CVE-2023-38203 deserialization paths.
func (f *ColdFusionFingerprinter) ProbeEndpoint() string {
	return "/CFIDE/administrator/"
}

// Match returns true when the response is a candidate for ColdFusion detection.
// Rejects status < 200 or >= 500.
// Returns true if X-Powered-By or Server header contains "ColdFusion" (case-insensitive),
// or if Content-Type contains "text/html" (passive body scan candidate).
func (f *ColdFusionFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Header-based fast-path.
	if strings.Contains(strings.ToLower(resp.Header.Get("X-Powered-By")), "coldfusion") {
		return true
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "coldfusion") {
		return true
	}

	// Body-scan candidate: any text/html response in 200–499 range.
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection requires at least one of:
//   - X-Powered-By header containing "coldfusion" (case-insensitive)
//   - Server header containing "coldfusion" (case-insensitive)
//   - Body (lowercased) containing "coldfusion" AND one of "cfide", ".cfm", "adobe"
//
// Version extraction priority:
//  1. X-Powered-By header value (e.g., "ColdFusion/2023.0.1")
//  2. Body text patterns (e.g., "ColdFusion 2023", "Version: 2023.0.6")
func (f *ColdFusionFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter — mirrors screenconnect.go and boa.go.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: internal 2 MiB body cap — defense-in-depth above the engine's
	// io.LimitReader. A legitimate ColdFusion admin page is <<1 MiB; bodies
	// >2 MiB are almost certainly not ColdFusion and would waste regex time.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Gate 3: CPE-injection defense — reject bodies containing ":*:" (copy boa.go:97-99).
	// Attacker-controlled bodies could attempt to inject CPE metacharacters.
	if strings.Contains(string(body), ":*:") {
		return nil, nil
	}

	poweredBy := resp.Header.Get("X-Powered-By")
	poweredByLower := strings.ToLower(poweredBy)
	serverLower := strings.ToLower(resp.Header.Get("Server"))
	bodyLower := strings.ToLower(string(body))

	// Detection signal 1: X-Powered-By header.
	hasPoweredBy := strings.Contains(poweredByLower, "coldfusion")

	// Detection signal 2: Server header.
	hasServer := strings.Contains(serverLower, "coldfusion")

	// Detection signal 3: body token — "coldfusion" + corroborating marker.
	hasBody := strings.Contains(bodyLower, "coldfusion") &&
		(strings.Contains(bodyLower, "cfide") ||
			strings.Contains(bodyLower, ".cfm") ||
			strings.Contains(bodyLower, "adobe"))

	if !hasPoweredBy && !hasServer && !hasBody {
		return nil, nil
	}

	// Determine detection method.
	detectionMethod := "body"
	if hasPoweredBy || hasServer {
		if !hasBody {
			detectionMethod = "header"
		}
	}

	// Determine if this response came from the active probe.
	isActiveProbe := false
	if resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/CFIDE/administrator/") {
			isActiveProbe = true
			if detectionMethod == "body" {
				detectionMethod = "active_probe"
			}
		}
	}

	// Version extraction: X-Powered-By first, then body.
	var version string
	if hasPoweredBy {
		version = extractColdFusionVersionFromHeader(poweredBy)
	}
	if version == "" {
		version = extractColdFusionVersionFromBody(body)
	}

	// Build metadata — only include keys with non-empty values (YAGNI).
	metadata := map[string]any{
		"vendor":           "Adobe",
		"product":          "ColdFusion",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if isActiveProbe {
		metadata["probe_path"] = "/CFIDE/administrator/"
	}
	if hasPoweredBy {
		metadata["powered_by"] = sanitizeColdFusionHeaderValue(poweredBy)
	}

	return &FingerprintResult{
		Technology: "coldfusion",
		Version:    version,
		CPEs:       []string{buildColdFusionCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityHigh,
	}, nil
}

// extractColdFusionVersionFromHeader extracts the version from an X-Powered-By
// header value and applies two-stage validation before returning.
// Returns empty string if no valid version is found.
func extractColdFusionVersionFromHeader(header string) string {
	if m := coldfusionPoweredByVersionRegex.FindStringSubmatch(header); len(m) >= 2 {
		if v := m[1]; coldfusionVersionValidateRegex.MatchString(v) {
			return v
		}
	}
	return ""
}

// extractColdFusionVersionFromBody extracts the version from body text using the
// body version regex and applies two-stage validation before returning.
// Returns empty string if no valid version is found.
func extractColdFusionVersionFromBody(body []byte) string {
	if m := coldfusionBodyVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); coldfusionVersionValidateRegex.MatchString(v) {
			return v
		}
	}
	return ""
}

// sanitizeColdFusionHeaderValue strips control characters and limits length to
// prevent log injection or oversized metadata values from attacker-controlled headers.
func sanitizeColdFusionHeaderValue(s string) string {
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

// buildColdFusionCPE constructs a CPE 2.3 string for Adobe ColdFusion.
// NVD vendor/product: adobe:coldfusion.
// When version is empty, a wildcard CPE is emitted.
func buildColdFusionCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:adobe:coldfusion:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:adobe:coldfusion:%s:*:*:*:*:*:*:*", version)
}
