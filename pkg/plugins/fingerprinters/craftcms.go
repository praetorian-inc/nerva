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
Package fingerprinters provides HTTP fingerprinting for Craft CMS.

# What We Detect

  - Craft CMS via X-Powered-By header containing "Craft CMS" (passive)
  - Craft CMS via body tokens containing "craft cms" combined with corroborating
    markers: "craftcms", "/admin/login", or "craft-cms"

# CVE Context

  - CVE-2025-32432 (CVSS 10.0, CISA KEV 2025): Unauthenticated remote code
    execution via image transform functionality.
  - CVE-2024-56145 (CVSS 9.8): Remote code execution via Twig Server-Side
    Template Injection (SSTI).

# Active Probe Safety

The active probe issues a plain GET /admin/login with no query string and
no request body. Neither CVE-2025-32432 nor CVE-2024-56145 are triggered by
a plain GET to the admin login page. The probe is safe to run against any target.

# Version Extraction

Version extracted from X-Powered-By header (e.g., "Craft CMS/5.6.17" or "Craft CMS 4.14.15").
Uses regex: (?i)Craft\s*CMS[/ ]*(\d+(?:\.\d+){0,4})
Validated with anchored regex: ^[0-9]+(?:\.[0-9]+){0,4}$

# CPE

cpe:2.3:a:craftcms:craft_cms:{version}:*:*:*:*:*:*:*
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

// CraftCMSFingerprinter detects Craft CMS instances.
type CraftCMSFingerprinter struct{}

// craftcmsVersionRegex extracts the version from the X-Powered-By header.
// Example: "Craft CMS/5.6.17" or "Craft CMS 4.14.15".
var craftcmsVersionRegex = regexp.MustCompile(
	`(?i)Craft\s*CMS[/ ]*(\d+(?:\.\d+){0,4})`,
)

// craftcmsVersionValidateRegex is the anchored two-stage validation gate.
var craftcmsVersionValidateRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,4}$`)

func init() {
	Register(&CraftCMSFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *CraftCMSFingerprinter) Name() string {
	return "craftcms"
}

// ProbeEndpoint returns the active probe path.
func (f *CraftCMSFingerprinter) ProbeEndpoint() string {
	return "/admin/login"
}

// Match returns true when the response is a candidate for Craft CMS detection.
// Rejects status < 200 or >= 500.
func (f *CraftCMSFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Header-based fast-path: X-Powered-By containing "craft cms".
	if strings.Contains(strings.ToLower(resp.Header.Get("X-Powered-By")), "craft cms") {
		return true
	}

	// Body-scan candidate: any text/html response.
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full Craft CMS detection and extracts technology information.
//
// Detection requires at least one of:
//   - X-Powered-By header containing "craft cms" (case-insensitive)
//   - Body containing "craft cms" AND corroborating marker ("craftcms",
//     "/admin/login", or "craft-cms")
func (f *CraftCMSFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: internal 2 MiB body cap.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	poweredBy := resp.Header.Get("X-Powered-By")
	poweredByLower := strings.ToLower(poweredBy)
	bodyLower := strings.ToLower(string(body))

	// Detection signal 1: X-Powered-By header.
	hasPoweredBy := strings.Contains(poweredByLower, "craft cms")

	// Detection signal 2: body token — "craft cms" + corroborating marker.
	hasBody := strings.Contains(bodyLower, "craft cms") &&
		(strings.Contains(bodyLower, "craftcms") ||
			strings.Contains(bodyLower, "/admin/login") ||
			strings.Contains(bodyLower, "craft-cms"))

	if !hasPoweredBy && !hasBody {
		return nil, nil
	}

	// Determine detection method.
	detectionMethod := "body"
	if hasPoweredBy && !hasBody {
		detectionMethod = "header"
	}

	// Determine if this response came from the active probe.
	isActiveProbe := false
	if resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/admin/login") {
			isActiveProbe = true
			if detectionMethod == "body" {
				detectionMethod = "active_probe"
			}
		}
	}

	// Version extraction from X-Powered-By header.
	var version string
	if hasPoweredBy {
		version = extractCraftCMSVersion(poweredBy)
	}

	// CPE metacharacter defense.
	if strings.ContainsAny(version, ":*") {
		version = ""
	}

	// Build metadata.
	metadata := map[string]any{
		"vendor":           "CraftCMS",
		"product":          "Craft CMS",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if isActiveProbe {
		metadata["probe_path"] = "/admin/login"
	}
	if hasPoweredBy {
		metadata["powered_by"] = sanitizeHTTPHeaderValue(poweredBy)
	}

	return &FingerprintResult{
		Technology: "craftcms",
		Version:    version,
		CPEs:       []string{buildCraftCMSCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityHigh,
	}, nil
}

// extractCraftCMSVersion extracts and validates the version from an
// X-Powered-By header value. Returns empty string if no valid version is found.
func extractCraftCMSVersion(header string) string {
	if m := craftcmsVersionRegex.FindStringSubmatch(header); len(m) >= 2 {
		if v := m[1]; craftcmsVersionValidateRegex.MatchString(v) {
			return v
		}
	}
	return ""
}

// buildCraftCMSCPE constructs a CPE 2.3 string for Craft CMS.
func buildCraftCMSCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:craftcms:craft_cms:%s:*:*:*:*:*:*:*", version)
}
