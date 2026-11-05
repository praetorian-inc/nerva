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
Package fingerprinters provides HTTP fingerprinting for Sitecore Experience Platform.

# What We Detect

  - Sitecore Experience Platform via X-Powered-By header containing "Sitecore" (passive)
  - Sitecore via body tokens containing "sitecore" combined with corroborating markers:
    "/sitecore/login", "sitecore.net", or "sitecore.css"
  - Sitecore login page via active probe to /sitecore/login

# CVE Context

  - CVE-2025-27218 (CVSS 9.8, CISA KEV 2025): Deserialization of untrusted data
    allows unauthenticated remote code execution.
  - CVE-2021-42237 (CVSS 9.8, CISA KEV): Remote code execution via
    Report.ashx deserialization endpoint.

# Active Probe Safety

The active probe issues a plain GET /sitecore/login with no query string and
no request body. Neither CVE-2025-27218 nor CVE-2021-42237 are triggered by
a plain GET to the login page. The probe is safe to run against any target.

# Version Extraction

Version extracted from X-Powered-By header (e.g., "Sitecore/10.3.1" or "Sitecore 10.3").
Uses regex: (?i)Sitecore[/ ]*(\d+(?:\.\d+){0,4})
Validated with anchored regex: ^[0-9]+(?:\.[0-9]+){0,4}$

# CPE

cpe:2.3:a:sitecore:experience_platform:{version}:*:*:*:*:*:*:*
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

// SitecoreFingerprinter detects Sitecore Experience Platform instances.
type SitecoreFingerprinter struct{}

// sitecoreVersionRegex extracts the version from the X-Powered-By header.
// Example: "Sitecore/10.3.1" or "Sitecore 10.3".
var sitecoreVersionRegex = regexp.MustCompile(
	`(?i)Sitecore[/ ]*(\d+(?:\.\d+){0,4})`,
)

// sitecoreVersionValidateRegex is the anchored two-stage validation gate.
var sitecoreVersionValidateRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,4}$`)

func init() {
	Register(&SitecoreFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *SitecoreFingerprinter) Name() string {
	return "sitecore"
}

// ProbeEndpoint returns the active probe path.
func (f *SitecoreFingerprinter) ProbeEndpoint() string {
	return "/sitecore/login"
}

// Match returns true when the response is a candidate for Sitecore detection.
// Rejects status < 200 or >= 500.
func (f *SitecoreFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Header-based fast-path: X-Powered-By containing "sitecore".
	if strings.Contains(strings.ToLower(resp.Header.Get("X-Powered-By")), "sitecore") {
		return true
	}

	// Body-scan candidate: any text/html response.
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full Sitecore detection and extracts technology information.
//
// Detection requires at least one of:
//   - X-Powered-By header containing "sitecore" (case-insensitive)
//   - Body containing "sitecore" AND corroborating marker ("/sitecore/login",
//     "sitecore.net", or "sitecore.css")
func (f *SitecoreFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
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
	hasPoweredBy := strings.Contains(poweredByLower, "sitecore")

	// Detection signal 2: body token — "sitecore" + corroborating marker.
	hasBody := strings.Contains(bodyLower, "sitecore") &&
		(strings.Contains(bodyLower, "/sitecore/login") ||
			strings.Contains(bodyLower, "sitecore.net") ||
			strings.Contains(bodyLower, "sitecore.css"))

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
		if strings.EqualFold(resp.Request.URL.Path, "/sitecore/login") {
			isActiveProbe = true
			if detectionMethod == "body" {
				detectionMethod = "active_probe"
			}
		}
	}

	// Version extraction from X-Powered-By header.
	var version string
	if hasPoweredBy {
		version = extractSitecoreVersion(poweredBy)
	}

	// CPE metacharacter defense.
	if strings.ContainsAny(version, ":*") {
		version = ""
	}

	// Build metadata.
	metadata := map[string]any{
		"vendor":           "Sitecore",
		"product":          "Experience Platform",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if isActiveProbe {
		metadata["probe_path"] = "/sitecore/login"
	}
	if hasPoweredBy {
		metadata["powered_by"] = sanitizeHTTPHeaderValue(poweredBy)
	}

	return &FingerprintResult{
		Technology: "sitecore",
		Version:    version,
		CPEs:       []string{buildSitecoreCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityHigh,
	}, nil
}

// extractSitecoreVersion extracts and validates the version from an
// X-Powered-By header value. Returns empty string if no valid version is found.
func extractSitecoreVersion(header string) string {
	if m := sitecoreVersionRegex.FindStringSubmatch(header); len(m) >= 2 {
		if v := m[1]; sitecoreVersionValidateRegex.MatchString(v) {
			return v
		}
	}
	return ""
}

// buildSitecoreCPE constructs a CPE 2.3 string for Sitecore Experience Platform.
func buildSitecoreCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:sitecore:experience_platform:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:sitecore:experience_platform:%s:*:*:*:*:*:*:*", version)
}
