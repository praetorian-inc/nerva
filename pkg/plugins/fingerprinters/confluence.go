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
Package fingerprinters provides HTTP fingerprinting for Atlassian Confluence
wiki and collaboration platform.

# What We Detect

  - Confluence Server — self-hosted instances
  - Confluence Data Center — clustered self-hosted instances (detected via ajs-data-center-id meta tag)

Both passive (root response) and active (/login.action probe) responses are handled
by the same Match/Fingerprint functions.

# What We Do NOT Detect

  - Confluence Cloud (atlassian.net) — cloud-hosted SaaS instances do not expose
    the identifying meta tags or headers used here. They are out of scope.

# CVE Context

  - CVE-2023-22527 (CVSS 10.0, CISA KEV): Template injection RCE in Confluence
    Data Center and Server. Affects versions < 8.5.4 and 8.6.0–8.7.1.
    Our probe is a plain GET /login.action with no body — it does not trigger
    the OGNL template injection path (POST /_template/... with crafted body).
  - CVE-2024-21683: RCE in Confluence Data Center via macro upload endpoint.
  - CVE-2022-26134: OGNL injection via HTTP request URI.

# Active Probe Safety

The active probe issues a plain GET /login.action with no query string and no
request body. None of the CVEs above are triggered by a plain GET to the login
page. The probe is safe to run against any target.

# CPE Format

For Server (always emitted):
cpe:2.3:a:atlassian:confluence_server:{version}:*:*:*:*:*:*:*

For Data Center (also emitted when detected):
cpe:2.3:a:atlassian:confluence_data_center:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// confluenceVersionMetaRegex extracts the version from a Confluence ajs-version-number meta tag.
// Example: <meta name="ajs-version-number" content="8.5.4">
// Handles name before content attribute order.
var confluenceVersionMetaRegex = regexp.MustCompile(
	`(?i)<meta\s[^>]{0,200}?name=["']ajs-version-number["'][^>]{0,200}?content=["']([0-9]+(?:\.[0-9]+){1,4})["']`,
)

// confluenceVersionMetaRegexAlt handles content before name attribute order.
// Example: <meta content="8.5.4" name="ajs-version-number">
var confluenceVersionMetaRegexAlt = regexp.MustCompile(
	`(?i)<meta\s[^>]{0,200}?content=["']([0-9]+(?:\.[0-9]+){1,4})["'][^>]{0,200}?name=["']ajs-version-number["']`,
)

// confluenceBuildMetaRegex extracts the build number from ajs-build-number meta tag.
// Example: <meta name="ajs-build-number" content="9802">
var confluenceBuildMetaRegex = regexp.MustCompile(
	`(?i)<meta\s[^>]{0,200}?name=["']ajs-build-number["'][^>]{0,200}?content=["']([0-9]+)["']`,
)

// confluenceBuildMetaRegexAlt handles content before name attribute order.
var confluenceBuildMetaRegexAlt = regexp.MustCompile(
	`(?i)<meta\s[^>]{0,200}?content=["']([0-9]+)["'][^>]{0,200}?name=["']ajs-build-number["']`,
)

// confluenceDataCenterRegex detects the presence of the ajs-data-center-id meta tag,
// which is only present in Confluence Data Center deployments.
var confluenceDataCenterRegex = regexp.MustCompile(
	`(?i)<meta\s[^>]{0,200}?name=["']ajs-data-center-id["']`,
)

// confluenceVersionValidateRegex is the anchored two-stage validation gate.
// Accepts 2–5 dotted digit groups (e.g., "8.5.4", "8.5.4.1", "8.5.4.1.0").
// Rejects partial matches, semver qualifiers, and CPE metacharacters.
var confluenceVersionValidateRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,4}$`)

// confluenceBuildValidateRegex validates that the build number is purely numeric.
var confluenceBuildValidateRegex = regexp.MustCompile(`^[0-9]+$`)

// ConfluenceFingerprinter detects Atlassian Confluence wiki instances.
type ConfluenceFingerprinter struct{}

func init() {
	Register(&ConfluenceFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *ConfluenceFingerprinter) Name() string {
	return "confluence"
}

// ProbeEndpoint returns the active probe path. The Confluence login page at
// /login.action reliably includes version meta tags and brand text.
func (f *ConfluenceFingerprinter) ProbeEndpoint() string {
	return "/login.action"
}

// Match returns true when the response is likely worth inspecting for Confluence signals.
// Rejects status < 200 or >= 500 (server errors provide no usable data).
// Returns true for X-Confluence-Request-Time header (definitive signal) or
// text/html Content-Type (needed for body-driven meta tag detection).
func (f *ConfluenceFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	if resp.Header.Get("X-Confluence-Request-Time") != "" {
		return true
	}
	return strings.Contains(resp.Header.Get("Content-Type"), "text/html")
}

// Fingerprint performs full Confluence detection and metadata extraction.
// Requires at least one definitive signal: brand text in body, X-Confluence-Request-Time
// header, or ajs-version-number meta tag. Returns nil when no signal is found.
func (f *ConfluenceFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: internal 2 MiB body cap. A legitimate Confluence login page is <200 KiB;
	// bodies >2 MiB are almost certainly not Confluence and waste regex time.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Gate 3: CPE-injection defense. Reject bodies containing `:*:` to prevent
	// attacker-controlled content from injecting CPE metacharacters via version strings.
	if strings.Contains(string(body), ":*:") {
		return nil, nil
	}

	bodyLower := strings.ToLower(string(body))
	hasRequestTimeHeader := resp.Header.Get("X-Confluence-Request-Time") != ""
	hasBrandInBody := strings.Contains(bodyLower, "atlassian confluence")
	hasVersionMeta := confluenceVersionMetaRegex.Match(body) || confluenceVersionMetaRegexAlt.Match(body)

	// Require at least one definitive signal.
	if !hasBrandInBody && !hasRequestTimeHeader && !hasVersionMeta {
		return nil, nil
	}

	// Determine detection method.
	detectionMethod := "body"
	isActiveProbe := false
	if resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/login.action") {
			isActiveProbe = true
		}
	}
	if !hasBrandInBody && !hasVersionMeta && hasRequestTimeHeader {
		detectionMethod = "header"
	} else if isActiveProbe {
		detectionMethod = "active_probe"
	}

	version := extractConfluenceVersion(body)
	buildNumber := extractConfluenceBuildNumber(body)
	deploymentType := detectConfluenceDeploymentType(body)

	metadata := map[string]any{
		"vendor":           "Atlassian",
		"product":          "Confluence",
		"deployment_type":  deploymentType,
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if buildNumber != "" {
		metadata["build_number"] = buildNumber
	}
	if isActiveProbe {
		metadata["probe_path"] = "/login.action"
	}
	if asen := resp.Header.Get("X-ASEN"); asen != "" {
		metadata["asen"] = sanitizeConfluenceHeaderValue(asen)
	}
	if hasRequestTimeHeader {
		metadata["confluence_request_time"] = sanitizeConfluenceHeaderValue(
			resp.Header.Get("X-Confluence-Request-Time"),
		)
	}

	return &FingerprintResult{
		Technology: "confluence",
		Version:    version,
		CPEs:       buildConfluenceCPEs(version, deploymentType),
		Metadata:   metadata,
		Severity:   plugins.SeverityHigh,
	}, nil
}

// extractConfluenceVersion tries both attribute orders for ajs-version-number and
// applies two-stage validation before returning. Returns empty string if not found.
func extractConfluenceVersion(body []byte) string {
	if m := confluenceVersionMetaRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); confluenceVersionValidateRegex.MatchString(v) {
			return v
		}
	}
	if m := confluenceVersionMetaRegexAlt.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); confluenceVersionValidateRegex.MatchString(v) {
			return v
		}
	}
	return ""
}

// extractConfluenceBuildNumber tries both attribute orders for ajs-build-number and
// applies numeric validation before returning. Returns empty string if not found.
func extractConfluenceBuildNumber(body []byte) string {
	if m := confluenceBuildMetaRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); confluenceBuildValidateRegex.MatchString(v) {
			return v
		}
	}
	if m := confluenceBuildMetaRegexAlt.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); confluenceBuildValidateRegex.MatchString(v) {
			return v
		}
	}
	return ""
}

// detectConfluenceDeploymentType returns "data_center" when the ajs-data-center-id
// meta tag is present (exclusive to Data Center deployments), otherwise "server".
func detectConfluenceDeploymentType(body []byte) string {
	if confluenceDataCenterRegex.Match(body) {
		return "data_center"
	}
	return "server"
}

// buildConfluenceCPEs constructs CPE 2.3 strings for Confluence.
// Always emits confluence_server CPE; also emits confluence_data_center when
// deploymentType is "data_center". Wildcard version used when version is empty.
func buildConfluenceCPEs(version, deploymentType string) []string {
	v := version
	if v == "" {
		v = "*"
	}
	cpes := []string{
		fmt.Sprintf("cpe:2.3:a:atlassian:confluence_server:%s:*:*:*:*:*:*:*", v),
	}
	if deploymentType == "data_center" {
		cpes = append(cpes,
			fmt.Sprintf("cpe:2.3:a:atlassian:confluence_data_center:%s:*:*:*:*:*:*:*", v),
		)
	}
	return cpes
}

// sanitizeConfluenceHeaderValue strips control characters (< 0x20 or == 0x7F)
// and caps length at 256 bytes to prevent log injection from attacker-controlled headers.
func sanitizeConfluenceHeaderValue(s string) string {
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
