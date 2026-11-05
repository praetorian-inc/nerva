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
Package fingerprinters provides HTTP fingerprinting for Kentico CMS / Xperience.

# What We Detect

Kentico is an ASP.NET-based CMS and digital experience platform. This
fingerprinter detects it from any page via meta generator tags, CMS-prefixed
cookies, and /CMSPages/ resource paths.

# Detection Strategy

Tier-1 (any one alone is sufficient), priority order:
  - Meta generator: <meta name="generator" content="Kentico CMS ..."> (also provides version)
  - CMS cookies: CMSPreferredCulture, CMSCookieLevel, CMSCsrfCookie, or CMSCurrentTheme present in Set-Cookie
  - Resource path: body contains "/CMSPages/GetResource.ashx"

Detection method priority for metadata:
generator > cookies > body_path

# Version Extraction

The meta generator tag contains the build number:

	Kentico CMS 7.0 (build 7.0.5000)

The build number (e.g., "7.0.5000") is extracted and used for the CPE version.
Falls back to the main version (e.g., "7.0") when no build is present.

# CPE

cpe:2.3:a:kentico:xperience:*:*:*:*:*:*:*:*

# CVE Context

  - CVE-2025-2746 (CVSS 9.8, CISA KEV): Staging Sync Server auth bypass.
  - CVE-2025-2747 (CVSS 9.8, CISA KEV): Staging Sync Server auth bypass.
  - CVE-2025-2749 (CVSS 7.2, CISA KEV): Path traversal + file upload via
    Staging Sync Server. All three actively exploited.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// KenticoFingerprinter detects Kentico CMS / Xperience instances.
type KenticoFingerprinter struct{}

// kenticoBuildVersionRegex extracts the build number from the meta generator tag.
// Example: `<meta name="generator" content="Kentico CMS 7.0 (build 7.0.5000)">` -> "7.0.5000"
var kenticoBuildVersionRegex = regexp.MustCompile(
	`(?i)<meta[^>]{0,200}?name=["']?generator["']?[^>]{0,200}?content=["']Kentico\s+(?:CMS|Xperience)\s+[^"']{0,30}\(build\s+([0-9]+(?:\.[0-9]+){1,3})\)`,
)

// kenticoMainVersionRegex extracts the version when no build number is present.
// Example: `<meta name="generator" content="Kentico CMS 13.0">` -> "13.0"
var kenticoMainVersionRegex = regexp.MustCompile(
	`(?i)<meta[^>]{0,200}?name=["']?generator["']?[^>]{0,200}?content=["']Kentico\s+(?:CMS|Xperience)\s+([0-9]+(?:\.[0-9]+){1,3})`,
)

// kenticoVersionValidateRegex is the anchored validation gate.
var kenticoVersionValidateRegex = regexp.MustCompile(
	`^[0-9]+(?:\.[0-9]+){1,3}$`,
)

// kenticoGeneratorDetectRegex checks for the presence of the Kentico generator tag
// without extracting a version (for cases where the version format is unusual).
var kenticoGeneratorDetectRegex = regexp.MustCompile(
	`(?i)<meta[^>]{0,200}?name=["']?generator["']?[^>]{0,200}?content=["']Kentico\s+(?:CMS|Xperience)`,
)

func init() {
	Register(&KenticoFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *KenticoFingerprinter) Name() string {
	return "kentico"
}

// Match returns true when the response status is in the 200-499 range.
func (f *KenticoFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return true
}

// Fingerprint performs detection and extracts technology information.
//
// Detection requires at least one Tier-1 signal (in priority order):
//   - Meta generator tag contains "Kentico CMS" or "Kentico Xperience"
//   - CMSPreferredCulture or CMSCookieLevel cookie present
//   - Body contains "/CMSPages/GetResource.ashx"
func (f *KenticoFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}
	if len(body) > 2*1024*1024 {
		return nil, nil
	}
	if strings.Contains(string(body), ":*:") {
		return nil, nil
	}

	bodyLower := strings.ToLower(string(body))

	hasGenerator := kenticoGeneratorDetectRegex.Match(body)
	hasCMSCookies := kenticoHasCMSCookies(resp.Cookies())
	hasResourcePath := strings.Contains(bodyLower, "/cmspages/getresource.ashx")

	if !hasGenerator && !hasCMSCookies && !hasResourcePath {
		return nil, nil
	}

	var detectionMethod string
	if hasResourcePath {
		detectionMethod = "body_path"
	}
	if hasCMSCookies {
		detectionMethod = "cookies"
	}
	if hasGenerator {
		detectionMethod = "generator"
	}

	version := extractKenticoVersion(body)

	metadata := map[string]any{
		"vendor":           "Kentico",
		"product":          "Kentico CMS",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}

	return &FingerprintResult{
		Technology: "kentico-cms",
		Version:    version,
		CPEs:       []string{buildKenticoCPE(version)},
		Metadata:   metadata,
	}, nil
}

// kenticoHasCMSCookies returns true when CMSPreferredCulture or CMSCookieLevel
// cookies are present. These cookies are set on every Kentico page visit.
func kenticoHasCMSCookies(cookies []*http.Cookie) bool {
	for _, c := range cookies {
		switch c.Name {
		case "CMSPreferredCulture", "CMSCookieLevel", "CMSCsrfCookie", "CMSCurrentTheme":
			return true
		}
	}
	return false
}

// extractKenticoVersion attempts version extraction from the meta generator tag.
// Prefers the build number ("7.0.5000") over the main version ("7.0").
func extractKenticoVersion(body []byte) string {
	if m := kenticoBuildVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); kenticoVersionValidateRegex.MatchString(v) {
			return v
		}
	}
	if m := kenticoMainVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); kenticoVersionValidateRegex.MatchString(v) {
			return v
		}
	}
	return ""
}

// buildKenticoCPE constructs the NVD-canonical CPE 2.3 string for Kentico CMS.
func buildKenticoCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:kentico:xperience:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:kentico:xperience:%s:*:*:*:*:*:*:*", version)
}
