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
Package fingerprinters provides HTTP fingerprinting for Quest KACE Systems
Management Appliance (SMA).

# What We Detect

Quest KACE SMA is an endpoint management and security appliance. This
fingerprinter targets its web management interface at /admin.

# Detection Strategy

Tier-1 (any one alone is sufficient), priority order:
  - X-KACE-Version header: present in responses, contains version string
  - X-KACE-Appliance header: present in responses
  - Page brand: body contains "KACE Systems Management Appliance" (title or branding text)

Detection method priority for metadata:
kace_version_header > kace_appliance_header > title

# Active Probe

ProbeEndpoint() returns "/admin" — the administrator console login page.
Safe plain GET; does not approach any known CVE exploit surface.

# Version Extraction

The X-KACE-Version response header contains the version in major.minor.patch
format (e.g., "14.1.101").

# CPE

cpe:2.3:a:quest:kace_systems_management_appliance:*:*:*:*:*:*:*:*

# CVE Context

  - CVE-2025-32975 (CVSS 10.0, CISA KEV): Authentication bypass via SSO
    handling flaw allows impersonating any user including admin without
    credentials. Actively exploited.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// QuestKACEFingerprinter detects Quest KACE SMA instances.
type QuestKACEFingerprinter struct{}

// questKACEVersionValidateRegex validates the X-KACE-Version header value.
// Format: major.minor.patch (e.g., "14.1.101", "8.0.318").
var questKACEVersionValidateRegex = regexp.MustCompile(
	`^[0-9]+(?:\.[0-9]+){1,3}$`,
)

func init() {
	Register(&QuestKACEFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *QuestKACEFingerprinter) Name() string {
	return "quest-kace"
}

// ProbeEndpoint returns "/admin" — the administrator console login page.
func (f *QuestKACEFingerprinter) ProbeEndpoint() string {
	return "/admin"
}

// Match returns true when the response status is in the 200-499 range.
func (f *QuestKACEFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return true
}

// Fingerprint performs detection and extracts technology information.
//
// Detection requires at least one Tier-1 signal (in priority order):
//   - X-KACE-Version header present (also provides version)
//   - X-KACE-Appliance header present
//   - Body contains "KACE Systems Management Appliance"
func (f *QuestKACEFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}
	if len(body) > 2*1024*1024 {
		return nil, nil
	}
	if strings.Contains(string(body), ":*:") {
		return nil, nil
	}

	kaceVersionHeader := resp.Header.Get("X-KACE-Version")
	hasKACEVersion := kaceVersionHeader != "" && questKACEVersionValidateRegex.MatchString(kaceVersionHeader)
	hasKACEAppliance := resp.Header.Get("X-KACE-Appliance") != ""
	bodyLower := strings.ToLower(string(body))
	hasBrandInBody := strings.Contains(bodyLower, "kace systems management appliance")

	if !hasKACEVersion && !hasKACEAppliance && !hasBrandInBody {
		return nil, nil
	}

	var detectionMethod string
	if hasBrandInBody {
		detectionMethod = "title"
	}
	if hasKACEAppliance {
		detectionMethod = "kace_appliance_header"
	}
	if hasKACEVersion {
		detectionMethod = "kace_version_header"
	}

	version := ""
	if hasKACEVersion {
		version = kaceVersionHeader
	}

	metadata := map[string]any{
		"vendor":           "Quest",
		"product":          "KACE Systems Management Appliance",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}

	return &FingerprintResult{
		Technology: "quest-kace-sma",
		Version:    version,
		CPEs:       []string{buildQuestKACECPE(version)},
		Metadata:   metadata,
	}, nil
}

// buildQuestKACECPE constructs the NVD-canonical CPE 2.3 string for Quest KACE SMA.
func buildQuestKACECPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:quest:kace_systems_management_appliance:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:quest:kace_systems_management_appliance:%s:*:*:*:*:*:*:*", version)
}
