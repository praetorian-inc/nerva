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
Package fingerprinters provides HTTP fingerprinting for Microsoft SharePoint Server
(on-premises).

# What We Detect

  - SharePoint Server via MicrosoftSharePointTeamServices response header (passive)
  - SharePoint via body tokens containing "sharepoint" combined with corroborating
    markers: "/_layouts/", "microsoft.sharepoint", or "sharepoint.css"

# CVE Context

  - CVE-2024-38094 (CVSS 7.2, CISA KEV 2024): Authenticated remote code execution
    in SharePoint Server.
  - CVE-2023-29357 (CVSS 9.8, CISA KEV 2023): Privilege escalation via JWT token
    validation bypass.
  - CVE-2019-0604 (CVSS 9.8, CISA KEV): Remote code execution via deserialization
    of crafted data.

# Active Probe Safety

The active probe issues a plain GET /_layouts/ with no query string and no
request body. None of the CVEs above are triggered by a plain GET to the
layouts directory. The probe is safe to run against any target.

# Version Extraction

Version extracted directly from MicrosoftSharePointTeamServices header value
(e.g., "16.0.0.10416"). The header value IS the version.
Uses regex: ^(\d+\.\d+\.\d+(?:\.\d+)?)$
Validated with anchored regex: ^[0-9]+(?:\.[0-9]+){0,4}$

# CPE

cpe:2.3:a:microsoft:sharepoint_server:{version}:*:*:*:*:*:*:*
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

// SharePointFingerprinter detects Microsoft SharePoint Server instances.
type SharePointFingerprinter struct{}

// sharepointVersionRegex extracts the version from the MicrosoftSharePointTeamServices header.
// The header value IS the version (e.g., "16.0.0.10416").
var sharepointVersionRegex = regexp.MustCompile(`^(\d+\.\d+\.\d+(?:\.\d+)?)$`)

// sharepointVersionValidateRegex is the anchored two-stage validation gate.
var sharepointVersionValidateRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,4}$`)

func init() {
	Register(&SharePointFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *SharePointFingerprinter) Name() string {
	return "sharepoint"
}

// ProbeEndpoint returns the active probe path.
func (f *SharePointFingerprinter) ProbeEndpoint() string {
	return "/_layouts/"
}

// Match returns true when the response is a candidate for SharePoint detection.
// Rejects status < 200 or >= 500.
func (f *SharePointFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Header-based fast-path: MicrosoftSharePointTeamServices header present.
	if resp.Header.Get("MicrosoftSharePointTeamServices") != "" {
		return true
	}

	// Body-scan candidate: any text/html response.
	if strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full SharePoint detection and extracts technology information.
//
// Detection requires at least one of:
//   - MicrosoftSharePointTeamServices header present (value IS the version)
//   - Body containing "sharepoint" AND corroborating marker ("/_layouts/",
//     "microsoft.sharepoint", or "sharepoint.css")
func (f *SharePointFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: internal 2 MiB body cap.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	spHeader := resp.Header.Get("MicrosoftSharePointTeamServices")
	bodyLower := strings.ToLower(string(body))

	// Detection signal 1: MicrosoftSharePointTeamServices header.
	hasHeader := spHeader != ""

	// Detection signal 2: body token — "sharepoint" + corroborating marker.
	hasBody := strings.Contains(bodyLower, "sharepoint") &&
		(strings.Contains(bodyLower, "/_layouts/") ||
			strings.Contains(bodyLower, "microsoft.sharepoint") ||
			strings.Contains(bodyLower, "sharepoint.css"))

	if !hasHeader && !hasBody {
		return nil, nil
	}

	// Determine detection method.
	detectionMethod := "body"
	if hasHeader && !hasBody {
		detectionMethod = "header"
	}

	// Determine if this response came from the active probe.
	isActiveProbe := false
	if resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/_layouts/") {
			isActiveProbe = true
			if detectionMethod == "body" {
				detectionMethod = "active_probe"
			}
		}
	}

	// Version extraction from MicrosoftSharePointTeamServices header.
	var version string
	if hasHeader {
		version = extractSharePointVersion(spHeader)
	}

	// CPE metacharacter defense.
	if strings.ContainsAny(version, ":*") {
		version = ""
	}

	// Build metadata.
	metadata := map[string]any{
		"vendor":           "Microsoft",
		"product":          "SharePoint Server",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if isActiveProbe {
		metadata["probe_path"] = "/_layouts/"
	}
	if hasHeader {
		metadata["sharepoint_header"] = sanitizeHTTPHeaderValue(spHeader)

		// Edition mapping based on major.minor version.
		edition := mapSharePointEdition(version)
		if edition != "" {
			metadata["sharepoint_edition"] = edition
		}
	}

	return &FingerprintResult{
		Technology: "sharepoint",
		Version:    version,
		CPEs:       []string{buildSharePointCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityHigh,
	}, nil
}

// extractSharePointVersion extracts and validates the version from the
// MicrosoftSharePointTeamServices header value. Returns empty string if invalid.
func extractSharePointVersion(header string) string {
	header = strings.TrimSpace(header)
	if m := sharepointVersionRegex.FindStringSubmatch(header); len(m) >= 2 {
		if v := m[1]; sharepointVersionValidateRegex.MatchString(v) {
			return v
		}
	}
	return ""
}

// buildSharePointCPE constructs a CPE 2.3 string for Microsoft SharePoint Server.
func buildSharePointCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:microsoft:sharepoint_server:%s:*:*:*:*:*:*:*", version)
}

// mapSharePointEdition maps a SharePoint version's major.minor prefix to the
// product edition name. Returns empty string for unknown versions.
func mapSharePointEdition(version string) string {
	parts := strings.Split(version, ".")
	if len(parts) < 2 {
		return ""
	}
	majorMinor := parts[0] + "." + parts[1]

	switch majorMinor {
	case "16.0":
		return "SharePoint Server 2016/2019/SE"
	case "15.0":
		return "SharePoint Server 2013"
	case "14.0":
		return "SharePoint Server 2010"
	default:
		return ""
	}
}
