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

package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// BigIPFingerprinter detects F5 BIG-IP management interfaces and load balancers
type BigIPFingerprinter struct{}

func init() {
	Register(&BigIPFingerprinter{})
}

// BIG-IP detection patterns in response body
var bigIPBodyPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)<title>[^<]*BIG-IP[^<]*</title>`),
	regexp.MustCompile(`(?i)F5\s+Networks`),
	regexp.MustCompile(`(?i)/tmui/`),
	regexp.MustCompile(`(?i)tmui/login\.jsp`),
	regexp.MustCompile(`(?i)Configuration\s+Utility`),
	regexp.MustCompile(`(?i)support@f5\.com`),
}

// BIG-IP version extraction patterns
var bigIPVersionPattern = regexp.MustCompile(`(?i)BIG-IP\s+([0-9]+(?:\.[0-9]+)+)`)

// iControlVersionResponse represents the /mgmt/tm/sys/version JSON structure
type iControlVersionResponse struct {
	Kind    string `json:"kind"`
	Entries map[string]struct {
		NestedStats struct {
			Entries map[string]struct {
				Description string `json:"description"`
			} `json:"entries"`
		} `json:"nestedStats"`
	} `json:"entries"`
}

func (f *BigIPFingerprinter) Name() string {
	return "bigip"
}

func (f *BigIPFingerprinter) ProbeEndpoint() string {
	return "/mgmt/tm/sys/version"
}

func (f *BigIPFingerprinter) Match(resp *http.Response) bool {
	// Accept 2xx, 3xx, and 4xx responses (management interfaces often return 401)
	// Reject 1xx and 5xx
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	return matchHeaders(resp)
}

func (f *BigIPFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Accept 2xx, 3xx, and 4xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Check headers first
	headerMatch := matchHeaders(resp)

	// Check response body for BIG-IP markers
	bodyMatch := matchBody(body)

	if !bodyMatch && !headerMatch {
		return nil, nil
	}

	// Extract version (try iControl JSON first, then HTML)
	version := ""
	build := ""

	// Try parsing as iControl REST JSON
	if jsonVersion, jsonBuild := parseIControlVersion(body); jsonVersion != "" {
		version = jsonVersion
		build = jsonBuild
	} else {
		// Try extracting from HTML body
		version = extractBigIPVersionFromHTML(body)
	}

	metadata := map[string]any{
		"vendor":  "F5",
		"product": "BIG-IP",
	}

	if build != "" {
		metadata["build"] = build
	}

	// Determine interface type based on response
	if resp.StatusCode == 401 && strings.Contains(resp.Header.Get("WWW-Authenticate"), "iControl") {
		metadata["interface"] = "iControl REST API"
		metadata["unauthenticated_api"] = false
	} else if resp.StatusCode == 401 && strings.Contains(resp.Header.Get("WWW-Authenticate"), "Enterprise Manager") {
		metadata["interface"] = "Enterprise Manager"
		metadata["unauthenticated_api"] = false
	} else if strings.Contains(string(body), `"kind":"tm:sys:version:versionstats"`) {
		metadata["interface"] = "iControl REST API"
		metadata["unauthenticated_api"] = true
	} else if strings.Contains(string(body), "tmui") || strings.Contains(string(body), "Configuration Utility") {
		metadata["interface"] = "management"
	}

	return &FingerprintResult{
		Technology: "f5-bigip",
		Version:    version,
		CPEs:       []string{buildBigIPCPE(version)},
		Metadata:   metadata,
	}, nil
}

func matchHeaders(resp *http.Response) bool {
	// Check Server header for BigIP or BIG-IP
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverHeader, "bigip") || strings.Contains(serverHeader, "big-ip") {
		return true
	}

	// Check Set-Cookie header for BIGipServer cookies
	cookies := resp.Header.Values("Set-Cookie")
	for _, cookie := range cookies {
		if strings.Contains(cookie, "BIGipServer") {
			return true
		}
	}

	// Check WWW-Authenticate for iControl REST realm or Enterprise Manager realm
	wwwAuth := resp.Header.Get("WWW-Authenticate")
	if strings.Contains(wwwAuth, "iControl") || strings.Contains(wwwAuth, "Enterprise Manager") {
		return true
	}

	// Check F5-Login-Page header (present on TMUI login pages)
	if resp.Header.Get("F5-Login-Page") != "" {
		return true
	}

	return false
}

func matchBody(body []byte) bool {
	bodyStr := string(body)

	// Check for iControl REST API JSON response (specific to BIG-IP)
	if strings.Contains(bodyStr, `"kind":"tm:sys:version:versionstats"`) ||
	   strings.Contains(bodyStr, `"kind": "tm:sys:version:versionstats"`) {
		return true
	}

	for _, pattern := range bigIPBodyPatterns {
		if pattern.MatchString(bodyStr) {
			return true
		}
	}
	return false
}

func parseIControlVersion(body []byte) (string, string) {
	var iControl iControlVersionResponse
	if err := json.Unmarshal(body, &iControl); err != nil {
		return "", ""
	}

	// Validate it's actually iControl REST API by checking kind field
	if iControl.Kind != "tm:sys:version:versionstats" {
		return "", ""
	}

	// Extract version and build from nested structure
	version := ""
	build := ""

	for _, entry := range iControl.Entries {
		if versionEntry, ok := entry.NestedStats.Entries["Version"]; ok {
			version = versionEntry.Description
		}
		if buildEntry, ok := entry.NestedStats.Entries["Build"]; ok {
			build = buildEntry.Description
		}
		break // Use first entry only; iControl typically has a single entry
	}

	return version, build
}

func extractBigIPVersionFromHTML(body []byte) string {
	if matches := bigIPVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}
	return ""
}

func buildBigIPCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:f5:big-ip_local_traffic_manager:%s:*:*:*:*:*:*:*", version)
}
