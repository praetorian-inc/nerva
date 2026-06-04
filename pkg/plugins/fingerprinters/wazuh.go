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
Package fingerprinters provides HTTP fingerprinting for Wazuh SIEM/XDR.

# Detection Strategy

Wazuh is an open-source security platform combining SIEM and XDR capabilities.
Two distinct surfaces are detected passively from the root `/` response:

  - Surface A: Wazuh Manager REST API (default port 55000). The API self-identifies
    via a JSON body containing `"title":"Wazuh API"`. Version is extracted from the
    `api_version` field in the same body. This is a strong, canonical signal per the
    Wazuh API documentation.

  - Surface B: Wazuh Dashboard (an OpenSearch Dashboards fork, default ports 443/5601).
    The HTML login page contains `Wazuh` in <title> and references `/plugins/wazuh/`
    asset paths. The dual-marker requirement defeats vanilla OpenSearch Dashboards and
    incidental "Wazuh" string mentions. Version is rarely exposed unauthenticated;
    best-effort regex extraction with wildcard CPE fallback.

# CPE

cpe:2.3:a:wazuh:wazuh:VERSION:*:*:*:*:*:*:* (NVD-canonical, both surfaces)
*/
package fingerprinters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const (
	wazuhDashboardTitleMarker = "Wazuh"
	wazuhDashboardAssetMarker = "/plugins/wazuh/"
	wazuhBodyCap              = 2 * 1024 * 1024 // 2 MiB
	maxWazuhVersionFieldLen   = 256
)

// wazuhVersionRegex is the anchored validator for extracted version strings.
// Constrained to major versions 3-5 to reduce false-positive risk.
var wazuhVersionRegex = regexp.MustCompile(`^[3-5]\.\d{1,2}\.\d{1,2}$`)

// wazuhAPITitleRegex matches the canonical Wazuh API title field, tolerating
// whitespace variants between key and value (minified or pretty-printed JSON).
var wazuhAPITitleRegex = regexp.MustCompile(`"title"\s*:\s*"Wazuh API"`)

// wazuhAPIVersionExtractRegex extracts api_version from Wazuh API JSON responses.
var wazuhAPIVersionExtractRegex = regexp.MustCompile(`"api_version"\s*:\s*"(\d+\.\d+\.\d+)"`)

// wazuhDashboardVersionExtractRegex is a best-effort extractor for version numbers
// appearing near "Wazuh" in HTML/JS bodies. The generous prefix allows for labels
// like "Wazuh 4.9.1" or "wazuh/4.9.1" in asset URLs.
var wazuhDashboardVersionExtractRegex = regexp.MustCompile(`[Ww]azuh[^0-9]{0,40}(\d+\.\d+\.\d+)`)

// WazuhAPIFingerprinter detects the Wazuh Manager REST API via root `/` JSON response.
type WazuhAPIFingerprinter struct{}

// WazuhDashboardFingerprinter detects the Wazuh Dashboard via root `/` HTML response.
type WazuhDashboardFingerprinter struct{}

func init() {
	Register(&WazuhAPIFingerprinter{})
	Register(&WazuhDashboardFingerprinter{})
}

// --- WazuhAPIFingerprinter ---

func (f *WazuhAPIFingerprinter) Name() string {
	return "wazuh-api"
}

func (f *WazuhAPIFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json")
}

func (f *WazuhAPIFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}
	if len(body) > wazuhBodyCap {
		return nil, nil
	}
	if bytes.Contains(body, []byte(":*:")) {
		return nil, nil
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json") {
		return nil, nil
	}
	if !wazuhAPITitleRegex.Match(body) {
		return nil, nil
	}

	version := extractWazuhAPIVersion(body)

	metadata := map[string]any{
		"vendor":  "Wazuh",
		"product": "Wazuh API",
		"surface": "manager-api",
	}

	return &FingerprintResult{
		Technology: "wazuh-api",
		Version:    version,
		CPEs:       []string{buildWazuhCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityInfo,
	}, nil
}

// --- WazuhDashboardFingerprinter ---

func (f *WazuhDashboardFingerprinter) Name() string {
	return "wazuh-dashboard"
}

func (f *WazuhDashboardFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html")
}

func (f *WazuhDashboardFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}
	if len(body) > wazuhBodyCap {
		return nil, nil
	}
	if bytes.Contains(body, []byte(":*:")) {
		return nil, nil
	}
	if !strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return nil, nil
	}

	// Dual-marker requirement: defeats vanilla OpenSearch Dashboards and incidental Wazuh mentions.
	if !bytes.Contains(body, []byte(wazuhDashboardTitleMarker)) {
		return nil, nil
	}
	if !bytes.Contains(body, []byte(wazuhDashboardAssetMarker)) {
		return nil, nil
	}

	version := extractWazuhDashboardVersion(body)

	metadata := map[string]any{
		"vendor":  "Wazuh",
		"product": "Wazuh Dashboard",
		"surface": "dashboard",
	}
	if version != "" {
		metadata["version_source"] = "html_pattern"
	}

	return &FingerprintResult{
		Technology: "wazuh-dashboard",
		Version:    version,
		CPEs:       []string{buildWazuhCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityInfo,
	}, nil
}

// --- Shared helpers ---

// extractWazuhAPIVersion attempts JSON-parse first for clean extraction, falls back
// to regex. Returns empty string when no valid version is found.
func extractWazuhAPIVersion(body []byte) string {
	var parsed struct {
		Data struct {
			APIVersion string `json:"api_version"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err == nil && parsed.Data.APIVersion != "" {
		v := parsed.Data.APIVersion
		if len(v) <= maxWazuhVersionFieldLen && wazuhVersionRegex.MatchString(v) {
			return v
		}
	}

	// Regex fallback for non-standard JSON formatting.
	m := wazuhAPIVersionExtractRegex.FindSubmatch(body)
	if len(m) >= 2 {
		v := string(m[1])
		if len(v) <= maxWazuhVersionFieldLen && wazuhVersionRegex.MatchString(v) {
			return v
		}
	}
	return ""
}

// extractWazuhDashboardVersion uses a best-effort regex to find a version string
// in the HTML/JS body. Returns empty string when no valid version is found.
func extractWazuhDashboardVersion(body []byte) string {
	m := wazuhDashboardVersionExtractRegex.FindSubmatch(body)
	if len(m) >= 2 {
		v := string(m[1])
		if len(v) <= maxWazuhVersionFieldLen && wazuhVersionRegex.MatchString(v) {
			return v
		}
	}
	return ""
}

// buildWazuhCPE constructs a CPE 2.3 identifier for Wazuh.
// When version is empty or fails the anchored validator, the wildcard "*" is substituted.
func buildWazuhCPE(version string) string {
	if version == "" || !wazuhVersionRegex.MatchString(version) {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:wazuh:wazuh:%s:*:*:*:*:*:*:*", version)
}
