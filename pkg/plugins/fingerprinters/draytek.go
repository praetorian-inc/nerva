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
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// DrayTekVigorFingerprinter detects DrayTek Vigor routers.
//
// Detection Strategy:
// DrayTek Vigor routers expose a web management interface. Detection uses
// corroborated signals: body must contain BOTH a brand pattern AND a model
// pattern. Brand alone is NOT sufficient — "DrayTek" appears on comparison
// pages, news sites, and third-party documentation.
//
// False-positive surface: a third-party page (news article, Shodan results)
// could contain both "DrayTek" and a Vigor model number. The probe path
// /weblogin.htm is the primary mitigating factor — generic web servers do not
// serve this path.
//
// Active Probe: GET /weblogin.htm (standard DrayTek Vigor login endpoint)
//
// Default Ports:
//   - 80: HTTP management interface
//   - 443: HTTPS management interface
//
// Version Detection:
// DrayTek firmware versions appear in several body contexts:
//   - fwVersion=4.4.5.3
//   - fw_ver: 1.5.1
//   - FwVer:"4.4.5"
//   - firmware version 4.4.5.3
//
// Model Detection:
// Vigor series: Vigor3910, Vigor2960, Vigor165, Vigor1000B, VigorLTE200
//
// CPE Generation:
//   - Model known → cpe:2.3:o:draytek:{model}_firmware:{version}:*:*:*:*:*:*:*
//   - Unknown model → cpe:2.3:o:draytek:vigor_firmware:{version}:*:*:*:*:*:*:*
type DrayTekVigorFingerprinter struct{}

func init() {
	Register(&DrayTekVigorFingerprinter{})
}

// draytekBrandPattern matches DrayTek brand in page body (case-insensitive).
var draytekBrandPattern = regexp.MustCompile(`(?i)DrayTek`)

// draytekModelPattern matches DrayTek Vigor model identifiers including LTE variants.
// Captures: "Vigor3910", "Vigor2960", "Vigor165", "Vigor1000B", "VigorLTE200"
//
// Vigor series examples: Vigor3910 (4-digit), Vigor2960 (4-digit), Vigor165 (3-digit)
// LTE variants:          VigorLTE200 (LTE prefix with 3-digit)
// Suffix variants:       Vigor1000B (4-digit with letter suffix)
var draytekModelPattern = regexp.MustCompile(`(?i)\bVigor\s?(?:LTE\s?)?\d{3,4}[A-Za-z]{0,3}\b`)

// draytekModelExtractPattern captures the full Vigor model identifier for extraction.
var draytekModelExtractPattern = regexp.MustCompile(`(?i)\b(Vigor\s?(?:LTE\s?)?\d{3,4}[A-Za-z]{0,3})\b`)

// draytekFirmwareContextPattern extracts firmware version preceded by firmware context keywords.
// Matches: fwVersion=4.4.5.3, fw_ver: 1.5.1, FwVer:"4.4.5", firmware: 4.4.5.3,
//          firmware version 4.4.5.3
//
// The trailing `(?:["\s,}<]|$)` ensures the version ends at a JSON/config/HTML delimiter,
// preventing partial matches on version-like strings in other contexts.
var draytekFirmwareContextPattern = regexp.MustCompile(
	`(?i)(?:fwVersion|fw_ver|firmware(?:\s+version)?|FwVer)["\s:=]*["\s]*(\d+\.\d+\.\d+(?:\.\d+)?)(?:["\s,}<]|$)`,
)

// draytekVersionValidRegex validates extracted version strings before CPE use.
var draytekVersionValidRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(\.\d+)?$`)

// draytekMaxVersionLen caps version string length to guard against pathologically long strings.
const draytekMaxVersionLen = 20

func (f *DrayTekVigorFingerprinter) Name() string {
	return "draytek-vigor"
}

func (f *DrayTekVigorFingerprinter) ProbeEndpoint() string {
	return "/weblogin.htm"
}

// ProbeAccept returns the Accept header for the active probe.
// /weblogin.htm serves HTML; requesting text/html avoids 406 from devices
// that respect content negotiation.
func (f *DrayTekVigorFingerprinter) ProbeAccept() string {
	return "text/html"
}

// Match is a fast pre-filter. Accepts responses with text/html content-type
// and status codes 200-499. Rejects 5xx server errors.
func (f *DrayTekVigorFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Accept text/html for body-based detection
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(strings.ToLower(ct), "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full detection and returns a result if this is a DrayTek Vigor device.
// Returns nil, nil for non-matching responses.
func (f *DrayTekVigorFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Require text/html — DrayTek management interface always serves HTML.
	ct := resp.Header.Get("Content-Type")
	if !strings.Contains(strings.ToLower(ct), "text/html") {
		return nil, nil
	}

	if len(body) > 1<<20 {
		return nil, nil
	}

	bodyStr := string(body)

	// Corroborated detection: Brand pattern AND model pattern are both required.
	// Brand alone is insufficient — DrayTek appears on news and comparison sites.
	hasBrand := draytekBrandPattern.MatchString(bodyStr)
	hasModel := draytekModelPattern.MatchString(bodyStr)

	if !hasBrand || !hasModel {
		return nil, nil
	}

	metadata := make(map[string]any)
	metadata["vendor"] = "DrayTek"
	metadata["product"] = "DrayTek Vigor Router"

	model := extractDrayTekModel(bodyStr)
	if model != "" {
		metadata["product_model"] = model
	}

	version := extractDrayTekVersion(bodyStr)
	cpeProduct := draytekCPEProduct(model)

	return &FingerprintResult{
		Technology: "draytek-vigor",
		Version:    version,
		CPEs:       buildDrayTekCPEs(cpeProduct, version),
		Metadata:   metadata,
	}, nil
}

// extractDrayTekVersion extracts firmware version from DrayTek Vigor page body.
// Requires firmware context keyword to avoid false matches on JS/CSS versions.
// Returns empty string if no version is found or validation fails.
func extractDrayTekVersion(bodyStr string) string {
	allMatches := draytekFirmwareContextPattern.FindAllStringSubmatch(bodyStr, -1)
	for _, matches := range allMatches {
		if len(matches) < 2 {
			continue
		}
		version := matches[1]
		if len(version) > draytekMaxVersionLen {
			continue
		}
		if !draytekVersionValidRegex.MatchString(version) {
			continue
		}
		return version
	}
	return ""
}

// extractDrayTekModel extracts a DrayTek Vigor model identifier from the page body.
// Normalizes to lowercase with spaces removed.
// Returns empty string if no model is identified.
func extractDrayTekModel(bodyStr string) string {
	matches := draytekModelExtractPattern.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return ""
	}
	// Normalize: lowercase, remove spaces
	model := strings.ToLower(matches[1])
	model = strings.ReplaceAll(model, " ", "")
	return model
}

// draytekCPEProduct maps a normalized model identifier to the NVD CPE product string.
// Appends _firmware per NVD convention.
func draytekCPEProduct(model string) string {
	if model == "" {
		return "vigor_firmware"
	}
	return model + "_firmware"
}

// buildDrayTekCPEs constructs CPE strings for a DrayTek Vigor device.
// When version is empty, uses "*" per CPE 2.3 spec.
// Rejects CPE metacharacters (:, *, ?) in product and version to prevent injection.
func buildDrayTekCPEs(product, version string) []string {
	v := version
	if v == "" || strings.ContainsAny(v, ":*?") {
		v = "*"
	}
	if strings.ContainsAny(product, ":*?") {
		product = "vigor_firmware"
	}
	return []string{
		fmt.Sprintf("cpe:2.3:o:draytek:%s:%s:*:*:*:*:*:*:*", product, v),
	}
}
