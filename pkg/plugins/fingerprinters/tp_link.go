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

// TPLinkFingerprinter detects TP-Link consumer/SOHO routers.
//
// Detection Strategy:
// TP-Link routers expose a web management interface. Detection uses multiple signals:
//
//  1. WWW-Authenticate header realm contains "TP-LINK" — standalone-sufficient
//  2. Corroborated: Body matches TP-Link brand pattern AND (model pattern OR
//     known TP-Link path like /webpages/ or /cgi/getParm) — both required together
//
// "TP-Link" brand alone in body is NOT sufficient — the brand name appears on
// comparison pages, news sites, and third-party documentation.
//
// Active Probe: GET /webpages/login.html (standard TP-Link login endpoint)
//
// Default Ports:
//   - 80: HTTP management interface
//   - 443: HTTPS management interface
//
// Version Detection:
// TP-Link firmware versions appear in several body contexts:
//   - "firmwareVersion":"1.0.0"
//   - fw_ver=1.0.0
//   - var modelVersion = "1.0.0"
//
// Model Detection:
// TL-series: TL-WR841N, TL-WR940N, TL-SG1005P
// Archer series: Archer C7, Archer AX3000, Archer A7
//
// CPE Generation:
//   - Model known → cpe:2.3:o:tp-link:{model_firmware}:{version}:*:*:*:*:*:*:*
//   - Unknown model → cpe:2.3:o:tp-link:router_firmware:{version}:*:*:*:*:*:*:*
type TPLinkFingerprinter struct{}

func init() {
	Register(&TPLinkFingerprinter{})
}

// tplinkBrandPattern matches TP-Link brand in page body (case-insensitive).
var tplinkBrandPattern = regexp.MustCompile(`(?i)TP-?LINK`)

// tplinkModelPattern matches TP-Link model identifiers including TL-series and Archer series.
// Captures: "TL-WR841N", "Archer C7", "Archer AX3000", "TL-SG1005P"
//
// TL-series examples: TL-WR841N (letters WR, digits 841, suffix N)
//
//	TL-SG1005P (letters SG, digits 1005, suffix P)
//
// Archer-series:      Archer C7 (letter C, digit 7)
//
//	Archer AX3000 (letters AX, digits 3000)
var tplinkModelPattern = regexp.MustCompile(`(?i)\b((?:TL-[A-Z]{1,4}[0-9]{1,5}[A-Z]?|Archer\s+[A-Z]{1,3}[0-9]{1,5}[A-Z]?))\b`)

// tplinkPathPattern matches known TP-Link management paths in body.
var tplinkPathPattern = regexp.MustCompile(`(?i)(?:/webpages/|/cgi/getParm|tplinkwifi\.net)`)

// tplinkFirmwareContextPattern extracts firmware version preceded by firmware context keywords.
// Matches: "firmwareVersion":"1.0.0", fw_ver=1.0.0, var modelVersion = "1.0.0"
//
// The trailing `(?:"|\s|,|}|$)` ensures the version ends at a JSON/config delimiter,
// preventing partial matches like "1.0" from "1.0.0abc" (where "." would satisfy
// the looser `[^0-9a-zA-Z]` boundary via backtracking).
var tplinkFirmwareContextPattern = regexp.MustCompile(
	`(?i)(?:firmwareVersion|fw_?ver|modelVersion|firmware)["\s:=]*["\s]*(\d+\.\d+(?:\.\d+)*)(?:"|\s|,|}|$)`,
)

// tplinkVersionValidRegex validates extracted version strings before CPE use.
var tplinkVersionValidRegex = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)*$`)

// tplinkMaxVersionLen caps version string length to guard against pathologically long strings.
const tplinkMaxVersionLen = 20

func (f *TPLinkFingerprinter) Name() string {
	return "tp-link-router"
}

func (f *TPLinkFingerprinter) ProbeEndpoint() string {
	return "/webpages/login.html"
}

// Match is a fast pre-filter. Accepts responses with TP-Link WWW-Authenticate or
// text/html content-type. Rejects 5xx server errors.
func (f *TPLinkFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Accept if WWW-Authenticate header contains "TP-LINK" (case-insensitive).
	// Check both the canonical Go form ("Www-Authenticate") and the wire form
	// ("WWW-Authenticate") because test http.Header literals use the wire form.
	wwwAuthVals := append(resp.Header["Www-Authenticate"], resp.Header["WWW-Authenticate"]...)
	for _, v := range wwwAuthVals {
		if strings.Contains(strings.ToLower(v), "tp-link") {
			return true
		}
	}

	// Accept text/html for body-based detection
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(strings.ToLower(ct), "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full detection and returns a result if this is a TP-Link device.
// Returns nil, nil for non-matching responses.
func (f *TPLinkFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > 1<<20 {
		return nil, nil
	}

	bodyStr := string(body)

	// Signal 1 (standalone): WWW-Authenticate realm contains "TP-LINK".
	// Check both canonical and wire-form keys (same reason as Match).
	authHasTPLink := false
	for _, v := range append(resp.Header["Www-Authenticate"], resp.Header["WWW-Authenticate"]...) {
		if strings.Contains(strings.ToLower(v), "tp-link") {
			authHasTPLink = true
			break
		}
	}

	// Signal 2 (corroborated): Brand pattern AND (model OR known path)
	hasBrand := tplinkBrandPattern.MatchString(bodyStr)
	hasModel := tplinkModelPattern.MatchString(bodyStr)
	hasPath := tplinkPathPattern.MatchString(bodyStr)
	brandCorroborated := hasBrand && (hasModel || hasPath)

	detected := authHasTPLink || brandCorroborated
	if !detected {
		return nil, nil
	}

	metadata := make(map[string]any)
	metadata["vendor"] = "TP-Link"
	metadata["product"] = "TP-Link Router"

	model := extractTPLinkModel(bodyStr)
	if model != "" {
		metadata["product_model"] = model
	}

	version := extractTPLinkVersion(bodyStr)
	cpeProduct := tplinkCPEProduct(model)

	return &FingerprintResult{
		Technology: "tp-link-router",
		Version:    version,
		CPEs:       buildTPLinkCPEs(cpeProduct, version),
		Metadata:   metadata,
	}, nil
}

// extractTPLinkVersion extracts firmware version from TP-Link page body.
// Requires firmware context keyword to avoid false matches on JS/CSS versions.
// Returns empty string if no version is found or validation fails.
func extractTPLinkVersion(bodyStr string) string {
	allMatches := tplinkFirmwareContextPattern.FindAllStringSubmatch(bodyStr, -1)
	for _, matches := range allMatches {
		if len(matches) < 2 {
			continue
		}
		version := matches[1]
		if len(version) > tplinkMaxVersionLen {
			continue
		}
		if !tplinkVersionValidRegex.MatchString(version) {
			continue
		}
		return version
	}
	return ""
}

// extractTPLinkModel extracts a TP-Link model identifier from the page body.
// Returns empty string if no model is identified.
func extractTPLinkModel(bodyStr string) string {
	matches := tplinkModelPattern.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// tplinkCPEProduct maps a model identifier to the NVD CPE product string.
// Lowercases the model and appends _firmware per NVD convention.
func tplinkCPEProduct(model string) string {
	if model == "" {
		return "router_firmware"
	}
	// Normalize: lowercase, replace spaces with underscores, collapse multiple underscores
	product := strings.ToLower(model)
	product = strings.ReplaceAll(product, " ", "_")
	return product + "_firmware"
}

// buildTPLinkCPEs constructs CPE strings for a TP-Link device.
// When version is empty, uses "*" per CPE 2.3 spec.
func buildTPLinkCPEs(product, version string) []string {
	v := version
	if v == "" {
		v = "*"
	}
	return []string{
		fmt.Sprintf("cpe:2.3:o:tp-link:%s:%s:*:*:*:*:*:*:*", product, v),
	}
}
