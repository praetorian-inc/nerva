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

// NetgearFingerprinter detects Netgear consumer/SOHO routers.
//
// Detection Strategy:
// Netgear routers expose a web management interface and a /currentsetting.htm
// endpoint that returns key=value pairs. Detection uses multiple signals:
//
//  1. WWW-Authenticate header realm contains "NETGEAR" — standalone-sufficient
//  2. Body contains both "Model=" and "Firmware=" — standalone-sufficient
//     (currentsetting.htm format, unique to Netgear)
//  3. Corroborated: Body matches NETGEAR brand AND (model pattern OR known
//     Netgear UI elements like routerlogin.net, NETGEAR_) — both required
//
// "NETGEAR" brand alone in body is NOT sufficient — the brand name appears on
// comparison pages, news sites, and third-party documentation.
//
// Active Probe: GET /currentsetting.htm (unique Netgear endpoint)
//
// Default Ports:
//   - 80: HTTP management interface
//   - 443: HTTPS management interface
//
// Version Detection:
// From /currentsetting.htm: Firmware=V1.3.2.134 format
// From body: firmware context keyword followed by version number
//
// Model Detection:
// From /currentsetting.htm: Model=R7000P format
// From body: R-series (R7000P, R8000), RAX-series (RAX50), Nighthawk
//
// CPE Generation:
//   - Model known → cpe:2.3:o:netgear:{model_firmware}:{version}:*:*:*:*:*:*:*
//   - Unknown model → cpe:2.3:o:netgear:router_firmware:{version}:*:*:*:*:*:*:*
type NetgearFingerprinter struct{}

func init() {
	Register(&NetgearFingerprinter{})
}

// netgearBrandPattern matches NETGEAR brand in page body (case-insensitive).
var netgearBrandPattern = regexp.MustCompile(`(?i)NETGEAR`)

// netgearModelFromSettingsPattern extracts model from currentsetting.htm format.
// Captures: "R7000P", "R8000", "RAX50"
var netgearModelFromSettingsPattern = regexp.MustCompile(`Model=([A-Z0-9]+(?:[-_][A-Z0-9]+)?)`)

// netgearModelFromBodyPattern matches Netgear model identifiers in page body.
// Captures R-series and RAX-series models, plus Nighthawk brand.
var netgearModelFromBodyPattern = regexp.MustCompile(`(?i)\b(R[0-9]{4,5}[A-Z]?|RAX[0-9]+|Nighthawk)\b`)

// netgearPathPattern matches known Netgear UI elements in body.
var netgearPathPattern = regexp.MustCompile(`(?i)(?:routerlogin\.net|NETGEAR_)`)

// netgearFirmwareFromSettingsPattern extracts firmware from currentsetting.htm format.
// Captures: "1.3.2.134" from "Firmware=V1.3.2.134"
var netgearFirmwareFromSettingsPattern = regexp.MustCompile(
	`Firmware=V?([0-9]+\.[0-9]+(?:\.[0-9]+)*(?:\.[0-9]+)?)`,
)

// netgearFirmwareContextPattern extracts firmware version from body with context keyword.
// The trailing `(?:"|\s|,|}|$)` anchors to a JSON/config delimiter to prevent backtracking
// matches like "1.0" from "1.0.0abc".
var netgearFirmwareContextPattern = regexp.MustCompile(
	`(?i)(?:firmwareVersion|fw_?ver|firmware)[:\s"=]*V?([0-9]+\.[0-9]+(?:\.[0-9]+)*)(?:"|\s|,|}|$)`,
)

// netgearVersionValidRegex validates extracted version strings before CPE use.
var netgearVersionValidRegex = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)*$`)

// netgearMaxVersionLen caps version string length to guard against pathologically long strings.
const netgearMaxVersionLen = 20

func (f *NetgearFingerprinter) Name() string {
	return "netgear-router"
}

func (f *NetgearFingerprinter) ProbeEndpoint() string {
	return "/currentsetting.htm"
}

// Match is a fast pre-filter. Accepts responses with NETGEAR WWW-Authenticate or
// text/html content-type. Rejects 5xx server errors.
func (f *NetgearFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Accept if WWW-Authenticate header contains "NETGEAR" (case-insensitive).
	// Check both canonical ("Www-Authenticate") and wire form ("WWW-Authenticate").
	for _, v := range append(resp.Header["Www-Authenticate"], resp.Header["WWW-Authenticate"]...) {
		if strings.Contains(strings.ToLower(v), "netgear") {
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

// Fingerprint performs full detection and returns a result if this is a Netgear device.
// Returns nil, nil for non-matching responses.
func (f *NetgearFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > 1<<20 {
		return nil, nil
	}

	bodyStr := string(body)

	// Signal 1 (standalone): WWW-Authenticate realm contains "NETGEAR".
	// Check both canonical and wire-form keys.
	authHasNetgear := false
	for _, v := range append(resp.Header["Www-Authenticate"], resp.Header["WWW-Authenticate"]...) {
		if strings.Contains(strings.ToLower(v), "netgear") {
			authHasNetgear = true
			break
		}
	}

	// Signal 2 (standalone): currentsetting.htm format — both Model= and Firmware= present
	hasModelField := strings.Contains(bodyStr, "Model=")
	hasFirmwareField := strings.Contains(bodyStr, "Firmware=")
	isCurrentSettings := hasModelField && hasFirmwareField

	// Signal 3 (corroborated): NETGEAR brand AND (model pattern OR known Netgear UI element)
	hasBrand := netgearBrandPattern.MatchString(bodyStr)
	hasModel := netgearModelFromBodyPattern.MatchString(bodyStr)
	hasPath := netgearPathPattern.MatchString(bodyStr)
	brandCorroborated := hasBrand && (hasModel || hasPath)

	detected := authHasNetgear || isCurrentSettings || brandCorroborated
	if !detected {
		return nil, nil
	}

	metadata := make(map[string]any)
	metadata["vendor"] = "Netgear"
	metadata["product"] = "Netgear Router"

	// Extract model: prefer currentsetting.htm format, fall back to body pattern
	model := extractNetgearModelFromSettings(bodyStr)
	if model == "" {
		model = extractNetgearModelFromBody(bodyStr)
	}
	if model != "" {
		metadata["product_model"] = model
	}

	// Extract version: prefer currentsetting.htm format, fall back to body context
	version := extractNetgearVersionFromSettings(bodyStr)
	if version == "" {
		version = extractNetgearVersionFromBody(bodyStr)
	}

	cpeProduct := netgearCPEProduct(model)

	return &FingerprintResult{
		Technology: "netgear-router",
		Version:    version,
		CPEs:       buildNetgearCPEs(cpeProduct, version),
		Metadata:   metadata,
	}, nil
}

// extractNetgearVersionFromSettings extracts firmware version from currentsetting.htm format.
// Handles "Firmware=V1.3.2.134" — strips the V prefix.
// Returns empty string if not found or validation fails.
func extractNetgearVersionFromSettings(bodyStr string) string {
	matches := netgearFirmwareFromSettingsPattern.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return ""
	}
	version := matches[1]
	if len(version) > netgearMaxVersionLen {
		return ""
	}
	if !netgearVersionValidRegex.MatchString(version) {
		return ""
	}
	return version
}

// extractNetgearVersionFromBody extracts firmware version from body with context keyword.
// Returns empty string if not found or validation fails.
func extractNetgearVersionFromBody(bodyStr string) string {
	allMatches := netgearFirmwareContextPattern.FindAllStringSubmatch(bodyStr, -1)
	for _, matches := range allMatches {
		if len(matches) < 2 {
			continue
		}
		version := matches[1]
		if len(version) > netgearMaxVersionLen {
			continue
		}
		if !netgearVersionValidRegex.MatchString(version) {
			continue
		}
		return version
	}
	return ""
}

// extractNetgearModelFromSettings extracts model from currentsetting.htm format.
// Handles "Model=R7000P" format.
func extractNetgearModelFromSettings(bodyStr string) string {
	matches := netgearModelFromSettingsPattern.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// extractNetgearModelFromBody extracts a Netgear model identifier from the page body.
// Returns empty string if no model is identified.
func extractNetgearModelFromBody(bodyStr string) string {
	matches := netgearModelFromBodyPattern.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// netgearCPEProduct maps a model identifier to the NVD CPE product string.
func netgearCPEProduct(model string) string {
	if model == "" {
		return "router_firmware"
	}
	product := strings.ToLower(model)
	return product + "_firmware"
}

// buildNetgearCPEs constructs CPE strings for a Netgear device.
// When version is empty, uses "*" per CPE 2.3 spec.
func buildNetgearCPEs(product, version string) []string {
	v := version
	if v == "" {
		v = "*"
	}
	return []string{
		fmt.Sprintf("cpe:2.3:o:netgear:%s:%s:*:*:*:*:*:*:*", product, v),
	}
}
