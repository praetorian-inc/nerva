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

// DLinkFingerprinter detects D-Link consumer/SOHO routers.
//
// Detection Strategy:
// D-Link routers expose a web management interface. Detection uses multiple signals:
//
//  1. Server header matches D-Link model pattern — standalone-sufficient
//  2. Corroborated: Body matches D-Link brand pattern AND (model pattern in body OR
//     known D-Link path like /login.htm, /info/Login.html, dlinkrouter.local) —
//     both required together
//
// "D-Link" brand alone in body is NOT sufficient — the brand name appears on
// comparison pages, news sites, and third-party documentation.
//
// Active Probe: GET / (root path)
//
// Default Ports:
//   - 80: HTTP management interface
//   - 8080: Alternative HTTP management interface
//
// Version Detection:
// D-Link firmware versions appear in body firmware fields or Server header version suffix.
//
// Model Detection:
// DIR series: DIR-825, DIR-615, DIR-300
// DAP series: DAP-1520, DAP-2610
// DSL series: DSL-2640B, DSL-2750B
// DCS series: DCS-930L, DCS-5020L
// DWR series: DWR-932, DWR-118
// DHP series: DHP-1565
//
// CPE Generation:
//   - Note: NVD vendor string is "dlink" (NO HYPHEN)
//   - Model known → cpe:2.3:o:dlink:{model_firmware}:{version}:*:*:*:*:*:*:*
//   - Unknown model → cpe:2.3:o:dlink:router_firmware:{version}:*:*:*:*:*:*:*
type DLinkFingerprinter struct{}

func init() {
	Register(&DLinkFingerprinter{})
}

// dlinkServerPattern matches D-Link model identifiers in the Server header.
// Captures DIR, DAP, DSL, DCS, DWR, DHP model prefixes.
var dlinkServerPattern = regexp.MustCompile(`(?i)(?:DIR|DAP|DSL|DCS|DWR|DHP)-\d+`)

// dlinkBrandPattern matches D-Link brand in page body (case-insensitive).
var dlinkBrandPattern = regexp.MustCompile(`(?i)D-?Link`)

// dlinkModelPattern matches D-Link model identifiers in page body.
// Captures: "DIR-825", "DAP-1520", "DSL-2640B", "DWR-932"
var dlinkModelPattern = regexp.MustCompile(`(?i)\b((?:DIR|DAP|DSL|DCS|DWR|DHP)-[A-Z0-9]+(?:[-][A-Z0-9]+)?)\b`)

// dlinkPathPattern matches known D-Link management paths in body.
var dlinkPathPattern = regexp.MustCompile(`(?i)(?:/info/Login\.html|dlinkrouter\.local)`)

// dlinkFirmwareContextPattern extracts firmware version preceded by context keywords.
var dlinkFirmwareContextPattern = regexp.MustCompile(
	`(?i)(?:firmwareVersion|fw_?ver|firmware)[:\s"=]*(\d+\.\d+(?:\.\d+)*)(?:"|\s|,|}|$)`,
)

// dlinkVersionValidRegex validates extracted version strings before CPE use.
var dlinkVersionValidRegex = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)*$`)

// dlinkMaxVersionLen caps version string length to guard against pathologically long strings.
const dlinkMaxVersionLen = 20

func (f *DLinkFingerprinter) Name() string {
	return "d-link-router"
}

func (f *DLinkFingerprinter) ProbeEndpoint() string {
	return ""
}

// Match is a fast pre-filter. Accepts responses with a D-Link model in Server header or
// text/html content-type. Rejects 5xx server errors.
func (f *DLinkFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Accept if Server header matches D-Link model pattern
	server := resp.Header.Get("Server")
	if server != "" && dlinkServerPattern.MatchString(server) {
		return true
	}

	// Accept text/html for body-based detection
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(strings.ToLower(ct), "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full detection and returns a result if this is a D-Link device.
// Returns nil, nil for non-matching responses.
func (f *DLinkFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > 1<<20 {
		return nil, nil
	}

	bodyStr := string(body)

	// Signal 1 (standalone): Server header contains D-Link model pattern
	server := resp.Header.Get("Server")
	serverHasModel := server != "" && dlinkServerPattern.MatchString(server)

	// Signal 2 (corroborated): Brand AND (model in body OR known D-Link path)
	hasBrand := dlinkBrandPattern.MatchString(bodyStr)
	hasModel := dlinkModelPattern.MatchString(bodyStr)
	hasPath := dlinkPathPattern.MatchString(bodyStr)
	brandCorroborated := hasBrand && (hasModel || hasPath)

	detected := serverHasModel || brandCorroborated
	if !detected {
		return nil, nil
	}

	metadata := make(map[string]any)
	metadata["vendor"] = "D-Link"
	metadata["product"] = "D-Link Router"

	// Prefer model from body; fall back to Server header
	model := extractDLinkModel(bodyStr)
	if model == "" && server != "" {
		serverMatches := dlinkModelPattern.FindStringSubmatch(server)
		if len(serverMatches) >= 2 {
			model = serverMatches[1]
		}
	}
	if model != "" {
		metadata["product_model"] = model
	}

	version := extractDLinkVersion(bodyStr)
	// Also try extracting version from Server header suffix if body yields nothing
	if version == "" && server != "" {
		version = extractDLinkVersion(server)
	}

	cpeProduct := dlinkCPEProduct(model)

	return &FingerprintResult{
		Technology: "d-link-router",
		Version:    version,
		CPEs:       buildDLinkCPEs(cpeProduct, version),
		Metadata:   metadata,
	}, nil
}

// extractDLinkVersion extracts firmware version from D-Link page body or header.
// Returns empty string if no version is found or validation fails.
func extractDLinkVersion(bodyStr string) string {
	allMatches := dlinkFirmwareContextPattern.FindAllStringSubmatch(bodyStr, -1)
	for _, matches := range allMatches {
		if len(matches) < 2 {
			continue
		}
		version := matches[1]
		if len(version) > dlinkMaxVersionLen {
			continue
		}
		if !dlinkVersionValidRegex.MatchString(version) {
			continue
		}
		return version
	}
	return ""
}

// extractDLinkModel extracts a D-Link model identifier from the page body.
// Returns empty string if no model is identified.
func extractDLinkModel(bodyStr string) string {
	matches := dlinkModelPattern.FindStringSubmatch(bodyStr)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// dlinkCPEProduct maps a model identifier to the NVD CPE product string.
// NVD uses "dlink" (NO HYPHEN) as the vendor name.
func dlinkCPEProduct(model string) string {
	if model == "" {
		return "router_firmware"
	}
	product := strings.ToLower(model)
	return product + "_firmware"
}

// buildDLinkCPEs constructs CPE strings for a D-Link device.
// NVD vendor is "dlink" (no hyphen). When version is empty, uses "*" per CPE 2.3 spec.
func buildDLinkCPEs(product, version string) []string {
	v := version
	if v == "" {
		v = "*"
	}
	return []string{
		fmt.Sprintf("cpe:2.3:o:dlink:%s:%s:*:*:*:*:*:*:*", product, v),
	}
}
