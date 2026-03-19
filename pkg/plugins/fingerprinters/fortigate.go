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
	"strconv"
	"strings"
	"time"
)

// FortiGateFingerprinter detects Fortinet FortiGate appliances.
//
// Detection Strategy:
// FortiGate appliances run FortiOS with a distinctive obfuscated Server header
// (xxxxxxxx-xxxxx) and characteristic HTTP responses. Detection uses:
//
// 1. Server Header: xxxxxxxx-xxxxx (primary indicator, highest confidence)
// 2. ETag Format: "XX-XXXXXXXX" where second hex is Unix timestamp (firmware build date)
// 3. Body Patterns: /remote/login redirect, ftnt-fortinet-grid icon class (only with Server/ETag)
//
// This fingerprinter addresses a detection gap where 3 FortiGate appliances on
// non-standard ports were invisible to the Chariot pipeline. FortiGate is a
// common enterprise security appliance, and detection is critical for attack
// surface visibility.
type FortiGateFingerprinter struct{}

func init() {
	Register(&FortiGateFingerprinter{})
}

// FortiGate ETag pattern: "XX-XXXXXXXX" (hex-hex format)
var fortiGateETagPattern = regexp.MustCompile(`^"[0-9a-fA-F]+-([0-9a-fA-F]{8})"$`)

func (f *FortiGateFingerprinter) Name() string {
	return "fortinet-fortigate"
}

func (f *FortiGateFingerprinter) Match(resp *http.Response) bool {
	// Only accept 2xx-4xx responses (reject 5xx server errors)
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Primary indicator: FortiOS obfuscated Server header
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	if serverHeader == "xxxxxxxx-xxxxx" {
		return true
	}

	// Secondary indicator: FortiOS ETag format
	etag := resp.Header.Get("Etag")
	return fortiGateETagPattern.MatchString(etag)
}

func (f *FortiGateFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Only accept 2xx-4xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Check Server header
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	serverMatch := serverHeader == "xxxxxxxx-xxxxx"

	// Check ETag format
	etag := resp.Header.Get("Etag")
	etagMatch := fortiGateETagPattern.MatchString(etag)

	// Require Server header OR ETag match (not just body patterns)
	// Body patterns alone are too prone to false positives (e.g., 404 pages mentioning /remote/login)
	if !serverMatch && !etagMatch {
		return nil, nil
	}

	// Build metadata
	metadata := make(map[string]any)
	metadata["vendor"] = "Fortinet"
	metadata["product"] = "FortiGate"

	// Extract firmware build date from ETag if present
	if etagMatch {
		if buildDate, ok := parseFortiGateETagTimestamp(etag); ok {
			metadata["firmware_build_date"] = buildDate
		}
	}

	// Detect SSL VPN feature from body patterns
	bodyStr := string(body)
	if strings.Contains(bodyStr, "/remote/login") {
		metadata["ssl_vpn"] = true
	}

	result := &FingerprintResult{
		Technology: "fortinet-fortigate",
		Version:    "", // FortiOS doesn't expose version in root response
		CPEs:       []string{buildFortiGateCPE("")},
		Metadata:   metadata,
	}

	return result, nil
}

// parseFortiGateETagTimestamp extracts firmware build date from FortiOS ETag header.
// FortiOS ETags use format "XX-XXXXXXXX" where the second hex value is a Unix timestamp.
// Example: "83-6011f49f" → 0x6011f49f = 1611789471 = 2021-01-27
func parseFortiGateETagTimestamp(etag string) (string, bool) {
	if etag == "" {
		return "", false
	}

	// Match FortiOS ETag format: "XX-XXXXXXXX"
	matches := fortiGateETagPattern.FindStringSubmatch(etag)
	if len(matches) < 2 {
		return "", false
	}

	// Parse hex timestamp (second group)
	timestampHex := matches[1]
	timestamp, err := strconv.ParseInt(timestampHex, 16, 64)
	if err != nil {
		return "", false
	}

	// Sanity check: timestamp must be between 2010 and 2030
	// 2010-01-01 = 1262304000, 2030-01-01 = 1893456000
	if timestamp < 1262304000 || timestamp > 1893456000 {
		return "", false
	}

	// Convert to UTC date (YYYY-MM-DD)
	buildDate := time.Unix(timestamp, 0).UTC().Format("2006-01-02")
	return buildDate, true
}

// buildFortiGateCPE constructs a CPE string for FortiGate/FortiOS.
// CPE format: cpe:2.3:o:fortinet:fortios:<version>:*:*:*:*:*:*:*
func buildFortiGateCPE(version string) string {
	if version == "" {
		return "cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:o:fortinet:fortios:%s:*:*:*:*:*:*:*", version)
}
