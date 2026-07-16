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
	"net/http"
	"regexp"
	"strings"
)

// apcNMCMaxBodySize caps the body slice before scanning. 1 MiB is more than
// sufficient for an APC NMC login page; guards against adversarially large
// responses.
const apcNMCMaxBodySize = 1 << 20

// APCNMCFingerprinter detects APC Network Management Card (NMC) web
// interfaces used to manage APC UPS and PDU appliances.
//
// Detection Strategy:
// APC NMC devices expose a web-based management interface at /logon.htm.
// Detection uses multiple signals:
//
//  1. Standalone: `<title>APC | Log On</title>` in the response body —
//     unique to the APC NMC login page.
//  2. Standalone: The exact string "APC Management Web Server" in the body —
//     appears on APC-specific error pages (e.g., 404s) and is specific
//     enough to confirm the product without corroboration.
//  3. Corroborated: A Set-Cookie header containing "C0=apc" AND the body
//     matching an "APC" brand pattern — both required together. Neither is
//     sufficient alone: "APC" is a common three-letter acronym that appears
//     in unrelated contexts (news articles, other products), and a cookie
//     name/value could coincidentally match without other corroboration.
//
// Active Probe: GET /logon.htm
//
// Version Detection:
// Firmware version is not extractable via unauthenticated HTTP; Version is
// always the empty string.
//
// CPE Generation:
// NMC2 and NMC3 firmware cannot be differentiated from unauthenticated HTTP
// responses alone, so both CPEs are always emitted:
//   - cpe:2.3:o:schneider-electric:network_management_card_2_firmware:*:*:*:*:*:*:*:*
//   - cpe:2.3:o:schneider-electric:network_management_card_3_firmware:*:*:*:*:*:*:*:*
type APCNMCFingerprinter struct{}

func init() {
	Register(&APCNMCFingerprinter{})
}

// apcNMCTitlePattern matches the APC NMC login page title, tolerant of
// whitespace variations around the pipe separator and casing.
var apcNMCTitlePattern = regexp.MustCompile(`(?i)<title>\s*APC\s*\|\s*Log\s*On\s*</title>`)

// apcNMCBrandPattern is a precompiled case-insensitive regex for the "APC"
// brand token. Used only in corroboration with the session cookie signal —
// never sufficient alone since "APC" is a common acronym.
var apcNMCBrandPattern = regexp.MustCompile(`(?i)\bAPC\b`)

// Name returns the fingerprinter identifier.
func (f *APCNMCFingerprinter) Name() string {
	return "apc-nmc"
}

// ProbeEndpoint returns the endpoint to probe for APC NMC detection.
func (f *APCNMCFingerprinter) ProbeEndpoint() string {
	return "/logon.htm"
}

// Match is a fast pre-filter. Accepts status 200-499 with a text/html
// Content-Type (case-insensitive). Rejects 5xx server errors.
func (f *APCNMCFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full detection and returns a result if this is an
// APC NMC device. Returns nil, nil for non-matching responses.
func (f *APCNMCFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > apcNMCMaxBodySize {
		body = body[:apcNMCMaxBodySize]
	}

	bodyStr := string(body)

	// Signal 1 (standalone): APC NMC login page title.
	hasTitle := apcNMCTitlePattern.MatchString(bodyStr)

	// Signal 2 (standalone): APC-specific error page text.
	hasErrorPageText := strings.Contains(bodyStr, "APC Management Web Server")

	// Signal 3 (corroborated): C0=apc session cookie AND APC brand in body.
	// Iterate over resp.Header["Set-Cookie"] (case-sensitive raw header
	// access) rather than resp.Header.Get("Set-Cookie"), which only returns
	// the first value.
	hasAPCCookie := false
	for _, cookie := range resp.Header["Set-Cookie"] {
		if strings.Contains(cookie, "C0=apc") {
			hasAPCCookie = true
			break
		}
	}
	hasBrand := apcNMCBrandPattern.MatchString(bodyStr)
	cookieCorroborated := hasAPCCookie && hasBrand

	detected := hasTitle || hasErrorPageText || cookieCorroborated
	if !detected {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":  "APC",
		"product": "Network Management Card",
	}
	if hasAPCCookie {
		metadata["cookie_fingerprint"] = "C0=apc"
	}

	return &FingerprintResult{
		Technology: "apc-nmc",
		Version:    "",
		CPEs:       buildAPCNMCCPEs(),
		Metadata:   metadata,
	}, nil
}

// buildAPCNMCCPEs returns CPE strings for both NMC2 and NMC3 firmware, since
// the two generations cannot be differentiated from unauthenticated HTTP
// responses.
func buildAPCNMCCPEs() []string {
	return []string{
		"cpe:2.3:o:schneider-electric:network_management_card_2_firmware:*:*:*:*:*:*:*:*",
		"cpe:2.3:o:schneider-electric:network_management_card_3_firmware:*:*:*:*:*:*:*:*",
	}
}
