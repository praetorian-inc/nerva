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

const beyondtrustMaxBodySize = 1 << 20

// BeyondtrustPRAFingerprinter detects BeyondTrust Privileged Remote Access (PRA) portals.
//
// Detection Strategy:
//
// BeyondTrust PRA (formerly Bomgar) exposes a web portal for privileged access management.
// Detection uses multiple signals:
//
//  1. Standalone: Body contains "BeyondTrust Privileged Remote Access" — this exact phrase
//     is specific enough to confirm the product without corroboration.
//  2. Corroborated: "BeyondTrust" brand (case-insensitive) AND a product-specific path
//     ("/appliance" or "/api/client_script") in the body — both required.
//  3. Corroborated: Legacy "Bomgar" brand (case-insensitive) AND support portal patterns
//     ("powered_by_text" or "%POWERED_BY%") in the body — both required.
//
// "BeyondTrust" or "Bomgar" brand alone is NOT sufficient — these brand names appear on
// security news sites, vendor comparison pages, and third-party documentation.
//
// Version Detection:
// Version is not extractable unauthenticated. CPE uses "*".
//
// CPE: cpe:2.3:a:beyondtrust:privileged_remote_access:*:*:*:*:*:*:*:*
type BeyondtrustPRAFingerprinter struct{}

func init() {
	Register(&BeyondtrustPRAFingerprinter{})
}

// beyondtrustBrandPattern matches "BeyondTrust" case-insensitively.
// Precompiled to avoid per-call allocation in Fingerprint().
var beyondtrustBrandPattern = regexp.MustCompile(`(?i)beyondtrust`)

// bomgarBrandPattern matches the legacy "Bomgar" brand case-insensitively.
var bomgarBrandPattern = regexp.MustCompile(`(?i)bomgar`)

func (f *BeyondtrustPRAFingerprinter) Name() string {
	return "beyondtrust-pra"
}

// Match accepts text/html responses with status 200-499. Rejects 5xx.
func (f *BeyondtrustPRAFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode >= 500 {
		return false
	}
	if resp.StatusCode < 200 {
		return false
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full detection and returns a result if this is a BeyondTrust PRA portal.
// Returns nil, nil for non-matching responses.
func (f *BeyondtrustPRAFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode >= 500 {
		return nil, nil
	}
	if resp.StatusCode < 200 {
		return nil, nil
	}

	if len(body) > beyondtrustMaxBodySize {
		body = body[:beyondtrustMaxBodySize]
	}

	bodyStr := string(body)

	// Signal 1 (standalone): exact product name — specific enough alone.
	if strings.Contains(bodyStr, "BeyondTrust Privileged Remote Access") {
		return buildBeyondtrustResult(), nil
	}

	// Signal 2 (corroborated): BeyondTrust brand + product-specific path.
	hasBeyondtrustBrand := beyondtrustBrandPattern.MatchString(bodyStr)
	hasProductPath := strings.Contains(bodyStr, "/appliance") || strings.Contains(bodyStr, "/api/client_script")
	if hasBeyondtrustBrand && hasProductPath {
		return buildBeyondtrustResult(), nil
	}

	// Signal 3 (corroborated): Legacy Bomgar brand + support portal patterns.
	hasBomgarBrand := bomgarBrandPattern.MatchString(bodyStr)
	hasSupportPortalPattern := strings.Contains(bodyStr, "powered_by_text") || strings.Contains(bodyStr, "%POWERED_BY%")
	if hasBomgarBrand && hasSupportPortalPattern {
		return buildBeyondtrustResult(), nil
	}

	return nil, nil
}

func buildBeyondtrustResult() *FingerprintResult {
	return &FingerprintResult{
		Technology: "beyondtrust-pra",
		Version:    "",
		CPEs:       []string{"cpe:2.3:a:beyondtrust:privileged_remote_access:*:*:*:*:*:*:*:*"},
		Metadata: map[string]any{
			"vendor":  "BeyondTrust",
			"product": "Privileged Remote Access",
		},
	}
}
