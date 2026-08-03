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
Package fingerprinters provides HTTP fingerprinting for Cisco SD-WAN Manager
(formerly vManage).

# What We Detect

Cisco SD-WAN Manager is the management plane of Cisco's SD-WAN solution.
This fingerprinter detects the web management interface login page served
at the root path.

# Detection Strategy

Tier-1 (sufficient alone):
  - Page title: case-insensitive match for "Cisco vManage", "Cisco SD-WAN",
    "Cisco Catalyst SD-WAN", or "Viptela vManage"

Tier-2 (both required together):
  - Login form: body contains "j_security_check" (Java EE form-based auth)
  - API prefix: body contains "/dataservice/" (REST API path unique to vManage)

Detection method priority for metadata:
title > login_form > api_prefix

# Version Extraction

Version (platformVersion) is only available via the authenticated
/dataservice/client/server endpoint. No version is extractable from the
unauthenticated login page. CPE is emitted with wildcard version.

# CPE

cpe:2.3:a:cisco:catalyst_sd-wan_manager:*:*:*:*:*:*:*:*

# CVE Context

  - CVE-2026-20182 (CVSS 10.0, CISA KEV): Auth bypass, admin access.
  - CVE-2026-20127 (CVSS 10.0, CISA KEV): Auth bypass in DTLS peering.
  - CVE-2023-20214 (CVSS 9.1): REST API authentication bypass.
  - Eight CVEs total in CISA KEV. Threat actor UAT-8616 attributed.
    CISA Emergency Directive ED 26-03 issued.
*/
package fingerprinters

import (
	"net/http"
	"strings"
)

// CiscoSDWANFingerprinter detects Cisco SD-WAN Manager (vManage) instances.
type CiscoSDWANFingerprinter struct{}

func init() {
	Register(&CiscoSDWANFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *CiscoSDWANFingerprinter) Name() string {
	return "cisco-sdwan"
}

// Match returns true when the response status is in the 200-499 range.
func (f *CiscoSDWANFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return true
}

// Fingerprint performs detection of the Cisco SD-WAN Manager login page.
//
// Detection fires on a Tier-1 signal (any title variant alone) or when both
// Tier-2 signals are present together (j_security_check AND /dataservice/).
// A single Tier-2 signal alone is too generic (j_security_check is standard
// Java EE; /dataservice/ could appear in unrelated contexts).
func (f *CiscoSDWANFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}
	if len(body) > 2*1024*1024 {
		return nil, nil
	}
	if strings.Contains(string(body), ":*:") {
		return nil, nil
	}

	bodyLower := strings.ToLower(string(body))

	hasBrandInTitle := strings.Contains(bodyLower, "<title>cisco vmanage</title>") ||
		strings.Contains(bodyLower, "<title>cisco sd-wan</title>") ||
		strings.Contains(bodyLower, "<title>cisco catalyst sd-wan</title>") ||
		strings.Contains(bodyLower, "<title>viptela vmanage</title>")
	hasLoginForm := strings.Contains(bodyLower, "j_security_check")
	hasAPIPrefix := strings.Contains(bodyLower, "/dataservice/")

	if !hasBrandInTitle && !(hasLoginForm && hasAPIPrefix) {
		return nil, nil
	}

	detectionMethod := "body"
	if hasAPIPrefix {
		detectionMethod = "api_prefix"
	}
	if hasLoginForm {
		detectionMethod = "login_form"
	}
	if hasBrandInTitle {
		detectionMethod = "title"
	}

	metadata := map[string]any{
		"vendor":           "Cisco",
		"product":          "SD-WAN Manager",
		"detection_method": detectionMethod,
	}

	return &FingerprintResult{
		Technology: "cisco-sdwan-manager",
		Version:    "",
		CPEs:       []string{"cpe:2.3:a:cisco:catalyst_sd-wan_manager:*:*:*:*:*:*:*:*"},
		Metadata:   metadata,
	}, nil
}
