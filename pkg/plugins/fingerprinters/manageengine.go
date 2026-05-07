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

// ManageEngineFingerprinter detects Zoho ManageEngine product family web UIs.
//
// Detection Strategy:
//
//  1. TITLE/BODY: "ManageEngine" branding + product-specific names
//     (ServiceDesk Plus, ADSelfService Plus, Endpoint/Desktop Central,
//     PAM360, Password Manager Pro, OpManager, Applications Manager, ADAudit Plus)
//  2. URLS:    Product-specific paths (/showLogin.cc, /STATE_ID=, /servlet/)
//  3. HEADERS: Server/X-Frame-Options patterns, custom X-ManageEngine headers
//  4. PROBE:   "/" home page typically redirects to a product login containing branding
//
// Security Relevance:
//   - CVE-2022-47966 (CVSS 9.8) — SAML-based unauth RCE across 24+ products (Five Eyes Top 15)
//   - CVE-2021-40539 (CVSS 9.8) — ADSelfService Plus auth-bypass RCE (CISA AA21-259A)
//   - CVE-2021-44077 (CVSS 9.8) — ServiceDesk Plus unauth RCE (CISA AA21-336A)
//   - CVE-2022-35405 (CVSS 9.8) — PAM360 / Password Manager Pro RCE
//   - CISA AA23-250A — nation-state exploitation in US aeronautical sector
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// manageEngineVersionRegex extracts a version number embedded in branding text,
// e.g. "ManageEngine ServiceDesk Plus 14.0 Build 14000".
var manageEngineVersionRegex = regexp.MustCompile(`(?i)manageengine\s+[a-z0-9 +/]+?\s+(?:v(?:ersion)?\s*)?(\d+\.\d+(?:\.\d+){0,2})`)

// manageEngineBuildRegex extracts the explicit Build number, e.g. "Build 14000".
var manageEngineBuildRegex = regexp.MustCompile(`(?i)build\s+(\d{3,6})`)

// manageEngineSafeVersionRegex validates version format for CPE safety.
var manageEngineSafeVersionRegex = regexp.MustCompile(`^\d+[\d.]*$`)

// manageEngineProduct describes one ManageEngine product variant: how to detect
// it from response strings, the canonical name to record in metadata, and the
// CPE product slug used to build a CPE string.
type manageEngineProduct struct {
	component string   // canonical metadata.component value
	cpeName   string   // CPE 2.3 product field
	signals   []string // case-insensitive substrings unique to this product
}

// manageEngineProducts lists product variants in priority order. The first
// match wins. More specific products (e.g. ADSelfService Plus) come before
// more generic ones to avoid mis-classification.
var manageEngineProducts = []manageEngineProduct{
	{
		component: "ADSelfService Plus",
		cpeName:   "adselfservice_plus",
		signals: []string{
			"adselfservice plus",
			"/adsspscripts/",
			"adssp",
		},
	},
	{
		component: "ADAudit Plus",
		cpeName:   "adaudit_plus",
		signals: []string{
			"adaudit plus",
			"/adap/",
		},
	},
	{
		component: "ADManager Plus",
		cpeName:   "admanager_plus",
		signals: []string{
			"admanager plus",
			"/admp/",
		},
	},
	{
		component: "ServiceDesk Plus",
		cpeName:   "servicedesk_plus",
		signals: []string{
			"servicedesk plus",
			"/showlogin.cc",
			"sdpapi",
		},
	},
	{
		component: "Endpoint Central",
		cpeName:   "endpoint_central",
		signals: []string{
			"endpoint central",
			"desktop central",
			"/desktop/",
			"dcdownloads",
		},
	},
	{
		component: "PAM360",
		cpeName:   "pam360",
		signals: []string{
			"pam360",
			"pam 360",
		},
	},
	{
		component: "Password Manager Pro",
		cpeName:   "password_manager_pro",
		signals: []string{
			"password manager pro",
			"/passwordmanager",
			"pmp.servlet",
		},
	},
	{
		component: "OpManager",
		cpeName:   "opmanager",
		signals: []string{
			"opmanager",
			"/opmanager/",
		},
	},
	{
		component: "Applications Manager",
		cpeName:   "applications_manager",
		signals: []string{
			"applications manager",
			"/appmanager/",
		},
	},
	{
		component: "EventLog Analyzer",
		cpeName:   "eventlog_analyzer",
		signals: []string{
			"eventlog analyzer",
		},
	},
	{
		component: "Log360",
		cpeName:   "log360",
		signals: []string{
			"log360",
		},
	},
}

type ManageEngineFingerprinter struct{}

func init() {
	Register(&ManageEngineFingerprinter{})
}

func (f *ManageEngineFingerprinter) Name() string {
	return "manageengine"
}

func (f *ManageEngineFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Custom ManageEngine headers seen in the wild.
	for h := range resp.Header {
		if strings.HasPrefix(strings.ToLower(h), "x-manageengine") {
			return true
		}
	}

	// Server header sometimes leaks ManageEngine identity.
	if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "manageengine") {
		return true
	}

	// Some products set a JSESSIONIDSSO cookie; alone it's not specific enough,
	// so fall through to body inspection on HTML responses.
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml") {
		return true
	}

	return false
}

func (f *ManageEngineFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	bodyLower := strings.ToLower(string(body))
	server := resp.Header.Get("Server")
	serverLower := strings.ToLower(server)

	// Header signals.
	hasMEHeader := false
	for h := range resp.Header {
		if strings.HasPrefix(strings.ToLower(h), "x-manageengine") {
			hasMEHeader = true
			break
		}
	}
	hasMEServer := strings.Contains(serverLower, "manageengine")

	// Body signal: ManageEngine branding (title, copyright, scripts, links).
	hasMEBranding := strings.Contains(bodyLower, "manageengine") ||
		strings.Contains(bodyLower, "zoho corp")

	// Body signal: ServiceDesk Plus login URL is unique enough to act on alone.
	hasSDPMarker := strings.Contains(bodyLower, "/showlogin.cc")

	if !hasMEHeader && !hasMEServer && !hasMEBranding && !hasSDPMarker {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor": "Zoho",
	}

	// Identify product variant.
	product := classifyManageEngineProduct(bodyLower)
	if product != nil {
		metadata["component"] = product.component
		metadata["product"] = "ManageEngine " + product.component
	} else {
		metadata["product"] = "ManageEngine"
	}

	// Version extraction from branding text. Search the original-case body so
	// the regex's case-insensitive flag still matches mixed-case product names.
	version := extractManageEngineVersion(string(body))

	// Build number is sometimes the only useful version indicator (e.g. ADSSP 6.2 Build 6203).
	if build := manageEngineBuildRegex.FindStringSubmatch(string(body)); build != nil {
		metadata["build"] = build[1]
	}

	cpeName := "manageengine"
	if product != nil {
		cpeName = product.cpeName
	}

	return &FingerprintResult{
		Technology: "manageengine",
		Version:    version,
		CPEs:       []string{buildManageEngineCPE(cpeName, version)},
		Metadata:   metadata,
	}, nil
}

func classifyManageEngineProduct(bodyLower string) *manageEngineProduct {
	for i := range manageEngineProducts {
		p := &manageEngineProducts[i]
		for _, sig := range p.signals {
			if strings.Contains(bodyLower, sig) {
				return p
			}
		}
	}
	return nil
}

func extractManageEngineVersion(body string) string {
	matches := manageEngineVersionRegex.FindStringSubmatch(body)
	if matches == nil {
		return ""
	}
	v := matches[1]
	if !manageEngineSafeVersionRegex.MatchString(v) {
		return ""
	}
	return v
}

func buildManageEngineCPE(product, version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:zohocorp:manageengine_%s:%s:*:*:*:*:*:*:*", product, version)
}
