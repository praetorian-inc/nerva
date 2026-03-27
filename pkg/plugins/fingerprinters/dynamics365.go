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

// Dynamics365Fingerprinter detects Microsoft Dynamics 365 and Power Apps Portals
// (Power Pages) web-facing instances.
//
// Detection Strategy:
// Multiple signal categories detect both Dynamics 365 CRM and Power Apps Portals:
//
//  1. HEADERS:  x-ms-request-id, OData-Version, ms-dyn-aid, REQ_ID
//  2. COOKIES:  Dynamics365PortalAnalytics, CrmOwinAuth
//  3. BODY:     adx_ entity prefixes (Adxstudio lineage), Xrm.Page, Microsoft.Dynamics,
//     ClientGlobalContext.js.aspx, entityform/entitylist Liquid tags, dynamics.com refs
//  4. PROBE:    /_services/about returns portal version info
//
// Security Relevance:
//   - OData API may expose sensitive business data
//   - Default portal configurations may leak entity metadata
//   - XPath injection false positives from scanners need triage
//   - Authentication endpoints for credential brute-force
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// portalVersionRegex extracts version from /_services/about page.
// Matches patterns like "Portal version: 9.4.8.13" or "Version: 8.2.1.3".
var portalVersionRegex = regexp.MustCompile(`(?i)(?:portal\s+)?version[:\s]+(\d+\.\d+(?:\.\d+){0,2})`)

// portalVersionSafeRegex validates version format for CPE safety.
var portalVersionSafeRegex = regexp.MustCompile(`^\d+[\d.]*$`)

type Dynamics365Fingerprinter struct{}

func init() {
	Register(&Dynamics365Fingerprinter{})
}

func (f *Dynamics365Fingerprinter) Name() string {
	return "dynamics365"
}

func (f *Dynamics365Fingerprinter) ProbeEndpoint() string {
	return "/_services/about"
}

func (f *Dynamics365Fingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Dynamics-specific response headers.
	if resp.Header.Get("x-ms-request-id") != "" {
		return true
	}
	if resp.Header.Get("REQ_ID") != "" {
		return true
	}
	if resp.Header.Get("ms-dyn-aid") != "" {
		return true
	}
	if resp.Header.Get("OData-Version") != "" {
		return true
	}

	// Dynamics/Portal cookies.
	for _, cookie := range resp.Cookies() {
		switch cookie.Name {
		case "Dynamics365PortalAnalytics", "CrmOwinAuth":
			return true
		}
	}

	// Accept HTML/JSON for body-based detection.
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") || strings.Contains(ct, "application/json") {
		return true
	}

	return false
}

func (f *Dynamics365Fingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	bodyStr := string(body)

	// --- Header signals ---
	hasMsRequestID := resp.Header.Get("x-ms-request-id") != ""
	hasReqID := resp.Header.Get("REQ_ID") != ""
	hasDynAID := resp.Header.Get("ms-dyn-aid") != ""
	hasOData := resp.Header.Get("OData-Version") != ""

	// --- Cookie signals ---
	hasPortalCookie := false
	hasCrmCookie := false
	for _, cookie := range resp.Cookies() {
		switch cookie.Name {
		case "Dynamics365PortalAnalytics":
			hasPortalCookie = true
		case "CrmOwinAuth":
			hasCrmCookie = true
		}
	}

	// --- Body signals ---

	// Power Pages / Portal indicators (Adxstudio lineage).
	hasAdxPrefix := strings.Contains(bodyStr, "adx_entityform") ||
		strings.Contains(bodyStr, "adx_entitylist") ||
		strings.Contains(bodyStr, "adx_webpage") ||
		strings.Contains(bodyStr, "adx_webtemplate") ||
		strings.Contains(bodyStr, "adx_copy")

	// Liquid template tags.
	hasLiquidTags := strings.Contains(bodyStr, "{% entityform") ||
		strings.Contains(bodyStr, "{% entitylist")

	// Dynamics CRM client-side indicators.
	hasCrmJS := strings.Contains(bodyStr, "Xrm.Page") ||
		strings.Contains(bodyStr, "Xrm.Utility") ||
		strings.Contains(bodyStr, "Microsoft.Dynamics") ||
		strings.Contains(bodyStr, "ClientGlobalContext.js.aspx")

	// Domain references.
	hasDynamicsDomain := strings.Contains(bodyStr, ".dynamics.com") ||
		strings.Contains(bodyStr, "powerappsportals.com") ||
		strings.Contains(bodyStr, "powerpagesites.com") ||
		strings.Contains(bodyStr, "microsoftcrmportals.com")

	// Portal about page (from probe endpoint).
	hasAboutPage := strings.Contains(bodyStr, "Portal") &&
		portalVersionRegex.MatchString(bodyStr)

	// Managed solution entity prefix.
	hasMsdynPrefix := strings.Contains(bodyStr, "msdyn_")

	// Entity form view.
	hasCrmFormView := strings.Contains(bodyStr, "crmEntityFormView")

	// Require at least one signal.
	headerSignal := hasMsRequestID || hasReqID || hasDynAID || hasOData
	cookieSignal := hasPortalCookie || hasCrmCookie
	bodySignal := hasAdxPrefix || hasLiquidTags || hasCrmJS || hasDynamicsDomain ||
		hasAboutPage || hasMsdynPrefix || hasCrmFormView

	if !headerSignal && !cookieSignal && !bodySignal {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":  "Microsoft",
		"product": "Dynamics 365",
	}

	// Classify the detected component.
	if hasAdxPrefix || hasLiquidTags || hasPortalCookie || hasAboutPage {
		metadata["component"] = "Power Apps Portal"
	} else if hasDynAID {
		metadata["component"] = "Finance & Operations"
	} else if hasCrmJS || hasCrmCookie || hasCrmFormView {
		metadata["component"] = "CRM"
	}

	// Detect on-premises vs online.
	serverHeader := resp.Header.Get("Server")
	if strings.Contains(serverHeader, "Microsoft-IIS") {
		metadata["deployment"] = "on-premises"
	} else if hasDynamicsDomain {
		metadata["deployment"] = "online"
	}

	// OData API detection.
	if hasOData {
		metadata["odata_api"] = true
	}

	// Version extraction from /_services/about probe.
	version := ""
	if matches := portalVersionRegex.FindStringSubmatch(bodyStr); matches != nil {
		v := matches[1]
		if portalVersionSafeRegex.MatchString(v) {
			version = v
		}
	}

	return &FingerprintResult{
		Technology: "dynamics365",
		Version:    version,
		CPEs:       []string{buildDynamics365CPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildDynamics365CPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:microsoft:dynamics_365:%s:*:*:*:*:*:*:*", version)
}
