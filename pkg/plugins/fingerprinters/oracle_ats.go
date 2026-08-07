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
Package fingerprinters includes detection for Oracle Application Testing Suite (OATS).

# What We Detect

Oracle Application Testing Suite (OATS) is detected via the Oracle Load Testing
(OLT) login page served at /olt. Typical deployment runs on WebLogic Server,
default port 8088. Detection relies on multiple signals:

  - Form action "/olt/LoginSubmit.do" (Struts-style .do servlet, highly distinctive)
  - Body text "Oracle Load Testing" (OLT component branding)
  - Body text "Oracle Application Testing Suite" (OATS suite branding)
  - Path reference "/otm" (Oracle Test Manager, sibling component)

At least one signal must be present to produce a result.

# What We Do NOT Detect

  - OATS deployments that have removed or proxied away the /olt endpoint
  - Installations where the login page has been heavily customised to remove all branding

# CPE

cpe:2.3:a:oracle:application_testing_suite:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// oatsVersionRegex matches version strings like "Version 13.3.0.1".
// The "Version" prefix provides necessary context; bare four-component
// numbers are not matched to avoid capturing IP addresses or unrelated values.
var oatsVersionRegex = regexp.MustCompile(
	`(?i)Version\s+(\d+(?:\.\d+){1,3})`,
)

// OracleATSFingerprinter detects Oracle Application Testing Suite via the
// Oracle Load Testing login page at /olt.
type OracleATSFingerprinter struct{}

func init() {
	Register(&OracleATSFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *OracleATSFingerprinter) Name() string {
	return "oracle_ats"
}

// ProbeEndpoint returns the OLT login page endpoint.
func (f *OracleATSFingerprinter) ProbeEndpoint() string {
	return "/olt"
}

// ProbeAccept requests text/html since the OLT login page is an HTML form.
func (f *OracleATSFingerprinter) ProbeAccept() string {
	return "text/html"
}

// Match returns true when the response status is in the 200–499 range and the
// Content-Type contains "text/html".
func (f *OracleATSFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full detection by searching the OLT login page body for
// distinctive OATS signals. Returns nil if no signals are found.
func (f *OracleATSFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// 2 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	bodyStr := string(body)
	bodyLower := strings.ToLower(bodyStr)

	// Signal 1: Struts-style form action — highly distinctive path.
	hasOLTLoginAction := strings.Contains(bodyStr, `action="/olt/LoginSubmit.do"`)

	// Signal 2: Oracle Load Testing branding in body.
	hasOLTBranding := strings.Contains(bodyLower, "oracle load testing")

	// Signal 3: Oracle Application Testing Suite branding in body.
	hasOATSBranding := strings.Contains(bodyLower, "oracle application testing suite")

	// Signal 4: Oracle Test Manager sibling component — match href link or branding text.
	hasOTMReference := strings.Contains(bodyStr, `href="/otm"`) ||
		strings.Contains(bodyLower, "oracle test manager")

	if !hasOLTLoginAction && !hasOLTBranding && !hasOATSBranding && !hasOTMReference {
		return nil, nil
	}

	// Collect matched signal names.
	var detectedSignals []string
	if hasOLTLoginAction {
		detectedSignals = append(detectedSignals, "olt_login_action")
	}
	if hasOLTBranding {
		detectedSignals = append(detectedSignals, "olt_branding")
	}
	if hasOATSBranding {
		detectedSignals = append(detectedSignals, "oats_branding")
	}
	if hasOTMReference {
		detectedSignals = append(detectedSignals, "otm_reference")
	}

	// Collect detected components.
	var components []string
	if hasOLTBranding || hasOLTLoginAction {
		components = append(components, "Oracle Load Testing")
	}
	if hasOTMReference {
		components = append(components, "Oracle Test Manager")
	}

	// Best-effort version extraction.
	version := extractOATSVersion(bodyStr)

	metadata := map[string]any{
		"vendor":           "Oracle",
		"product":          "Application Testing Suite",
		"detection_method": "olt_login_page",
		"detected_signals": detectedSignals,
		"components":       components,
	}

	return &FingerprintResult{
		Technology: "oracle_ats",
		Version:    version,
		CPEs:       []string{buildOracleATSCPE(version)},
		Metadata:   metadata,
	}, nil
}

// extractOATSVersion attempts to find a version string in the page body.
// Returns an empty string when no version is found.
func extractOATSVersion(body string) string {
	matches := oatsVersionRegex.FindStringSubmatch(body)
	if matches == nil || matches[1] == "" {
		return ""
	}
	return matches[1]
}

// buildOracleATSCPE constructs a CPE 2.3 string for Oracle Application Testing Suite.
// When version is empty, a wildcard CPE is emitted to support asset inventory.
func buildOracleATSCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:oracle:application_testing_suite:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:oracle:application_testing_suite:%s:*:*:*:*:*:*:*", version)
}
