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
Package fingerprinters provides HTTP fingerprinting for Maipu network equipment.

# Detection Strategy

Maipu Communication Technology Co., Ltd. manufactures network routers/switches/firewalls
deployed in Latin America and Asia. The web management login page has distinctive markers
that enable fingerprinting with high confidence.

Detection uses a scoring system requiring at least 3 points:

  - maipu.com or support@maipu.com in body (2 points - vendor domain)
  - /form/formUserLogin or /form/formDeviceVerGet in body (2 points - Maipu-specific forms)
  - /assets/css/login.css AND /assets/css/ui-dialog.css in body (1 point - CSS structure)
  - data-i18n="loginPageTitle" or data-i18n="login" with Chinese comments (1 point - i18n pattern)

The scoring system prevents false positives from generic HTML that might contain
individual indicators.

# Version Extraction

Version information is NOT available from the login page. The /form/formDeviceVerGet
endpoint that returns version information is commented out in the login page JavaScript
for security reasons. The fingerprinter returns an empty version string.

# Model Extraction

The commented-out JavaScript code shows a regex for extracting hardware model:
Hardware\s+Model\s*:\s*(\S+)\(\S+\)?\s*with

This regex is included for documentation but won't match the login page. It would
require active probing of /form/formDeviceVerGet (which requires authentication).

# Example Usage

	fp := &MaipuFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s\n", result.Technology)
		}
	}
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// MaipuFingerprinter detects Maipu network equipment web interfaces
type MaipuFingerprinter struct{}

// maipuVersionRegex validates version format for CPE injection prevention
// Accepts: X.Y.Z with optional alphanumeric/underscore/dash suffixes
var maipuVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+[a-zA-Z0-9._-]*$`)

func init() {
	Register(&MaipuFingerprinter{})
}

func (f *MaipuFingerprinter) Name() string {
	return "maipu-network-device"
}

func (f *MaipuFingerprinter) Match(resp *http.Response) bool {
	// Only accept 2xx-3xx responses (exclude 4xx client errors and 5xx server errors)
	// Login pages typically return 200 or 302 (redirect)
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false
	}

	// Check for text/html Content-Type or empty (defaults to text/html)
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if contentType == "" {
		// No Content-Type header, assume text/html (common for login pages)
		return true
	}

	// Must be HTML content (application/json, etc. should be rejected)
	return strings.Contains(contentType, "text/html")
}

func (f *MaipuFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Only accept 2xx-3xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return nil, nil
	}

	bodyStr := string(body)

	// Score-based detection to avoid false positives
	// Require at least 3 points to confirm Maipu
	score := 0

	// Indicator 1: Maipu domain (2 points - strongest signal)
	if strings.Contains(bodyStr, "maipu.com") || strings.Contains(bodyStr, "support@maipu.com") {
		score += 2
	}

	// Indicator 2: Maipu-specific form endpoints (2 points - very specific)
	if strings.Contains(bodyStr, "/form/formUserLogin") || strings.Contains(bodyStr, "/form/formDeviceVerGet") {
		score += 2
	}

	// Indicator 3: Maipu CSS structure (1 point - both must be present)
	if strings.Contains(bodyStr, "/assets/css/login.css") && strings.Contains(bodyStr, "/assets/css/ui-dialog.css") {
		score += 1
	}

	// Indicator 4: i18n pattern with data-i18n attributes (1 point)
	if strings.Contains(bodyStr, `data-i18n="loginPageTitle"`) || strings.Contains(bodyStr, `data-i18n="login"`) {
		score += 1
	}

	// Require at least 3 points to avoid false positives
	if score < 3 {
		return nil, nil
	}

	// Build metadata
	metadata := make(map[string]any)
	metadata["vendor"] = "Maipu"
	metadata["product"] = "Network Equipment"

	// Version is not extractable from login page
	// The /form/formDeviceVerGet endpoint is commented out in the JS
	version := ""

	result := &FingerprintResult{
		Technology: "maipu-network-device",
		Version:    version,
		CPEs:       []string{buildMaipuCPE(version)},
		Metadata:   metadata,
	}

	return result, nil
}

// buildMaipuCPE constructs a CPE string for Maipu network devices.
// CPE format: cpe:2.3:h:maipu:network_device:<version>:*:*:*:*:*:*:*
// Part 'h' indicates hardware (network appliance)
func buildMaipuCPE(version string) string {
	if version == "" {
		return "cpe:2.3:h:maipu:network_device:*:*:*:*:*:*:*:*"
	}

	// Validate version format to prevent CPE injection
	if !maipuVersionRegex.MatchString(version) {
		return "cpe:2.3:h:maipu:network_device:*:*:*:*:*:*:*:*"
	}

	return fmt.Sprintf("cpe:2.3:h:maipu:network_device:%s:*:*:*:*:*:*:*", version)
}
