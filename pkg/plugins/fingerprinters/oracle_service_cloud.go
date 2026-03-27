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
Package fingerprinters includes detection for Oracle Service Cloud (formerly RightNow CX).

# Detection Strategy

Oracle Service Cloud is a customer support SaaS platform. Instances are identified via
multiple signals in the HTTP response:

  - Body markers: "RightNow.Env", "RightNow.Widgets" JS namespaces
  - Asset paths: "/euf/core/{version}/js/" static framework URLs
  - Cookie: "cp_session" (Customer Portal session cookie)
  - About page: "/ci/about" discloses product name and version

# Version Extraction

The /ci/about endpoint returns a page containing:

	Oracle Service Cloud 25C (Build 3, CP 319) SP4

The CP framework version is embedded in asset paths:

	/euf/core/3.9/js/4.315/min/modules/...

# Security Relevance

  - PHP eval() capability — code injection risk
  - Known CVEs on CVEDetails (product ID 31504)
  - SaaS instance — credential harvesting via login pages
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// Version extraction patterns:
//   - /ci/about: "Oracle Service Cloud 25C (Build 3, CP 319) SP4"
//   - JS assets: /euf/core/3.9/js/4.315/min/...
var (
	oscAboutVersionRegex = regexp.MustCompile(
		`Oracle Service Cloud\s+(\d+[A-Z])\s+\(Build\s+(\d+),\s+CP\s+(\d+)\)(?:\s+(SP\d+))?`,
	)
	oscEUFCoreVersionRegex = regexp.MustCompile(`/euf/core/(\d+\.\d+)/js/([\d.]+)/`)
	oscCPVersionRegex      = regexp.MustCompile(`^[\d.]+$`)
	oscAlphanumVersionRegex = regexp.MustCompile(`^[\dA-Za-z.]+$`)
)

type OracleServiceCloudFingerprinter struct{}

func init() {
	Register(&OracleServiceCloudFingerprinter{})
}

func (f *OracleServiceCloudFingerprinter) Name() string {
	return "oracle-service-cloud"
}

func (f *OracleServiceCloudFingerprinter) ProbeEndpoint() string {
	return "/ci/about"
}

func (f *OracleServiceCloudFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Check for cp_session cookie (Customer Portal session).
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "cp_session" {
			return true
		}
	}

	// Accept any HTML response — body patterns checked in Fingerprint().
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/html") {
		return true
	}

	return false
}

func (f *OracleServiceCloudFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	bodyStr := string(body)

	// Signal 1: RightNow JS namespace (highest confidence).
	hasRightNowJS := strings.Contains(bodyStr, "RightNow.Env") ||
		strings.Contains(bodyStr, "RightNow.Widgets")

	// Signal 2: /euf/core/ asset path.
	hasEUFPath := strings.Contains(bodyStr, "/euf/core/")

	// Signal 3: /ci/about identity string.
	hasAboutPage := strings.Contains(bodyStr, "Oracle Service Cloud") ||
		strings.Contains(bodyStr, "RightNow Customer Portal")

	// Signal 4: cp_session cookie.
	hasCPSession := false
	for _, cookie := range resp.Cookies() {
		if cookie.Name == "cp_session" {
			hasCPSession = true
			break
		}
	}

	// Signal 5: rightnow.com XML namespace in templates.
	hasRNNamespace := strings.Contains(bodyStr, "schemas.rightnow.com")

	if !hasRightNowJS && !hasEUFPath && !hasAboutPage && !hasCPSession && !hasRNNamespace {
		return nil, nil
	}

	metadata := map[string]any{}

	// Extract version from /ci/about page.
	var release, cpVersion string
	if matches := oscAboutVersionRegex.FindStringSubmatch(bodyStr); matches != nil {
		release = matches[1]
		metadata["build"] = matches[2]
		metadata["cp"] = matches[3]
		if matches[4] != "" {
			metadata["servicePack"] = matches[4]
		}
	}

	// Extract CP framework version from /euf/core/{version}/js/{build}/ paths.
	if matches := oscEUFCoreVersionRegex.FindStringSubmatch(bodyStr); matches != nil {
		cpVersion = matches[1]
		metadata["cpFrameworkVersion"] = cpVersion
		metadata["jsBuild"] = matches[2]
	}

	// Use release for CPE if available, else CP framework version.
	version := release
	if version == "" {
		version = cpVersion
	}

	// Validate version format for CPE safety.
	if version != "" && !oscCPVersionRegex.MatchString(version) {
		// Release versions like "25C" contain letters — allow alphanumeric.
		if !oscAlphanumVersionRegex.MatchString(version) {
			version = ""
		}
	}

	if release != "" {
		metadata["release"] = release
	}

	return &FingerprintResult{
		Technology: "oracle-service-cloud",
		Version:    version,
		CPEs:       []string{buildOracleServiceCloudCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildOracleServiceCloudCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:oracle:service_cloud:%s:*:*:*:*:*:*:*", version)
}
