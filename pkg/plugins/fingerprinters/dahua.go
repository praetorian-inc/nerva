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
Package fingerprinters provides HTTP fingerprinting for Dahua IP cameras and NVR/DVR devices.

# What We Detect

  - Dahua IP cameras (IPC series, e.g. IPC-HDW5831R-ZE)
  - Dahua NVR and DVR devices
  - Unauthenticated access to the magicBox CGI endpoint
  - Dahua-branded login pages

# What We Do NOT Detect

  - Third-party OEM devices that rebrand Dahua firmware without Dahua identifiers
  - Non-HTTP Dahua protocols (RTSP, Dahua SDK over TCP)
  - Dahua SmartPSS desktop client
  - Boa web server alone (shared with many non-Dahua devices; see boa.go)

# Security Context

When the magicBox CGI endpoint (/cgi-bin/magicBox.cgi?action=getDeviceType) is
accessible without authentication, it reveals device type information. This
constitutes unauthenticated access to a surveillance device and is treated as a
high-severity finding. The anonymous_access metadata key is set to true when
this condition is detected.

# Active Probe Safety

The active probe issues a plain GET /cgi-bin/magicBox.cgi?action=getDeviceType.
This is a read-only, idempotent request that retrieves device type information.
It does not trigger recording, modify configuration, or constitute exploitation
of any known CVE. The probe is safe to run against any target.

# CPE

cpe:2.3:o:dahuasecurity:{model}:{version}:*:*:*:*:*:*:*

The `o:` component type (operating system/firmware) is the NVD standard for
Dahua firmware. The vendor in CPE is "dahuasecurity" (NVD convention). The
model component is derived from the device type response when available;
a wildcard is used when the model cannot be determined.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// DahuaFingerprinter detects Dahua IP cameras, NVRs, and DVRs via the magicBox
// CGI endpoint and login page HTML markers.
type DahuaFingerprinter struct{}

// dahuaMagicBoxTypeRegex extracts the device type from a magicBox response.
// The response is plain text, typically: "type=IPC-HDW5831R-ZE\r\n"
// Bounded: captures up to 64 characters of printable non-whitespace.
var dahuaMagicBoxTypeRegex = regexp.MustCompile(
	`(?i)^type=([^\s]{1,64})`,
)

// dahuaTitleRegex matches Dahua branding in the HTML <title> tag.
// Matches titles containing "Dahua" or "DH" as a standalone word.
// [^<]{0,200} prevents runaway matching on malformed HTML.
var dahuaTitleRegex = regexp.MustCompile(
	`(?i)<title[^>]{0,100}>[^<]{0,200}dahua[^<]{0,200}</title>`,
)

// dahuaResourcePathRegex matches Dahua-specific resource paths in src/href attributes.
// Dahua login pages load JS/CSS from /webpages/ or /RPC2-related paths.
// This matches structural HTML attributes, not prose text.
var dahuaResourcePathRegex = regexp.MustCompile(
	`(?i)(?:src|href)=["'][^"']{0,200}/webpages/[^"']{0,200}["']`,
)

// dahuaVersionValidateRegex is the two-stage validation gate applied after
// version extraction. Anchored ^…$ to reject partial matches.
// Allows digits, dots, letters, hyphens (for firmware strings like "2.820.0000000.2.R").
var dahuaVersionValidateRegex = regexp.MustCompile(
	`^[0-9A-Za-z][0-9A-Za-z.\-]{0,63}$`,
)

// dahuaModelValidateRegex validates extracted model strings.
// Anchored ^…$ ; allows alphanumeric, hyphens, underscores.
var dahuaModelValidateRegex = regexp.MustCompile(
	`^[0-9A-Za-z][0-9A-Za-z\-_]{0,63}$`,
)

func init() {
	Register(&DahuaFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *DahuaFingerprinter) Name() string {
	return "dahua"
}

// ProbeEndpoint returns the active probe path for the magicBox CGI endpoint.
// This endpoint returns the device type in plain text when accessible without authentication.
func (f *DahuaFingerprinter) ProbeEndpoint() string {
	return "/cgi-bin/magicBox.cgi?action=getDeviceType"
}

// ProbeAccept returns the Accept header for the probe request.
// The magicBox endpoint returns plain text.
func (f *DahuaFingerprinter) ProbeAccept() string {
	return "text/plain"
}

// Match returns true when the response could be from a Dahua device.
// This is a broad pre-filter: status in 200–499, or a DH-prefixed header present.
// The Fingerprint function applies more specific brand-signal checks.
func (f *DahuaFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// DH-prefixed headers (e.g., X-DH-State) are Dahua-specific.
	for key := range resp.Header {
		if strings.HasPrefix(strings.ToUpper(key), "X-DH-") {
			return true
		}
	}

	// Content-Type text/plain is consistent with magicBox endpoint response.
	ct := resp.Header.Get("Content-Type")
	if strings.HasPrefix(ct, "text/plain") {
		return true
	}

	// HTML responses: match on text/html or no content-type (assume HTML).
	return strings.HasPrefix(ct, "text/html") || ct == ""
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection priority:
//  1. magicBox response — plain text with "type=<device-type>"; indicates unauthenticated access
//  2. Login page HTML — <title> containing "Dahua" or src/href containing "/webpages/"
//  3. DH-prefixed response headers alone
//
// When the magicBox endpoint returns a device type, anonymous_access is set to
// true and the severity is elevated to SeverityHigh.
func (f *DahuaFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: 2 MiB body cap — defense-in-depth.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Determine if this is an active probe response from the magicBox endpoint.
	isActiveProbe := false
	if resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/cgi-bin/magicBox.cgi") {
			isActiveProbe = true
		}
	}

	// Check for DH-prefixed headers.
	var dhHeaderKey, dhHeaderVal string
	for key, vals := range resp.Header {
		if strings.HasPrefix(strings.ToUpper(key), "X-DH-") {
			dhHeaderKey = key
			if len(vals) > 0 {
				dhHeaderVal = sanitizeHTTPHeaderValue(vals[0])
			}
			break
		}
	}
	hasDHHeader := dhHeaderKey != ""

	// Attempt magicBox detection: plain-text body starting with "type=".
	model, version, isMagicBox := extractDahuaMagicBoxInfo(body)

	if isMagicBox || isActiveProbe {
		// magicBox response indicates unauthenticated device-info access.
		metadata := map[string]any{
			"vendor":           "Dahua",
			"detection_method": "magicbox",
			"anonymous_access": true,
		}
		if model != "" {
			metadata["model"] = model
		}
		if version != "" {
			metadata["version"] = version
		}
		if isActiveProbe {
			metadata["detection_method"] = "active_probe"
			metadata["probe_path"] = "/cgi-bin/magicBox.cgi?action=getDeviceType"
		}
		if hasDHHeader {
			metadata["dh_header"] = dhHeaderKey
			if dhHeaderVal != "" {
				metadata["dh_header_value"] = dhHeaderVal
			}
		}
		return &FingerprintResult{
			Technology: "dahua",
			Version:    version,
			CPEs:       []string{buildDahuaCPE(model, version)},
			Metadata:   metadata,
			Severity:   plugins.SeverityHigh,
		}, nil
	}

	// Attempt login page detection: HTML with Dahua title or resource paths.
	hasTitle := dahuaTitleRegex.Match(body)
	hasResourcePath := dahuaResourcePathRegex.Match(body)

	if hasTitle || hasResourcePath {
		detectionMethod := "web_ui"
		metadata := map[string]any{
			"vendor":           "Dahua",
			"detection_method": detectionMethod,
		}
		if hasTitle {
			metadata["login_page_title"] = true
		}
		if hasResourcePath {
			metadata["dahua_resource_path"] = true
		}
		if hasDHHeader {
			metadata["dh_header"] = dhHeaderKey
			if dhHeaderVal != "" {
				metadata["dh_header_value"] = dhHeaderVal
			}
		}
		return &FingerprintResult{
			Technology: "dahua",
			Version:    "",
			CPEs:       []string{buildDahuaCPE("", "")},
			Metadata:   metadata,
		}, nil
	}

	// DH-prefixed header only: weak signal but worth noting.
	if hasDHHeader {
		metadata := map[string]any{
			"vendor":           "Dahua",
			"detection_method": "response_header",
			"dh_header":        dhHeaderKey,
		}
		if dhHeaderVal != "" {
			metadata["dh_header_value"] = dhHeaderVal
		}
		return &FingerprintResult{
			Technology: "dahua",
			Version:    "",
			CPEs:       []string{buildDahuaCPE("", "")},
			Metadata:   metadata,
		}, nil
	}

	return nil, nil
}

// extractDahuaMagicBoxInfo parses a magicBox CGI plain-text response.
// Returns (model, version, isMagicBox). isMagicBox is true only when
// a valid "type=<model>" line is found.
//
// Example magicBox response:
//
//	type=IPC-HDW5831R-ZE
func extractDahuaMagicBoxInfo(body []byte) (model, version string, isMagicBox bool) {
	if len(body) == 0 {
		return "", "", false
	}

	// Match "type=<value>" at start of body (may have leading/trailing whitespace).
	trimmed := strings.TrimSpace(string(body))
	m := dahuaMagicBoxTypeRegex.FindStringSubmatch(trimmed)
	if len(m) < 2 {
		return "", "", false
	}

	rawModel := m[1]
	// CPE injection defense: reject if model contains CPE metacharacters.
	if strings.ContainsAny(rawModel, ":*") {
		return "", "", false
	}
	// Two-stage validation.
	if !dahuaModelValidateRegex.MatchString(rawModel) {
		return "", "", false
	}

	return rawModel, "", true
}

// buildDahuaCPE constructs a CPE 2.3 string for Dahua firmware/OS.
// NVD standard: cpe:2.3:o:dahuasecurity:*:{version}:*:*:*:*:*:*:*
// When model is known, it replaces the wildcard product component.
// When version is empty, a wildcard is used for the version component.
func buildDahuaCPE(model, version string) string {
	// CPE injection defense on both inputs.
	if strings.ContainsAny(model, ":*") {
		model = ""
	}
	if strings.ContainsAny(version, ":*") {
		version = ""
	}

	product := "*"
	if model != "" && dahuaModelValidateRegex.MatchString(model) {
		product = strings.ToLower(model)
	}

	ver := "*"
	if version != "" && dahuaVersionValidateRegex.MatchString(version) {
		ver = version
	}

	return fmt.Sprintf("cpe:2.3:o:dahuasecurity:%s:%s:*:*:*:*:*:*:*", product, ver)
}
