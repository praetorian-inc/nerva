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
	"strings"
)

const solarwindsWHDMaxBodySize = 1 << 20

// SolarWindsWHDFingerprinter detects SolarWinds Web Help Desk instances.
//
// Detection Strategy:
//
//  1. Standalone: x-webobjects-loadaverage or x-webobjects-servlet response
//     header present. These headers are emitted by the WebObjects application
//     server underlying WHD, and the probe path (/helpdesk/WebObjects/Helpdesk.woa)
//     is itself WHD-specific, so a WebObjects response on that path is sufficient.
//  2. Corroborated: body contains "Web Help Desk" AND "SolarWinds" (both
//     case-insensitive). Neither brand term alone is sufficient — "SolarWinds"
//     and "Web Help Desk" can each appear independently in unrelated marketing
//     or documentation content.
//
// Version Detection:
// WHD does not expose a version unauthenticated, so Version is always empty
// and the CPE is always wildcarded.
//
// CPE: cpe:2.3:a:solarwinds:web_help_desk:*:*:*:*:*:*:*:*
type SolarWindsWHDFingerprinter struct{}

func init() {
	Register(&SolarWindsWHDFingerprinter{})
}

func (f *SolarWindsWHDFingerprinter) Name() string {
	return "solarwinds-whd"
}

func (f *SolarWindsWHDFingerprinter) ProbeEndpoint() string {
	return "/helpdesk/WebObjects/Helpdesk.woa"
}

func (f *SolarWindsWHDFingerprinter) ProbeAccept() string {
	return "text/html"
}

// Match is a fast pre-filter. Accepts 200-499 responses with a WebObjects
// header or text/html content type. Rejects 5xx server errors.
func (f *SolarWindsWHDFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode > 499 {
		return false
	}

	if resp.Header.Get("X-Webobjects-Loadaverage") != "" || resp.Header.Get("X-Webobjects-Servlet") != "" {
		return true
	}

	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full detection and returns a result if this is a
// SolarWinds Web Help Desk instance. Returns nil, nil for non-matching responses.
func (f *SolarWindsWHDFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode > 499 {
		return nil, nil
	}

	if len(body) > solarwindsWHDMaxBodySize {
		body = body[:solarwindsWHDMaxBodySize]
	}

	// Signal 1 (standalone): WebObjects headers on the WHD-specific probe path.
	// Gated on 2xx — non-WHD WebObjects apps can 404 with these headers.
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		if resp.Header.Get("X-Webobjects-Loadaverage") != "" || resp.Header.Get("X-Webobjects-Servlet") != "" {
			return buildSolarWindsWHDResult(), nil
		}
	}

	// Signal 2 (corroborated): both brand terms required — either alone is too common.
	bodyStr := strings.ToLower(string(body))
	if strings.Contains(bodyStr, "web help desk") && strings.Contains(bodyStr, "solarwinds") {
		return buildSolarWindsWHDResult(), nil
	}

	return nil, nil
}

func buildSolarWindsWHDResult() *FingerprintResult {
	return &FingerprintResult{
		Technology: "solarwinds-whd",
		Version:    "",
		CPEs:       []string{buildSolarWindsWHDCPE()},
		Metadata: map[string]any{
			"vendor":  "SolarWinds",
			"product": "Web Help Desk",
		},
	}
}

// buildSolarWindsWHDCPE constructs the CPE 2.3 string. Always wildcarded
// since no version is available unauthenticated.
func buildSolarWindsWHDCPE() string {
	return "cpe:2.3:a:solarwinds:web_help_desk:*:*:*:*:*:*:*:*"
}
