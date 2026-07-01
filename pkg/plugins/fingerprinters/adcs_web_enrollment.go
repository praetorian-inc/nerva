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

// ADCSWebEnrollmentFingerprinter detects Active Directory Certificate Services (ADCS) Web Enrollment via the /certsrv endpoint.
type ADCSWebEnrollmentFingerprinter struct{}

func init() {
	Register(&ADCSWebEnrollmentFingerprinter{})
}

func (f *ADCSWebEnrollmentFingerprinter) Name() string { return "adcs-web-enrollment" }

func (f *ADCSWebEnrollmentFingerprinter) ProbeEndpoint() string { return "/certsrv/" }

func (f *ADCSWebEnrollmentFingerprinter) ProbeAccept() string {
	return "*/*"
}

func (f *ADCSWebEnrollmentFingerprinter) Match(resp *http.Response) bool {
	// If we are on IIS, as well as behind auth,
	// it is very safe to probe for ADCS
	wwwAuth := strings.ToLower(resp.Header.Get("WWW-Authenticate"))
	if (resp.StatusCode == 401 || resp.StatusCode == 403) &&
		(strings.Contains(wwwAuth, "ntlm") || strings.Contains(wwwAuth, "negotiate")) {
		if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "microsoft-iis") {
			return true
		}
	}

	return false
}

func (f *ADCSWebEnrollmentFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Check again if in this response from /certsrv,
	// we are still on IIS and behind auth

	wwwAuth := strings.ToLower(resp.Header.Get("WWW-Authenticate"))
	if (resp.StatusCode == 401 || resp.StatusCode == 403) &&
		(strings.Contains(wwwAuth, "ntlm") || strings.Contains(wwwAuth, "negotiate")) {
		if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "microsoft-iis") {
			return &FingerprintResult{
				Technology: "adcs-web-enrollment",
				CPEs:       buildADCSCPEs(),
				Metadata: map[string]any{
					"vendor":  "Microsoft",
					"product": "Active Directory Certificate Services (ADCS) - Web Enrollment",
				},
			}, nil
		}
	}

	return nil, nil
}

func buildADCSCPEs() []string {
	return []string{
		"cpe:2.3:a:microsoft:certificate_services:*:*:*:*:*:*:*:*",
	}
}
