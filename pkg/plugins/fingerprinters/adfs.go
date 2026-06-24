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

// Strings which are present in the response
// from ProbeEndpoint()
var adfsBodyStrings = []string{
	"adfs/portal/css",    // HTML CSS ressource
	"adfs/portal/images", // HTML icon ressource
}

// ADFSFingerprinter detects Active Directory Federation Services (ADFS) via the common /adfs/ls endpoint.
type ADFSFingerprinter struct{}

func init() {
	Register(&ADFSFingerprinter{})
}

func (f *ADFSFingerprinter) Name() string { return "adfs" }

func (f *ADFSFingerprinter) ProbeEndpoint() string { return "/adfs/ls" }

func (f *ADFSFingerprinter) Match(resp *http.Response) bool {
	// HTTPAPI is enough to valid a probe for ADFS
	return strings.Contains(resp.Header.Get("Server"), "Microsoft-HTTPAPI")
}

func (f *ADFSFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	bodyStr := string(body)

	if len(body) == 0 {
		return nil, nil
	}

	// Confirm body contains a string when we have a body to check.
	// This prevents false positives from other IIS apps that return 200 on any path.
	hasStr := false
	for _, s := range adfsBodyStrings {
		if strings.Contains(bodyStr, s) {
			hasStr = true
			break
		}
	}

	if !hasStr {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "adfs",
		CPEs:       buildADFSCPEs(),
		Metadata: map[string]any{
			"vendor":  "Microsoft",
			"product": "Active Directory Federation Services (ADFS)",
		},
	}, nil
}

func buildADFSCPEs() []string {
	return []string{
		"cpe:2.3:a:microsoft:active_directory_federation_services:*:*:*:*:*:*:*:*",
	}
}
