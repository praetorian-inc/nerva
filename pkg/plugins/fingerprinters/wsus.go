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
var wsusBodyStrings = []string{
	"ClientWebServiceClient",
}

// WSUSFingerprinter detects Windows Server Update Services via its client ASMX endpoint.
type WSUSFingerprinter struct{}

func init() {
	Register(&WSUSFingerprinter{})
}

func (f *WSUSFingerprinter) Name() string { return "wsus" }

func (f *WSUSFingerprinter) ProbeEndpoint() string { return "/ClientWebService/client.asmx" }

func (f *WSUSFingerprinter) Match(resp *http.Response) bool {
	// IIS is enough to let Nerva probe for WSUS
	return strings.Contains(resp.Header.Get("Server"), "Microsoft-IIS")
}

func (f *WSUSFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	bodyStr := string(body)

	if len(body) == 0 {
		return nil, nil
	}

	// Confirm body contains a string when we have a body to check.
	// This prevents false positives from other IIS apps that return 200 on any path.
	hasStr := false
	for _, s := range wsusBodyStrings {
		if strings.Contains(bodyStr, s) {
			hasStr = true
			break
		}
	}

	if !hasStr {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "wsus",
		CPEs:       buildWSUSCPEs(),
		Metadata: map[string]any{
			"vendor":  "Microsoft",
			"product": "Windows Server Update Services (WSUS)",
		},
	}, nil
}

func buildWSUSCPEs() []string {
	return []string{
		"cpe:2.3:a:microsoft:windows_server_update_services:*:*:*:*:*:*:*:*",
	}
}
