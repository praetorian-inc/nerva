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

// CommvaultFingerprinter detects Commvault backup/data management instances.
//
// Detection Strategy (passive, header-based only):
//
// Standalone: Server response header contains "Commvault" (case-insensitive).
// This is set by the Commvault WebServer component and is a reliable
// standalone indicator. Commvault does not expose version unauthenticated,
// so no version extraction is attempted.
//
// CPE: cpe:2.3:a:commvault:commvault:*:*:*:*:*:*:*:*
type CommvaultFingerprinter struct{}

func init() {
	Register(&CommvaultFingerprinter{})
}

func (f *CommvaultFingerprinter) Name() string {
	return "commvault"
}

// Match accepts any non-5xx response with a Server header containing "Commvault".
func (f *CommvaultFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode >= 500 {
		return false
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("Server")), "commvault")
}

// Fingerprint performs full detection and returns a result if this is a Commvault instance.
// Returns nil, nil for non-matching responses.
func (f *CommvaultFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode >= 500 {
		return nil, nil
	}

	serverHeader := resp.Header.Get("Server")
	if !strings.Contains(strings.ToLower(serverHeader), "commvault") {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":  "Commvault",
		"product": "Commvault",
	}

	if flag := resp.Header.Get("WEBSERVERCORE-FLAG"); flag != "" {
		metadata["webservercore_flag"] = flag
	}

	if gorkha := resp.Header.Get("cv-gorkha"); gorkha != "" {
		metadata["gorkha"] = gorkha
	}

	return &FingerprintResult{
		Technology: "commvault",
		CPEs:       []string{"cpe:2.3:a:commvault:commvault:*:*:*:*:*:*:*:*"},
		Metadata:   metadata,
	}, nil
}
