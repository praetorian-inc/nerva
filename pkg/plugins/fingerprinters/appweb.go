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
Package fingerprinters provides HTTP fingerprinting for Appweb embedded web server.

# Detection Strategy

Appweb is an embedded web server by Embedthis Software, used in embedded devices,
IoT appliances, and as the web frontend for Juniper Junos J-Web. Detection uses
the Server header:

  - Modern (3.x-4.x): "Embedthis-Appweb/4.1.0"
  - Legacy (1.x-2.x): "Mbedthis-Appweb/2.4.2" (pre-rename)
  - Custom/OEM: "Appweb/7.0.1" or bare "Appweb"

Note: Appweb v5+ defaults to "Embedthis-http" with no "Appweb" in the header.
Those responses are out of scope for this fingerprinter.

# Detection Method

 1. Check Server header for "appweb" substring (case-insensitive)
 2. Accept status codes 200-499 (reject 5xx server errors)
 3. Extract version if present in Server header
 4. Validate version format to prevent CPE injection
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
)

// AppwebFingerprinter detects Appweb embedded web server via Server header
type AppwebFingerprinter struct{}

// appwebVersionRegex extracts version from Server header.
// Matches: Embedthis-Appweb/4.1.0, Mbedthis-Appweb/2.4.2, Appweb/7.0.1
var appwebVersionRegex = regexp.MustCompile(`(?i)(?:(?:Embedthis|Mbedthis)-)?Appweb/(\d+\.\d+\.\d+)`)

// appwebVersionValidationRegex validates extracted version format.
// Prevents CPE injection by ensuring version contains only digits and dots.
var appwebVersionValidationRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&AppwebFingerprinter{})
}

func (f *AppwebFingerprinter) Name() string {
	return "appweb"
}

func (f *AppwebFingerprinter) Match(resp *http.Response) bool {
	return false
}

func (f *AppwebFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	return nil, nil
}

func buildAppwebCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:embedthis:appweb:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:embedthis:appweb:%s:*:*:*:*:*:*:*", version)
}
