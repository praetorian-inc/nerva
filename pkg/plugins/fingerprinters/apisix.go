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
Package fingerprinters provides HTTP fingerprinting for Apache APISIX.

Detection Strategy:
  - Passive: Server response header only — zero extra probes.
  - Required field: Server header contains "apisix" (case-insensitive).
  - Version extraction: Server header value matched against
    "APISIX" or "APISIX/{version}", validated against a strict 3-part
    dotted numeric pattern. Falls back to "*" on mismatch or absence.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// APISIXFingerprinter detects Apache APISIX via the Server response header.
type APISIXFingerprinter struct{}

// apisixServerRegex matches Server header values identifying Apache APISIX,
// capturing an unvalidated substring after "/" (if present) for later
// validation against apisixVersionRegex.
// Matches: "APISIX", "APISIX/3.9.0", "apisix/2.0.0".
var apisixServerRegex = regexp.MustCompile(`(?i)^APISIX(?:/(.+))?$`)

// apisixVersionRegex is the anchored validation gate applied after version
// extraction: strict 3-part dotted numeric version (e.g. "3.9.0").
var apisixVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&APISIXFingerprinter{})
}

func (f *APISIXFingerprinter) Name() string {
	return "apisix"
}

func (f *APISIXFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(strings.ToLower(resp.Header.Get("Server")), "apisix")
}

func (f *APISIXFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	rawServerHeader := resp.Header.Get("Server")

	m := apisixServerRegex.FindStringSubmatch(strings.TrimSpace(rawServerHeader))
	if m == nil {
		return nil, nil
	}

	version := m[1]
	if version == "" || !apisixVersionRegex.MatchString(version) {
		version = "*"
	}

	return &FingerprintResult{
		Technology: "apisix",
		Version:    version,
		CPEs:       []string{buildAPISIXCPE(version)},
		Metadata:   map[string]any{"server_header": sanitizeHTTPHeaderValue(rawServerHeader)},
	}, nil
}

// buildAPISIXCPE returns the NVD-correct CPE 2.3 string for Apache APISIX.
// Vendor: apache, Product: apisix.
func buildAPISIXCPE(version string) string {
	if version != "" && version != "*" && !strings.ContainsAny(version, ":*?") && apisixVersionRegex.MatchString(version) {
		return fmt.Sprintf("cpe:2.3:a:apache:apisix:%s:*:*:*:*:*:*:*", version)
	}
	return "cpe:2.3:a:apache:apisix:*:*:*:*:*:*:*:*"
}
