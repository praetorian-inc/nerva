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
Package fingerprinters provides HTTP fingerprinting for the CivetWeb embedded web server.

# Detection Strategy

CivetWeb is an embedded HTTP/HTTPS server library and a fork of Mongoose, commonly
embedded in medical and industrial devices. Roughly 10K-50K instances are exposed on
the public internet. The CivetWeb core does NOT emit a Server header by default, so
detection here is presence-positive / absence-neutral: a "Server: CivetWeb/..." header
is a positive signal, but the absence of the header is NOT evidence against CivetWeb.

Version casing changed across releases:
  - v1.6-1.9 used "Civetweb/"
  - v1.10+   used "CivetWeb/"

All matching is therefore case-insensitive.

# Detection Method

 1. Check Server header for "civetweb/" (case-insensitive, slash required) or bare
    "civetweb" (case-insensitive). Server header ONLY; no body fallback.
 2. Accept status codes 200-499 (reject 5xx server errors).
 3. Extract version via token-boundary scan after "civetweb/", validate format.
 4. Reject CPE-injection patterns to keep the emitted CPE safe.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// CivetWebFingerprinter detects the CivetWeb embedded web server via Server header.
type CivetWebFingerprinter struct{}

// civetWebVersionValidateRegex validates an extracted version token for CPE safety.
// CivetWeb publishes MAJOR.MINOR (1.15) and MAJOR.MINOR.PATCH (1.9.1) versions.
var civetWebVersionValidateRegex = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)

func init() {
	Register(&CivetWebFingerprinter{})
}

func (f *CivetWebFingerprinter) Name() string {
	return "civetweb"
}

func (f *CivetWebFingerprinter) Match(resp *http.Response) bool {
	// Reject 5xx server errors and anything below 200 (parallels boa.go:67-69).
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	// Server-header ONLY. Absence of the header is neutral (the Contains/== checks
	// simply return false), never a hard negative beyond this.
	server := strings.ToLower(resp.Header.Get("Server"))
	return strings.Contains(server, "civetweb/") || server == "civetweb"
}

func (f *CivetWebFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// 1. Re-apply the status gate (Fingerprint may be called directly in tests).
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// 2. Read raw Server header; empty => neutral, no detection.
	serverHeader := resp.Header.Get("Server")
	if serverHeader == "" {
		return nil, nil
	}

	// 3. Confirm CivetWeb signal (case-insensitive): "civetweb/" or bare "civetweb".
	serverLower := strings.ToLower(serverHeader)
	if !strings.Contains(serverLower, "civetweb/") && serverLower != "civetweb" {
		return nil, nil
	}

	// 4. CPE-injection guard: reject Server headers carrying ":*:" (parallels boa.go:97-99).
	if strings.Contains(serverHeader, ":*:") {
		return nil, nil
	}

	// 5. Extract + validate version (helper returns "" for bare/invalid).
	version := extractCivetWebVersion(serverHeader)

	// 6. Build metadata (raw header preserved).
	metadata := map[string]any{
		"vendor":        "CivetWeb",
		"product":       "CivetWeb",
		"server_header": serverHeader,
	}

	// 7. Emit result. Severity left unset (zero value) like boa/mongoose.
	return &FingerprintResult{
		Technology: "civetweb",
		Version:    version,
		CPEs:       []string{buildCivetWebCPE(version)},
		Metadata:   metadata,
	}, nil
}

// extractCivetWebVersion finds "civetweb/" (case-insensitive) in the Server header,
// reads the token up to the next space, '(' or ')' (or end of string), and validates
// the WHOLE token against civetWebVersionValidateRegex. Returns "" if the marker is
// absent or the token is not a clean version. Validating the whole token (not a
// capturing group) is what prevents "CivetWeb/1.15:*:*" from yielding "1.15".
func extractCivetWebVersion(server string) string {
	idx := strings.Index(strings.ToLower(server), "civetweb/")
	if idx == -1 {
		return ""
	}
	versionPart := server[idx+9:] // 9 == len("civetweb/")

	endIdx := len(versionPart)
	for i, ch := range versionPart {
		if ch == ' ' || ch == '(' || ch == ')' {
			endIdx = i
			break
		}
	}
	candidate := versionPart[:endIdx]

	if civetWebVersionValidateRegex.MatchString(candidate) {
		return candidate
	}
	return ""
}

// buildCivetWebCPE returns the CPE 2.3 string. Empty version => "*" wildcard.
// Vendor/product are the NVD-confirmed civetweb_project:civetweb (NOT civetweb:civetweb).
func buildCivetWebCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:civetweb_project:civetweb:%s:*:*:*:*:*:*:*", version)
}
