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
Package fingerprinters provides HTTP fingerprinting for ACME Labs micro_httpd.

# Detection Strategy

micro_httpd is a minimal embedded web server by ACME Labs, even smaller than
mini_httpd, commonly found on very constrained embedded devices. Detection uses
the Server header:

  - micro_httpd (standard, no version): "micro_httpd"
  - micro_httpd with version (hypothetical): "micro_httpd/1.0"

Note: micro_httpd does not include a version in its Server header by default.
Version extraction is implemented for completeness in case custom or patched
builds include a version string (e.g., "micro_httpd/1.0").

# Example Usage

	fp := &MicroHTTPDFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s\n", result.Technology, result.Version)
		}
	}
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// MicroHTTPDFingerprinter detects ACME Labs micro_httpd via Server header
type MicroHTTPDFingerprinter struct{}

// microHTTPDVersionRegex extracts version from micro_httpd Server header
// Note: micro_httpd does not include a version in its Server header by default,
// but custom or patched builds may. This regex supports version extraction
// if a version is present (e.g., "micro_httpd/1.0").
var microHTTPDVersionRegex = regexp.MustCompile(`^micro_httpd/(\d+\.\d+[a-z]?)`)

// microHTTPDVersionValidateRegex validates extracted version format to prevent CPE injection
// Accepts: 1.0, 1.19, 1.19a (digits, dot, digits, optional lowercase letter)
var microHTTPDVersionValidateRegex = regexp.MustCompile(`^\d+\.\d+[a-z]?$`)

func init() {
	Register(&MicroHTTPDFingerprinter{})
}

func (f *MicroHTTPDFingerprinter) Name() string {
	return "micro_httpd"
}

func (f *MicroHTTPDFingerprinter) Match(resp *http.Response) bool {
	server := resp.Header.Get("Server")
	if server == "" {
		return false
	}

	// Exact match for "micro_httpd" (no version) or starts with "micro_httpd/"
	if server == "micro_httpd" || strings.HasPrefix(server, "micro_httpd/") {
		return true
	}

	return false
}

func (f *MicroHTTPDFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	server := resp.Header.Get("Server")

	// Reject any Server header containing colons (CPE injection attempt)
	if strings.Contains(server, ":") {
		return nil, nil
	}
	if !f.Match(resp) {
		return nil, nil
	}

	metadata := make(map[string]any)

	// Extract version from Server header if present
	// Note: micro_httpd does not include a version by default; this handles
	// custom or patched builds that may include a version string.
	version := ""
	versionMatches := microHTTPDVersionRegex.FindStringSubmatch(server)
	if len(versionMatches) > 1 {
		extractedVersion := versionMatches[1]
		// Validate version format to prevent CPE injection
		if microHTTPDVersionValidateRegex.MatchString(extractedVersion) {
			version = extractedVersion
		} else {
			// Invalid version format, skip it
			return nil, nil
		}
	}

	return &FingerprintResult{
		Technology: "micro_httpd",
		Version:    version,
		CPEs:       []string{buildMicroHTTPDCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildMicroHTTPDCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:acme:micro_httpd:%s:*:*:*:*:*:*:*", version)
}
