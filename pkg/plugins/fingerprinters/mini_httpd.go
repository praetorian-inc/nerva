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
Package fingerprinters provides HTTP fingerprinting for ACME Labs mini_httpd.

# Detection Strategy

mini_httpd is a lightweight embedded web server by ACME Labs,
commonly found on embedded devices and minimal Linux installations. Detection uses
the Server header:

  - mini_httpd with version: "mini_httpd/1.30 26Oct2018"
  - mini_httpd without version: "mini_httpd"

# Example Usage

	fp := &MiniHTTPDFingerprinter{}
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

// MiniHTTPDFingerprinter detects ACME Labs mini_httpd via Server header
type MiniHTTPDFingerprinter struct{}

// miniHTTPDVersionRegex extracts version from mini_httpd Server header
// Matches: mini_httpd/1.30, mini_httpd/1.19a (optional trailing letter)
var miniHTTPDVersionRegex = regexp.MustCompile(`^mini_httpd/(\d+\.\d+[a-z]?)`)

// miniHTTPDVersionValidateRegex validates extracted version format to prevent CPE injection
// Accepts: 1.30, 1.19, 1.19a (digits, dot, digits, optional lowercase letter)
var miniHTTPDVersionValidateRegex = regexp.MustCompile(`^\d+\.\d+[a-z]?$`)

// miniHTTPDBuildDateRegex extracts build date from mini_httpd Server header
// Matches: mini_httpd/1.30 26Oct2018, mini_httpd/1.19 19dec2003
var miniHTTPDBuildDateRegex = regexp.MustCompile(`^mini_httpd/\S+\s+(\d{1,2}[A-Za-z]{3}\d{4})`)

func init() {
	Register(&MiniHTTPDFingerprinter{})
}

func (f *MiniHTTPDFingerprinter) Name() string {
	return "mini_httpd"
}

func (f *MiniHTTPDFingerprinter) Match(resp *http.Response) bool {
	server := resp.Header.Get("Server")
	if server == "" {
		return false
	}

	// Exact match for "mini_httpd" (no version) or starts with "mini_httpd/"
	if server == "mini_httpd" || strings.HasPrefix(server, "mini_httpd/") {
		return true
	}

	return false
}

func (f *MiniHTTPDFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	server := resp.Header.Get("Server")

	// Reject any Server header containing colons (CPE injection attempt)
	if strings.Contains(server, ":") {
		return nil, nil
	}
	if !f.Match(resp) {
		return nil, nil
	}

	metadata := make(map[string]any)

	// Extract version from Server header
	version := ""
	versionMatches := miniHTTPDVersionRegex.FindStringSubmatch(server)
	if len(versionMatches) > 1 {
		extractedVersion := versionMatches[1]
		// Validate version format to prevent CPE injection
		if miniHTTPDVersionValidateRegex.MatchString(extractedVersion) {
			version = extractedVersion
		} else {
			// Invalid version format, skip it
			return nil, nil
		}
	}

	// Extract build date from Server header if present
	buildDateMatches := miniHTTPDBuildDateRegex.FindStringSubmatch(server)
	if len(buildDateMatches) > 1 {
		metadata["build_date"] = buildDateMatches[1]
	}

	return &FingerprintResult{
		Technology: "mini_httpd",
		Version:    version,
		CPEs:       []string{buildMiniHTTPDCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildMiniHTTPDCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:acme:mini_httpd:%s:*:*:*:*:*:*:*", version)
}

