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
Package fingerprinters provides HTTP fingerprinting for GoAhead embedded web server.

# Detection Strategy

GoAhead is an embedded web server by Embedthis Software, commonly found in
IoT devices, routers, cameras, and network equipment. Detection uses Server header:

  - Modern (3.x+): "GoAhead-http"
  - Legacy (2.x): "GoAhead-Webs" or "GoAhead-Webs/2.5.0"
  - OEM Branded: "Webs" (Maipu devices strip GoAhead branding)

Server header may include additional components:
  - "GoAhead-Webs/2.5.0 PeerSec-MatrixSSL/3.4.2-OPEN"

# Detection Method

 1. Check Server header for "GoAhead" (case-insensitive) OR exact match "Webs" (case-insensitive)
 2. Accept status codes 200-499 (reject 5xx server errors)
 3. Extract version if present in Server header
 4. Validate version format to prevent CPE injection

Note: "Webs" detection uses exact match to avoid false positives with other servers
containing "webs" as substring (e.g., "WebServer", "WebService").

# Example Usage

	fp := &GoAheadFingerprinter{}
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

// GoAheadFingerprinter detects GoAhead embedded web server via Server header
type GoAheadFingerprinter struct{}

// goaheadVersionRegex extracts version from Server header
// Matches: GoAhead-Webs/2.5.0 or GoAhead-Webs/3.6.5 (any format)
var goaheadVersionRegex = regexp.MustCompile(`GoAhead-Webs/(\d+\.\d+\.\d+)`)

// goaheadVersionValidationRegex validates extracted version format
// Prevents CPE injection by ensuring version contains only digits and dots
var goaheadVersionValidationRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&GoAheadFingerprinter{})
}

func (f *GoAheadFingerprinter) Name() string {
	return "goahead"
}

func (f *GoAheadFingerprinter) Match(resp *http.Response) bool {
	// Only accept 2xx-4xx responses (reject 5xx server errors)
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Check Server header for "GoAhead" (case-insensitive) or exact "Webs" (OEM branding)
	serverHeader := strings.ToLower(resp.Header.Get("Server"))
	return strings.Contains(serverHeader, "goahead") || serverHeader == "webs"
}

func (f *GoAheadFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Only accept 2xx-4xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Extract Server header
	serverHeader := resp.Header.Get("Server")
	if serverHeader == "" {
		return nil, nil
	}

	// Verify it contains "GoAhead" (case-insensitive) or exact "Webs" (OEM branding)
	serverLower := strings.ToLower(serverHeader)
	if !strings.Contains(serverLower, "goahead") && serverLower != "webs" {
		return nil, nil
	}

	// Extract version from Server header if present
	version := ""
	matches := goaheadVersionRegex.FindStringSubmatch(serverHeader)
	if len(matches) >= 2 {
		version = matches[1]

		// Validate version format to prevent CPE injection
		// The extracted version must contain only digits and dots
		if !goaheadVersionValidationRegex.MatchString(version) {
			return nil, nil
		}
	}

	// Additional check: Ensure Server header doesn't contain CPE-like patterns
	// that could indicate injection attempts (e.g., "GoAhead-Webs/1.0.0:*:*:*:*:*:*:*")
	if strings.Contains(serverHeader, ":*:") {
		return nil, nil
	}

	// Build metadata
	metadata := map[string]any{
		"vendor":       "Embedthis",
		"product":      "GoAhead",
		"serverHeader": serverHeader,
	}

	return &FingerprintResult{
		Technology: "goahead",
		Version:    version,
		CPEs:       []string{buildGoAheadCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildGoAheadCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:embedthis:goahead:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:embedthis:goahead:%s:*:*:*:*:*:*:*", version)
}
