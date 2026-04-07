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

// LighttpdFingerprinter detects lighttpd web server instances.
//
// Detection Strategy:
// lighttpd is a lightweight, high-performance open-source web server optimized
// for speed-critical environments. It is commonly deployed on embedded devices,
// CDNs, and low-resource systems.
// Exposed instances are identified via the Server header.
//
// Detection uses Server header matching:
//  1. Server header equals "lighttpd" (when server.tag hides the version)
//  2. Server header starts with "lighttpd/" (default, version exposed)
//
// Version Format:
// lighttpd uses three-part versioning: MAJOR.MINOR.PATCH (e.g., 1.4.69).
//
// Server Header Examples:
//   - "lighttpd/1.4.69" — version exposed (default config)
//   - "lighttpd/1.4.64" — another common version
//   - "lighttpd"        — version hidden (when server.tag = "lighttpd" in config)
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// LighttpdFingerprinter detects lighttpd web server instances via Server header
type LighttpdFingerprinter struct{}

// lighttpdVersionValidateRegex validates extracted version format for CPE safety.
// lighttpd uses strict three-part versioning: MAJOR.MINOR.PATCH
var lighttpdVersionValidateRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&LighttpdFingerprinter{})
}

func (f *LighttpdFingerprinter) Name() string {
	return "lighttpd"
}

func (f *LighttpdFingerprinter) Match(resp *http.Response) bool {
	server := resp.Header.Get("Server")
	if server == "" {
		return false
	}
	lower := strings.ToLower(server)
	return lower == "lighttpd" || strings.HasPrefix(lower, "lighttpd/")
}

func (f *LighttpdFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	server := resp.Header.Get("Server")

	// Reject any Server header containing colons (CPE injection prevention)
	if strings.Contains(server, ":") {
		return nil, nil
	}

	// Safety guard: re-check Match
	if !f.Match(resp) {
		return nil, nil
	}

	version := extractLighttpdVersion(server)

	return &FingerprintResult{
		Technology: "lighttpd",
		Version:    version,
		CPEs:       []string{buildLighttpdCPE(version)},
		Metadata: map[string]any{
			"vendor":  "lighttpd",
			"product": "lighttpd",
		},
	}, nil
}

// extractLighttpdVersion extracts and validates the version from a Server header.
// It finds "lighttpd/" (case-insensitive), extracts the token until the next space or
// end of string, and validates the entire token against the version regex.
// This prevents CPE injection where "lighttpd/1.4.69:*:*" would extract "1.4.69" if we
// only used a capturing group.
func extractLighttpdVersion(server string) string {
	idx := strings.Index(strings.ToLower(server), "lighttpd/")
	if idx == -1 {
		return ""
	}
	versionPart := server[idx+9:] // Skip "lighttpd/"

	// Find end of version token (space, parenthesis, or end of string)
	endIdx := len(versionPart)
	for i, ch := range versionPart {
		if ch == ' ' || ch == '(' || ch == ')' {
			endIdx = i
			break
		}
	}
	candidate := versionPart[:endIdx]

	if lighttpdVersionValidateRegex.MatchString(candidate) {
		return candidate
	}
	return ""
}

func buildLighttpdCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:lighttpd:lighttpd:%s:*:*:*:*:*:*:*", version)
}
