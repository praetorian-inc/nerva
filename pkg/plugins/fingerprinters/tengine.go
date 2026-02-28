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
Package fingerprinters provides HTTP fingerprinting for Tengine.

# Detection Strategy

Tengine is an Alibaba-developed fork of nginx with additional features.
Exposed instances represent a security concern due to:
  - Server header disclosure
  - Version information exposure
  - Potential vulnerabilities in specific versions

Detection uses passive analysis:
  - Passive: Check Server header for "Tengine" (case-insensitive)
  - Version extraction from Server header format: "Tengine/X.X.X"

# Server Header Format

The Server header typically contains:

	Tengine/2.3.3
	Tengine
	tengine/2.4.0

# Port Configuration

Tengine typically runs on:
  - 80:  Default HTTP port
  - 443: HTTPS in production

# Example Usage

	fp := &TengineFingerprinter{}
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

// TengineFingerprinter detects Tengine instances via Server header
type TengineFingerprinter struct{}

// tengineVersionRegex validates Tengine version format
// Accepts: 2.3.3, 2.4.0, 3.0.0 (standard semver)
var tengineVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&TengineFingerprinter{})
}

func (f *TengineFingerprinter) Name() string {
	return "tengine"
}

func (f *TengineFingerprinter) Match(resp *http.Response) bool {
	// Check Server header for "Tengine" (case-insensitive)
	server := resp.Header.Get("Server")
	return strings.Contains(strings.ToLower(server), "tengine")
}

func (f *TengineFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Get Server header
	server := resp.Header.Get("Server")
	if server == "" {
		return nil, nil
	}

	// Check if it contains "tengine" (case-insensitive)
	if !strings.Contains(strings.ToLower(server), "tengine") {
		return nil, nil
	}

	// Extract version from "Tengine/X.X.X" format
	version := ""
	if idx := strings.Index(strings.ToLower(server), "tengine/"); idx != -1 {
		versionPart := server[idx+8:] // Skip "tengine/"
		// Find the end of the version (space, parenthesis, or end of string)
		endIdx := len(versionPart)
		for i, ch := range versionPart {
			if ch == ' ' || ch == '(' {
				endIdx = i
				break
			}
		}
		candidate := versionPart[:endIdx]

		// Validate version format to prevent CPE injection
		if tengineVersionRegex.MatchString(candidate) {
			version = candidate
		} else if candidate != "" {
			// Has version attempt but invalid format - likely injection attempt
			return nil, nil
		}
	}

	// Build metadata with nginx base mapping if known
	metadata := make(map[string]any)
	if nginxBase := getNginxBaseVersion(version); nginxBase != "" {
		metadata["nginx_base"] = nginxBase
	}

	return &FingerprintResult{
		Technology: "tengine",
		Version:    version,
		CPEs:       []string{buildTengineCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildTengineCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:alibaba:tengine:%s:*:*:*:*:*:*:*", version)
}

// getNginxBaseVersion returns the nginx version that Tengine is based on
// This mapping is based on Tengine release notes
func getNginxBaseVersion(tengineVersion string) string {
	baseVersions := map[string]string{
		"2.3.3": "1.18.0",
		"2.4.0": "1.23.0",
	}
	return baseVersions[tengineVersion]
}
