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
Package fingerprinters provides HTTP fingerprinting for VMware Horizon.

# Detection Strategy

VMware Horizon is a VDI (Virtual Desktop Infrastructure) platform. When accessed
via HTTPS, two response patterns indicate Horizon:

Pattern 1 - UAG (Unified Access Gateway) Blast endpoint:
  - Body exactly: "Missing route token in request"
  - This appears on port 8443 when accessing the Blast Secure Gateway without a session token
  - Very distinctive — no other product returns this exact message

Pattern 2 - Horizon Connection Server web portal:
  - HTML containing <title>VMware Horizon</title>
  - Path /portal/webclient/index.html returns the Horizon HTML5 client
  - Path /portal/info.jsp may return JSON with clientVersion field (CVE-2019-5513, may be patched)

Match():
  - Accept status 200-499
  - Check body for "Missing route token in request" (exact match, very distinctive)
  - OR check body for "VMware Horizon" (title or any reference)
  - This is a two-pass approach: Match() does a quick check, Fingerprint() validates

Fingerprint():
 1. Check if body contains "Missing route token in request" → UAG detected
 2. Check if body contains <title>VMware Horizon</title> → Connection Server web portal
 3. Check if body contains "clientVersion" (info.jsp JSON) → extract version
 4. If none match, return nil

ProbeEndpoint(): Return /portal/webclient/index.html — this is the pre-auth web client
endpoint that returns distinctive Horizon HTML.

Version extraction:
  - From info.jsp: regex "clientVersion"\s*:\s*"([^"]+)"
  - Version regex: ^\d+\.\d+\.\d+(\.\d+)?$ for CPE injection prevention

CPE: cpe:2.3:a:vmware:horizon:${version}:*:*:*:*:*:*:*

Metadata:
  - vendor: "VMware", product: "Horizon"
  - component: "UAG" or "Connection Server" depending on which pattern matched

# Example Usage

	fp := &VMwareHorizonFingerprinter{}
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

// VMwareHorizonFingerprinter detects VMware Horizon instances (Connection Server and UAG)
type VMwareHorizonFingerprinter struct{}

// horizonVersionRegex validates Horizon version format
// Accepts: 8.10.0 (standard), 2111.1 (build number format)
var horizonVersionRegex = regexp.MustCompile(`^\d+\.\d+(\.\d+)?(\.\d+)?$`)

// horizonClientVersionRegex extracts clientVersion from info.jsp JSON
var horizonClientVersionRegex = regexp.MustCompile(`"clientVersion"\s*:\s*"([^"]+)"`)

func init() {
	Register(&VMwareHorizonFingerprinter{})
}

func (f *VMwareHorizonFingerprinter) Name() string {
	return "vmware-horizon"
}

func (f *VMwareHorizonFingerprinter) ProbeEndpoint() string {
	return "/portal/webclient/index.html"
}

func (f *VMwareHorizonFingerprinter) Match(resp *http.Response) bool {
	// Only accept 2xx-4xx responses (reject 5xx server errors)
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Note: Match() is called before body is read, so we can't check body here
	// This fingerprinter relies on body content, so we return true for all valid status codes
	// and do the actual matching in Fingerprint()
	return true
}

func (f *VMwareHorizonFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Only accept 2xx-4xx responses
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	bodyStr := string(body)

	// Pattern 1: UAG Blast endpoint
	if strings.Contains(bodyStr, "Missing route token in request") {
		return &FingerprintResult{
			Technology: "vmware-horizon",
			Version:    "",
			CPEs:       []string{buildVMwareHorizonCPE("")},
			Metadata: map[string]any{
				"vendor":    "VMware",
				"product":   "Horizon",
				"component": "UAG",
			},
		}, nil
	}

	// Pattern 2: Check for "VMware Horizon" in body (case-insensitive)
	// OR check for clientVersion in JSON (info.jsp endpoint) with valid version format
	hasHorizonText := strings.Contains(strings.ToLower(bodyStr), "vmware horizon")

	// Check if clientVersion exists AND has valid format (prevents CPE injection)
	hasValidClientVersion := false
	if matches := horizonClientVersionRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
		if horizonVersionRegex.MatchString(matches[1]) {
			hasValidClientVersion = true
		}
	}

	if !hasHorizonText && !hasValidClientVersion {
		return nil, nil
	}

	// At this point we know it's VMware Horizon (Connection Server)
	metadata := map[string]any{
		"vendor":    "VMware",
		"product":   "Horizon",
		"component": "Connection Server",
	}

	// Try to extract version from info.jsp JSON
	version := ""
	if matches := horizonClientVersionRegex.FindStringSubmatch(bodyStr); len(matches) > 1 {
		candidateVersion := matches[1]
		// Validate version format to prevent CPE injection
		if horizonVersionRegex.MatchString(candidateVersion) {
			version = candidateVersion
		}
	}

	// If no clientVersion, try to find version in other patterns (like script variables)
	if version == "" {
		// Look for patterns like: var version = "2111.1";
		versionPattern := regexp.MustCompile(`version\s*=\s*"(\d+\.\d+(?:\.\d+)?(?:\.\d+)?)"`)
		if matches := versionPattern.FindStringSubmatch(bodyStr); len(matches) > 1 {
			candidateVersion := matches[1]
			if horizonVersionRegex.MatchString(candidateVersion) {
				version = candidateVersion
			}
		}
	}

	return &FingerprintResult{
		Technology: "vmware-horizon",
		Version:    version,
		CPEs:       []string{buildVMwareHorizonCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildVMwareHorizonCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:vmware:horizon:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:vmware:horizon:%s:*:*:*:*:*:*:*", version)
}
