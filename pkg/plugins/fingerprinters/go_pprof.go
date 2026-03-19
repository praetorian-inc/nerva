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
Package fingerprinters provides HTTP fingerprinting for Go pprof debug endpoints.

# Detection Strategy

Go applications with pprof enabled expose runtime profiling data at /debug/pprof/.
This represents a security concern due to:
  - Exposure of goroutine dumps revealing application logic
  - Heap profiles exposing memory contents
  - CPU profiles revealing performance characteristics
  - Often enabled in development and mistakenly left in production

Detection uses a three-signal approach:

Signal 1 (active): /debug/pprof/ endpoint returns HTML index page
  - GET /debug/pprof/ triggers Go's default pprof handler
  - Response body contains "Types of profiles available" — unique to pprof
  - Status code 200, Content-Type: text/html

Signal 2 (body enrichment): Parse available profile types
  - Extract profile links from HTML: goroutine, heap, threadcreate, block, allocs, mutex, etc.
  - Store as exposedProfiles list in metadata

Signal 3 (version enrichment): Go version extraction
  - Look for go(\d+\.\d+\.\d+) pattern in response body
  - Common in "Profile Coverage: go1.21.5" footer text
  - Stored as Version field

# Response Format

Go pprof index page:

	<html>
	<head>
	<title>/debug/pprof/</title>
	</head>
	<body>
	/debug/pprof/<br>
	<br>
	Types of profiles available:
	<table>
	<tr><td align=right>0<td><a href="goroutine?debug=2">goroutine</a>
	<tr><td align=right>0<td><a href="heap?debug=1">heap</a>
	<tr><td align=right>0<td><a href="threadcreate?debug=1">threadcreate</a>
	<tr><td align=right>0<td><a href="block?debug=1">block</a>
	<tr><td align=right>0<td><a href="allocs?debug=1">allocs</a>
	<tr><td align=right>0<td><a href="mutex?debug=1">mutex</a>
	</table>
	<a href="goroutine?debug=2">full goroutine stack dump</a>
	<br>
	<p>
	Profile Coverage: go1.21.5
	</p>
	</body>
	</html>

# Port Configuration

Go pprof typically runs on:
  - 6060: Common pprof-only port (import _ "net/http/pprof")
  - 8080: Application HTTP port with pprof mux registered
  - Custom: Any port where http.DefaultServeMux is used

# Example Usage

	fp := &GoPprofFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s\n",
				result.Technology, result.Version)
			fmt.Printf("Exposed profiles: %v\n", result.Metadata["exposedProfiles"])
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

// goVersionRegex matches Go version in pprof page content.
// Patterns: go1.21.5, go1.20.0
var goVersionRegex = regexp.MustCompile(`go(\d+\.\d+\.\d+)`)

// pprofProfileRegex extracts profile names from href links.
// Matches patterns like <a href="goroutine?debug=2">goroutine</a>
var pprofProfileRegex = regexp.MustCompile(`href="([a-z]+)\?`)

// GoPprofFingerprinter detects Go pprof debug endpoints via /debug/pprof/ index page.
type GoPprofFingerprinter struct{}

func init() {
	Register(&GoPprofFingerprinter{})
}

func (f *GoPprofFingerprinter) Name() string {
	return "go_pprof"
}

// ProbeEndpoint returns the path used for active detection.
// Go's pprof package serves an HTML index at /debug/pprof/ listing available profiles.
func (f *GoPprofFingerprinter) ProbeEndpoint() string {
	return "/debug/pprof/"
}

// Match returns true if this fingerprinter should attempt detection.
// Called for the probe "/debug/pprof/" response.
//
// Returns true if:
//  1. Status is 200 AND Content-Type is text/html (allows Fingerprint to
//     validate the pprof index page body)
func (f *GoPprofFingerprinter) Match(resp *http.Response) bool {
	// Status 200 with text/html — may be pprof index page.
	// Fingerprint() will validate the body contains "Types of profiles available"
	if resp.StatusCode == 200 && strings.Contains(resp.Header.Get("Content-Type"), "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full detection and extracts Go pprof metadata.
// Must validate the actual pprof signature before returning a result,
// since Match() may produce false positives (e.g., any 200 text/html page).
func (f *GoPprofFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	metadata := make(map[string]any)

	// Must contain the distinctive pprof index page text
	bodyStr := string(body)
	hasProfilesText := strings.Contains(bodyStr, "Types of profiles available")

	// Must have confirmed pprof signal
	if !hasProfilesText {
		return nil, nil
	}

	// Signal 2: Extract exposed profiles from href links
	matches := pprofProfileRegex.FindAllStringSubmatch(bodyStr, -1)
	if len(matches) > 0 {
		profiles := make([]string, 0, len(matches))
		seen := make(map[string]bool)
		for _, match := range matches {
			if len(match) == 2 {
				profile := match[1]
				if !seen[profile] {
					profiles = append(profiles, profile)
					seen[profile] = true
				}
			}
		}
		if len(profiles) > 0 {
			metadata["exposed_profiles"] = profiles
		}
	}

	// Signal 3: Version extraction from Go version string (e.g., go1.21.5)
	version := ""
	if versionMatches := goVersionRegex.FindStringSubmatch(bodyStr); len(versionMatches) == 2 {
		version = versionMatches[1]
	}

	return &FingerprintResult{
		Technology: "go_pprof",
		Version:    version,
		CPEs:       []string{buildGoPprofCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildGoPprofCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:golang:go:%s:*:*:*:*:*:*:*", version)
}
