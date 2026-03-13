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
Package fingerprinters provides HTTP fingerprinting for Gotenberg.

# Detection Strategy

Gotenberg is a Docker-based API for converting documents to PDF using Chromium
and LibreOffice. Exposed instances represent a security concern because they
allow unauthenticated SSRF via /forms/chromium/convert/url.

Detection uses two signals:
  - Passive: Presence of the Gotenberg-Trace header (a UUID), which is present
    on ALL Gotenberg responses including 404s. This header is product-specific
    and unique to Gotenberg.
  - Active: Query /version endpoint, which returns a plain-text semver string
    without authentication.

# API Response Format

The /version endpoint returns plain text without authentication:

	8.9.1

The Gotenberg-Trace header (a UUID) is present on every response:

	Gotenberg-Trace: dc34af5f-4e94-43b3-b8d6-5e2d99f42dc5

# Port Configuration

Gotenberg typically runs on:
  - 3000: Default Gotenberg HTTP port
  - 80:   HTTP in production
  - 443:  HTTPS in production

# Example Usage

	fp := &GotenbergFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s\n", result.Technology, result.Version)
		}
	}
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// GotenbergFingerprinter detects Gotenberg instances via the Gotenberg-Trace header
// and the /version endpoint.
type GotenbergFingerprinter struct{}

// gotenbergVersionRegex validates that the version body is a clean semver string.
// Anchored to prevent CPE injection (e.g., "8.9.1:*:*" would be rejected).
var gotenbergVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// GotenbergHealthFingerprinter detects older Gotenberg instances (v7.x, v8.0) via
// the /health endpoint, which is available on all Gotenberg versions.
type GotenbergHealthFingerprinter struct{}

// gotenbergHealthResponse models the JSON body returned by /health.
type gotenbergHealthResponse struct {
	Status  string                            `json:"status"`
	Details map[string]gotenbergComponentStatus `json:"details"`
}

// gotenbergComponentStatus models a single service component in the health response.
type gotenbergComponentStatus struct {
	Status    string `json:"status"`
	Timestamp string `json:"timestamp"`
}

// gotenbergKnownComponents is an allowlist of valid Gotenberg service component names.
// Requiring at least one known component prevents false-positive matches against
// generic health endpoints that happen to return {"status":"up"}.
var gotenbergKnownComponents = map[string]bool{
	"chromium":    true,
	"libreoffice": true,
}

func init() {
	Register(&GotenbergFingerprinter{})
	Register(&GotenbergHealthFingerprinter{})
}

func (f *GotenbergFingerprinter) Name() string {
	return "gotenberg"
}

func (f *GotenbergFingerprinter) ProbeEndpoint() string {
	return "/version"
}

// Match returns true if the Gotenberg-Trace header is present.
// This header is product-specific and present on all Gotenberg responses,
// making it a reliable pre-filter before reading the response body.
func (f *GotenbergFingerprinter) Match(resp *http.Response) bool {
	return resp.Header.Get("Gotenberg-Trace") != ""
}

// Fingerprint extracts the Gotenberg version from the response body and
// validates it is a clean semver string to prevent CPE injection.
func (f *GotenbergFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	trace := resp.Header.Get("Gotenberg-Trace")
	if trace == "" {
		return nil, nil
	}

	version := strings.TrimSpace(string(body))
	if !gotenbergVersionRegex.MatchString(version) {
		return nil, nil
	}

	metadata := map[string]any{
		"traceId": trace,
	}

	return &FingerprintResult{
		Technology: "gotenberg",
		Version:    version,
		CPEs:       []string{buildGotenbergCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildGotenbergCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:gotenberg:gotenberg:%s:*:*:*:*:*:*:*", version)
}

func (f *GotenbergHealthFingerprinter) Name() string {
	return "gotenberg-health"
}

func (f *GotenbergHealthFingerprinter) ProbeEndpoint() string {
	return "/health"
}

// Match returns true if the Gotenberg-Trace header is present AND the Content-Type
// is application/json. The /health endpoint always returns JSON, so a non-JSON
// response means this is not a Gotenberg health endpoint.
func (f *GotenbergHealthFingerprinter) Match(resp *http.Response) bool {
	if resp.Header.Get("Gotenberg-Trace") == "" {
		return false
	}
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

// Fingerprint parses the Gotenberg /health JSON response and validates it contains
// at least one known Gotenberg component (chromium or libreoffice) to prevent
// false positives against generic health endpoints.
func (f *GotenbergHealthFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	trace := resp.Header.Get("Gotenberg-Trace")
	if trace == "" {
		return nil, nil
	}

	var health gotenbergHealthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		return nil, nil
	}

	// Require a non-empty status field.
	if health.Status == "" {
		return nil, nil
	}

	// Require at least one known Gotenberg component to avoid false positives.
	if len(health.Details) == 0 {
		return nil, nil
	}

	var components []string
	for name := range health.Details {
		if gotenbergKnownComponents[name] {
			components = append(components, name)
		}
	}
	if len(components) == 0 {
		return nil, nil
	}

	// Sort for deterministic output.
	sort.Strings(components)

	metadata := map[string]any{
		"status":     health.Status,
		"components": components,
		"traceId":    trace,
	}

	return &FingerprintResult{
		Technology: "gotenberg",
		Version:    "",
		CPEs:       []string{buildGotenbergCPE("")},
		Metadata:   metadata,
	}, nil
}
