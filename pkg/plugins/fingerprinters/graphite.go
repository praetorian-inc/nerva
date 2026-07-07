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
Package fingerprinters provides HTTP fingerprinting for Graphite Web.

# What We Detect

  - Graphite-web instances via the /version endpoint, which returns a bare
    semver string (e.g., "1.1.10") as text/html, with no JSON or HTML wrapper.

# What We Do NOT Detect

  - Graphite-web deployments that remove or proxy away the /version endpoint
  - Graphite-web behind a reverse proxy that alters the response content type

# CPE

cpe:2.3:a:graphite_project:graphite:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// GraphiteFingerprinter detects Graphite Web instances via the bare version
// string returned by the /version endpoint.
type GraphiteFingerprinter struct{}

// graphiteVersionRegex matches a bare semver string with 2 or 3 components,
// anchored to reject partial matches (e.g., "5.38abc").
var graphiteVersionRegex = regexp.MustCompile(`^\d+\.\d+(\.\d+)?$`)

func init() {
	Register(&GraphiteFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *GraphiteFingerprinter) Name() string {
	return "graphite"
}

// ProbeEndpoint returns the Graphite-web version endpoint, which returns a
// bare version string with no authentication required.
func (f *GraphiteFingerprinter) ProbeEndpoint() string {
	return "/version"
}

// ProbeAccept requests text/html explicitly, since graphite-web's /version
// endpoint returns text/html and content-negotiating proxies could otherwise
// alter the response if the engine's default Accept header were used.
func (f *GraphiteFingerprinter) ProbeAccept() string {
	return "text/html"
}

// Match returns true when the response is a 200 with a text/html content type.
func (f *GraphiteFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode != http.StatusOK {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full detection by validating that the response body is
// a bare semver string, matching the exact shape of the Graphite-web /version
// endpoint response (no JSON wrapper, no HTML wrapper).
func (f *GraphiteFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// 2 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	trimmed := strings.TrimSpace(string(body))

	// A bare version string is short; anything else is not this endpoint.
	if len(trimmed) >= 50 {
		return nil, nil
	}

	if !graphiteVersionRegex.MatchString(trimmed) {
		return nil, nil
	}

	version := trimmed
	// CPE injection defense — belt-and-suspenders guard.
	if strings.ContainsAny(version, ":*") {
		version = ""
	}

	metadata := map[string]any{
		"vendor":           "Graphite Project",
		"product":          "Graphite",
		"detection_method": "version_endpoint",
	}

	return &FingerprintResult{
		Technology: "graphite",
		Version:    version,
		CPEs:       []string{buildGraphiteCPE(version)},
		Metadata:   metadata,
	}, nil
}

// buildGraphiteCPE constructs a CPE 2.3 string for Graphite.
// When version is empty, a wildcard CPE is emitted to support asset inventory.
func buildGraphiteCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:graphite_project:graphite:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:graphite_project:graphite:%s:*:*:*:*:*:*:*", version)
}
