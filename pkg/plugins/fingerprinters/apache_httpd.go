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
Package fingerprinters provides HTTP fingerprinting for Apache HTTP Server.

# Detection Strategy

Apache HTTP Server (httpd) is the most widely deployed web server. Detection uses:
  - Server header: "Apache/X.Y.Z" or "Apache"
  - Excludes Apache Tomcat (Java servlet container) and Apache-Coyote
  - Extracts OS from parenthetical (e.g., "(Ubuntu)")
  - Extracts loaded modules from Server header (e.g., "mod_ssl/2.2.31")
  - Optional PHP detection via X-Powered-By header

# Server Header Format

The Server header varies by ServerTokens configuration:
  - "Apache/2.4.52" - Version exposed (ServerTokens Major/Minor/Min)
  - "Apache/2.4.52 (Ubuntu)" - Version with OS (ServerTokens OS)
  - "Apache/2.4.52 (Ubuntu) mod_ssl/2.4.52 OpenSSL/3.0.2" - Full (ServerTokens Full)
  - "Apache" - Version hidden (ServerTokens Prod)

# Example Usage

	fp := &ApacheHTTPDFingerprinter{}
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

// ApacheHTTPDFingerprinter detects Apache HTTP Server via Server header
type ApacheHTTPDFingerprinter struct{}

// apacheVersionRegex extracts version from Server header
// Matches: Apache/2.4.52, Apache/2.4.52 (Ubuntu), Apache/2.2.15
var apacheVersionRegex = regexp.MustCompile(`^Apache/(\d+\.\d+\.\d+)`)

// apacheVersionValidateRegex validates extracted version format to prevent CPE injection
// Accepts: 2.4.52, 2.2.15 (standard semantic versioning)
var apacheVersionValidateRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// apacheOSRegex extracts OS from parenthetical in Server header
// Matches: (Ubuntu), (Debian), (CentOS), (Unix), (Win64)
var apacheOSRegex = regexp.MustCompile(`\(([^)]+)\)`)

// moduleVersionRegex extracts module name/version pairs from Server header
// Matches: mod_ssl/2.4.52, OpenSSL/3.0.2, PHP/8.1.2, Resin/3.1.6
var moduleVersionRegex = regexp.MustCompile(`(\w+)/([\w.-]+)`)

// moduleVersionValidateRegex validates module version format
// Accepts: 2.4.52, 3.0.2-fips, 1.0.1e-fips (alphanumeric with dots/hyphens)
var moduleVersionValidateRegex = regexp.MustCompile(`^[\w][\w.-]*$`)

// phpVersionRegex extracts PHP version from X-Powered-By header
// Matches: PHP/8.1.2, PHP/7.4.3
var phpVersionRegex = regexp.MustCompile(`^PHP/(\d+\.\d+\.\d+)`)

func init() {
	Register(&ApacheHTTPDFingerprinter{})
}

func (f *ApacheHTTPDFingerprinter) Name() string {
	return "apache_httpd"
}

func (f *ApacheHTTPDFingerprinter) Match(resp *http.Response) bool {
	// Check for Apache in Server header
	// Must be "Apache" or "Apache/" to exclude "Apache Tomcat" and "Apache-Coyote"
	server := resp.Header.Get("Server")
	if server == "" {
		return false
	}

	// Exact match for "Apache" or starts with "Apache/"
	if server == "Apache" {
		return true
	}
	if strings.HasPrefix(server, "Apache/") {
		return true
	}

	return false
}

func (f *ApacheHTTPDFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	server := resp.Header.Get("Server")

	// Reject any Server header containing colons (CPE injection attempt)
	if strings.Contains(server, ":") {
		return nil, nil
	}
	if !f.Match(resp) {
		return nil, nil
	}

	// Extract version from Server header
	version := ""
	matches := apacheVersionRegex.FindStringSubmatch(server)
	if len(matches) > 1 {
		extractedVersion := matches[1]
		// Validate version format to prevent CPE injection
		if apacheVersionValidateRegex.MatchString(extractedVersion) {
			version = extractedVersion
		} else {
			// Invalid version format, skip it
			return nil, nil
		}
	}

	// Build metadata
	metadata := make(map[string]any)

	// Extract OS from parenthetical in Server header
	osMatches := apacheOSRegex.FindStringSubmatch(server)
	if len(osMatches) > 1 {
		metadata["os"] = osMatches[1]
	}

	// Extract modules from Server header
	// Server header format: Apache/2.4.52 (Ubuntu) mod_ssl/2.4.52 OpenSSL/3.0.2
	// We skip "Apache" (it's the main product) and "PHP" (handled via X-Powered-By)
	modules := make(map[string]string)
	moduleMatches := moduleVersionRegex.FindAllStringSubmatch(server, -1)
	for _, m := range moduleMatches {
		if len(m) < 3 {
			continue
		}
		name := m[1]
		ver := m[2]

		// Skip "Apache" (it's the main product, already extracted)
		if strings.EqualFold(name, "Apache") {
			continue
		}
		// Skip "PHP" (handled via X-Powered-By header below)
		if strings.EqualFold(name, "PHP") {
			continue
		}
		// Validate module version format
		if moduleVersionValidateRegex.MatchString(ver) {
			modules[name] = ver
		}
	}
	if len(modules) > 0 {
		metadata["modules"] = modules
	}

	// Check for PHP module via X-Powered-By header
	xPoweredBy := resp.Header.Get("X-Powered-By")
	if xPoweredBy != "" {
		phpMatches := phpVersionRegex.FindStringSubmatch(xPoweredBy)
		if len(phpMatches) > 1 {
			metadata["php_version"] = phpMatches[1]
		}
	}

	return &FingerprintResult{
		Technology: "apache_httpd",
		Version:    version,
		CPEs:       []string{buildApacheHTTPDCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildApacheHTTPDCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:apache:http_server:%s:*:*:*:*:*:*:*", version)
}
