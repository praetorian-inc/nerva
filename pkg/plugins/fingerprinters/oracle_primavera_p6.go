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
Package fingerprinters includes detection for Oracle Primavera P6 EPPM.

# Detection Strategy

Oracle Primavera P6 Enterprise Project Portfolio Management (EPPM) is a
WebLogic-hosted project portfolio management platform. Instances are identified
via the unauthenticated login page at /p6/action/login, which returns the full
HTML login UI including version information in its footer.

Three detection signals are evaluated (any one is sufficient):

  - hasP6Title: <title> tag containing "Oracle Primavera P6 EPPM" (most distinctive)
  - hasP6Logo: body references the product-unique logo file "oracle-primavera-logo-cmyk.png"
  - hasP6Branding: body contains both "Primavera P6" and "EPPM" together

All signals are reflection-safe against the probe path /p6/action/login, which
contains only "p6", "action", and "login" — none sufficient to trigger detection
on their own.

# Version Extraction

The login page footer includes a version string in the format:

	Version 24.12.8.0 (B0109) 08.07.2025.2306

The fingerprinter extracts:
  - version (e.g., "24.12.8.0") from group 1 of p6VersionRegex
  - build number (e.g., "0109") from group 2, stored in metadata["build"]

# Out of Scope

Primavera Gateway is out of scope (separate product, separate ticket).

# CPE

cpe:2.3:a:oracle:primavera_p6_enterprise_project_portfolio_management:*:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// p6VersionRegex matches the login footer version string:
//
//	Version 24.12.8.0 (B0109) 08.07.2025.2306
//
// Group 1: version (e.g., "24.12.8.0")
// Group 2: build number (e.g., "0109")
var p6VersionRegex = regexp.MustCompile(`Version\s+(\d+(?:\.\d+){1,4})\s*\(B(\d+)\)`)

// p6TitleRegex matches the Primavera P6 EPPM login page title.
// Case-insensitive and tolerant of tag attributes and surrounding whitespace.
var p6TitleRegex = regexp.MustCompile(`(?i)<title[^>]*>\s*Oracle Primavera P6 EPPM\s*</title>`)

// OraclePrimaveraP6Fingerprinter detects Oracle Primavera P6 EPPM instances
// via the unauthenticated login page.
type OraclePrimaveraP6Fingerprinter struct{}

func init() {
	Register(&OraclePrimaveraP6Fingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *OraclePrimaveraP6Fingerprinter) Name() string {
	return "oracle_primavera_p6"
}

// ProbeEndpoint returns the P6 EPPM login page path.
// An unauthenticated GET returns the full login HTML including version information.
func (f *OraclePrimaveraP6Fingerprinter) ProbeEndpoint() string {
	return "/p6/action/login"
}

// ProbeAccept returns the Accept header value for the active probe.
func (f *OraclePrimaveraP6Fingerprinter) ProbeAccept() string {
	return "text/html"
}

// Match returns true when the response is a candidate for P6 EPPM detection.
// Accepts 2xx–4xx responses with a text/html Content-Type.
func (f *OraclePrimaveraP6Fingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection signals (any one triggers detection):
//  1. hasP6Title   — <title> contains "Oracle Primavera P6 EPPM"
//  2. hasP6Logo    — body contains "oracle-primavera-logo-cmyk.png"
//  3. hasP6Branding — body contains both "Primavera P6" and "EPPM"
//
// Detection method priority: p6_title > p6_logo > p6_branding.
func (f *OraclePrimaveraP6Fingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// 2 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	bodyStr := string(body)

	// Signal 1: product title tag (most distinctive signal).
	hasP6Title := p6TitleRegex.MatchString(bodyStr)

	// Signal 2: product-unique logo filename.
	hasP6Logo := strings.Contains(bodyStr, "oracle-primavera-logo-cmyk.png")

	// Signal 3: combined product branding.
	hasP6Branding := strings.Contains(bodyStr, "Primavera P6") && strings.Contains(bodyStr, "EPPM")

	if !hasP6Title && !hasP6Logo && !hasP6Branding {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":           "Oracle",
		"product":          "Oracle Primavera P6 EPPM",
		"detection_method": p6DetectionMethod(hasP6Title, hasP6Logo, hasP6Branding),
	}

	// Version extraction from login footer.
	version := ""
	if matches := p6VersionRegex.FindStringSubmatch(bodyStr); matches != nil {
		version = matches[1]
		if matches[2] != "" {
			metadata["build"] = matches[2]
		}
		metadata["version_note"] = "extracted from login page footer"
	}

	return &FingerprintResult{
		Technology: "oracle_primavera_p6",
		Version:    version,
		CPEs:       []string{buildPrimaveraP6CPE(version)},
		Metadata:   metadata,
	}, nil
}

// p6DetectionMethod returns the highest-priority detection method that fired.
func p6DetectionMethod(hasP6Title, hasP6Logo, hasP6Branding bool) string {
	switch {
	case hasP6Title:
		return "p6_title"
	case hasP6Logo:
		return "p6_logo"
	case hasP6Branding:
		return "p6_branding"
	default:
		return ""
	}
}

// buildPrimaveraP6CPE constructs a CPE 2.3 string for Oracle Primavera P6 EPPM.
// When version is empty or contains CPE metacharacters, a wildcard is used.
func buildPrimaveraP6CPE(version string) string {
	if version == "" || strings.ContainsAny(version, ":*?") {
		version = "*"
	}
	return fmt.Sprintf(
		"cpe:2.3:a:oracle:primavera_p6_enterprise_project_portfolio_management:%s:*:*:*:*:*:*:*",
		version,
	)
}
