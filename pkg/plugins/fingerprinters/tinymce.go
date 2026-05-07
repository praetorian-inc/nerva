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
Package fingerprinters provides HTTP fingerprinting for TinyMCE rich text editor.

# Detection Strategy

TinyMCE is a widely-used rich text editor embedded in web applications. Exposed
instances represent a security concern due to multiple XSS CVEs:
  - CVE-2024-38356: XSS via iframe sandbox bypass
  - CVE-2024-38357: XSS via specially crafted HTML
  - CVE-2024-29203: XSS in parsing of specially crafted URLs
  - CVE-2023-48219: XSS via SVG data URIs
  - CVE-2023-45818: XSS via crafted content in special elements
  - CVE-2022-23494: XSS via the Notification plugin

Detection uses a passive-only approach by scanning the HTML response body:
  - Look for <script> tags that load tinymce.min.js or tinymce.js
  - Match CDN URLs (cdn.tiny.cloud) or local/custom paths

# Version Extraction

TinyMCE version is extracted from the script URL in two ways:

CDN pattern:
  - cdn.tiny.cloud/1/{API_KEY}/tinymce/{MAJOR}/tinymce.min.js
  - Extracts the major version number (e.g. "7")

Path-based pattern:
  - /tinymce-5.7.1/tinymce.min.js
  - /tinymce/5.7.1/tinymce.min.js
  - Extracts the full semver string (e.g. "5.7.1")

If no version is found in the URL the version field is left empty.

# Port Configuration

TinyMCE runs embedded in web applications on standard HTTP ports:
  - 80:   HTTP
  - 443:  HTTPS
  - 8080: Common alternate HTTP port

# Example Usage

	fp := &TinyMCEFingerprinter{}
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

// TinyMCEFingerprinter detects TinyMCE instances by scanning the HTML body for
// TinyMCE script references. It is a passive fingerprinter that operates on the
// initial "/" response and does not make additional HTTP requests.
type TinyMCEFingerprinter struct{}

// tinymceScriptRegex matches <script> src attributes that reference tinymce.min.js
// or tinymce.js. It captures the full URL/path so version extraction can be applied.
var tinymceScriptRegex = regexp.MustCompile(`(?i)src=["'][^"']*tinymce(?:\.min)?\.js[^"']*["']`)

// tinymceCDNVersionRegex matches CDN URLs of the form:
//
//	cdn.tiny.cloud/1/{KEY}/tinymce/{VERSION}/tinymce.min.js
//
// It captures the version component (typically a major version like "7").
var tinymceCDNVersionRegex = regexp.MustCompile(`cdn\.tiny\.cloud/\d+/[^/]+/tinymce/([^/]+)/tinymce`)

// tinymcePathVersionRegex matches path-based version directories such as:
//
//	tinymce-5.7.1/tinymce.min.js
//	tinymce/5.7.1/tinymce.min.js
var tinymcePathVersionRegex = regexp.MustCompile(`tinymce[/-](\d+\.\d+\.\d+[^/"]*)`)

func init() {
	Register(&TinyMCEFingerprinter{})
}

func (f *TinyMCEFingerprinter) Name() string {
	return "tinymce"
}

// Match returns true when the response Content-Type indicates an HTML page.
// TinyMCE is embedded in HTML pages so only HTML responses need body scanning.
func (f *TinyMCEFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "text/html")
}

// Fingerprint scans the HTML body for TinyMCE script references and extracts
// version information from the URL if present.
func (f *TinyMCEFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	bodyStr := string(body)

	// Check for any tinymce script reference in the page body.
	if !tinymceScriptRegex.MatchString(bodyStr) {
		return nil, nil
	}

	version := extractTinyMCEVersion(bodyStr)

	return &FingerprintResult{
		Technology: "tinymce",
		Version:    version,
		CPEs:       []string{buildTinyMCECPE(version)},
		Metadata:   make(map[string]any),
	}, nil
}

// extractTinyMCEVersion attempts to extract a version string from the TinyMCE
// script URL embedded in the HTML body. Returns an empty string if no version
// can be determined.
func extractTinyMCEVersion(body string) string {
	// Try CDN pattern first: cdn.tiny.cloud/1/KEY/tinymce/VERSION/tinymce.min.js
	if matches := tinymceCDNVersionRegex.FindStringSubmatch(body); len(matches) >= 2 {
		v := sanitizeVersion(matches[1])
		if v != "" {
			return v
		}
		// CDN may use a bare major version like "7" which sanitizeVersion won't
		// match because it requires at least "N.N". Return as-is if it looks like
		// a short numeric version token.
		if isSimpleVersion(matches[1]) {
			return matches[1]
		}
	}

	// Try path-based versioned directory: tinymce-5.7.1/ or tinymce/5.7.1/
	if matches := tinymcePathVersionRegex.FindStringSubmatch(body); len(matches) >= 2 {
		v := sanitizeVersion(matches[1])
		if v != "" {
			return v
		}
	}

	return ""
}

// isSimpleVersion returns true for numeric-only version tokens such as "7" or "6"
// which are used by the TinyMCE CDN to identify major versions.
var simpleVersionRegex = regexp.MustCompile(`^\d+$`)

func isSimpleVersion(s string) bool {
	return simpleVersionRegex.MatchString(s)
}

// buildTinyMCECPE generates a CPE string for TinyMCE.
// CPE format: cpe:2.3:a:tinymce:tinymce:{version}:*:*:*:*:*:*:*
func buildTinyMCECPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:tinymce:tinymce:%s:*:*:*:*:*:*:*", version)
}
