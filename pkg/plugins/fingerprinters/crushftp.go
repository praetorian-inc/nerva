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
Package fingerprinters provides HTTP fingerprinting for CrushFTP file transfer server.

# What We Detect

CrushFTP is a multi-protocol file transfer server (FTP/FTPS/SFTP/HTTP/HTTPS/WebDAV/AS2).
This fingerprinter targets its built-in HTTP WebInterface.

# Detection Strategy

Tier-1 (any one alone is sufficient), priority order:
  - Server header: case-insensitive contains "crushftp" in Server value
  - Cookies: BOTH CrushAuth AND currentAuth cookies present simultaneously
  - P3P header: contains "/WebInterface/w3c/p3p.xml" (case-sensitive; unique to CrushFTP)
  - Page title: `<title>CrushFTP WebInterface</title>` or `<title>CrushFTP - Login</title>`
  - Asset path: `/WebInterface/Resources/js/crushftp.customize.js` in body

Detection method priority for metadata:
server_header > cookies > p3p_header > title > asset_path > active_probe

# Active Probe

ProbeEndpoint() returns "/WebInterface/" — the root returns 404 but sets the pathognomonic
CrushAuth and currentAuth cookies and includes the P3P header and Server header. Status
200-499 covers the 404. The plain GET is safe — no CVE exploit surface.

# Version Extraction

Version extraction from CrushFTP HTTP responses is not supported: the Server header is a
fixed string "CrushFTP HTTP Server" (no version), and the WebInterface emits no version
meta tag on real instances. Versions can only be obtained via authenticated admin access
or via SSTI-class CVEs (CVE-2024-4040), which are explicitly out of scope. CPE is emitted
with wildcard version.

# CPE

cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*

# CVE Context

  - CVE-2025-2825 (CVSS 9.8): Authentication bypass, March 2025. Unauthenticated users
    can access the WebInterface with admin privileges via crafted HTTP request.
    Do NOT probe administrative endpoints.
  - CVE-2024-4040 (CVSS 10.0, CISA KEV): Server-Side Template Injection → VFS sandbox
    escape allowing arbitrary file read as root. Actively exploited in the wild.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// CrushFTPFingerprinter detects CrushFTP file transfer server instances.
type CrushFTPFingerprinter struct{}

// crushFTPMetaVersionRegex extracts the version from the HTML meta generator tag.
// Real CrushFTP instances do not emit this tag; retained for completeness.
// Example: `<meta name="generator" content="CrushFTP 10.7.0">` → "10.7.0"
var crushFTPMetaVersionRegex = regexp.MustCompile(
	`(?i)<meta[^>]{0,200}?name=["']?generator["']?[^>]{0,200}?content=["']CrushFTP\s+([0-9]+(?:\.[0-9]+){1,3})["']`,
)

// crushFTPVersionValidateRegex is the two-stage validation gate.
// Anchored ^…$ to reject partial matches.
var crushFTPVersionValidateRegex = regexp.MustCompile(
	`^[0-9]+(?:\.[0-9]+){1,3}$`,
)

func init() {
	Register(&CrushFTPFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *CrushFTPFingerprinter) Name() string {
	return "crushftp"
}

// ProbeEndpoint returns "/WebInterface/" — the root returns 404 but sets the
// pathognomonic CrushAuth + currentAuth cookies and the P3P header. This is
// the recommended probe per research §2.6 and §2.11.
// Safe plain GET; does not approach any known CVE exploit surface.
func (f *CrushFTPFingerprinter) ProbeEndpoint() string {
	return "/WebInterface/"
}

// Match returns true when the response status is in the 200–499 range (inclusive).
// 5xx responses are rejected as they provide no usable fingerprint data.
func (f *CrushFTPFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return true
}

// Fingerprint performs full detection and extracts technology information.
//
// Detection requires at least one Tier-1 signal (in priority order):
//   - Server header contains "crushftp" (case-insensitive)
//   - Both CrushAuth AND currentAuth cookies present
//   - P3P header contains "/WebInterface/w3c/p3p.xml"
//   - Title is "CrushFTP WebInterface" or "CrushFTP - Login"
//   - Body contains the crushftp.customize.js asset path
func (f *CrushFTPFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: internal 2 MiB body cap.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Gate 3: CPE-injection defense.
	if strings.Contains(string(body), ":*:") {
		return nil, nil
	}

	serverHeader := resp.Header.Get("Server")
	serverLower := strings.ToLower(serverHeader)
	bodyLower := strings.ToLower(string(body))

	// Evaluate all Tier-1 signals.
	hasBrandInServer := strings.Contains(serverLower, "crushftp")
	hasCookiePair := crushFTPHasCookiePair(resp.Cookies())
	hasP3PHeader := crushFTPHasP3PHeader(resp.Header)
	hasBrandInTitle := strings.Contains(bodyLower, "<title>crushftp webinterface</title>") ||
		strings.Contains(bodyLower, "<title>crushftp - login</title>")
	hasAssetPath := strings.Contains(bodyLower, "/webinterface/resources/js/crushftp.customize.js")

	if !hasBrandInServer && !hasCookiePair && !hasP3PHeader && !hasBrandInTitle && !hasAssetPath {
		return nil, nil
	}

	// Determine detection method by priority: server_header > cookies > p3p_header > title > asset_path.
	detectionMethod := "body"
	if hasBrandInTitle {
		detectionMethod = "title"
	}
	if hasAssetPath {
		detectionMethod = "asset_path"
	}
	if hasP3PHeader {
		detectionMethod = "p3p_header"
	}
	if hasCookiePair {
		detectionMethod = "cookies"
	}
	if hasBrandInServer {
		detectionMethod = "server_header"
	}

	// Determine if this came from the active probe.
	probePath := ""
	if resp.Request != nil && resp.Request.URL != nil {
		reqPath := resp.Request.URL.Path
		if strings.EqualFold(reqPath, "/WebInterface/") || strings.EqualFold(reqPath, "/WebInterface/login.html") {
			probePath = reqPath
			// Only override to active_probe when no stronger signal was found.
			if detectionMethod == "body" {
				detectionMethod = "active_probe"
			}
		}
	}

	// Version: only meta generator tag (server header is a fixed string with no version).
	version := extractCrushFTPVersion(body)

	metadata := map[string]any{
		"vendor":           "CrushFTP",
		"product":          "CrushFTP",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if probePath != "" {
		metadata["probe_path"] = probePath
	}
	if serverHeader != "" {
		metadata["server_header"] = sanitizeCrushFTPHeaderValue(serverHeader)
	}

	return &FingerprintResult{
		Technology: "crushftp",
		Version:    version,
		CPEs:       []string{buildCrushFTPCPE(version)},
		Metadata:   metadata,
	}, nil
}

// crushFTPHasCookiePair returns true when both CrushAuth AND currentAuth cookies are
// present in the response. Both must be present; either alone is insufficient.
// Cookie names are case-sensitive per RFC 6265.
func crushFTPHasCookiePair(cookies []*http.Cookie) bool {
	hasCrushAuth := false
	hasCurrentAuth := false
	for _, c := range cookies {
		switch c.Name {
		case "CrushAuth":
			hasCrushAuth = true
		case "currentAuth":
			hasCurrentAuth = true
		}
	}
	return hasCrushAuth && hasCurrentAuth
}

// crushFTPHasP3PHeader returns true when any P3P header value contains the unique
// CrushFTP path "/WebInterface/w3c/p3p.xml" (case-sensitive — CrushFTP always uses
// this exact capitalization).
func crushFTPHasP3PHeader(header http.Header) bool {
	for _, v := range header.Values("P3P") {
		if strings.Contains(v, "/WebInterface/w3c/p3p.xml") {
			return true
		}
	}
	return false
}

// extractCrushFTPVersion attempts version extraction from the HTML meta generator tag.
// The Server header is a fixed string "CrushFTP HTTP Server" with no version — see
// package documentation.
// Returns "" if no valid version is found (which is expected for real deployments).
func extractCrushFTPVersion(body []byte) string {
	if m := crushFTPMetaVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); crushFTPVersionValidateRegex.MatchString(v) {
			return v
		}
	}
	return ""
}

// sanitizeCrushFTPHeaderValue strips control characters and limits length to 256 chars.
func sanitizeCrushFTPHeaderValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 0x20 && r != 0x7F {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if len(result) > 256 {
		result = result[:256]
	}
	return result
}

// buildCrushFTPCPE constructs the NVD-canonical CPE 2.3 string for CrushFTP.
// When version is empty, a wildcard CPE is emitted.
func buildCrushFTPCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:crushftp:crushftp:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:crushftp:crushftp:%s:*:*:*:*:*:*:*", version)
}
