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
Package fingerprinters provides HTTP fingerprinting for Adobe Experience Manager (AEM).

# Detection Strategy

Adobe Experience Manager (AEM) is an enterprise content management system.
Exposed instances represent a security concern due to:
  - CRX/DE content repository access
  - Administrative interfaces on author ports
  - Known CVEs and misconfigurations in older versions

Detection uses active probing:
  - Active: Query /libs/granite/core/content/login.html (Granite login page)
  - Body markers: "granite/core/content/login", "AEM Sign In",
    "Adobe Experience Manager", "cq-login-form", "granite-login"
  - Header markers: Server: Day-Servlet-Engine,
    X-Powered-By: Day CQ/Communique/Adobe Experience Manager

# Version Detection

Version is extracted from:
  - granite.version meta tag in the HTML body
  - "AEM X.Y" or "AEM X.Y.Z" patterns in body
  - "Adobe Experience Manager X.Y" patterns in body
  - Server header version string

# Port Configuration

AEM typically runs on:
  - 80:   HTTP standard
  - 443:  HTTPS standard
  - 4502: AEM Author
  - 4503: AEM Publish

# CPE Format

cpe:2.3:a:adobe:experience_manager:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// AEMFingerprinter detects Adobe Experience Manager via the Granite login page
type AEMFingerprinter struct{}

// aemVersionAtStartRegex matches a version string only at the start of the input
var aemVersionAtStartRegex = regexp.MustCompile(`^(\d+\.\d+(?:\.\d+)*)`)

// aemBodyMarkers are strings that confirm AEM presence in HTML body
var aemBodyMarkers = []string{
	"granite/core/content/login",
	"AEM Sign In",
	"Adobe Experience Manager",
	"cq-login-form",
	"granite-login",
}

// aemServerHeaders are Server header values that indicate AEM
var aemServerHeaders = []string{
	"Day-Servlet-Engine",
}

// aemXPoweredByPatterns are X-Powered-By header values that indicate AEM
var aemXPoweredByPatterns = []string{
	"Day CQ",
	"Communique",
	"Adobe Experience Manager",
}

func init() {
	Register(&AEMFingerprinter{})
}

func (f *AEMFingerprinter) Name() string {
	return "adobe_experience_manager"
}

// ProbeEndpoint returns the AEM Granite login page, the most reliable single
// endpoint for detecting AEM presence across author and publish instances.
func (f *AEMFingerprinter) ProbeEndpoint() string {
	return "/libs/granite/core/content/login.html"
}

// hasAEMHeaders returns true if the response headers contain AEM-specific markers.
// Checks Server, X-Powered-By, and Dispatcher headers.
func hasAEMHeaders(resp *http.Response) bool {
	serverHeader := resp.Header.Get("Server")
	for _, marker := range aemServerHeaders {
		if strings.Contains(serverHeader, marker) {
			return true
		}
	}

	xPoweredBy := resp.Header.Get("X-Powered-By")
	for _, pattern := range aemXPoweredByPatterns {
		if strings.Contains(xPoweredBy, pattern) {
			return true
		}
	}

	return resp.Header.Get("Dispatcher") != ""
}

// Match returns true if the response could be from AEM based on headers.
// Checks for AEM-specific Server/X-Powered-By headers or text/html content type.
func (f *AEMFingerprinter) Match(resp *http.Response) bool {
	if hasAEMHeaders(resp) {
		return true
	}

	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "text/html")
}

// Fingerprint performs full AEM detection and extracts version information.
// Returns nil if the response does not confirm AEM presence.
func (f *AEMFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Verify AEM presence via body markers
	bodyStr := string(body)
	isAEM := false
	for _, marker := range aemBodyMarkers {
		if strings.Contains(bodyStr, marker) {
			isAEM = true
			break
		}
	}

	// Fall back to header-based verification if body doesn't confirm AEM
	if !isAEM {
		isAEM = hasAEMHeaders(resp)
	}

	if !isAEM {
		return nil, nil
	}

	version := extractAEMVersion(resp, bodyStr)
	if version == "" {
		version = "*"
	}

	dispatcher := resp.Header.Get("Dispatcher") != ""

	metadata := map[string]any{
		"dispatcher": dispatcher,
		"server":     resp.Header.Get("Server"),
	}

	return &FingerprintResult{
		Technology: "adobe_experience_manager",
		Version:    version,
		CPEs:       []string{buildAEMCPE(version)},
		Metadata:   metadata,
	}, nil
}

// extractAEMVersion attempts to extract an AEM version string from the response.
// It checks in priority order: granite.version meta tag, body patterns, Server header.
func extractAEMVersion(resp *http.Response, bodyStr string) string {
	// 1. Check for granite.version meta tag: <meta name="granite.version" content="6.5.21.0">
	if version := extractMetaVersion(bodyStr); version != "" {
		return version
	}

	// 2. Check body for "AEM X.Y" or "Adobe Experience Manager X.Y" patterns
	if version := extractBodyVersion(bodyStr); version != "" {
		return version
	}

	// 3. Check Server header for version
	if version := extractHeaderVersion(resp.Header.Get("Server")); version != "" {
		return version
	}

	return ""
}

// extractMetaVersion extracts the version from a granite.version meta tag.
func extractMetaVersion(bodyStr string) string {
	// Look for: content="6.5.21.0" in close proximity to granite.version
	graniteIdx := strings.Index(bodyStr, "granite.version")
	if graniteIdx == -1 {
		return ""
	}
	// Search within the next 200 bytes for a content= attribute
	searchArea := bodyStr[graniteIdx:]
	if len(searchArea) > 200 {
		searchArea = searchArea[:200]
	}
	contentIdx := strings.Index(searchArea, `content="`)
	if contentIdx == -1 {
		return ""
	}
	start := contentIdx + len(`content="`)
	rest := searchArea[start:]
	endIdx := strings.IndexByte(rest, '"')
	if endIdx == -1 {
		return ""
	}
	candidate := rest[:endIdx]
	if match := aemVersionAtStartRegex.FindString(candidate); match != "" {
		return match
	}
	return ""
}

// extractBodyVersion extracts AEM version from known body patterns.
func extractBodyVersion(bodyStr string) string {
	patterns := []string{
		"AEM ",
		"Adobe Experience Manager ",
	}

	for _, prefix := range patterns {
		searchFrom := 0
		for {
			idx := strings.Index(bodyStr[searchFrom:], prefix)
			if idx == -1 {
				break
			}
			absIdx := searchFrom + idx
			rest := bodyStr[absIdx+len(prefix):]
			matches := aemVersionAtStartRegex.FindString(rest)
			if matches != "" {
				return matches
			}
			searchFrom = absIdx + len(prefix)
		}
	}
	return ""
}

// extractHeaderVersion extracts a version from an AEM Server header value.
// It prefers the version after "AEM/" (e.g., "AEM/6.4" from "Day-Servlet-Engine/4.1.22 AEM/6.4").
// Falls back to the version after the first "/" if "AEM/" is not present.
func extractHeaderVersion(serverHeader string) string {
	if serverHeader == "" {
		return ""
	}
	// Prefer "AEM/" prefix to extract the AEM version rather than the servlet version
	if aemIdx := strings.Index(serverHeader, "AEM/"); aemIdx != -1 {
		rest := serverHeader[aemIdx+len("AEM/"):]
		return aemVersionAtStartRegex.FindString(rest)
	}
	slashIdx := strings.Index(serverHeader, "/")
	if slashIdx == -1 {
		return ""
	}
	rest := serverHeader[slashIdx+1:]
	return aemVersionAtStartRegex.FindString(rest)
}

// buildAEMCPE generates a CPE string for Adobe Experience Manager.
// CPE format: cpe:2.3:a:adobe:experience_manager:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for the version field.
func buildAEMCPE(version string) string {
	if version == "" || version == "*" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:adobe:experience_manager:%s:*:*:*:*:*:*:*", version)
}
