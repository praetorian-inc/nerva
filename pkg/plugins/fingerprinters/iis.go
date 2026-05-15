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
Package fingerprinters provides HTTP fingerprinting for Microsoft Internet
Information Services (IIS).

# What We Detect

Microsoft Internet Information Services (IIS) — all versions from IIS 6.0+
(Windows Server 2003+). Detection is fully header-driven: no active probe is
needed because IIS is reliably identified via the Server and X-Powered-By
response headers that it emits by default.

# What We Do NOT Detect

  - IIS Express: a development server distributed with Visual Studio. It is a
    separate product with a different CPE and distinct security characteristics.
  - Azure App Service: although Azure App Service runs on IIS internally, its
    responses are fronted by Azure's infrastructure. The Server header does not
    report "Microsoft-IIS" in the standard way, and the security characteristics
    differ from on-premises IIS.

# Security Context

IIS version directly maps to Windows Server version, enabling OS-level
vulnerability assessment without additional probing. The mapping is encoded in
iisWindowsVersionMap. IIS combined with ASP.NET is a frequent target for .NET
deserialization attacks (e.g., ViewState deserialization, gadget chains against
ObjectStateFormatter). Exposed IIS instances may also be affected by historical
CVEs such as CVE-2017-7269 (IIS 6.0 WebDAV buffer overflow, CVSS 9.8).

# Detection Signals

Definitive signals (at least one required to fire):

  - Server: Microsoft-IIS/{version} — present on nearly all IIS versions.
  - X-Powered-By: ASP.NET — ASP.NET runs exclusively on IIS in production.
  - X-AspNet-Version: {version} — only IIS/ASP.NET emits this header.

Corroborating signal (not sufficient alone):

  - Default welcome page body: title contains "IIS Windows Server" or
    "Internet Information Services".

# CPE

cpe:2.3:a:microsoft:internet_information_services:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// IISFingerprinter detects Microsoft Internet Information Services via HTTP
// response headers. No active probe is required.
type IISFingerprinter struct{}

// iisServerVersionRegex extracts the IIS version from the Server response header.
// Examples: "Microsoft-IIS/10.0", "Microsoft-IIS/8.5", "microsoft-iis/7.5".
// Capture group 1 = version string (1–4 dotted digit groups).
var iisServerVersionRegex = regexp.MustCompile(
	`(?i)Microsoft-IIS/([0-9]+(?:\.[0-9]+){0,3})`,
)

// iisVersionValidateRegex is the anchored second-stage validator applied after
// iisServerVersionRegex. Rejects partial matches, dot-edge cases, and any
// value that does not consist solely of digits and dots.
var iisVersionValidateRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}$`)

// iisAspNetVersionRegex validates the X-AspNet-Version header value.
// The header value IS the version (e.g., "4.0.30319"), so we validate it
// directly with an anchored pattern.
var iisAspNetVersionRegex = regexp.MustCompile(`^([0-9]+(?:\.[0-9]+){1,3})$`)

// iisDefaultPageRegex detects the IIS default welcome page in a response body
// by matching the title element content.
var iisDefaultPageRegex = regexp.MustCompile(
	`(?i)<title[^>]*>\s*(?:IIS\s+Windows\s+Server|Internet\s+Information\s+Services)\s*</title>`,
)

// iisDotNetCLRVersionRegex extracts a .NET or .NET CLR version from the
// X-Powered-By header. Examples: "ASP.NET", "ASP.NET (.NET CLR 4.0.30319)",
// ".NET 8.0", ".NET CLR 2.0.50727".
var iisDotNetCLRVersionRegex = regexp.MustCompile(
	`(?i)\.NET(?:\s+CLR)?\s+([0-9]+(?:\.[0-9]+){1,3})`,
)

// iisWindowsVersionMap maps IIS major.minor version to the Windows Server
// release(s) that ship with that IIS version.
var iisWindowsVersionMap = map[string]string{
	"6.0":  "Windows Server 2003",
	"7.0":  "Windows Server 2008",
	"7.5":  "Windows Server 2008 R2",
	"8.0":  "Windows Server 2012",
	"8.5":  "Windows Server 2012 R2",
	"10.0": "Windows Server 2016/2019/2022",
}

func init() {
	Register(&IISFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *IISFingerprinter) Name() string {
	return "iis"
}

// Match returns true when the response carries at least one IIS-correlated
// signal. It is a fast pre-filter; heavy body analysis happens in Fingerprint.
//
// Signals checked (any one is sufficient):
//   - Status in 200–499 AND Server header contains "microsoft-iis" (definitive).
//   - Status in 200–499 AND X-Powered-By header contains "asp.net" (strong).
//   - Status in 200–499 AND X-AspNet-Version header is non-empty (definitive).
func (f *IISFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	serverLower := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverLower, "microsoft-iis") {
		return true
	}

	poweredByLower := strings.ToLower(resp.Header.Get("X-Powered-By"))
	if strings.Contains(poweredByLower, "asp.net") {
		return true
	}

	if resp.Header.Get("X-AspNet-Version") != "" {
		return true
	}

	return false
}

// Fingerprint performs full IIS detection and metadata extraction.
//
// Gates applied before analysis:
//  1. Status filter: 200–499 (mirrors boa.go / checkpoint.go pattern).
//  2. Body cap: 2 MiB — legitimate IIS pages are far smaller.
//
// At least one definitive signal must be present:
//   - Server header contains "microsoft-iis" (case-insensitive).
//   - X-Powered-By header contains "asp.net" (case-insensitive).
//   - X-AspNet-Version header is non-empty.
//
// Version is extracted exclusively from the Server header. The detection_method
// metadata key reflects whether the Server header, another header, or body
// corroboration contributed to detection.
func (f *IISFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: 2 MiB body cap.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	serverHeader := resp.Header.Get("Server")
	serverLower := strings.ToLower(serverHeader)
	poweredByHeader := resp.Header.Get("X-Powered-By")
	poweredByLower := strings.ToLower(poweredByHeader)
	aspNetVersionHeader := resp.Header.Get("X-AspNet-Version")

	hasServerSignal := strings.Contains(serverLower, "microsoft-iis")
	hasPoweredBySignal := strings.Contains(poweredByLower, "asp.net")
	hasAspNetVersionSignal := aspNetVersionHeader != ""

	// At least one definitive signal must be present.
	if !hasServerSignal && !hasPoweredBySignal && !hasAspNetVersionSignal {
		return nil, nil
	}

	// Detect default welcome page in body (corroborating).
	hasDefaultPage := isIISDefaultPage(body)

	// Determine detection method.
	var detectionMethod string
	switch {
	case hasServerSignal:
		detectionMethod = "server_header"
	case hasPoweredBySignal || hasAspNetVersionSignal:
		detectionMethod = "header"
	}

	// Extract IIS version from Server header (primary source).
	version := extractIISVersion(serverHeader)
	// Defense-in-depth: discard version if it somehow contains CPE metacharacters.
	// The extraction regex only captures digits and dots, so this should never trigger.
	if strings.ContainsAny(version, ":*") {
		version = ""
	}

	// Extract ASP.NET version from X-AspNet-Version header.
	aspNetVersion := extractASPNetVersion(aspNetVersionHeader)

	// Extract .NET CLR version from X-Powered-By header.
	dotNetCLRVersion := extractDotNetCLRVersion(poweredByHeader)

	// Map IIS version to Windows Server version.
	windowsVersion := mapIISToWindowsVersion(version)

	// Build metadata — only include non-empty values.
	metadata := map[string]any{
		"vendor":           "Microsoft",
		"product":          "IIS",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if windowsVersion != "" {
		metadata["windows_version"] = windowsVersion
	}
	if aspNetVersion != "" {
		metadata["aspnet_version"] = aspNetVersion
	}
	if dotNetCLRVersion != "" {
		metadata["dotnet_clr_version"] = dotNetCLRVersion
	}
	if hasDefaultPage {
		metadata["default_page"] = true
	}
	if serverHeader != "" {
		metadata["server_header"] = sanitizeIISHeaderValue(serverHeader)
	}
	if poweredByHeader != "" {
		metadata["powered_by"] = sanitizeIISHeaderValue(poweredByHeader)
	}

	return &FingerprintResult{
		Technology: "iis",
		Version:    version,
		CPEs:       []string{buildIISCPE(version)},
		Metadata:   metadata,
	}, nil
}

// extractIISVersion extracts and validates the IIS version from a Server header
// value. Returns empty string when no valid version is found.
func extractIISVersion(serverHeader string) string {
	m := iisServerVersionRegex.FindStringSubmatch(serverHeader)
	if len(m) < 2 {
		return ""
	}
	v := m[1]
	if !iisVersionValidateRegex.MatchString(v) {
		return ""
	}
	return v
}

// extractASPNetVersion extracts and validates the ASP.NET version from the
// X-AspNet-Version header value. Returns empty string when the value is absent
// or does not match the expected dotted-digit format.
func extractASPNetVersion(header string) string {
	if header == "" {
		return ""
	}
	m := iisAspNetVersionRegex.FindStringSubmatch(header)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// extractDotNetCLRVersion extracts a .NET CLR version from the X-Powered-By
// header. Returns empty string when no version is found.
func extractDotNetCLRVersion(poweredBy string) string {
	m := iisDotNetCLRVersionRegex.FindStringSubmatch(poweredBy)
	if len(m) < 2 {
		return ""
	}
	return m[1]
}

// mapIISToWindowsVersion returns the Windows Server version(s) that correspond
// to the given IIS major.minor version string. Returns empty string for unknown
// versions or when version is empty.
func mapIISToWindowsVersion(iisVersion string) string {
	if iisVersion == "" {
		return ""
	}
	// Normalize to major.minor (first two components).
	parts := strings.SplitN(iisVersion, ".", 3)
	if len(parts) < 2 {
		return iisWindowsVersionMap[iisVersion]
	}
	majorMinor := parts[0] + "." + parts[1]
	return iisWindowsVersionMap[majorMinor]
}

// isIISDefaultPage returns true when the response body appears to be the IIS
// default welcome page, identified by a title element containing "IIS Windows
// Server" or "Internet Information Services".
func isIISDefaultPage(body []byte) bool {
	return iisDefaultPageRegex.Match(body)
}

// sanitizeIISHeaderValue strips control characters and caps output at 256 bytes
// to prevent log injection or oversized metadata values from attacker-controlled
// headers. Only printable, non-DEL runes (0x20 ≤ r < 0x7F) are retained.
func sanitizeIISHeaderValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= 256 {
			break
		}
		if r >= 0x20 && r != 0x7F {
			b.WriteRune(r)
		}
	}
	return b.String()
}

// buildIISCPE constructs a CPE 2.3 string for Microsoft IIS. When version is
// empty, a wildcard CPE is emitted.
//
// NVD vendor/product: microsoft:internet_information_services
func buildIISCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf(
		"cpe:2.3:a:microsoft:internet_information_services:%s:*:*:*:*:*:*:*",
		version,
	)
}
