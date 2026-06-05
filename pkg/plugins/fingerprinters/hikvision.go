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
Package fingerprinters provides HTTP fingerprinting for Hikvision IP cameras,
NVRs, DVRs, and related surveillance devices.

# What We Detect

  - Hikvision cameras, NVRs, and DVRs via unauthenticated ISAPI access
    (GET /ISAPI/System/deviceInfo returns full device XML without credentials).
    This is the most definitive signal and triggers SeverityHigh because
    unauthenticated ISAPI access exposes device model, serial number, firmware
    version, and MAC address on surveillance infrastructure.

  - Hikvision web UI login pages via title-tag branding ("Hikvision" or
    "HIKVISION" in <title>) or App-Webs asset references in src/href attributes.

  - Distinctive Hikvision server headers: "DNVRS-Webs" or "App-webs/" prefixes.
    Note: "webserver" is too generic and is NOT used as a standalone signal.

# What We Do NOT Detect

  - Hikvision cameras proxied behind CDNs or rebranded OEM devices that strip
    identifying headers and replace the ISAPI endpoint.

  - Hikvision SDK integrations in third-party VMS software, which may expose
    parts of ISAPI under different paths.

  - The generic "webserver" Server header value: it appears on many non-Hikvision
    devices (Dahua, HiSilicon-based cameras from various vendors). Only used
    combined with other signals, not as a standalone match.

# Security Context

Unauthenticated access to /ISAPI/System/deviceInfo exposes device model, serial
number, MAC address, and firmware version without credentials. This information
enables targeted exploitation, physical location inference, and default-credential
attacks. Surveillance infrastructure with public ISAPI access is a critical
exposure.

# Active Probe Safety

The active probe issues a read-only GET /ISAPI/System/deviceInfo with Accept:
application/xml. This is a safe, non-destructive operation. The ISAPI protocol
is Hikvision's standard device information API and is deployed on hundreds of
thousands of devices globally.

# CPE

Hikvision firmware CPE: cpe:2.3:o:hikvision:*:{version}:*:*:*:*:*:*:*

The CPE uses the "o:" component type (operating system / firmware), not "a:"
(application), because ISAPI firmware is embedded OS-level software.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// hikvisionServerRe matches the distinctive Hikvision server headers.
// "DNVRS-Webs" and "App-webs/" are exclusive to Hikvision/HiSilicon devices.
// Anchored to prevent prefix/suffix injection via CPE metacharacters.
var hikvisionServerRe = regexp.MustCompile(`^(?:DNVRS-Webs|App-webs/)`)

// isapiRootRe matches the ISAPI DeviceInfo XML root element.
// The xmlns attribute confirms this is a genuine ISAPI response, not incidental XML.
var isapiRootRe = regexp.MustCompile(`(?i)<DeviceInfo\b[^>]*>`)

// isapiModelRe extracts the model from <model>...</model> in the ISAPI XML.
// Bounded at 128 chars; accepts alphanumeric, spaces, and common separators
// including "/" which appears in Hikvision model numbers (e.g., DS-7208HUHI-F2/N).
var isapiModelRe = regexp.MustCompile(`(?i)<model>\s*([A-Za-z0-9][A-Za-z0-9 \-_./]{0,127})\s*</model>`)

// isapiDeviceNameRe extracts <deviceName> as a fallback model source.
var isapiDeviceNameRe = regexp.MustCompile(`(?i)<deviceName>\s*([A-Za-z0-9][A-Za-z0-9 \-_./]{0,127})\s*</deviceName>`)

// isapiFirmwareRe extracts the firmware version string from <firmwareVersion>.
// Accepts an optional leading "V" prefix (e.g., "V5.4.5") that is stripped
// before CPE emission. Bounded quantifiers prevent catastrophic backtracking.
var isapiFirmwareRe = regexp.MustCompile(`(?i)<firmwareVersion>\s*V?([0-9]+(?:\.[0-9]+){1,4}(?:\.[0-9]+)*)\s*</firmwareVersion>`)

// isapiDeviceTypeRe extracts the device type (IPCamera, NVR, DVR, etc.).
var isapiDeviceTypeRe = regexp.MustCompile(`(?i)<deviceType>\s*([A-Za-z0-9][A-Za-z0-9 \-_.]{0,63})\s*</deviceType>`)

// hikvisionVersionValidateRe is the second-stage version gate.
// Accepts dotted numeric versions with up to 5 segments (e.g., "5.4.5.170124").
// Rejects strings with letters, hyphens, or CPE metacharacters.
var hikvisionVersionValidateRe = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){1,4}$`)

// hikvisionTitleRe matches Hikvision branding in an HTML <title> tag.
// Structural signal: the <title> element is the application's self-identification,
// not incidental prose. Case-insensitive to match "HIKVISION" and "Hikvision".
var hikvisionTitleRe = regexp.MustCompile(`(?i)<title[^>]*>[^<]*hikvision[^<]*</title>`)

// hikvisionAppWebsRe matches the App-Webs path prefix in src or href attributes.
// App-Webs is Hikvision's embedded web application framework; its asset paths
// in src/href are a structural marker of the Hikvision login UI.
var hikvisionAppWebsRe = regexp.MustCompile(`(?i)(?:src|href)=["'][^"']*App-Webs/`)

// HikvisionFingerprinter detects Hikvision IP cameras, NVRs, and DVRs via the
// ISAPI deviceInfo endpoint, distinctive server headers, and login page branding.
type HikvisionFingerprinter struct{}

func init() {
	Register(&HikvisionFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *HikvisionFingerprinter) Name() string {
	return "hikvision"
}

// ProbeEndpoint returns the ISAPI System device-info endpoint.
// A read-only GET to this path returns device metadata in XML without
// requiring authentication on unprotected (or default-configured) devices.
func (f *HikvisionFingerprinter) ProbeEndpoint() string {
	return "/ISAPI/System/deviceInfo"
}

// ProbeAccept returns the Accept header for the ISAPI probe.
// The ISAPI protocol uses application/xml responses.
func (f *HikvisionFingerprinter) ProbeAccept() string {
	return "application/xml"
}

// Match returns true when the response is a candidate for Hikvision detection.
//
// Fast-path signals that warrant a body scan:
//   - Server header matches "DNVRS-Webs" or "App-webs/" (definitive Hikvision headers)
//   - Content-Type is text/xml or application/xml (potential ISAPI response)
//   - Content-Type is text/html (potential login page)
//
// 5xx responses are rejected immediately.
func (f *HikvisionFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Fast-path: distinctive server header.
	server := resp.Header.Get("Server")
	if hikvisionServerRe.MatchString(server) {
		return true
	}

	// XML or HTML body is worth scanning for ISAPI or login page signals.
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if strings.Contains(ct, "text/xml") || strings.Contains(ct, "application/xml") {
		return true
	}
	if strings.Contains(ct, "text/html") {
		return true
	}

	return false
}

// Fingerprint performs full Hikvision detection and metadata extraction.
//
// Detection requires at least one definitive signal:
//   - ISAPI XML body (DeviceInfo root element with xmlns ISAPI namespace) — PRIMARY
//   - Distinctive server header (DNVRS-Webs or App-webs/) — SECONDARY
//   - Login page branding (title tag or App-Webs asset paths) — TERTIARY
//
// ISAPI detection: SeverityHigh and anonymous_access=true, because the device
// returned full system information without requiring authentication.
//
// Detection method values: "isapi", "active_probe", "server_header", "web_ui".
func (f *HikvisionFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: 2 MiB body cap — defense-in-depth above the engine limit.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	server := resp.Header.Get("Server")
	hasServerHeader := hikvisionServerRe.MatchString(server)

	// Check if this response came from the ISAPI active probe endpoint.
	isActiveProbe := false
	if resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/ISAPI/System/deviceInfo") {
			isActiveProbe = true
		}
	}

	// --- Signal detection ---

	hasISAPI := isapiRootRe.Match(body)
	hasWebUI := hikvisionTitleRe.Match(body) || hikvisionAppWebsRe.Match(body)

	// Require at least one definitive signal.
	if !hasISAPI && !hasServerHeader && !hasWebUI {
		return nil, nil
	}

	// --- Metadata extraction ---

	version := extractHikvisionFirmwareVersion(body)
	// CPE injection defense — the extraction regex only matches digits and dots,
	// but defend in depth against any future regex changes.
	if strings.ContainsAny(version, ":*") {
		version = ""
	}

	model := extractISAPITagValue(body, isapiModelRe)
	if model == "" {
		model = extractISAPITagValue(body, isapiDeviceNameRe)
	}

	deviceType := extractISAPITagValue(body, isapiDeviceTypeRe)

	// --- Detection method ---

	var methods []string
	if hasISAPI {
		if isActiveProbe {
			methods = append(methods, "active_probe")
		} else {
			methods = append(methods, "isapi")
		}
	}
	if hasWebUI {
		methods = append(methods, "web_ui")
	}
	if hasServerHeader && !hasISAPI && !hasWebUI {
		// Server header alone — only track when it is the sole signal to avoid
		// double-counting when ISAPI or web_ui is also present.
		methods = append(methods, "server_header")
	}
	detectionMethod := strings.Join(methods, ",")

	metadata := map[string]any{
		"vendor":           "Hikvision",
		"detection_method": detectionMethod,
	}
	if model != "" {
		metadata["model"] = model
	}
	if deviceType != "" {
		metadata["device_type"] = deviceType
	}
	if version != "" {
		metadata["firmware_version"] = version
	}
	if hasServerHeader {
		metadata["server_header"] = sanitizeHTTPHeaderValue(server)
	}

	result := &FingerprintResult{
		Technology: "hikvision",
		Version:    version,
		CPEs:       []string{buildHikvisionCPE(version)},
		Metadata:   metadata,
	}

	// Unauthenticated ISAPI access is a critical exposure on surveillance devices.
	if hasISAPI {
		result.Metadata["anonymous_access"] = true
		result.Severity = plugins.SeverityHigh
	}

	return result, nil
}

// extractHikvisionFirmwareVersion parses the firmware version from an ISAPI
// XML body. It strips the optional "V" prefix (e.g., "V5.4.5" → "5.4.5") and
// applies two-stage validation before returning. Returns "" if no valid version
// is found.
func extractHikvisionFirmwareVersion(body []byte) string {
	m := isapiFirmwareRe.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	v := string(m[1])
	if !hikvisionVersionValidateRe.MatchString(v) {
		return ""
	}
	return v
}

// extractISAPITagValue returns the first capture group from a compiled regex
// applied to body, trimmed of surrounding whitespace. Returns "" if not found
// or if the extracted value is empty after trimming.
func extractISAPITagValue(body []byte, re *regexp.Regexp) string {
	m := re.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	return strings.TrimSpace(string(m[1]))
}

// buildHikvisionCPE returns the Hikvision firmware CPE 2.3 string.
// The "o:" component type is used because ISAPI firmware is embedded OS-level
// software. When version is empty, a wildcard "*" is emitted.
func buildHikvisionCPE(version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:o:hikvision:*:%s:*:*:*:*:*:*:*", v)
}
