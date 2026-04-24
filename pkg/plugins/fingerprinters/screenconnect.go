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
Package fingerprinters provides HTTP fingerprinting for ConnectWise ScreenConnect
remote access software.

# What We Detect

  - ScreenConnect (original branding: 2008–2016 and 2024–present)
  - ConnectWise Control (rebranded 2016–2023, same product)
  - ConnectWise ScreenConnect (transitional branding 2023–2024, same product)

Both passive (root `/` response) and active (`/SetupWizard.aspx` probe) responses
are handled by the same Match/Fingerprint functions.

# What We Do NOT Detect

  - ConnectWise Automate — different product, separate CPE
  - ConnectWise Manage — different product, separate CPE
  - ConnectWise RMM — different product
  - Historical agent installer binaries deployed to managed endpoints

# CVE Context

  - CVE-2024-1709 (auth bypass, CVSS 10.0, CISA KEV): affects versions ≤ 23.9.7.
    Exploitation requires POST to /SetupWizard.aspx/<trailing-segment> with crafted
    form parameters. Our probe is a plain GET /SetupWizard.aspx (no trailing segment,
    no body, no POST) — it does not constitute exploitation.
  - CVE-2024-1708 (path traversal): also affects versions ≤ 23.9.7.

# Active Probe Safety

The active probe issues a plain GET /SetupWizard.aspx with no query string, no
trailing path segment, and no request body. CVE-2024-1709 exploitation requires
POST with a crafted ViewState and a trailing path segment; our probe differs on
all three axes. The probe is therefore safe to run against any target, including
patched instances.

The engine sends Accept: application/json on active probes; ScreenConnect's
SetupWizard.aspx is an ASP.NET Web Forms page that ignores the Accept header and
returns HTML regardless. We do not rely on Content-Type for matching.

# Instance ID

The instance_id metadata field is BEST-EFFORT. It is extracted from the
window.ScreenConnect JS block when present in the login page (some modern versions).
When absent, the instance_id key is omitted entirely from Metadata — no empty
string is emitted. Detection is never gated on instance ID presence.

The instance_id is a ConnectWise installation-scoped 16-hex-char identifier.
It appears in agent installer filenames distributed to managed endpoints and in
.ClientLaunchParameters config files on those endpoints, making it semi-public
(not an authentication secret). It is useful for asset correlation.

# CPE

cpe:2.3:a:connectwise:screenconnect:{version}:*:*:*:*:*:*:*

NVD unified the old "ConnectWise Control" CPE alias under connectwise:screenconnect.
No separate CPE exists for the legacy branding; emitting a single CPE is correct
and intentional.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// ScreenConnectFingerprinter detects ConnectWise ScreenConnect remote access instances.
type ScreenConnectFingerprinter struct{}

// screenConnectScriptVersionRegex extracts the version from the Script.ashx cache-buster
// URL embedded in <script> tags. Example: <script src="/Script.ashx?sv=24.2.5"></script>
// Bounded: 2–4 dotted digit groups; bounded quantifier guards against adversarial input.
var screenConnectScriptVersionRegex = regexp.MustCompile(
	`Script\.ashx\?sv=([0-9]+(?:\.[0-9]+){1,3})`,
)

// screenConnectJSVersionRegex extracts the version from the inline JavaScript
// window.ScreenConnect object. Example: window.ScreenConnect = {Version: "25.2.4", ...}
// [^}]{0,500} prevents runaway matching on bodies without a closing brace.
var screenConnectJSVersionRegex = regexp.MustCompile(
	`window\.ScreenConnect\s*=\s*\{[^}]{0,500}?Version\s*:\s*"([0-9]+(?:\.[0-9]+){1,3})"`,
)

// screenConnectInstanceIDRegex extracts the instance ID from the inline JavaScript
// window.ScreenConnect object. Example: InstanceID: "abcd1234ef567890"
// Bounded: 8–64 lowercase hex characters.
var screenConnectInstanceIDRegex = regexp.MustCompile(
	`InstanceID\s*:\s*"([a-f0-9]{8,64})"`,
)

// screenConnectMetaVersionRegex extracts the version from an HTML meta tag.
// Example: <meta name="screenconnect-version" content="24.2.5">
// [^>]{0,200} prevents runaway matching on malformed HTML.
var screenConnectMetaVersionRegex = regexp.MustCompile(
	`(?i)<meta[^>]{0,200}?name=["']?screenconnect-version["']?[^>]{0,200}?content=["']([0-9]+(?:\.[0-9]+){1,3})["']`,
)

// screenConnectVersionValidateRegex is the two-stage validation gate applied after
// version extraction. Anchored ^…$ to reject partial matches; only digits and dots.
// Rejects values like "24.2.5-beta", "24.2.5:*:", ".1", "..".
var screenConnectVersionValidateRegex = regexp.MustCompile(
	`^[0-9]+(?:\.[0-9]+){1,3}$`,
)

// screenConnectInstanceIDValidateRegex is the belt-and-suspenders validation applied
// after extracting the instance ID from the window.ScreenConnect JS block.
// Anchored ^…$ to reject partial matches; only lowercase hex.
var screenConnectInstanceIDValidateRegex = regexp.MustCompile(`^[a-f0-9]{8,64}$`)

func init() {
	Register(&ScreenConnectFingerprinter{})
}

// Name returns the fingerprinter identifier.
func (f *ScreenConnectFingerprinter) Name() string {
	return "screenconnect"
}

// ProbeEndpoint returns the active probe path. The returned value is pinned to the
// canonical path with no trailing slash, no trailing segment, and no query string.
// Adding any of these could approach the CVE-2024-1709 exploit surface (POST to
// /SetupWizard.aspx/<trailing-segment>); this method must never return a variant form.
func (f *ScreenConnectFingerprinter) ProbeEndpoint() string {
	return "/SetupWizard.aspx"
}

// Match returns true when the response status is in the 200–499 range (inclusive).
// 5xx responses are rejected: a server error does not provide usable fingerprint data.
// Responses in 200–499 (including 302 redirect from a configured SetupWizard probe)
// are passed to Fingerprint for body/header analysis.
//
// Additionally, if the Server header contains "screenconnect" (case-insensitive), this
// is treated as a corroborating header-based signal and also returns true, allowing
// Fingerprint to emit a header-only result when no body brand token is present.
func (f *ScreenConnectFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	// Header-based hit: Server: ScreenConnect (exact) or Server: ScreenConnect/<version>.
	server := resp.Header.Get("Server")
	serverLower := strings.ToLower(server)
	if serverLower == "screenconnect" || strings.HasPrefix(serverLower, "screenconnect/") {
		return true
	}

	// Status in 200–499 is sufficient for body-driven detection.
	return true
}

// Fingerprint performs full detection and extracts technology information.
// It handles both passive (root `/`) and active (`/SetupWizard.aspx`) responses
// through the same code path.
//
// Detection requires at least one brand token in the lowercased body
// ("screenconnect" or "connectwise control") OR a "screenconnect" substring in
// the Server header. Neither generic tokens like "connect" or "control" alone,
// nor URL paths, are sufficient.
//
// Version extraction priority:
//  1. Script.ashx?sv= URL parameter (most reliable)
//  2. window.ScreenConnect JS block Version field
//  3. <meta name="screenconnect-version"> tag
//  4. Empty (wildcard CPE emitted)
func (f *ScreenConnectFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter — mirrors boa.go and checkpoint.go.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	// Gate 2: internal 2 MiB body cap — defense-in-depth above the engine's
	// 10 MiB io.LimitReader. A legitimate ScreenConnect login page is <100 KiB;
	// bodies >2 MiB are almost certainly not ScreenConnect and would waste regex time.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Gate 3: CPE-injection defense — reject bodies containing `:*:` (copy boa.go:97-99).
	// Attacker-controlled bodies could attempt to inject CPE metacharacters via the version string.
	if strings.Contains(string(body), ":*:") {
		return nil, nil
	}

	// Brand-token check: at least one of the canonical brand tokens must be present in the
	// lowercased body, OR the Server header must contain "screenconnect".
	// This prevents detection on URL paths, generic tokens, or unrelated content.
	bodyLower := strings.ToLower(string(body))
	serverLower := strings.ToLower(resp.Header.Get("Server"))

	hasBrandInBody := strings.Contains(bodyLower, "screenconnect") ||
		strings.Contains(bodyLower, "connectwise control")
	hasBrandInServer := serverLower == "screenconnect" || strings.HasPrefix(serverLower, "screenconnect/")

	if !hasBrandInBody && !hasBrandInServer {
		return nil, nil
	}

	// Determine detection method for metadata.
	detectionMethod := "body"
	if !hasBrandInBody && hasBrandInServer {
		// Header-only match: emit result with empty version and server_header signal.
		detectionMethod = "server_header"
	}

	// Determine if this response came from the active probe.
	isActiveProbe := false
	if resp.Request != nil && resp.Request.URL != nil {
		if strings.EqualFold(resp.Request.URL.Path, "/SetupWizard.aspx") {
			isActiveProbe = true
			if detectionMethod == "body" {
				detectionMethod = "active_probe"
			}
		}
	}

	var version string
	if hasBrandInBody {
		version = extractScreenConnectVersion(body)
	}

	instanceID := ""
	if hasBrandInBody {
		instanceID = extractScreenConnectInstanceID(body)
	}

	// Build metadata — only include keys with non-empty values (YAGNI).
	metadata := map[string]any{
		"vendor":           "ConnectWise",
		"product":          "ScreenConnect",
		"detection_method": detectionMethod,
	}
	if version != "" {
		metadata["version"] = version
	}
	if instanceID != "" {
		metadata["instance_id"] = instanceID
	}
	if isActiveProbe {
		metadata["probe_path"] = "/SetupWizard.aspx"
	}
	serverHeader := resp.Header.Get("Server")
	if serverHeader != "" {
		metadata["server_header"] = sanitizeScreenConnectHeaderValue(serverHeader)
	}

	return &FingerprintResult{
		Technology: "screenconnect",
		Version:    version,
		CPEs:       []string{buildScreenConnectCPE(version)},
		Metadata:   metadata,
	}, nil
}

// extractScreenConnectVersion tries the three version sources in priority order and
// applies two-stage validation before returning. Returns empty string if no valid
// version is found.
func extractScreenConnectVersion(body []byte) string {
	// Priority 1: Script.ashx?sv= (most reliable — present in nearly all modern versions).
	if m := screenConnectScriptVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); screenConnectVersionValidateRegex.MatchString(v) {
			return v
		}
	}

	// Priority 2: window.ScreenConnect JS block.
	if m := screenConnectJSVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); screenConnectVersionValidateRegex.MatchString(v) {
			return v
		}
	}

	// Priority 3: meta tag (not always present).
	if m := screenConnectMetaVersionRegex.FindSubmatch(body); len(m) >= 2 {
		if v := string(m[1]); screenConnectVersionValidateRegex.MatchString(v) {
			return v
		}
	}

	return ""
}

// extractScreenConnectInstanceID extracts the InstanceID from the window.ScreenConnect
// JS block when present. Returns empty string when absent — callers must treat this as
// optional. Validates that the captured value is 8–64 lowercase hex characters.
func extractScreenConnectInstanceID(body []byte) string {
	m := screenConnectInstanceIDRegex.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	id := string(m[1])
	// Two-stage validation: regex already enforces [a-f0-9]{8,64};
	// re-validate with the anchored pattern as belt-and-suspenders.
	if !screenConnectInstanceIDValidateRegex.MatchString(id) {
		return ""
	}
	return id
}

// sanitizeScreenConnectHeaderValue strips control characters and limits length to
// prevent log injection or oversized metadata values from attacker-controlled headers.
func sanitizeScreenConnectHeaderValue(s string) string {
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

// buildScreenConnectCPE constructs a CPE 2.3 string for ConnectWise ScreenConnect.
// NVD vendor/product: connectwise:screenconnect (unified; covers both "ConnectWise Control"
// legacy branding 2016–2023 and "ScreenConnect" 2008–2016 / 2024-present).
// When version is empty, a wildcard CPE is emitted.
func buildScreenConnectCPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:connectwise:screenconnect:%s:*:*:*:*:*:*:*", version)
}
