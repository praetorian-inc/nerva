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
Package fingerprinters provides HTTP fingerprinting for Veeam Backup
Enterprise Manager (EM).

# What We Detect

  - EM Web UI on 9443/443 via GET /login.aspx — confirmed by the verbatim
    page title "Veeam Backup Enterprise Manager : Login". An exact build is
    leaked unauthenticated in the login.bundle.js?v=<version> script tag.
  - EM legacy REST API on 9398 via GET /api/ — confirmed by the XML root
    element <EnterpriseManager and the namespace www.veeam.com/ent/v1.0.
    The unauthenticated entry document lists SupportedVersion Name="v1_N"
    tokens, which map to a coarse product band (never an exact build).

# What We Do NOT Detect

  - B&R modern JSON RESTful API on 9419 (/api/v1/, OAuth2) — out of scope.
  - Veeam ONE (port 1239) — out of scope (it also serves /login.aspx but with
    a different title, so it will simply not match our required EM title).
  - v13 Linux SPA web UI on :443 — no published signature, out of scope.
  - Binary remoting ports 9401 / 6170 — not HTTP, out of scope.

# Active Probe Safety

Both fingerprinters are ActiveHTTPFingerprinters; the engine issues a plain
unauthenticated GET with no request body. There is no code path by which this
plugin can POST. We therefore structurally cannot send anything resembling the
CVE-2024-29849 / CVE-2024-40711 / CVE-2025-23120 exploit payloads. /login.aspx
renders a login form and /api/ returns the unauthenticated REST entry document;
neither performs a state change, carries credentials, or triggers a CVE path.
No MisconfigHTTPFingerprinter is implemented for Veeam.

# CPE Format

Both surfaces report the same human-facing product and emit BOTH CPEs:

	cpe:2.3:a:veeam:backup_enterprise_manager:{version}:*:*:*:*:*:*:*
	cpe:2.3:a:veeam:veeam_backup_&_replication:{version}:*:*:*:*:*:*:*

The literal '&' in the B&R token is intentional and NVD-verified — do NOT
"fix" it to "and". Version is a wildcard '*' when no exact build is known.
*/
package fingerprinters

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
)

// veeamLoginBundleVersionRegex extracts the exact EM build from the login page
// script tag, e.g. <script src=".../login.bundle.js?v=12.1.2.172"></script>.
// The capture group is bounded to dotted digit groups so a hostile body cannot
// smuggle CPE metacharacters through it even before validation.
var veeamLoginBundleVersionRegex = regexp.MustCompile(`(?i)login\.bundle\.js\?v=([0-9]+(?:\.[0-9]+){1,3})`)

// veeamSupportedVersionRegex captures the numeric generation N from the EM REST
// entry document, e.g. <SupportedVersion Name="v1_7">. N is captured as one or
// more digits so a future two-digit generation (v1_10) parses rather than being
// silently dropped; unknown generations still degrade gracefully (empty band).
var veeamSupportedVersionRegex = regexp.MustCompile(`(?i)<SupportedVersion\s+Name="v1_([0-9]+)"`)

// veeamEntNamespaceRegex confirms the EM legacy REST XML namespace.
var veeamEntNamespaceRegex = regexp.MustCompile(`(?i)xmlns="http://www\.veeam\.com/ent/v1\.0"`)

// veeamDottedVersionValidateRegex is the anchored CPE-injection guard. It accepts
// only 1–4 dotted digit groups (e.g. 12, 12.1, 12.1.2.172) and rejects anything
// containing ':' '*' or other CPE metacharacters by construction. Mirrors the
// validation-regex pattern used by rompager.go / confluence.go.
var veeamDottedVersionValidateRegex = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,3}$`)

const (
	// veeamWebLoginTitle is the verbatim verified EM login page title (the single
	// strongest signal; case-sensitive). Veeam ONE serves a different title so it
	// will not match this string.
	//
	// Matched as an exact, case-sensitive byte substring (mirrors the upstream
	// ProjectDiscovery Nuclei signature). Known false-negative boundary: a future
	// build that HTML-encodes or splits the title across markup (e.g. an &nbsp;
	// before the colon) would not match. Accepted: it tracks the authoritative
	// public signature, and the REST fingerprinter provides an independent surface.
	veeamWebLoginTitle = "Veeam Backup Enterprise Manager : Login"

	// veeamRESTRootElement is the EM legacy REST entry-document root element.
	veeamRESTRootElement = "<EnterpriseManager"
)

// veeamSupportedVersionBands maps the EM REST API generation token (v1_N) to a
// coarse product band (research §4.3, [CONFIRMED]). The band is a range, not a
// point — v1_7 spans 12.x through 13.x.
var veeamSupportedVersionBands = map[string]string{
	"7": "12.x–13.x",
	"6": "11.x–11a",
	"5": "10.0–10a",
	"4": "9.5 U4–U4b",
	"3": "9.5–9.5 U3",
	"2": "9.0–9.0 U2",
	"1": "8.0–8.0 U3",
}

func init() {
	Register(&VeeamEnterpriseManagerWebFingerprinter{})
	Register(&VeeamEnterpriseManagerRESTFingerprinter{})
}

// buildVeeamCPEs returns the EM CPE (the detected surface) plus the associated
// B&R CPE. NVD CPE tokens verified by direct fetch (protocol-research.md §7):
//
//	EM:  cpe:2.3:a:veeam:backup_enterprise_manager
//	B&R: cpe:2.3:a:veeam:veeam_backup_&_replication   (literal '&', 'veeam_' prefix)
//
// The literal '&' is intentional and NVD-verified — do NOT "fix" it to "and".
// version is the already-validated exact build ("" => wildcard '*').
func buildVeeamCPEs(version string) []string {
	v := version
	if v == "" {
		v = "*"
	}
	return []string{
		fmt.Sprintf("cpe:2.3:a:veeam:backup_enterprise_manager:%s:*:*:*:*:*:*:*", v),
		fmt.Sprintf("cpe:2.3:a:veeam:veeam_backup_&_replication:%s:*:*:*:*:*:*:*", v),
	}
}

// validateVeeamVersion returns version if it passes the anchored CPE-injection
// guard and contains no CPE metacharacters, otherwise returns "". Belt-and-
// suspenders: the validation regex and the explicit ContainsAny check both
// reject ':' and '*' before any CPE interpolation.
func validateVeeamVersion(version string) string {
	if version == "" {
		return ""
	}
	if !veeamDottedVersionValidateRegex.MatchString(version) {
		return ""
	}
	if strings.ContainsAny(version, ":*") {
		return ""
	}
	return version
}

// --- VeeamEnterpriseManagerWebFingerprinter (EM Web UI / /login.aspx) ---

// VeeamEnterpriseManagerWebFingerprinter detects the Veeam Backup Enterprise
// Manager web login page and extracts the exact build from the JS bundle.
type VeeamEnterpriseManagerWebFingerprinter struct{}

// Name returns the fingerprinter identifier (must be unique per struct).
func (f *VeeamEnterpriseManagerWebFingerprinter) Name() string {
	return "veeam_enterprise_manager_web"
}

// ProbeEndpoint returns the EM web login page path.
func (f *VeeamEnterpriseManagerWebFingerprinter) ProbeEndpoint() string {
	return "/login.aspx"
}

// ProbeAccept returns the Accept header for the active probe (the login page is HTML).
func (f *VeeamEnterpriseManagerWebFingerprinter) ProbeAccept() string {
	return "text/html"
}

// Match is a cheap, lenient pre-filter: status 200–499 plus an HTML (or empty)
// Content-Type. The authoritative brand confirmation lives in Fingerprint —
// never match on generic IIS/ASP.NET/cookie/favicon alone.
func (f *VeeamEnterpriseManagerWebFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "text/html") || ct == ""
}

// Fingerprint confirms the EM login page via its verbatim title and best-effort
// extracts the exact build. Returns nil unless the definitive marker is present.
func (f *VeeamEnterpriseManagerWebFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter (defense-in-depth, re-applied after Match).
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}
	// Gate 2: 2 MiB body cap — bounds regex work on hostile/oversized bodies.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Definitive marker (REQUIRED): the verbatim EM login title. Use bytes.Contains
	// to avoid copying the (up to 2 MiB) body into a string.
	if !bytes.Contains(body, []byte(veeamWebLoginTitle)) {
		return nil, nil
	}

	// Best-effort exact build. Validate before any CPE interpolation.
	version := ""
	if m := veeamLoginBundleVersionRegex.FindSubmatch(body); len(m) >= 2 {
		version = validateVeeamVersion(string(m[1]))
	}

	metadata := map[string]any{
		"vendor":           "Veeam",
		"product":          "Backup Enterprise Manager",
		"variant":          "enterprise_manager_web",
		"detection_method": "active_probe",
		"probe_path":       "/login.aspx",
	}
	if version != "" {
		metadata["version"] = version
	}
	if server := resp.Header.Get("Server"); server != "" {
		metadata["server_header"] = sanitizeHTTPHeaderValue(server)
	}

	return &FingerprintResult{
		// Symmetric "..._web" / "..._rest" Technology labels keep the two surfaces
		// in distinct metadata buckets (http.go keys metadata by Technology) and
		// match the neighbor convention (unifi-controller/unifi-os, wazuh-api/-dashboard).
		Technology: "veeam_backup_enterprise_manager_web",
		Version:    version,
		CPEs:       buildVeeamCPEs(version),
		Metadata:   metadata,
	}, nil
}

// --- VeeamEnterpriseManagerRESTFingerprinter (EM legacy REST / /api/) ---

// VeeamEnterpriseManagerRESTFingerprinter detects the Veeam Backup Enterprise
// Manager legacy REST API entry document and maps its API generation to a band.
type VeeamEnterpriseManagerRESTFingerprinter struct{}

// Name returns the fingerprinter identifier (must be unique per struct).
func (f *VeeamEnterpriseManagerRESTFingerprinter) Name() string {
	return "veeam_enterprise_manager_rest"
}

// ProbeEndpoint returns the EM legacy REST API entry point.
func (f *VeeamEnterpriseManagerRESTFingerprinter) ProbeEndpoint() string {
	return "/api/"
}

// ProbeAccept returns the Accept header for the active probe (the entry doc is XML).
func (f *VeeamEnterpriseManagerRESTFingerprinter) ProbeAccept() string {
	return "application/xml"
}

// Match is a cheap, lenient pre-filter: status 200–499 plus any of an XML (or
// empty) Content-Type, the X-RestSvcSessionId header, or a RestSvc realm in
// WWW-Authenticate. Brand confirmation (XML root + namespace) lives in
// Fingerprint — header signals corroborate but are never the sole basis.
func (f *VeeamEnterpriseManagerRESTFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "xml") || ct == "" {
		return true
	}
	if resp.Header.Get("X-RestSvcSessionId") != "" {
		return true
	}
	return strings.Contains(resp.Header.Get("WWW-Authenticate"), "RestSvc")
}

// Fingerprint confirms the EM REST entry document via the XML root element AND
// namespace, then maps the highest SupportedVersion generation to a coarse band.
// Version stays "" (coarse — never fabricate an exact build); the band is
// recorded in metadata only and the CPE uses the '*' wildcard.
func (f *VeeamEnterpriseManagerRESTFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Gate 1: status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}
	// Gate 2: 2 MiB body cap.
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	// Definitive marker (REQUIRED): both the root element and the namespace.
	// Either one alone is too weak. bytes.Contains avoids copying the body.
	if !bytes.Contains(body, []byte(veeamRESTRootElement)) || !veeamEntNamespaceRegex.Match(body) {
		return nil, nil
	}

	// Coarse version band from the highest v1_N generation present in the doc.
	supportedVersion, versionBand := veeamHighestSupportedVersion(body)

	metadata := map[string]any{
		"vendor":           "Veeam",
		"product":          "Backup Enterprise Manager",
		"variant":          "enterprise_manager_rest",
		"detection_method": "active_probe",
		"probe_path":       "/api/",
		"api":              "enterprise_manager_legacy_rest",
	}
	if supportedVersion != "" {
		metadata["supported_version"] = supportedVersion
	}
	if versionBand != "" {
		metadata["version_band"] = versionBand
	}
	if sessionHeader := resp.Header.Get("X-RestSvcSessionId"); sessionHeader != "" {
		metadata["rest_session_header"] = sanitizeHTTPHeaderValue(sessionHeader)
	}
	if wwwAuth := resp.Header.Get("WWW-Authenticate"); wwwAuth != "" {
		metadata["www_authenticate"] = sanitizeHTTPHeaderValue(wwwAuth)
	}

	// Distinct Technology ("..._rest") avoids a metadata-map collision with the
	// web fingerprinter: pkg/plugins/services/http/http.go:516-518 keys
	// fingerprintMetadata by Technology,
	// so two results sharing a Technology would overwrite each other's metadata.
	return &FingerprintResult{
		Technology: "veeam_backup_enterprise_manager_rest",
		Version:    "",
		CPEs:       buildVeeamCPEs(""),
		Metadata:   metadata,
	}, nil
}

// veeamHighestSupportedVersion returns the highest SupportedVersion token
// (e.g. "v1_7") present in the EM REST entry document and its mapped product
// band. The newest generation indicates the installed band. Returns "", "" if
// no token is present.
func veeamHighestSupportedVersion(body []byte) (supportedVersion, versionBand string) {
	matches := veeamSupportedVersionRegex.FindAllSubmatch(body, -1)
	highest := -1
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		n, err := strconv.Atoi(string(m[1]))
		if err != nil {
			continue
		}
		if n > highest {
			highest = n
		}
	}
	if highest < 0 {
		return "", ""
	}
	digit := strconv.Itoa(highest)
	// versionBands has no entry for unknown (e.g. future two-digit) generations,
	// so versionBand is "" in that case while supported_version is still reported.
	return "v1_" + digit, veeamSupportedVersionBands[digit]
}
