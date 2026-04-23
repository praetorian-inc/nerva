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
Package fingerprinters provides HTTP fingerprinting for HP embedded management
and printing infrastructure:

  - HP iLO (Integrated Lights-Out): remote management firmware present on HPE
    ProLiant servers. Detected via Server: HP-iLO-Server/<version> or
    HPE-iLO-Server/<version>.

  - HP Embedded Web Server (EWS): the built-in HTTP server in HP printers.
    Detection is broad — any "HP HTTP Server; HP <model>" response is matched
    regardless of product family. However, family-specific CPEs are only emitted
    for the four NVD-published product lines (LaserJet, PageWide, OfficeJet,
    DesignJet). All other EWS responses receive the generic
    cpe:2.3:o:hp:laserjet_firmware:*:*:... fallback to avoid fabricating product
    names that have no entries in the NVD CPE dictionary (which would produce
    zero CVE matches and pollute findings).

  - HP ChaiSOE / ChaiServer: the embedded application framework (ChaiScript
    over Embedded, or "Chai Server") used in older HP printers. Detected via
    Server: HP-ChaiSOE/<version> or HP-ChaiServer/<version>.

# CPE Format

CPE names follow the NVD underscore form (not the hyphen form seen in some
ticket descriptions):

  - iLO: cpe:2.3:o:hp:integrated_lights_out_firmware:<version>:*:*:*:*:*:*:*
  - EWS (known family): cpe:2.3:o:hp:<family>_<model>_firmware:*:*:*:*:*:*:*:*
  - EWS (unknown family): cpe:2.3:o:hp:laserjet_firmware:*:*:*:*:*:*:*:* (generic fallback)
  - ChaiSOE: cpe:2.3:a:hp:chaisoe:<version>:*:*:*:*:*:*:*

# What We Deliberately Do NOT Detect

  - Virata-EmWeb: OEM'd to non-HP vendors (Cisco ATA devices, DSL modems,
    IoT devices). Matching on Server header alone produces false-positive HP
    CVE findings. Requires additional corroborating signals.

  - HP_Compact_Server: legacy, sparsely documented, and overlaps with other
    vendor strings. Not HP-exclusive; high false-positive risk.

# iLO Generation Note

iLO generation (iLO 4/5/6/7) is NOT inferred from the version number. Version
ranges are ambiguous: iLO 4 and iLO 5 both shipped 2.x firmware. Reliable
generation identification requires an active probe of /xmldata?item=all, which
is out of scope for a passive Server-header fingerprinter. Generation-less CPEs
are emitted; generation-specific CPE matching can be added via an active probe
in a follow-up ticket.
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode/utf8"
)

// iloRe matches HP iLO Server headers.
// Capture group 1 = version string.
// Anchored to reject prefix/suffix injection.
// Uses [0-9]+(?:\.[0-9]+)* to reject dot-only strings like "..." or ".1".
var iloRe = regexp.MustCompile(`^(?:HP|HPE)-iLO-Server/([0-9]+(?:\.[0-9]+)*)$`)

// ewsRe matches HP Embedded Web Server headers.
// Capture group 1 = model family (bounded char class, max 128 chars).
// Uses [A-Za-z0-9][A-Za-z0-9 \-_.]{0,127} to prevent trailing-whitespace capture
// and to restrict acceptable characters at the regex layer.
var ewsRe = regexp.MustCompile(`^HP HTTP Server;\s*HP\s+([A-Za-z0-9][A-Za-z0-9 \-_.]{0,127})\s*$`)

// chaiRe matches HP ChaiSOE and HP ChaiServer headers.
// Capture group 1 = version string.
// Covers both "HP-ChaiSOE/1.0" and "HP-ChaiServer/3.0" (same underlying server).
var chaiRe = regexp.MustCompile(`^HP-Chai(?:SOE|Server)/([0-9]+(?:\.[0-9]+)*)$`)

// versionValidationRe is the second-stage version validator.
// Mirrors the two-regex pattern from boa.go (extract then validate).
// Rejects dot-edge cases and non-numeric strings before CPE emission.
var versionValidationRe = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// EWS slug normalization regexes (package-level to avoid recompilation per call).
var (
	ewsWhitespaceRe = regexp.MustCompile(`\s+`)
	ewsStripRe      = regexp.MustCompile(`[^a-z0-9_]+`)
	ewsCollapseRe   = regexp.MustCompile(`_+`)
)

// HPiLOFingerprinter detects HP / HPE Integrated Lights-Out management firmware
// via the Server header.
type HPiLOFingerprinter struct{}

// HPLaserJetFingerprinter detects HP Embedded Web Server (EWS) on HP printers
// (LaserJet, PageWide, OfficeJet, DesignJet) via the Server header.
type HPLaserJetFingerprinter struct{}

// HPChaiSOEFingerprinter detects HP ChaiSOE / HP ChaiServer embedded application
// framework via the Server header.
type HPChaiSOEFingerprinter struct{}

func init() {
	Register(&HPiLOFingerprinter{})
	Register(&HPLaserJetFingerprinter{})
	Register(&HPChaiSOEFingerprinter{})
}

// sanitizeHeaderValue strips control characters and non-printable bytes from a
// header value before storing it in Metadata. Keeps only runes in the range
// 0x20–0x7E (printable ASCII). Caps output at 512 bytes.
func sanitizeHeaderValue(s string) string {
	if len(s) > 512 {
		s = s[:512]
	}
	b := make([]byte, 0, len(s))
	for _, r := range s {
		if r >= 0x20 && r <= 0x7E {
			b = utf8.AppendRune(b, r)
		}
	}
	return string(b)
}

// normalizeEWSModelSlug converts a raw HP model family string into a CPE-safe
// slug. Returns "" if normalization produces an empty or too-short result.
//
// Steps:
//  1. Lowercase and trim surrounding whitespace.
//  2. Collapse any run of whitespace to a single underscore.
//  3. Strip anything that is not [a-z0-9_] (allowlist, not denylist).
//  4. Collapse consecutive underscores and trim leading/trailing underscores.
//  5. Reject if resulting slug is shorter than 2 characters.
func normalizeEWSModelSlug(model string) string {
	s := strings.ToLower(strings.TrimSpace(model))

	// Step 1: collapse whitespace runs to underscore.
	s = ewsWhitespaceRe.ReplaceAllString(s, "_")

	// Step 2: strip anything not in [a-z0-9_] — allowlist approach.
	s = ewsStripRe.ReplaceAllString(s, "")

	// Step 3: collapse consecutive underscores and trim boundary underscores.
	s = ewsCollapseRe.ReplaceAllString(s, "_")
	s = strings.Trim(s, "_")

	if len(s) < 2 {
		return ""
	}
	return s
}

// --- HPiLOFingerprinter ---

func (f *HPiLOFingerprinter) Name() string { return "hp-ilo" }

func (f *HPiLOFingerprinter) Match(resp *http.Response) bool {
	// Reject 5xx responses; accept 2xx–4xx.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	server := resp.Header.Get("Server")
	// Length cap: reject empty or suspiciously large headers.
	if len(server) == 0 || len(server) > 512 {
		return false
	}

	return iloRe.MatchString(server)
}

func (f *HPiLOFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	server := resp.Header.Get("Server")
	// Length cap.
	if len(server) == 0 || len(server) > 512 {
		return nil, nil
	}

	// CPE injection defense (mirrors boa.go:97-99).
	if strings.Contains(server, ":*:") {
		return nil, nil
	}

	// Stage 1: extract version via anchored regex.
	m := iloRe.FindStringSubmatch(server)
	if m == nil {
		return nil, nil
	}
	version := m[1]

	// Stage 2: validate version format before CPE emission.
	if !versionValidationRe.MatchString(version) {
		return nil, nil
	}

	meta := map[string]any{
		"vendor":        "HP",
		"product":       "iLO",
		"server_header": sanitizeHeaderValue(server),
	}
	if version != "" {
		meta["version"] = version
		meta["firmware_version"] = version
	}
	return &FingerprintResult{
		Technology: "hp-ilo",
		Version:    version,
		CPEs:       []string{buildiLOCPE(version)},
		Metadata:   meta,
	}, nil
}

// --- HPLaserJetFingerprinter ---

func (f *HPLaserJetFingerprinter) Name() string { return "hp-ews" }

func (f *HPLaserJetFingerprinter) Match(resp *http.Response) bool {
	// Reject 5xx responses; accept 2xx–4xx.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	server := resp.Header.Get("Server")
	// Length cap.
	if len(server) == 0 || len(server) > 512 {
		return false
	}

	return ewsRe.MatchString(server)
}

func (f *HPLaserJetFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	server := resp.Header.Get("Server")
	// Length cap.
	if len(server) == 0 || len(server) > 512 {
		return nil, nil
	}

	// CPE injection defense.
	if strings.Contains(server, ":*:") {
		return nil, nil
	}

	// Extract model family via anchored regex.
	m := ewsRe.FindStringSubmatch(server)
	if m == nil {
		return nil, nil
	}
	rawModel := strings.TrimSpace(m[1])
	if rawModel == "" {
		return nil, nil
	}

	// Cap raw model before normalization (second defense layer behind regex bound).
	if len(rawModel) > 128 {
		rawModel = rawModel[:128]
	}

	// Build CPE — normalize slug or fall back to generic.
	slug := normalizeEWSModelSlug(rawModel)
	cpe := buildEWSCPE(slug)

	return &FingerprintResult{
		Technology: "hp-ews",
		Version:    "", // EWS headers do not carry firmware version.
		CPEs:       []string{cpe},
		Metadata: map[string]any{
			"vendor":        "HP",
			"product":       "EWS",
			"model":         rawModel,
			"server_header": sanitizeHeaderValue(server),
		},
	}, nil
}

// --- HPChaiSOEFingerprinter ---

func (f *HPChaiSOEFingerprinter) Name() string { return "hp-chaisoe" }

func (f *HPChaiSOEFingerprinter) Match(resp *http.Response) bool {
	// Reject 5xx responses; accept 2xx–4xx.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	server := resp.Header.Get("Server")
	// Length cap.
	if len(server) == 0 || len(server) > 512 {
		return false
	}

	return chaiRe.MatchString(server)
}

func (f *HPChaiSOEFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Status filter.
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	server := resp.Header.Get("Server")
	// Length cap.
	if len(server) == 0 || len(server) > 512 {
		return nil, nil
	}

	// CPE injection defense.
	if strings.Contains(server, ":*:") {
		return nil, nil
	}

	// Stage 1: extract version via anchored regex.
	m := chaiRe.FindStringSubmatch(server)
	if m == nil {
		return nil, nil
	}
	version := m[1]

	// Stage 2: validate version format before CPE emission.
	if !versionValidationRe.MatchString(version) {
		return nil, nil
	}

	meta := map[string]any{
		"vendor":        "HP",
		"product":       "ChaiSOE",
		"server_header": sanitizeHeaderValue(server),
	}
	if version != "" {
		meta["version"] = version
	}
	return &FingerprintResult{
		Technology: "hp-chaisoe",
		Version:    version,
		CPEs:       []string{buildChaiSOECPE(version)},
		Metadata:   meta,
	}, nil
}

// --- CPE builders ---

// buildiLOCPE returns the HP iLO firmware CPE in NVD underscore form.
// Generation (iLO 2/3/4/5/6/7) is NOT inferred from the header — too
// unreliable without an active /xmldata?item=all probe. The underscore form
// (integrated_lights_out_firmware) matches the NVD CPE dictionary; the hyphen
// form sometimes seen in ticket descriptions does not produce CVE matches.
func buildiLOCPE(version string) string {
	if version == "" {
		return "cpe:2.3:o:hp:integrated_lights_out_firmware:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:o:hp:integrated_lights_out_firmware:%s:*:*:*:*:*:*:*", version)
}

// Known HP EWS product family prefixes. When the normalized slug starts with one
// of these, we emit a family-specific CPE (which downstream vulnerability
// databases can match against). For any other slug — including unknown or
// freeform values from non-LaserJet/PageWide/OfficeJet/DesignJet HP products —
// we fall back to the generic laserjet_firmware CPE to avoid fabricating
// product names that do not exist in the NVD CPE dictionary.
var ewsKnownFamilies = []string{"laserjet_", "pagewide_", "officejet_", "designjet_"}

// buildEWSCPE builds the CPE for an HP printer EWS fingerprint.
// Detection via ewsRe is intentionally broad (any "HP HTTP Server; HP <model>"
// response), but CPE emission is tightened: a family-specific CPE is only
// produced when the normalized slug begins with one of the four known NVD
// product families. Any other slug — or an empty slug — receives the generic
// laserjet_firmware fallback to avoid emitting fabricated product names that
// produce zero CVE matches.
func buildEWSCPE(slug string) string {
	if slug == "" {
		return "cpe:2.3:o:hp:laserjet_firmware:*:*:*:*:*:*:*:*"
	}
	matchedFamily := false
	for _, prefix := range ewsKnownFamilies {
		if strings.HasPrefix(slug, prefix) {
			matchedFamily = true
			break
		}
	}
	if !matchedFamily {
		return "cpe:2.3:o:hp:laserjet_firmware:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:o:hp:%s_firmware:*:*:*:*:*:*:*:*", slug)
}

// buildChaiSOECPE returns the HP ChaiSOE application CPE.
// ChaiSOE is the application/firmware layer — use cpe:2.3:a (application).
func buildChaiSOECPE(version string) string {
	if version == "" {
		return "cpe:2.3:a:hp:chaisoe:*:*:*:*:*:*:*:*"
	}
	return fmt.Sprintf("cpe:2.3:a:hp:chaisoe:%s:*:*:*:*:*:*:*", version)
}
