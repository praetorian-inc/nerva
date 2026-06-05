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

// Package fingerprinters provides HTTP fingerprinting for Synology DiskStation
// Manager (DSM) — the Linux-based NAS operating system powering DiskStation,
// RackStation, and NAS-branded appliances.
//
// Detection strategy: passive multi-signal gate against the root path (HTTP 200
// HTML response containing a Synology DSM login chrome). Asymmetric gate
// (reference: citrix_netscaler.go): iron-clad signals (version-leak block,
// CSP synology.com) bypass corroboration; title-only requires a Class B
// corroborator.
//
// CPE classification: o: (operating system), not a:.
// Default ports: 5000 (HTTP) / 5001 (HTTPS).
package fingerprinters

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

var (
	// synologyTitlePattern matches the DSM login page title; group 1 = form factor.
	synologyTitlePattern = regexp.MustCompile(
		`(?i)<title[^>]{0,200}>[^<]{0,300}synology[^<]{0,30}(DiskStation|NAS|RackStation)[^<]{0,30}</title>`,
	)
	// synologyDSMHeaderPattern anchors on the unforgeable version-leak block.
	synologyDSMHeaderPattern = regexp.MustCompile(
		`Synology DiskStation Manager \(DSM\):\s*Version:\s*(\d+\.\d+(?:\.\d+)?(?:-\d+)?)`,
	)
	// synologyDSMVersionCharPattern is the charset allowlist (C1).
	synologyDSMVersionCharPattern = regexp.MustCompile(`^[0-9.\-]{1,32}$`)
	// synologyDSMVersionStructPattern is the structural allowlist (C1).
	synologyDSMVersionStructPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+(?:\.[0-9]+)?(?:-[0-9]+)?$`)
	// synologyCSPHostPattern matches synology.com or *.synology.com as a hostname,
	// rejecting substring false-positives like "notsynology.com" or
	// "synology.com.evil.example". The optional (\*\.)? prefix handles DNS
	// wildcard entries in CSP source lists. Bounded subdomain length prevents ReDoS.
	synologyCSPHostPattern = regexp.MustCompile(`(?i)(^|[^\w.-])(\*\.)?([a-z0-9-]{1,63}\.)*synology\.com([^\w.-]|$)`)
)

// Byte-literal slices for substring detection (allocation-free, C7).
var (
	synologyWebmanAsset      = []byte("webman/")
	synologySDSJslibAsset    = []byte("synoSDSjslib/")
	synologyCoreDesktopAsset = []byte("SYNO.Core.Desktop")
	synologyDSMMarker        = []byte("Synology DiskStation Manager (DSM):")
)

// SynologyDSMFingerprinter detects Synology DiskStation Manager via passive
// multi-signal HTML and header inspection (C8: no ProbeEndpoint).
type SynologyDSMFingerprinter struct{}

func init() { Register(&SynologyDSMFingerprinter{}) }

func (f *SynologyDSMFingerprinter) Name() string { return "synology-dsm" }

// Match accepts HTML, XHTML, plain-text, or empty Content-Type (C4: case-insensitive).
// text/plain is included because DSM serves its version-leak block with that
// Content-Type on some firmware versions (plaintext fallback path).
func (f *SynologyDSMFingerprinter) Match(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return ct == "" ||
		strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "application/xhtml+xml") ||
		strings.Contains(ct, "text/plain")
}

// Fingerprint applies an asymmetric gate:
//   - Version-leak block alone → DETECTED (iron-clad; uniquely Synology)
//   - CSP containing synology.com alone → DETECTED (iron-clad; vendor TLD)
//   - Title alone → REJECTED (require Class B corroborator)
//   - Title + Class B → DETECTED
func (f *SynologyDSMFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil {
		return nil, nil
	}

	// Class A: version-leak marker presence (iron-clad).
	versionLeakMatched := bytes.Contains(body, synologyDSMMarker)

	// Version extraction. Scan from the first marker occurrence up to 64 KB
	// forward — large enough that no real DSM response places the "Version:"
	// token further away, and small enough to remain well under 100 ms on a
	// 10 MB pathological body (C2). Unlike the original 512-byte window, this
	// window will not miss a version that follows a prose mention of the marker.
	const maxVersionScanBytes = 64 * 1024
	var dsmVersion string
	if versionLeakMatched {
		idx := bytes.Index(body, synologyDSMMarker)
		window := body[idx:]
		if len(window) > maxVersionScanBytes {
			window = window[:maxVersionScanBytes]
		}
		if m := synologyDSMHeaderPattern.FindSubmatch(window); len(m) >= 2 {
			dsmVersion = sanitizeSynologyDSMVersion(string(m[1]))
			// sanitizer failure: dsmVersion=""; versionLeakMatched still true
		}
	}

	titleMatch := synologyTitlePattern.FindSubmatch(body)
	titleMatched := len(titleMatch) >= 2

	formFactor := ""
	if titleMatched {
		formFactor = string(titleMatch[1])
	}

	cspMatched := false
	for _, csp := range resp.Header.Values("Content-Security-Policy") {
		if synologyCSPHostPattern.MatchString(csp) {
			cspMatched = true
			break
		}
	}

	classAMatched := versionLeakMatched || cspMatched || titleMatched

	// Gate: require at least one Class A signal.
	if !classAMatched {
		return nil, nil
	}

	// Title-only requires Class B corroborator (phishing protection).
	if !versionLeakMatched && !cspMatched && titleMatched && !hasSynologyDSMClassB(body) {
		return nil, nil
	}

	// Form factor fallback.
	if formFactor == "" {
		formFactor = "unknown"
	}

	return &FingerprintResult{
		Technology: "synology-dsm",
		Version:    dsmVersion,
		CPEs:       []string{buildSynologyDSMCPE(dsmVersion)},
		Metadata: map[string]any{
			"form_factor": formFactor,
			"login_path":  "/webman/index.cgi",
		},
	}, nil
}

// hasSynologyDSMClassB reports whether body contains at least one Class B
// corroborating signal: a Synology-specific asset path or JS namespace token.
func hasSynologyDSMClassB(body []byte) bool {
	return bytes.Contains(body, synologyWebmanAsset) ||
		bytes.Contains(body, synologySDSJslibAsset) ||
		bytes.Contains(body, synologyCoreDesktopAsset)
}

// sanitizeSynologyDSMVersion enforces charset + structural allowlists (C1).
// Returns "" on any violation.
func sanitizeSynologyDSMVersion(version string) string {
	if !synologyDSMVersionCharPattern.MatchString(version) {
		return ""
	}
	if !synologyDSMVersionStructPattern.MatchString(version) {
		return ""
	}
	return version
}

// buildSynologyDSMCPE returns the CPE 2.3 string; empty version → "*" (C9).
func buildSynologyDSMCPE(version string) string {
	v := version
	if v == "" {
		v = "*"
	}
	return fmt.Sprintf("cpe:2.3:o:synology:diskstation_manager:%s:*:*:*:*:*:*:*", v)
}
