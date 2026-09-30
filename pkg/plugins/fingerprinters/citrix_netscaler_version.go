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

// Package fingerprinters: active version detection for Citrix NetScaler ADC and
// Citrix NetScaler Gateway.
//
// NetScaler does not expose its build number on any unauthenticated HTML page,
// so the passive CitrixNetScalerFingerprinter can only report the product. This
// active fingerprinter recovers the exact build from the GZIP modification
// timestamp embedded in /vpn/js/rdx/core/lang/rdx_en.json.gz. The gzip header
// stores the firmware compile time (RFC 1952 MTIME, bytes 4-8, little-endian),
// which maps 1:1 to a published build.
//
// Technique and the MTIME->version dataset are from the Fox-IT Security Research
// Team (see citrix_netscaler_versions_data.go for attribution). Static-asset
// *hash* matching is deliberately NOT used: hashes collide across branches and
// can resolve a vulnerable appliance to a patched build, the worst failure mode
// for a detection tool. MTIME does not collide.
//
// When the build cannot be resolved (MTIME zeroed by `gzip -n`, or a build newer
// than the shipped table), the version is left empty and NO CVE advisory is
// emitted. The tool never guesses "vulnerable" from an unknown build.
package fingerprinters

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// citrixRdxProbePath is the versioned static asset whose gzip header carries the
// firmware compile timestamp. It is served by the NetScaler itself on Gateway
// and AAA vservers; a pure load-balancing vserver may proxy /vpn/ to a backend,
// in which case the probe will not resolve a version (handled gracefully).
const citrixRdxProbePath = "/vpn/js/rdx/core/lang/rdx_en.json.gz"

// citrixGzipMagic is the gzip magic + CM=deflate + FLG=FNAME that a genuine
// rdx_en.json.gz begins with. The FNAME flag means the original filename
// ("rdx_en.json") is stored in the header, which we additionally verify.
var citrixGzipMagic = []byte{0x1f, 0x8b, 0x08, 0x08}

// CitrixNetScalerVersionFingerprinter actively probes rdx_en.json.gz to recover
// the NetScaler build and flag known-affected versions for CTX697096.
type CitrixNetScalerVersionFingerprinter struct{}

func init() { Register(&CitrixNetScalerVersionFingerprinter{}) }

func (f *CitrixNetScalerVersionFingerprinter) Name() string { return "citrix-netscaler-version" }

// ProbeEndpoint marks this as an active fingerprinter; the HTTP service fetches
// this path and passes the response to Fingerprint.
func (f *CitrixNetScalerVersionFingerprinter) ProbeEndpoint() string { return citrixRdxProbePath }

// ProbeAccept requests any content type. The asset is served as
// application/octet-stream (or gzip); we must receive the raw gzip bytes, not a
// transparently decompressed body, so we avoid application/json.
func (f *CitrixNetScalerVersionFingerprinter) ProbeAccept() string { return "*/*" }

// Match is a fast header pre-filter: only a 200 with a body can carry the asset.
// The authoritative validation (gzip magic + embedded filename) happens in
// Fingerprint, where the body is available.
func (f *CitrixNetScalerVersionFingerprinter) Match(resp *http.Response) bool {
	return resp != nil && resp.StatusCode == http.StatusOK
}

// Fingerprint validates the gzip asset, extracts the MTIME, resolves the build,
// and, when the build is known and affected, emits a CTX697096 advisory.
func (f *CitrixNetScalerVersionFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Require the gzip magic AND the embedded filename. This rejects generic
	// 200 responses (e.g. a backend app or WAF returning HTML for /vpn/...),
	// which is essential on load-balancing vservers that proxy /vpn/ elsewhere.
	if len(body) < 8 || !bytes.HasPrefix(body, citrixGzipMagic) || !bytes.Contains(body, []byte("rdx_en.json")) {
		return nil, nil
	}

	stamp := binary.LittleEndian.Uint32(body[4:8])
	if stamp == 0 {
		// gzip -n zeroed the timestamp: confirms the asset but not the build.
		return nil, nil
	}

	version, known := citrixRdxStampToVersion[stamp]
	stampTime := time.Unix(int64(stamp), 0).UTC()

	metadata := map[string]any{
		"rdx_en_stamp": strconv.FormatUint(uint64(stamp), 10),
		"rdx_en_date":  stampTime.Format(time.RFC3339),
	}
	if !known {
		// Confirmed NetScaler asset, but the build is newer than the shipped
		// table or otherwise unmapped. Report the timestamp for manual lookup;
		// never infer a CVE state from an unknown build.
		metadata["version_status"] = "undetermined (rdx_en.json.gz timestamp not in build table)"
		return &FingerprintResult{
			Technology: "citrix-netscaler",
			CPEs:       []string{buildCitrixNetScalerCPE("")},
			Metadata:   metadata,
		}, nil
	}

	metadata["version_source"] = "rdx_en.json.gz gzip mtime (fox-it dataset)"

	result := &FingerprintResult{
		Technology: "citrix-netscaler",
		Version:    version,
		CPEs:       []string{buildCitrixNetScalerCPE(sanitizeCitrixNetScalerVersion(cpeVersion(version)))},
		Metadata:   metadata,
	}

	if findings := citrixCTX697096Findings(version); len(findings) > 0 {
		result.Severity = plugins.SeverityHigh
		result.SecurityFindings = findings
	}
	return result, nil
}

// cpeVersion converts NetScaler's "14.1-73.37" form to the dotted "14.1.73.37"
// the CPE builder / sanitizer expect. Returns "" if the shape is unexpected.
func cpeVersion(version string) string {
	v := strings.ReplaceAll(version, "-", ".")
	// keep only major.minor.build (semver-ish) for the sanitizer, which enforces
	// X.Y.Z; the full build.patch is preserved in Version/Metadata.
	parts := strings.Split(v, ".")
	if len(parts) < 3 {
		return ""
	}
	return strings.Join(parts[:3], ".")
}

// --- CTX697096 (CVE-2026-88771 / CVE-2026-88772) version logic ---
//
// Authoritative affected/fixed builds from the Citrix bulletin CTX697096
// (published 2026-09-27):
//   - 14.1                 fixed in 14.1-73.37
//   - 13.1                 fixed in 13.1-64.23
//   - 14.1-FIPS            fixed in 14.1-73.37 FIPS  (same numeric threshold)
//   - 13.1-FIPS / NDcPP    fixed in 13.1-37.279
//   - 12.1 and 13.0 are End Of Life (no fix): treated as affected.
//
// CVE-2026-88771 affects ALL deployments in the default configuration (LB or
// Gateway). CVE-2026-88772 additionally requires DTLS, which is on by default on
// VPN vservers; that precondition is called out in the advisory text rather than
// gating the finding, since DTLS state is not observable from this probe.

type citrixVersionTuple struct{ major, minor, build, patch int }

// parseCitrixVersion converts "14.1-73.37" -> {14,1,73,37}. ok is false for
// "unknown" or any unexpected shape.
func parseCitrixVersion(version string) (citrixVersionTuple, bool) {
	if version == "" || version == "unknown" {
		return citrixVersionTuple{}, false
	}
	fields := strings.FieldsFunc(version, func(r rune) bool { return r == '.' || r == '-' })
	if len(fields) != 4 {
		return citrixVersionTuple{}, false
	}
	nums := make([]int, 4)
	for i, fld := range fields {
		n, err := strconv.Atoi(fld)
		if err != nil {
			return citrixVersionTuple{}, false
		}
		nums[i] = n
	}
	return citrixVersionTuple{nums[0], nums[1], nums[2], nums[3]}, true
}

// less reports v < other in NetScaler build ordering (major, minor, build, patch).
func (v citrixVersionTuple) less(other citrixVersionTuple) bool {
	switch {
	case v.major != other.major:
		return v.major < other.major
	case v.minor != other.minor:
		return v.minor < other.minor
	case v.build != other.build:
		return v.build < other.build
	default:
		return v.patch < other.patch
	}
}

// isCitrixFips131 reports the 13.1-FIPS / NDcPP branch (13.1-37.x).
func isCitrixFips131(v citrixVersionTuple) bool {
	return v.major == 13 && v.minor == 1 && v.build == 37
}

// isCitrixFips121 reports the 12.1-FIPS branch (12.1-55.x).
func isCitrixFips121(v citrixVersionTuple) bool {
	return v.major == 12 && v.minor == 1 && v.build == 55
}

// isCitrixEOL reports End-Of-Life branches (12.1 and 13.0, excluding the still
// -supported FIPS branches). EOL builds receive no fix and are treated affected.
func isCitrixEOL(v citrixVersionTuple) bool {
	if isCitrixFips131(v) || isCitrixFips121(v) {
		return false
	}
	if v.major == 13 && v.minor == 0 {
		return true
	}
	return v.major <= 12
}

// isVulnCTX697096 reports whether a resolved build is affected by
// CVE-2026-88771 / CVE-2026-88772 per the bulletin's fixed builds.
func isVulnCTX697096(v citrixVersionTuple) bool {
	switch {
	case isCitrixFips131(v):
		return v.less(citrixVersionTuple{13, 1, 37, 279})
	case isCitrixFips121(v):
		// 12.1-FIPS is not enumerated in CTX697096; do not assert vulnerability.
		return false
	case v.major == 14:
		// Covers 14.1 and 14.1-FIPS (identical 14.1-73.37 threshold).
		return v.less(citrixVersionTuple{14, 1, 73, 37})
	case v.major == 13 && v.minor == 1:
		return v.less(citrixVersionTuple{13, 1, 64, 23})
	default:
		// 13.0, 12.x, 11.x, etc. -> EOL, no fix available.
		return isCitrixEOL(v)
	}
}

// citrixCTX697096Findings returns the advisory for an affected build, or nil.
func citrixCTX697096Findings(version string) []plugins.SecurityFinding {
	v, ok := parseCitrixVersion(version)
	if !ok || !isVulnCTX697096(v) {
		return nil
	}
	desc := fmt.Sprintf(
		"NetScaler build %s is below the CTX697096 fixed builds (14.1-73.37, 13.1-64.23, "+
			"13.1-37.279 FIPS/NDcPP) and is affected by CVE-2026-88771 and CVE-2026-88772, "+
			"both unauthenticated remote code execution flaws (CVSSv4 9.5) actively exploited "+
			"in the wild. CVE-2026-88771 affects all deployments in the default configuration; "+
			"CVE-2026-88772 additionally requires DTLS, which is enabled by default on VPN vservers.",
		version,
	)
	if isCitrixEOL(v) {
		desc += " This build is also End Of Life and will receive no vendor fix."
	}
	return []plugins.SecurityFinding{{
		ID:             "citrix-netscaler-ctx697096",
		Severity:       plugins.SeverityHigh,
		Title:          "Citrix NetScaler affected by CVE-2026-88771 / CVE-2026-88772 (CTX697096)",
		Description:    desc,
		Impact:         "Unauthenticated remote code execution on the appliance; actively exploited as a zero-day prior to disclosure.",
		Recommendation: "Upgrade to a CTX697096 fixed build (14.1-73.37, 13.1-64.23, or 13.1-37.279 FIPS/NDcPP) or later. This is a version-inferred finding; confirm exploitability with an active safe-check before final rating.",
		CVSS:           "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H",
		Evidence:       fmt.Sprintf("rdx_en.json.gz gzip mtime resolved to build %s (< fixed build for its branch)", version),
	}}
}
