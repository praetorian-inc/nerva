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
Package fingerprinters provides HTTP fingerprinting for Adminer, the
single-file PHP database management tool (and its forks AdminerEvo and
Adminer Editor).

# What We Detect

  - The Adminer login page, whether deployed as a single PHP file
    (/adminer.php — the most common deployment) or inside a directory
    (/adminer/ — common in Docker images that ship Adminer as a bundled app).
  - AdminerEvo, a community-maintained fork of Adminer with an updated UI.
  - Adminer Editor, a companion single-file content editor built on the same
    Adminer codebase.

# What We Do NOT Detect

  - Adminer instances deployed behind a reverse proxy path that strips or
    rewrites the HTML title and structural markers this fingerprinter relies on.
  - Adminer plugins or custom-branded forks that replace both the <title> tag
    and the driver-select form markup with fully custom content.
  - The specific database backend a given Adminer instance is configured to
    manage (MySQL, PostgreSQL, SQLite, etc.) — Adminer supports many drivers
    and this fingerprinter does not enumerate them.

# Security Context

Adminer exposes direct database administration (arbitrary SQL execution,
schema browsing, data export) through a single unauthenticated-by-default
login page. An internet-exposed instance is a high-value target: successful
authentication (default credentials, credential stuffing, or a known Adminer
auth-bypass CVE) grants full database access. Because Adminer ships as a
single file, it is frequently dropped by attackers as a post-exploitation
web shell alternative, so passive detection of unexpected Adminer instances
is also useful for internal exposure hunting.

# Detection Strategy

Detection uses two independent signals; either one alone is sufficient,
with one exception noted below:

Signal 1 (standalone title match): the HTML <title> tag reads "Login -
Adminer" or "Login - AdminerEvo" (case-insensitive, tolerating extra
whitespace and tag attributes). "Login - Editor" also matches the title
regex but requires corroboration (Signal 2) because "Editor" alone is
too generic.

Signal 2 (corroborated pair): the body contains both "System<td>" (the
database driver label rendered in a login-form table row) AND
`name="auth[driver]"` (the driver-select form field). Neither marker alone
is used — both are common enough in isolation that requiring both prevents
false positives on generic admin login forms.

# Version Extraction

Adminer embeds its release version in a <span class="version"> element:

	<span class="version">4.8.1</span>

The captured value is validated against a strict `MAJOR.MINOR.PATCH[-tag]`
pattern and checked for CPE metacharacters before being emitted. When no
valid version is found, the CPE is wildcarded.

# Variant Metadata

The detected variant is recorded in metadata:
  - "adminerevo" when the body references adminerevo.org
  - "editor" when the body references adminer.org/editor/ or the matched
    title is "Login - Editor"
  - "adminer" otherwise (the default upstream project)

# Active Probe Safety

Both probes are plain, unauthenticated GET requests with no request body:
GET /adminer.php (single-file deployment) and GET /adminer/ (directory
deployment). No write operations or authentication attempts are made.

# CPE

cpe:2.3:a:adminer:adminer:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// adminerMaxBodySize caps the body scanned by fingerprintAdminer. The Adminer
// login page is a small static HTML document, well under this cap.
const adminerMaxBodySize = 1024 * 1024 // 1 MiB

// adminerTitleRegex matches the Adminer/AdminerEvo/Editor login page title,
// tolerating tag attributes and surrounding whitespace.
// Examples: "<title>Login - Adminer</title>", "<title lang=\"en\"> Login - AdminerEvo </title>"
var adminerTitleRegex = regexp.MustCompile(`(?is)<title[^>]*>\s*Login\s*-\s*(Adminer(?:Evo)?|Editor)\s*</title>`)

// adminerVersionExtractRegex captures the release version from the
// <span class="version"> element rendered on the login page.
var adminerVersionExtractRegex = regexp.MustCompile(`<span class="version">([0-9]+\.[0-9]+\.[0-9]+(?:-[a-z]+)?)</span>`)

// adminerVersionValidateRegex is the anchored second-stage validator applied
// before a version is emitted into a CPE.
var adminerVersionValidateRegex = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z]+)?$`)

// Corroborated-pair markers for Signal 2. Neither is used alone.
const (
	adminerSystemTDMarker        = "System<td>"
	adminerAuthDriverMarkerDQ    = `name="auth[driver]"`
	adminerAuthDriverMarkerSQ    = "name='auth[driver]'"
)

// Variant markers.
const (
	adminerEvoDomainMarker  = "adminerevo.org"
	adminerEditorPathMarker = "adminer.org/editor/"
)

func init() {
	Register(&AdminerFingerprinter{})
	Register(&AdminerDirFingerprinter{})
}

// ── FP1: AdminerFingerprinter (single-file deployment, /adminer.php) ───────────

// AdminerFingerprinter detects Adminer deployed as a single PHP file, the
// most common deployment method.
type AdminerFingerprinter struct{}

// Name returns the fingerprinter identifier.
func (f *AdminerFingerprinter) Name() string { return "adminer" }

// ProbeEndpoint returns the single-file Adminer deployment path.
func (f *AdminerFingerprinter) ProbeEndpoint() string { return "/adminer.php" }

// ProbeAccept requests HTML for the login page.
func (f *AdminerFingerprinter) ProbeAccept() string { return "text/html" }

// Match is a fast pre-filter shared with AdminerDirFingerprinter.
func (f *AdminerFingerprinter) Match(resp *http.Response) bool { return matchAdminer(resp) }

// Fingerprint performs full Adminer detection, shared with AdminerDirFingerprinter.
func (f *AdminerFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	return fingerprintAdminer(resp, body)
}

// ── FP2: AdminerDirFingerprinter (directory deployment, /adminer/) ─────────────

// AdminerDirFingerprinter detects Adminer deployed inside a directory, common
// in Docker images that bundle Adminer as a standalone service.
type AdminerDirFingerprinter struct{}

// Name returns the fingerprinter identifier.
func (f *AdminerDirFingerprinter) Name() string { return "adminer_dir" }

// ProbeEndpoint returns the directory-deployment Adminer path.
func (f *AdminerDirFingerprinter) ProbeEndpoint() string { return "/adminer/" }

// ProbeAccept requests HTML for the login page.
func (f *AdminerDirFingerprinter) ProbeAccept() string { return "text/html" }

// Match is a fast pre-filter shared with AdminerFingerprinter.
func (f *AdminerDirFingerprinter) Match(resp *http.Response) bool { return matchAdminer(resp) }

// Fingerprint performs full Adminer detection, shared with AdminerFingerprinter.
func (f *AdminerDirFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	return fingerprintAdminer(resp, body)
}

// ── Shared detection logic ──────────────────────────────────────────────────────

// matchAdminer is a lenient pre-filter: any 2xx-4xx response with an HTML
// content-type is a candidate. Definitive confirmation happens in
// fingerprintAdminer.
func matchAdminer(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html")
}

// fingerprintAdminer confirms an Adminer login page and extracts version and
// variant metadata. Signal 1 (title "Login - Adminer" or "Login - AdminerEvo")
// is sufficient alone. Signal 2 (corroborated System<td> + auth[driver] pair)
// is sufficient alone. Title "Login - Editor" requires Signal 2 corroboration
// because "Editor" alone is too generic.
func fingerprintAdminer(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	if len(body) > adminerMaxBodySize {
		return nil, nil
	}

	titleMatches := adminerTitleRegex.FindSubmatch(body)
	hasTitleSignal := titleMatches != nil

	bodyStr := string(body)
	hasCorroboratedPair := strings.Contains(bodyStr, adminerSystemTDMarker) &&
		(strings.Contains(bodyStr, adminerAuthDriverMarkerDQ) || strings.Contains(bodyStr, adminerAuthDriverMarkerSQ))

	// "Editor" alone is too generic — require corroboration.
	isEditorOnly := hasTitleSignal && len(titleMatches) > 1 &&
		strings.EqualFold(string(titleMatches[1]), "Editor")
	if isEditorOnly && !hasCorroboratedPair {
		return nil, nil
	}

	if !hasTitleSignal && !hasCorroboratedPair {
		return nil, nil
	}

	titleVariant := ""
	if len(titleMatches) > 1 {
		titleVariant = string(titleMatches[1])
	}

	variant := detectAdminerVariant(body, titleVariant)

	var detectionMethod string
	switch {
	case hasTitleSignal && hasCorroboratedPair:
		detectionMethod = "title_match+corroborated_pair"
	case hasTitleSignal:
		detectionMethod = "title_match"
	default:
		detectionMethod = "corroborated_pair"
	}

	version := extractAdminerVersion(body)

	vendorName, productName := "Adminer", "Adminer"
	if variant == "adminerevo" {
		vendorName, productName = "AdminerEvo", "AdminerEvo"
	}
	metadata := map[string]any{
		"vendor":           vendorName,
		"product":          productName,
		"variant":          variant,
		"detection_method": detectionMethod,
	}

	return &FingerprintResult{
		Technology: "adminer",
		Version:    version,
		CPEs:       []string{buildAdminerCPE(version, variant)},
		Metadata:   metadata,
	}, nil
}

// detectAdminerVariant determines which Adminer variant produced the login
// page: "adminerevo" (community fork), "editor" (Adminer Editor), or
// "adminer" (the default upstream project).
func detectAdminerVariant(body []byte, titleVariant string) string {
	bodyStr := string(body)

	switch {
	case strings.Contains(bodyStr, adminerEvoDomainMarker) || strings.EqualFold(titleVariant, "AdminerEvo"):
		return "adminerevo"
	case strings.Contains(bodyStr, adminerEditorPathMarker) || strings.EqualFold(titleVariant, "editor"):
		return "editor"
	default:
		return "adminer"
	}
}

// extractAdminerVersion pulls the version from the <span class="version">
// element, applying anchored two-stage validation and a CPE-metacharacter
// guard before returning. Returns "" when no valid version is present.
func extractAdminerVersion(body []byte) string {
	m := adminerVersionExtractRegex.FindSubmatch(body)
	if len(m) < 2 {
		return ""
	}
	v := string(m[1])
	if !adminerVersionValidateRegex.MatchString(v) {
		return ""
	}
	// Belt-and-suspenders: the capture class only yields [0-9a-z.-], so this
	// guard is unreachable by construction, but protects against any future
	// regex change letting CPE metacharacters into the version field.
	if strings.ContainsAny(v, ":*?") {
		return ""
	}
	return v
}

// buildAdminerCPE constructs the CPE 2.3 identifier. AdminerEvo has its own
// NVD product (CVE-2023-45195, CVE-2023-45197); all other variants use
// adminer:adminer.
func buildAdminerCPE(version, variant string) string {
	vendor, product := "adminer", "adminer"
	if variant == "adminerevo" {
		vendor, product = "adminerevo", "adminerevo"
	}
	if version == "" {
		return fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*", vendor, product)
	}
	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, version)
}
