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
Package fingerprinters provides dedicated HTTP fingerprinting for PHP.

# Why A Dedicated PHP Fingerprinter

PHP was previously detected only as a side effect of the apache_httpd
fingerprinter parsing the X-Powered-By header. That path is header-only (it
misses hosts with expose_php=Off), produces a version-LESS CPE
(cpe:2.3:a:php:php:*), and only runs when the response flows through the Apache
fingerprinter. This plugin is a deterministic replacement that detects PHP from
its own signals and emits a version-pinned CPE.

# Detection Cascade (strongest source wins)

  - Tier 0  phpinfo content signature (any filename): exact version, Server API
    -> SAPI, Build Date, and System. Matched by the <title>...phpinfo()...
    marker or the "<h1 class=\"p\">PHP Version X" heading. Served by the active
    phpinfo path probes below AND by the passive path when the given body is
    itself a phpinfo page.
  - Tier 1  X-Powered-By: PHP/x.y.z banner (exact, but spoofable).
  - Tier 2  behavioral SAPI from the Server header (Apache -> mod_php?, nginx ->
    php-fpm-or-cgi, LiteSpeed -> litespeed). Low confidence.
  - Tier 3  error-format version family: PHP 8 raises "must be of type" /
    "Uncaught TypeError ... Argument #", PHP <= 7 raises "expects parameter".
    Resolves only the major family, from the given body.

# Active Path Probing

PHP exposes no canonical status endpoint, so Tier 0 relies on operator-left
phpinfo pages. Three ActiveHTTPFingerprinters probe the common filenames
(/phpinfo.php, /info.php, /test.php). This recovers the exact version even when
expose_php=Off strips X-Powered-By.

# Exposure Flags

php2shell (CVE-2026-109618 / CVE-2026-109619) is fixed at 8.2.35 / 8.3.36 /
8.4.27 / 8.5.12; every branch <= 8.1 is EOL with no upstream fix. A version
below its branch fix (or on an EOL branch) sets below_php2shell_fix=true. Because
distros backport fixes onto frozen version strings, backport_uncertain is always
set alongside it: the version string alone cannot clear a backported fix.

# CPE Format

cpe:2.3:a:php:php:{version}:*:*:*:*:*:*:*  (version-pinned when exact is known)
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// Security finding IDs emitted by the PHP fingerprinter. Canonical metadata
// (title, severity, impact, recommendation, CVSS) lives in the finding catalog
// (pkg/plugins/finding_catalog.go) and is applied by Service.EnrichFindings.
const (
	findingExposedPHPInfo = "exposed-phpinfo"
	findingPHP2Shell      = "php-vulnerable-php2shell"
)

// php2shellFix maps a PHP major.minor branch to the patch level that first
// carries the php2shell fix (CVE-2026-109618 / CVE-2026-109619, 2026-10-21).
var php2shellFix = map[[2]int]int{
	{8, 2}: 35,
	{8, 3}: 36,
	{8, 4}: 27,
	{8, 5}: 12,
}

// phpEOLMaxBranch is the highest major.minor branch that is end-of-life, i.e.
// has no upstream php2shell fix. Everything at or below it (<= 8.1) is EOL.
var phpEOLMaxBranch = [2]int{8, 1}

var (
	// phpVersionExtractRegex pulls a dotted triple out of an arbitrary string.
	phpVersionExtractRegex = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	// phpVersionValidateRegex gates any version before it reaches a CPE, to
	// prevent CPE field injection via crafted banners/bodies.
	phpVersionValidateRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

	// phpInfoTitleRegex matches the phpinfo <title> across versions:
	// "<title>phpinfo()</title>" (old) and "<title>PHP 8.2.34 - phpinfo()</title>".
	phpInfoTitleRegex = regexp.MustCompile(`(?i)<title>[^<]*phpinfo\(\)`)
	// phpInfoH1Regex matches the "PHP Version X" heading used on the phpinfo page.
	phpInfoH1Regex = regexp.MustCompile(`(?i)<h1 class="p">PHP Version [\d.]+`)

	// Version parsers for a phpinfo body, tried in order of specificity.
	phpInfoVersionH1Regex    = regexp.MustCompile(`(?i)<h1 class="p">PHP Version ([\d.]+)`)
	phpInfoVersionTitleRegex = regexp.MustCompile(`(?i)<title>PHP ([\d.]+) - phpinfo\(\)`)
	phpInfoVersionRowRegex   = regexp.MustCompile(`PHP Version\s*</td><td class="v">\s*([\d.]+)`)

	// phpInfo config-row value extractors ("Label </td><td class="v">value").
	phpInfoServerAPIRegex = regexp.MustCompile(`Server API\s*</td><td class="v">\s*([^<]+)`)
	phpInfoBuildDateRegex = regexp.MustCompile(`Build Date\s*</td><td class="v">\s*([^<]+)`)
	phpInfoSystemRegex    = regexp.MustCompile(`System\s*</td><td class="v">\s*([^<]+)`)

	// phpPoweredByRegex extracts the version from "X-Powered-By: PHP/8.2.34".
	phpPoweredByRegex = regexp.MustCompile(`(?i)PHP/(\d+\.\d+\.\d+)`)

	// phpServerTokenRegex matches a PHP token in the Server header
	// (e.g. "Apache/2.4 PHP/8.2.34"), used as a weak presence signal.
	phpServerTokenRegex = regexp.MustCompile(`(?i)\bPHP\b`)

	// phpErrorPrefixRegex anchors a body to a PHP runtime error. The Tier 3
	// error-format substrings ("must be of type", "expects parameter") are too
	// generic on their own — non-PHP HTML (docs, other-language stack traces,
	// user content) can contain them — so a match must be corroborated by a
	// strong, PHP-specific marker. Only unambiguous markers are accepted: a PHP
	// fatal/parse error, an uncaught exception, a stack trace, a ".php" source
	// reference, or an " on line N" location. Generic "warning:" / "notice:" /
	// "deprecated:" are deliberately excluded (non-PHP output uses them too).
	phpErrorPrefixRegex = regexp.MustCompile(`(?i)(fatal error:|parse error:|uncaught \w*error|stack trace:|\.php(:\d+| on line \d+)|\bon line \d+)`)

	// phpTypeErrorShapeRegex matches the PHP type-error shape: a function call
	// immediately followed by ": Argument #N" (PHP 8, e.g. "strlen(): Argument #1")
	// or an "expects parameter N" clause (PHP 7). A bare "foo()" token alone does
	// NOT anchor — the call must sit in this PHP error context.
	phpTypeErrorShapeRegex = regexp.MustCompile(`(?i)\(\):\s*Argument #\d+|expects parameter \d+`)
)

// php2shellCVSSVector is the CVSS v4.0 base vector for php2shell
// (CVE-2026-109618 / CVE-2026-109619), base score 9.2, per the GHSAs.
const php2shellCVSSVector = "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"

// phpInfoBodyLimit caps body scanning as defense-in-depth above the engine's
// own response-size limit.
const phpInfoBodyLimit = 4 * 1024 * 1024

func init() {
	Register(&PHPFingerprinter{})
	Register(&PHPInfoFingerprinter{})
	Register(&PHPInfoInfoFingerprinter{})
	Register(&PHPInfoTestFingerprinter{})
}

// ── Passive fingerprinter (root response) ───────────────────────────────────

// PHPFingerprinter runs the full detection cascade against the already-fetched
// root response and body. It is deterministic: it relies only on signals in the
// response it is given, never on the racy apache_httpd X-Powered-By enrichment.
type PHPFingerprinter struct{}

func (f *PHPFingerprinter) Name() string { return "php" }

// Match pre-filters cheaply: any explicit PHP header signal, or any HTML body
// (so Tier 0 phpinfo and Tier 3 error signatures can be inspected). Fingerprint
// still returns nil when no concrete PHP signal is present.
func (f *PHPFingerprinter) Match(resp *http.Response) bool {
	if phpPoweredByRegex.MatchString(resp.Header.Get("X-Powered-By")) {
		return true
	}
	if phpServerMentionsPHP(resp) || phpHasSessionCookie(resp) {
		return true
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

func (f *PHPFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	bodyStr := ""
	if len(body) <= phpInfoBodyLimit {
		bodyStr = string(body)
	}

	// Tier 0: the given body is itself a phpinfo page (matched by content, so
	// it works at any filename, not just /phpinfo.php). A phpinfo page served as
	// the root is itself the exposure, so emit both findings.
	if looksLikePHPInfo(bodyStr) {
		return phpWithFindings(fingerprintPHPInfoBody(bodyStr), "/"), nil
	}

	// Tier 2 SAPI is a weak hint; only surfaced once a PHP signal is confirmed.
	sapi, sapiSource := phpSAPIFromHeaders(resp)

	// Tier 1: X-Powered-By banner (exact version). This is the deterministic
	// php2shell contributor — it is computed from the already-fetched root
	// response, so it never depends on a follow-up request.
	if m := phpPoweredByRegex.FindStringSubmatch(resp.Header.Get("X-Powered-By")); len(m) > 1 {
		res := buildPHPResult(phpResult{
			version:       m[1],
			versionSource: "x-powered-by",
			confidence:    "exact",
			sapi:          sapi,
			sapiSource:    sapiSource,
		})
		return phpWithFindings(res, ""), nil
	}

	// Tier 3: error-format family from the given body.
	if family, source := phpVersionFamilyFromError(bodyStr); family != "" {
		res := buildPHPResult(phpResult{confidence: "major-family", sapi: sapi, sapiSource: sapiSource})
		res.Metadata["version_family"] = family
		res.Metadata["version_source"] = source
		return res, nil
	}

	// PHP present but no version (PHPSESSID cookie, or Server token).
	if phpHasSessionCookie(resp) || phpServerMentionsPHP(resp) {
		return buildPHPResult(phpResult{sapi: sapi, sapiSource: sapiSource}), nil
	}

	return nil, nil
}

// ── Active phpinfo path probes ──────────────────────────────────────────────

// PHPInfoFingerprinter probes /phpinfo.php, the canonical phpinfo filename.
type PHPInfoFingerprinter struct{}

func (f *PHPInfoFingerprinter) Name() string          { return "php-phpinfo" }
func (f *PHPInfoFingerprinter) ProbeEndpoint() string { return "/phpinfo.php" }
func (f *PHPInfoFingerprinter) ProbeAccept() string   { return "text/html" }
func (f *PHPInfoFingerprinter) Match(resp *http.Response) bool {
	return matchPHPInfoProbe(resp)
}
func (f *PHPInfoFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	result, _ := fingerprintPHPInfoProbe(body)
	return phpWithFindings(result, f.ProbeEndpoint()), nil
}

// PHPInfoInfoFingerprinter probes /info.php.
type PHPInfoInfoFingerprinter struct{}

func (f *PHPInfoInfoFingerprinter) Name() string          { return "php-info" }
func (f *PHPInfoInfoFingerprinter) ProbeEndpoint() string { return "/info.php" }
func (f *PHPInfoInfoFingerprinter) ProbeAccept() string   { return "text/html" }
func (f *PHPInfoInfoFingerprinter) Match(resp *http.Response) bool {
	return matchPHPInfoProbe(resp)
}
func (f *PHPInfoInfoFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	result, _ := fingerprintPHPInfoProbe(body)
	return phpWithFindings(result, f.ProbeEndpoint()), nil
}

// PHPInfoTestFingerprinter probes /test.php.
type PHPInfoTestFingerprinter struct{}

func (f *PHPInfoTestFingerprinter) Name() string          { return "php-test" }
func (f *PHPInfoTestFingerprinter) ProbeEndpoint() string { return "/test.php" }
func (f *PHPInfoTestFingerprinter) ProbeAccept() string   { return "text/html" }
func (f *PHPInfoTestFingerprinter) Match(resp *http.Response) bool {
	return matchPHPInfoProbe(resp)
}
func (f *PHPInfoTestFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	result, _ := fingerprintPHPInfoProbe(body)
	return phpWithFindings(result, f.ProbeEndpoint()), nil
}

// matchPHPInfoProbe is the shared probe pre-filter: a non-error-range HTML
// response is worth a body inspection. The body cannot be seen here, so the
// phpinfo signature check happens in Fingerprint.
func matchPHPInfoProbe(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode > 499 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

// fingerprintPHPInfoProbe confirms the body is a phpinfo page and parses it.
func fingerprintPHPInfoProbe(body []byte) (*FingerprintResult, error) {
	if len(body) > phpInfoBodyLimit {
		return nil, nil
	}
	bodyStr := string(body)
	if !looksLikePHPInfo(bodyStr) {
		return nil, nil
	}
	return fingerprintPHPInfoBody(bodyStr), nil
}

// ── Shared detection logic ──────────────────────────────────────────────────

// phpResult carries the per-field cascade output into buildPHPResult.
type phpResult struct {
	version       string
	versionSource string
	confidence    string // "exact", "major-family", or "" (presence only)
	sapi          string
	sapiSource    string
	buildDate     string
	system        string
}

// fingerprintPHPInfoBody parses a confirmed phpinfo body (Tier 0).
func fingerprintPHPInfoBody(bodyStr string) *FingerprintResult {
	version, sapi, buildDate, system := parsePHPInfo(bodyStr)
	r := phpResult{
		versionSource: "phpinfo",
		sapi:          sapi,
		buildDate:     buildDate,
		system:        system,
	}
	if sapi != "" {
		r.sapiSource = "phpinfo"
	}
	if phpVersionValidateRegex.MatchString(version) {
		r.version = version
		r.confidence = "exact"
	}
	return buildPHPResult(r)
}

// buildPHPResult assembles the FingerprintResult, version-pinned CPE, and
// exposure flags from a filled phpResult.
func buildPHPResult(r phpResult) *FingerprintResult {
	metadata := map[string]any{}
	if r.versionSource != "" {
		metadata["version_source"] = r.versionSource
	}
	if r.confidence != "" {
		metadata["version_confidence"] = r.confidence
	}
	if r.sapi != "" {
		metadata["sapi"] = r.sapi
	}
	if r.sapiSource != "" {
		metadata["sapi_source"] = r.sapiSource
	}
	if r.buildDate != "" {
		metadata["build_date"] = r.buildDate
	}
	if r.system != "" {
		metadata["system"] = r.system
	}

	cpeVersion := ""
	resultVersion := ""
	if r.confidence == "exact" && phpVersionValidateRegex.MatchString(r.version) {
		cpeVersion = r.version
		resultVersion = r.version
		for k, v := range evaluatePHPExposure(r.version) {
			metadata[k] = v
		}
	}

	return &FingerprintResult{
		Technology: "php",
		Version:    resultVersion,
		CPEs:       []string{buildPHPCPE(cpeVersion)},
		Metadata:   metadata,
	}
}

// looksLikePHPInfo reports whether a body is a phpinfo page, by content.
func looksLikePHPInfo(bodyStr string) bool {
	// Require the phpinfo value-table marker (class="v"), which real phpinfo
	// output always emits, so a page merely titled "phpinfo()" cannot
	// false-match. With that marker present, either the title or the version
	// heading confirms it.
	if bodyStr == "" || !strings.Contains(bodyStr, `class="v"`) {
		return false
	}
	return phpInfoTitleRegex.MatchString(bodyStr) || phpInfoH1Regex.MatchString(bodyStr)
}

// parsePHPInfo extracts version, SAPI, build date, and system from a phpinfo body.
func parsePHPInfo(bodyStr string) (version, sapi, buildDate, system string) {
	switch {
	case phpInfoVersionH1Regex.MatchString(bodyStr):
		version = phpInfoVersionH1Regex.FindStringSubmatch(bodyStr)[1]
	case phpInfoVersionTitleRegex.MatchString(bodyStr):
		version = phpInfoVersionTitleRegex.FindStringSubmatch(bodyStr)[1]
	case phpInfoVersionRowRegex.MatchString(bodyStr):
		version = phpInfoVersionRowRegex.FindStringSubmatch(bodyStr)[1]
	}
	if m := phpInfoServerAPIRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		sapi = normalizePHPSAPI(m[1])
	}
	if m := phpInfoBuildDateRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		buildDate = strings.TrimSpace(m[1])
	}
	if m := phpInfoSystemRegex.FindStringSubmatch(bodyStr); len(m) > 1 {
		system = strings.TrimSpace(m[1])
	}
	return version, sapi, buildDate, system
}

// normalizePHPSAPI maps a phpinfo "Server API" value to a canonical SAPI name.
func normalizePHPSAPI(raw string) string {
	r := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case strings.Contains(r, "apache 2.0 handler"), strings.Contains(r, "apache2handler"):
		return "mod_php"
	case strings.Contains(r, "fpm/fastcgi"):
		return "php-fpm"
	case strings.Contains(r, "cgi/fastcgi"):
		return "php-cgi"
	case strings.Contains(r, "litespeed"):
		return "litespeed"
	case strings.Contains(r, "command line"):
		return "cli"
	}
	return strings.TrimSpace(raw)
}

// phpSAPIFromHeaders infers a low-confidence SAPI family from the Server header.
func phpSAPIFromHeaders(resp *http.Response) (sapi, source string) {
	server := strings.ToLower(resp.Header.Get("Server"))
	switch {
	case strings.Contains(server, "litespeed"):
		return "litespeed", "server-header"
	case strings.Contains(server, "apache"):
		return "mod_php?", "server-header" // could be fpm-behind-apache; low confidence
	case strings.Contains(server, "nginx"):
		return "php-fpm-or-cgi", "server-header" // nginx never runs mod_php
	}
	return "", ""
}

// phpVersionFamilyFromError infers the PHP major family from a type-error body.
// It requires a PHP-specific anchor alongside the version-family phrase so that
// non-PHP HTML containing the same generic wording is not mislabeled as PHP.
func phpVersionFamilyFromError(bodyStr string) (family, source string) {
	if bodyStr == "" || !phpErrorAnchored(bodyStr) {
		return "", ""
	}
	if strings.Contains(bodyStr, "must be of type") ||
		(strings.Contains(bodyStr, "Uncaught TypeError") && strings.Contains(bodyStr, "Argument #")) {
		return "8.x", "error-format"
	}
	if strings.Contains(bodyStr, "expects parameter") {
		return "<=7.x", "error-format" // 5.x and 7.x share this wording
	}
	return "", ""
}

// phpErrorAnchored reports whether a body carries a strong PHP error marker
// (a PHP fatal/parse error, uncaught exception, stack trace, ".php" reference,
// or "on line N") or the PHP type-error shape ("(): Argument #N" / "expects
// parameter N"), either of which corroborates that a generic type-error phrase
// actually originates from PHP.
func phpErrorAnchored(bodyStr string) bool {
	return phpErrorPrefixRegex.MatchString(bodyStr) || phpTypeErrorShapeRegex.MatchString(bodyStr)
}

// phpServerMentionsPHP reports whether the Server header carries a PHP token.
func phpServerMentionsPHP(resp *http.Response) bool {
	return phpServerTokenRegex.MatchString(resp.Header.Get("Server"))
}

// phpHasSessionCookie reports whether any Set-Cookie sets a PHP session cookie.
func phpHasSessionCookie(resp *http.Response) bool {
	for _, cookie := range resp.Header["Set-Cookie"] {
		if strings.Contains(cookie, "PHPSESSID") {
			return true
		}
	}
	return false
}

// evaluatePHPExposure returns the php2shell / EOL exposure flags for an exact
// version, or nil when the version cannot be parsed.
func evaluatePHPExposure(version string) map[string]any {
	maj, min, patch, ok := phpVersionTuple(version)
	if !ok {
		return nil
	}
	branch := [2]int{maj, min}
	eol := phpBranchLessOrEqual(branch, phpEOLMaxBranch)

	flags := map[string]any{
		"eol":                eol,
		"backport_uncertain": true, // version string alone can't clear distro backports
	}
	switch {
	case eol:
		flags["below_php2shell_fix"] = true // EOL branch, no fix exists
	default:
		if fix, has := php2shellFix[branch]; has {
			flags["below_php2shell_fix"] = patch < fix
		} else {
			flags["below_php2shell_fix"] = false
		}
	}
	return flags
}

// phpVersionTuple parses a dotted-triple version into its numeric components.
func phpVersionTuple(version string) (maj, min, patch int, ok bool) {
	m := phpVersionExtractRegex.FindStringSubmatch(version)
	if len(m) < 4 {
		return 0, 0, 0, false
	}
	maj, _ = strconv.Atoi(m[1])
	min, _ = strconv.Atoi(m[2])
	patch, _ = strconv.Atoi(m[3])
	return maj, min, patch, true
}

// phpBranchLessOrEqual reports whether branch a is at or below branch b.
func phpBranchLessOrEqual(a, b [2]int) bool {
	if a[0] != b[0] {
		return a[0] < b[0]
	}
	return a[1] <= b[1]
}

// buildPHPCPE constructs a CPE 2.3 string for PHP, pinning the version when it
// is a valid dotted triple and falling back to a wildcard otherwise.
func buildPHPCPE(version string) string {
	if version == "" || !phpVersionValidateRegex.MatchString(version) {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:php:php:%s:*:*:*:*:*:*:*", version)
}

// ── Security findings (surfaced under --misconfigs) ─────────────────────────
//
// Findings are attached to FingerprintResult.SecurityFindings during the
// Fingerprint phase, when the response body is already in hand. The HTTP
// service layer surfaces them into the service only when --misconfigs is set
// (see fingerprint() / FingerprintResponse). This is deliberately NOT done via
// MisconfigHTTPFingerprinter.CheckMisconfigs: that interface re-fetches the
// host, but the service builds its client around a single pre-dialed connection
// (DialContext returns one fixed conn), and by the time CheckMisconfigs runs —
// after every fingerprinter's active probes — Apache has already closed that
// connection, so the re-fetch fails and no finding is emitted. Computing the
// findings at Fingerprint time avoids the follow-up request entirely, so the
// banner-derived php2shell finding is deterministic across server types.
//
// Each source contributes findings independently, and the service-level
// de-duplication in Service.EnrichFindings collapses them to exactly one
// finding per ID (keeping the most detailed, i.e. the phpinfo-confirmed SAPI):
//   - Passive PHPFingerprinter: php2shell from the root banner (deterministic,
//     behavioral SAPI); also exposed-phpinfo when the root body is itself phpinfo.
//   - Each phpinfo path probe (/phpinfo.php, /info.php, /test.php): exposed-phpinfo
//     plus php2shell with the phpinfo-confirmed SAPI.
// This removes the earlier "infer from the probe's own X-Powered-By" logic,
// which dropped php2shell on banner-less roots and duplicated it otherwise.

// phpWithFindings attaches the applicable exposure findings to a result. Every
// source contributes independently: exposedPath != "" attaches exposed-phpinfo
// (the builder no-ops unless the result is phpinfo-sourced), and php2shell is
// attached whenever the result is below the fix line (the builder no-ops for
// patched/unknown versions). Cross-source de-duplication to exactly one finding
// per ID — and selection of the highest-confidence SAPI — happens at the
// service level in Service.EnrichFindings, not here; this lets a host with no
// root banner but an exposed phpinfo, or with phpinfo at /info.php or /test.php
// only, still contribute both findings.
func phpWithFindings(result *FingerprintResult, exposedPath string) *FingerprintResult {
	if result == nil {
		return nil
	}
	if exposedPath != "" {
		if fnd := phpExposedPHPInfoFinding(result, exposedPath); fnd != nil {
			result.SecurityFindings = append(result.SecurityFindings, *fnd)
		}
	}
	if fnd := phpPHP2ShellFinding(result); fnd != nil {
		result.SecurityFindings = append(result.SecurityFindings, *fnd)
	}
	return result
}

// phpExposedPHPInfoFinding builds the exposed-phpinfo finding for a phpinfo
// result found at path. Returns nil unless the result came from a phpinfo page.
func phpExposedPHPInfoFinding(result *FingerprintResult, path string) *plugins.SecurityFinding {
	if result == nil || result.Metadata["version_source"] != "phpinfo" {
		return nil
	}
	version := result.Version
	sapi, _ := result.Metadata["sapi"].(string)

	evidence := fmt.Sprintf("phpinfo() reachable at %s", path)
	if version != "" {
		evidence += fmt.Sprintf(" disclosing PHP %s", version)
	}
	if sapi != "" {
		evidence += fmt.Sprintf(" (SAPI %s)", sapi)
	}

	return &plugins.SecurityFinding{
		ID:       findingExposedPHPInfo,
		Severity: plugins.SeverityInfo,
		Description: fmt.Sprintf("An unauthenticated phpinfo() page is exposed at %s. phpinfo() output "+
			"discloses the exact PHP version and SAPI, build date, host OS/distribution, loaded "+
			"extensions, absolute filesystem paths, and the server environment.", path),
		Evidence: evidence,
	}
}

// phpPHP2ShellFinding builds the php2shell finding when the result's exposure
// evaluation marks it below the branch fix line. Returns nil otherwise.
func phpPHP2ShellFinding(result *FingerprintResult) *plugins.SecurityFinding {
	if result == nil {
		return nil
	}
	below, _ := result.Metadata["below_php2shell_fix"].(bool)
	if !below {
		return nil
	}

	version := result.Version
	source, _ := result.Metadata["version_source"].(string)
	sapi, _ := result.Metadata["sapi"].(string)
	eol, _ := result.Metadata["eol"].(bool)
	buildDate, _ := result.Metadata["build_date"].(string)
	system, _ := result.Metadata["system"].(string)

	branchDetail := "below the branch fix line (8.2.35 / 8.3.36 / 8.4.27 / 8.5.12)"
	exposureTag := "below branch fix"
	if eol {
		branchDetail = "on an end-of-life branch (<= 8.1, no upstream fix)"
		exposureTag = "EOL branch"
	}

	// Caveat (b) adjudication pointer, with concrete build data when available.
	buildPointer := "the phpinfo Build Date and System"
	if buildDate != "" || system != "" {
		buildPointer = fmt.Sprintf("the phpinfo Build Date (%s) and System (%s)", buildDate, system)
	}

	// mod_php prioritization. mod_php is the configuration with publicly
	// validated php2shell RCE and the focus for scanning at scale, so surface it
	// as the priority target. Severity stays High for every affected SAPI —
	// php-fpm, php-cgi and litespeed are all listed as affected — this only
	// re-prioritizes. Only the phpinfo-confirmed SAPI ("mod_php", from Server
	// API = "Apache 2.0 Handler") earns the validated-RCE marker; the behavioral
	// Apache guess ("mod_php?") gets a clearly distinct unconfirmed triage
	// marker, and other SAPIs get none (the broad-SAPI note already covers them).
	modPHPDescNote := ""
	modPHPEvidenceTag := ""
	switch sapi {
	case "mod_php":
		modPHPDescNote = " mod_php is the configuration with publicly validated php2shell RCE, so prioritize these hosts."
		modPHPEvidenceTag = "; validated_rce_sapi=mod_php"
	case "mod_php?":
		modPHPEvidenceTag = "; likely_mod_php_unconfirmed"
	}

	description := fmt.Sprintf(
		"PHP %s is %s, so it predates the php2shell fix (CVE-2026-109618 / CVE-2026-109619; "+
			"advisory CVSS base score 9.2). Caveat (a): exploitability was NOT validated remotely — "+
			"php2shell is a memory-corruption bug with no safe remote probe, so this is a "+
			"version-inference finding only. Caveat (b): distributions backport security fixes onto "+
			"frozen version strings, so a distro build reporting a below-fix version may already be "+
			"patched; adjudicate using %s before concluding. All common SAPIs are affected (mod_php, "+
			"php-fpm, php-cgi, FrankenPHP, LiteSpeed), so this is not scoped out by SAPI.%s",
		version, branchDetail, buildPointer, modPHPDescNote)

	evidence := fmt.Sprintf("PHP %s", version)
	if source != "" {
		evidence += "; version source " + source
	}
	if sapi != "" {
		evidence += "; SAPI " + sapi
	}
	evidence += "; " + exposureTag + modPHPEvidenceTag

	return &plugins.SecurityFinding{
		ID:          findingPHP2Shell,
		Severity:    plugins.SeverityHigh,
		CVSS:        php2shellCVSSVector,
		Description: description,
		Evidence:    evidence,
	}
}
