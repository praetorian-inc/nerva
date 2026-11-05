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

package fingerprinters

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// findingByID returns the first finding with the given ID, or nil.
func findingByID(findings []plugins.SecurityFinding, id string) *plugins.SecurityFinding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}

// phpResultForVersion builds a cascade result for a version via the X-Powered-By path.
func phpResultForVersion(t *testing.T, version string) *FingerprintResult {
	t.Helper()
	resp := htmlResp(200)
	resp.Header.Set("X-Powered-By", "PHP/"+version)
	r, err := (&PHPFingerprinter{}).Fingerprint(resp, []byte("<html></html>"))
	require.NoError(t, err)
	require.NotNil(t, r)
	return r
}

// loadPHPFixture reads a captured phpinfo HTML fixture from testdata.
func loadPHPFixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	require.NoError(t, err)
	return b
}

func htmlResp(status int) *http.Response {
	resp := &http.Response{StatusCode: status, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	return resp
}

// ── Name / ProbeEndpoint / ProbeAccept ──────────────────────────────────────

func TestPHPFingerprinter_Name(t *testing.T) {
	assert.Equal(t, "php", (&PHPFingerprinter{}).Name())
}

func TestPHPInfoProbeFingerprinters_Metadata(t *testing.T) {
	cases := []struct {
		fp       ActiveHTTPFingerprinter
		name     string
		endpoint string
	}{
		{&PHPInfoFingerprinter{}, "php-phpinfo", "/phpinfo.php"},
		{&PHPInfoInfoFingerprinter{}, "php-info", "/info.php"},
		{&PHPInfoTestFingerprinter{}, "php-test", "/test.php"},
	}
	for _, c := range cases {
		assert.Equal(t, c.name, c.fp.Name())
		assert.Equal(t, c.endpoint, c.fp.ProbeEndpoint())
		accept, ok := c.fp.(AcceptHeaderProvider)
		require.True(t, ok, "%s must provide an Accept header", c.name)
		assert.Equal(t, "text/html", accept.ProbeAccept())
	}
}

// ── Tier 0: phpinfo content signature + parse (active probe path) ────────────

func TestPHPInfoFingerprint_ModPHP_RealFixture(t *testing.T) {
	body := loadPHPFixture(t, "phpinfo_mod_php_8_2_34.html")
	result, err := (&PHPInfoFingerprinter{}).Fingerprint(htmlResp(200), body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "php", result.Technology)
	assert.Equal(t, "8.2.34", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:php:php:8.2.34:*:*:*:*:*:*:*")
	assert.Equal(t, "mod_php", result.Metadata["sapi"])
	assert.Equal(t, "phpinfo", result.Metadata["version_source"])
	assert.Equal(t, "exact", result.Metadata["version_confidence"])
	// 8.2.34 < 8.2.35 php2shell fix line.
	assert.Equal(t, true, result.Metadata["below_php2shell_fix"])
	assert.Equal(t, true, result.Metadata["backport_uncertain"])
	assert.Equal(t, false, result.Metadata["eol"])
	assert.NotEmpty(t, result.Metadata["build_date"])
	assert.NotEmpty(t, result.Metadata["system"])
}

func TestPHPInfoFingerprint_FPM_RealFixture(t *testing.T) {
	body := loadPHPFixture(t, "phpinfo_fpm_8_2_34.html")
	result, err := (&PHPInfoFingerprinter{}).Fingerprint(htmlResp(200), body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "8.2.34", result.Version)
	assert.Equal(t, "php-fpm", result.Metadata["sapi"])
	assert.Contains(t, result.CPEs, "cpe:2.3:a:php:php:8.2.34:*:*:*:*:*:*:*")
}

func TestPHPInfoFingerprint_OldPHP_EOL_RealFixture(t *testing.T) {
	body := loadPHPFixture(t, "phpinfo_mod_php_5_6_40.html")
	result, err := (&PHPInfoFingerprinter{}).Fingerprint(htmlResp(200), body)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Old phpinfo uses "<title>phpinfo()</title>" (no inline version); version
	// still comes from the h1.
	assert.Equal(t, "5.6.40", result.Version)
	assert.Equal(t, "mod_php", result.Metadata["sapi"])
	assert.Equal(t, true, result.Metadata["eol"])
	// EOL branch has no upstream php2shell fix, so it is always below the fix.
	assert.Equal(t, true, result.Metadata["below_php2shell_fix"])
}

func TestPHPInfoFingerprint_NotPHPInfo_ReturnsNil(t *testing.T) {
	result, err := (&PHPInfoFingerprinter{}).Fingerprint(htmlResp(404),
		[]byte("<html><body>Not Found</body></html>"))
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ── Tier 1: X-Powered-By banner (passive root path) ─────────────────────────

func TestPHPPassive_XPoweredBy_VersionPinnedCPE(t *testing.T) {
	resp := htmlResp(200)
	resp.Header.Set("X-Powered-By", "PHP/8.3.35")
	resp.Header.Set("Server", "Apache/2.4.69 (Debian)")

	result, err := (&PHPFingerprinter{}).Fingerprint(resp, []byte("<html></html>"))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "php", result.Technology)
	assert.Equal(t, "8.3.35", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:php:php:8.3.35:*:*:*:*:*:*:*")
	assert.Equal(t, "x-powered-by", result.Metadata["version_source"])
	// 8.3.35 < 8.3.36 fix line.
	assert.Equal(t, true, result.Metadata["below_php2shell_fix"])
}

// expose_php=Off: a bare Apache root with no X-Powered-By carries no PHP signal,
// so the passive path returns nil. Such hosts are only resolved by the active
// phpinfo probe (see TestPHPInfoFingerprint_* above), which is why the active
// probe path exists.
func TestPHPPassive_ExposePhpOff_RootReturnsNil(t *testing.T) {
	resp := htmlResp(200)
	resp.Header.Set("Server", "Apache/2.4.69 (Debian)")

	result, err := (&PHPFingerprinter{}).Fingerprint(resp, []byte("<html>ok</html>"))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestPHPPassive_RootBodyIsPhpInfo_DetectedAnyFilename(t *testing.T) {
	// A phpinfo page served as the root body (e.g. target points directly at
	// /test.php) is detected by content signature, not by filename.
	body := loadPHPFixture(t, "phpinfo_mod_php_8_2_34.html")
	result, err := (&PHPFingerprinter{}).Fingerprint(htmlResp(200), body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "8.2.34", result.Version)
	assert.Equal(t, "mod_php", result.Metadata["sapi"])
}

// ── Tier 2: behavioral SAPI from headers ────────────────────────────────────

func TestPHPSAPIFromHeaders(t *testing.T) {
	cases := []struct {
		server string
		sapi   string
	}{
		{"Apache/2.4.69 (Debian)", "mod_php?"},
		{"nginx/1.30.6", "php-fpm-or-cgi"},
		{"LiteSpeed", "litespeed"},
	}
	for _, c := range cases {
		resp := &http.Response{Header: make(http.Header)}
		resp.Header.Set("Server", c.server)
		sapi, source := phpSAPIFromHeaders(resp)
		assert.Equal(t, c.sapi, sapi, c.server)
		assert.Equal(t, "server-header", source)
	}
}

// ── Tier 3: error-format version family ──────────────────────────────────────

func TestPHPVersionFamilyFromError(t *testing.T) {
	php8 := "Uncaught TypeError: strlen(): Argument #1 ($string) must be of type string, array given"
	fam, src := phpVersionFamilyFromError(php8)
	assert.Equal(t, "8.x", fam)
	assert.Equal(t, "error-format", src)

	php7 := "strlen() expects parameter 1 to be string, array given"
	fam, src = phpVersionFamilyFromError(php7)
	assert.Equal(t, "<=7.x", fam)
	assert.Equal(t, "error-format", src)

	fam, _ = phpVersionFamilyFromError("<html>fine</html>")
	assert.Equal(t, "", fam)
}

// Tier 3 requires a PHP anchor: generic non-PHP wording must not be labeled PHP.
func TestPHPVersionFamilyFromError_RequiresPHPAnchor(t *testing.T) {
	fam, src := phpVersionFamilyFromError("<html><body>The value must be of type string in our docs.</body></html>")
	assert.Equal(t, "", fam)
	assert.Equal(t, "", src)

	// End to end: non-PHP HTML with the phrase yields no php Technology/CPE.
	resp := htmlResp(200)
	r, err := (&PHPFingerprinter{}).Fingerprint(resp, []byte("<html>Argument must be of type int</html>"))
	require.NoError(t, err)
	if r != nil {
		assert.NotEqual(t, "php", r.Technology)
		for _, c := range r.CPEs {
			assert.NotContains(t, c, "cpe:2.3:a:php:php")
		}
	}
}

// ── Exposure evaluation (php2shell fix line) ────────────────────────────────

func TestEvaluatePHPExposure(t *testing.T) {
	cases := []struct {
		version  string
		belowFix bool
		eol      bool
	}{
		{"8.2.34", true, false},  // below 8.2.35
		{"8.2.35", false, false}, // at the fix line
		{"8.3.35", true, false},  // below 8.3.36
		{"8.3.36", false, false},
		{"8.4.27", false, false},
		{"8.5.12", false, false},
		{"8.1.34", true, true}, // EOL branch, always below fix
		{"7.4.33", true, true},
		{"5.6.40", true, true},
	}
	for _, c := range cases {
		flags := evaluatePHPExposure(c.version)
		require.NotNil(t, flags, c.version)
		assert.Equal(t, c.belowFix, flags["below_php2shell_fix"], "below fix: %s", c.version)
		assert.Equal(t, c.eol, flags["eol"], "eol: %s", c.version)
		assert.Equal(t, true, flags["backport_uncertain"], "backport uncertain: %s", c.version)
	}
}

// ── CPE safety ──────────────────────────────────────────────────────────────

func TestBuildPHPCPE_RejectsMalformedVersion(t *testing.T) {
	// A version carrying CPE metacharacters must not be interpolated raw.
	assert.Equal(t, "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", buildPHPCPE("8.2.34:injection"))
	assert.Equal(t, "cpe:2.3:a:php:php:*:*:*:*:*:*:*:*", buildPHPCPE(""))
	assert.Equal(t, "cpe:2.3:a:php:php:8.2.34:*:*:*:*:*:*:*", buildPHPCPE("8.2.34"))
}

// ── Findings: exposed-phpinfo ───────────────────────────────────────────────

func TestExposedPhpinfoFinding_FiresForPhpinfoFixture(t *testing.T) {
	for _, fx := range []string{"phpinfo_mod_php_8_2_34.html", "phpinfo_fpm_8_2_34.html", "phpinfo_mod_php_5_6_40.html"} {
		result := fingerprintPHPInfoBody(string(loadPHPFixture(t, fx)))
		fnd := phpExposedPHPInfoFinding(result, "/phpinfo.php")
		require.NotNil(t, fnd, fx)
		assert.Equal(t, "exposed-phpinfo", fnd.ID)
		assert.Equal(t, plugins.SeverityInfo, fnd.Severity)
		assert.Contains(t, fnd.Evidence, "/phpinfo.php")
		assert.Contains(t, fnd.Evidence, result.Version)
	}
}

func TestExposedPhpinfoFinding_NilWhenNotPhpinfoSourced(t *testing.T) {
	// A banner-only (X-Powered-By) result is not a phpinfo exposure.
	fnd := phpExposedPHPInfoFinding(phpResultForVersion(t, "8.2.34"), "/")
	assert.Nil(t, fnd)
}

// ── Findings: php-vulnerable-php2shell ──────────────────────────────────────

func TestPHP2ShellFinding_FiresForBelowFixVersions(t *testing.T) {
	for _, v := range []string{"8.2.34", "8.3.35", "8.1.34", "5.6.40"} {
		fnd := phpPHP2ShellFinding(phpResultForVersion(t, v))
		require.NotNil(t, fnd, v)
		assert.Equal(t, "php-vulnerable-php2shell", fnd.ID)
		assert.Equal(t, plugins.SeverityHigh, fnd.Severity)
		assert.Equal(t, php2shellCVSSVector, fnd.CVSS, v)
		assert.Contains(t, fnd.Description, "9.2", v) // human-readable base score
		// Both required caveats, in substance.
		assert.Contains(t, fnd.Description, "backport", v)               // caveat (b)
		assert.Contains(t, fnd.Description, "NOT validated remotely", v) // caveat (a)
		assert.Contains(t, fnd.Description, "memory-corruption", v)      // no safe probe
		assert.Contains(t, fnd.Description, "CVE-2026-109618", v)
		assert.Contains(t, fnd.Description, "php-fpm", v) // broad SAPI note
	}
}

// NEGATIVE case: a patched version (8.2.35) must NOT fire php2shell.
func TestPHP2ShellFinding_DoesNotFireForPatchedVersion(t *testing.T) {
	result := fingerprintPHPInfoBody(string(loadPHPFixture(t, "phpinfo_mod_php_8_2_35_patched.html")))
	require.Equal(t, "8.2.35", result.Version)
	assert.Equal(t, false, result.Metadata["below_php2shell_fix"])
	assert.Nil(t, phpPHP2ShellFinding(result))
}

// ── Findings attached to FingerprintResult (surfaced under --misconfigs) ────

// htmlRespXPB builds an HTML response carrying an optional X-Powered-By header.
func htmlRespXPB(status int, xpb string) *http.Response {
	resp := htmlResp(status)
	if xpb != "" {
		resp.Header.Set("X-Powered-By", xpb)
	}
	return resp
}

// expose_php=Off: the probed phpinfo response carries no banner, so the active
// probe emits BOTH findings via FingerprintResult.SecurityFindings.
func TestFingerprintFindings_ExposePhpOff_ActiveEmitsBoth(t *testing.T) {
	body := loadPHPFixture(t, "phpinfo_mod_php_8_2_34.html")
	result, err := (&PHPInfoFingerprinter{}).Fingerprint(htmlResp(200), body)
	require.NoError(t, err)
	require.NotNil(t, result)

	exposed := findingByID(result.SecurityFindings, "exposed-phpinfo")
	require.NotNil(t, exposed)
	assert.Equal(t, plugins.SeverityInfo, exposed.Severity)
	assert.Contains(t, exposed.Evidence, "/phpinfo.php")

	php2shell := findingByID(result.SecurityFindings, "php-vulnerable-php2shell")
	require.NotNil(t, php2shell)
	assert.Equal(t, plugins.SeverityHigh, php2shell.Severity)
	assert.Contains(t, php2shell.Description, "backport")
	assert.Contains(t, php2shell.Description, "NOT validated remotely")
}

// Every source emits independently; the service-level dedup in EnrichFindings
// collapses them to exactly one finding per ID, and the phpinfo-confirmed
// (richer) mod_php php2shell wins over the passive behavioral-banner one.
func TestFingerprintFindings_WithBanner_ServiceLevelDedup(t *testing.T) {
	// Passive root with banner + Apache server: php2shell with behavioral SAPI.
	passiveResp := htmlRespXPB(200, "PHP/8.2.34")
	passiveResp.Header.Set("Server", "Apache/2.4.69 (Debian)")
	passive, err := (&PHPFingerprinter{}).Fingerprint(passiveResp, []byte("<html>ok</html>"))
	require.NoError(t, err)
	require.NotNil(t, passive)
	passiveShell := findingByID(passive.SecurityFindings, "php-vulnerable-php2shell")
	require.NotNil(t, passiveShell, "passive emits php2shell from banner")
	assert.Contains(t, passiveShell.Evidence, "likely_mod_php_unconfirmed")
	assert.NotContains(t, passiveShell.Evidence, "validated_rce_sapi=mod_php")
	assert.Nil(t, findingByID(passive.SecurityFindings, "exposed-phpinfo"), "root is not phpinfo")

	// Active /phpinfo.php (also with banner) now emits BOTH per-source.
	body := loadPHPFixture(t, "phpinfo_mod_php_8_2_34.html")
	active, err := (&PHPInfoFingerprinter{}).Fingerprint(htmlRespXPB(200, "PHP/8.2.34"), body)
	require.NoError(t, err)
	require.NotNil(t, active)
	assert.NotNil(t, findingByID(active.SecurityFindings, "exposed-phpinfo"))
	activeShell := findingByID(active.SecurityFindings, "php-vulnerable-php2shell")
	require.NotNil(t, activeShell, "active emits php2shell per-source")
	assert.Contains(t, activeShell.Evidence, "validated_rce_sapi=mod_php")

	// Service-level dedup: exactly one of each, richer confirmed mod_php wins.
	svc := plugins.Service{}
	svc.SecurityFindings = append(svc.SecurityFindings, passive.SecurityFindings...)
	svc.SecurityFindings = append(svc.SecurityFindings, active.SecurityFindings...)
	svc.EnrichFindings()

	exposedCount, shellCount := 0, 0
	for _, f := range svc.SecurityFindings {
		switch f.ID {
		case "exposed-phpinfo":
			exposedCount++
		case "php-vulnerable-php2shell":
			shellCount++
		}
	}
	assert.Equal(t, 1, exposedCount)
	assert.Equal(t, 1, shellCount)
	kept := findingByID(svc.SecurityFindings, "php-vulnerable-php2shell")
	require.NotNil(t, kept)
	assert.Contains(t, kept.Evidence, "validated_rce_sapi=mod_php")
	assert.NotContains(t, kept.Evidence, "likely_mod_php_unconfirmed")
	assert.Equal(t, php2shellCVSSVector, kept.CVSS)
}

// Patched version: exposed-phpinfo fires, php2shell does not.
func TestFingerprintFindings_PatchedVersion_OnlyExposedPhpinfo(t *testing.T) {
	body := loadPHPFixture(t, "phpinfo_mod_php_8_2_35_patched.html")
	result, err := (&PHPInfoFingerprinter{}).Fingerprint(htmlResp(200), body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.NotNil(t, findingByID(result.SecurityFindings, "exposed-phpinfo"))
	assert.Nil(t, findingByID(result.SecurityFindings, "php-vulnerable-php2shell"))
}

// All three phpinfo path probes (/phpinfo.php, /info.php, /test.php) emit both
// findings; EnrichFindings then keeps one exposed-phpinfo per distinct path and
// a single php-vulnerable-php2shell per host.
func TestFingerprintFindings_SecondaryProbesEmitFindings(t *testing.T) {
	body := loadPHPFixture(t, "phpinfo_mod_php_8_2_34.html")
	svc := plugins.Service{}
	for _, fp := range []HTTPFingerprinter{&PHPInfoFingerprinter{}, &PHPInfoInfoFingerprinter{}, &PHPInfoTestFingerprinter{}} {
		result, err := fp.Fingerprint(htmlResp(200), body)
		require.NoError(t, err)
		require.NotNil(t, result)
		exposed := findingByID(result.SecurityFindings, "exposed-phpinfo")
		require.NotNil(t, exposed, fp.Name())
		assert.NotNil(t, findingByID(result.SecurityFindings, "php-vulnerable-php2shell"), fp.Name())
		assert.Contains(t, exposed.Evidence, fp.(interface{ ProbeEndpoint() string }).ProbeEndpoint(), fp.Name())
		svc.SecurityFindings = append(svc.SecurityFindings, result.SecurityFindings...)
	}
	require.Len(t, svc.SecurityFindings, 6)
	svc.EnrichFindings()
	assert.Len(t, svc.SecurityFindings, 4)
	exposedPaths := map[string]bool{}
	exposedCount, shellCount := 0, 0
	for _, f := range svc.SecurityFindings {
		switch f.ID {
		case "exposed-phpinfo":
			exposedCount++
			for _, path := range []string{"/phpinfo.php", "/info.php", "/test.php"} {
				if strings.Contains(f.Evidence, path) {
					exposedPaths[path] = true
				}
			}
		case "php-vulnerable-php2shell":
			shellCount++
		}
	}
	assert.Equal(t, 3, exposedCount)
	assert.Equal(t, 1, shellCount)
	assert.Len(t, exposedPaths, 3, "each exposed-phpinfo finding should name a distinct path")
}

// The catalog standardizes both IDs via EnrichFindings.
func TestPHPFindings_CatalogEnrichment(t *testing.T) {
	cases := []struct {
		id    string
		sev   plugins.Severity
		title string
	}{
		{"exposed-phpinfo", plugins.SeverityInfo, "Exposed phpinfo() page"},
		{"php-vulnerable-php2shell", plugins.SeverityHigh, "PHP affected by php2shell (CVE-2026-109618/109619)"},
	}
	for _, c := range cases {
		f := plugins.SecurityFinding{ID: c.id}
		f.Enrich()
		assert.Equal(t, c.sev, f.Severity, c.id)
		assert.Equal(t, c.title, f.Title, c.id)
		assert.NotEmpty(t, f.Recommendation, c.id)
		if strings.Contains(c.id, "php2shell") {
			assert.Equal(t, "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", f.CVSS)
		}
	}
}
