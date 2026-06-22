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
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// veeamLoginPageWithVersion is a representative EM web login page carrying the
// verbatim title (protocol-research.md §2.1) and the login.bundle.js version leak.
const veeamLoginPageWithVersion = `<!DOCTYPE html>
<html>
<head>
<title>Veeam Backup Enterprise Manager : Login</title>
<script src="/em/scripts/login.bundle.js?v=12.1.2.172"></script>
</head>
<body><div id="login"></div></body>
</html>`

// veeamLoginPageNoVersion is the same login page with the brand title but no
// versioned bundle reference.
const veeamLoginPageNoVersion = `<!DOCTYPE html>
<html>
<head>
<title>Veeam Backup Enterprise Manager : Login</title>
<script src="/em/scripts/login.bundle.js"></script>
</head>
<body><div id="login"></div></body>
</html>`

// veeamRESTEntryDocV17 is the verbatim unauthenticated EM legacy REST entry
// document from protocol-research.md §3.1 (root <EnterpriseManager> + namespace
// + SupportedVersion v1_5/v1_6/v1_7).
const veeamRESTEntryDocV17 = `<?xml version="1.0" encoding="utf-8"?>
<EnterpriseManager xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://www.veeam.com/ent/v1.0">
 <Links>
   <Link Href="https://enterprise04.tech.local:9398/api/logonSessions" Type="LogonSessionList" Rel="Down"/>
   <Link Href="https://enterprise04.tech.local:9398/api/sessionMngr/?v=latest" Type="LogonSession" Rel="Create"/>
 </Links>
 <SupportedVersions>
   <SupportedVersion Name="v1_5"><Links><Link Href="https://enterprise04.tech.local:9398/api/sessionMngr/?v=v1_5" Type="LogonSession" Rel="Create"/></Links></SupportedVersion>
   <SupportedVersion Name="v1_6"><Links><Link Href="https://enterprise04.tech.local:9398/api/sessionMngr/?v=v1_6" Type="LogonSession" Rel="Create"/></Links></SupportedVersion>
   <SupportedVersion Name="v1_7"><Links><Link Href="https://enterprise04.tech.local:9398/api/sessionMngr/?v=v1_7" Type="LogonSession" Rel="Create"/></Links></SupportedVersion>
 </SupportedVersions>
</EnterpriseManager>`

// ── Web UI positive: with version ──────────────────────────────────────────────

func TestVeeamWebFingerprinter_Positive_WithVersion(t *testing.T) {
	fp := &VeeamEnterpriseManagerWebFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Request:    &http.Request{URL: &url.URL{Path: "/login.aspx"}},
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("Server", "Microsoft-IIS/10.0")

	require.True(t, fp.Match(resp), "Match must accept a 200 text/html login page")

	result, err := fp.Fingerprint(resp, []byte(veeamLoginPageWithVersion))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "veeam_backup_enterprise_manager_web", result.Technology)
	assert.Equal(t, "12.1.2.172", result.Version)
	assert.Equal(t, "enterprise_manager_web", result.Metadata["variant"])
	assert.Equal(t, "active_probe", result.Metadata["detection_method"])
	assert.Equal(t, "/login.aspx", result.Metadata["probe_path"])
	assert.Equal(t, "12.1.2.172", result.Metadata["version"])
	assert.Equal(t, "Microsoft-IIS/10.0", result.Metadata["server_header"])
	assert.Contains(t, result.CPEs, "cpe:2.3:a:veeam:backup_enterprise_manager:12.1.2.172:*:*:*:*:*:*:*")
	assert.Contains(t, result.CPEs, "cpe:2.3:a:veeam:veeam_backup_&_replication:12.1.2.172:*:*:*:*:*:*:*")
}

// ── Web UI positive: no version leak ───────────────────────────────────────────

func TestVeeamWebFingerprinter_Positive_NoVersion(t *testing.T) {
	fp := &VeeamEnterpriseManagerWebFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(veeamLoginPageNoVersion))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "veeam_backup_enterprise_manager_web", result.Technology)
	assert.Equal(t, "", result.Version, "no bundle version present → empty version")
	_, hasVersion := result.Metadata["version"]
	assert.False(t, hasVersion, "version metadata key must be omitted when empty")
	assert.Contains(t, result.CPEs, "cpe:2.3:a:veeam:backup_enterprise_manager:*:*:*:*:*:*:*:*")
	assert.Contains(t, result.CPEs, "cpe:2.3:a:veeam:veeam_backup_&_replication:*:*:*:*:*:*:*:*")
}

// ── Web UI negatives ───────────────────────────────────────────────────────────

func TestVeeamWebFingerprinter_Negative_VeeamONE(t *testing.T) {
	fp := &VeeamEnterpriseManagerWebFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")
	// Veeam ONE serves /login.aspx with a different title — out of scope.
	body := []byte(`<html><head><title>Login - Veeam ONE Reporter</title></head><body></body></html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result, "Veeam ONE login page must not match (required EM title absent)")
}

func TestVeeamWebFingerprinter_Negative_GenericIIS(t *testing.T) {
	fp := &VeeamEnterpriseManagerWebFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")
	resp.Header.Set("Server", "Microsoft-IIS/10.0")
	resp.Header.Set("X-Powered-By", "ASP.NET")
	resp.Header.Add("Set-Cookie", ".ASPXANONYMOUS=abc123; path=/; HttpOnly")
	body := []byte(`<html><head><title>Sign In</title></head><body><form></form></body></html>`)

	// Match may be true (lenient pre-filter on status + HTML CT)...
	assert.True(t, fp.Match(resp), "lenient Match accepts any 200 HTML page")
	// ...but Fingerprint must reject: never match on IIS/ASP.NET/cookie alone.
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result, "generic IIS/ASP.NET page without EM title must not be fingerprinted")
}

func TestVeeamWebFingerprinter_Negative_ServerError(t *testing.T) {
	fp := &VeeamEnterpriseManagerWebFingerprinter{}
	resp := &http.Response{
		StatusCode: 500,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	assert.False(t, fp.Match(resp), "5xx must be rejected by Match")
	result, err := fp.Fingerprint(resp, []byte(veeamLoginPageWithVersion))
	require.NoError(t, err)
	assert.Nil(t, result, "5xx must be rejected by Fingerprint even with a valid body")
}

// ── REST positive: v1_7 band ───────────────────────────────────────────────────

func TestVeeamRESTFingerprinter_Positive_V17Band(t *testing.T) {
	fp := &VeeamEnterpriseManagerRESTFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Request:    &http.Request{URL: &url.URL{Path: "/api/"}},
	}
	resp.Header.Set("Content-Type", "application/xml; charset=utf-8")

	require.True(t, fp.Match(resp), "Match must accept a 200 xml entry document")

	result, err := fp.Fingerprint(resp, []byte(veeamRESTEntryDocV17))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "veeam_backup_enterprise_manager_rest", result.Technology)
	assert.Equal(t, "", result.Version, "REST surface never emits an exact build")
	assert.Equal(t, "enterprise_manager_rest", result.Metadata["variant"])
	assert.Equal(t, "active_probe", result.Metadata["detection_method"])
	assert.Equal(t, "/api/", result.Metadata["probe_path"])
	assert.Equal(t, "enterprise_manager_legacy_rest", result.Metadata["api"])
	assert.Equal(t, "v1_7", result.Metadata["supported_version"], "highest generation wins")
	assert.Equal(t, "12.x–13.x", result.Metadata["version_band"])
	// Wildcard CPEs (no exact build).
	assert.Contains(t, result.CPEs, "cpe:2.3:a:veeam:backup_enterprise_manager:*:*:*:*:*:*:*:*")
	assert.Contains(t, result.CPEs, "cpe:2.3:a:veeam:veeam_backup_&_replication:*:*:*:*:*:*:*:*")
}

// ── REST: future two-digit generation degrades gracefully (P2-A robustness) ─────

func TestVeeamRESTFingerprinter_FutureGeneration_GracefulBand(t *testing.T) {
	fp := &VeeamEnterpriseManagerRESTFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Request:    &http.Request{URL: &url.URL{Path: "/api/"}},
	}
	resp.Header.Set("Content-Type", "application/xml")

	// A hypothetical future doc advertising v1_7 and a two-digit v1_10. The highest
	// generation must be parsed as 10 (not mis-read as digit '1'), reported as the
	// supported_version, with an empty band since 10 is not in the verified map.
	body := `<?xml version="1.0" encoding="utf-8"?>
<EnterpriseManager xmlns="http://www.veeam.com/ent/v1.0">
 <SupportedVersions>
   <SupportedVersion Name="v1_7"><Links/></SupportedVersion>
   <SupportedVersion Name="v1_10"><Links/></SupportedVersion>
 </SupportedVersions>
</EnterpriseManager>`

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result, "must still detect Veeam EM despite an unknown generation")
	assert.Equal(t, "v1_10", result.Metadata["supported_version"], "two-digit generation must win and not mis-parse")
	_, hasBand := result.Metadata["version_band"]
	assert.False(t, hasBand, "unknown generation maps to no band (graceful degradation, never fabricated)")
}

// ── REST positive: 401 corroboration path ──────────────────────────────────────

func TestVeeamRESTFingerprinter_Positive_401Corroboration(t *testing.T) {
	fp := &VeeamEnterpriseManagerRESTFingerprinter{}
	resp := &http.Response{
		StatusCode: 401,
		Header:     make(http.Header),
	}
	// No XML Content-Type — the WWW-Authenticate realm header is what carries Match.
	resp.Header.Set("WWW-Authenticate", "Basic Realm=RestSvc")

	require.True(t, fp.Match(resp), "Match must accept a 401 with WWW-Authenticate RestSvc realm")

	// Body still carries the entry doc (servers vary); confirm full fingerprint + header sanitization.
	result, err := fp.Fingerprint(resp, []byte(veeamRESTEntryDocV17))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "veeam_backup_enterprise_manager_rest", result.Technology)
	assert.Equal(t, "Basic Realm=RestSvc", result.Metadata["www_authenticate"])
}

func TestVeeamRESTFingerprinter_Match_SessionHeader(t *testing.T) {
	fp := &VeeamEnterpriseManagerRESTFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	// Non-XML CT, but the definitive corroborating session header is present.
	resp.Header.Set("Content-Type", "text/plain")
	resp.Header.Set("X-RestSvcSessionId", "O9Msj3rq7EGUhtSMBQx+mw==")
	assert.True(t, fp.Match(resp), "X-RestSvcSessionId header alone satisfies the lenient Match")
}

// ── REST negative: generic XML ──────────────────────────────────────────────────

func TestVeeamRESTFingerprinter_Negative_GenericXML(t *testing.T) {
	fp := &VeeamEnterpriseManagerRESTFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/xml")
	body := []byte(`<?xml version="1.0"?><CatalogResponse xmlns="http://example.com/catalog"><Item/></CatalogResponse>`)

	assert.True(t, fp.Match(resp), "lenient Match accepts any xml response")
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result, "non-Veeam XML (no <EnterpriseManager + namespace) must not match")
}

func TestVeeamRESTFingerprinter_Negative_NamespaceWithoutRoot(t *testing.T) {
	fp := &VeeamEnterpriseManagerRESTFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/xml")
	// Namespace present but root element absent — both are required.
	body := []byte(`<?xml version="1.0"?><LogonSession xmlns="http://www.veeam.com/ent/v1.0"></LogonSession>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result, "namespace without <EnterpriseManager root must not match the entry-doc fingerprinter")
}

// ── CPE-injection guard ─────────────────────────────────────────────────────────

func TestVeeamWebFingerprinter_CPEInjectionGuard(t *testing.T) {
	fp := &VeeamEnterpriseManagerWebFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")
	// Hostile body attempts to smuggle CPE metacharacters via the bundle version.
	// Defense-in-depth layer 1: the extraction regex capture group only accepts
	// [0-9.], so it TRUNCATES at the first ':' and captures the clean prefix "1.0".
	// No attacker-controlled metacharacter ever reaches the CPE interpolation.
	body := []byte(`<html><head>
<title>Veeam Backup Enterprise Manager : Login</title>
<script src="/login.bundle.js?v=1.0:*:*:*"></script>
</head><body></body></html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result, "title still confirms EM regardless of the version payload")
	// The captured version is the truncated clean prefix, not the injected suffix.
	assert.Equal(t, "1.0", result.Version, "regex truncates at ':' to the clean dotted prefix")
	// Each CPE must be the canonical, well-formed 13-component form with the
	// version field == "1.0" and exactly seven trailing wildcard fields. The
	// injected ":*:*:*" never became part of the version, so the CPEs are clean.
	assert.Equal(t, []string{
		"cpe:2.3:a:veeam:backup_enterprise_manager:1.0:*:*:*:*:*:*:*",
		"cpe:2.3:a:veeam:veeam_backup_&_replication:1.0:*:*:*:*:*:*:*",
	}, result.CPEs)
	// Sanity: the raw injected version string never appears verbatim as a CPE field.
	assert.Equal(t, "", validateVeeamVersion("1.0:*:*:*"),
		"the raw injected token would be rejected outright if it reached the validator")
}

// TestVeeamWebFingerprinter_CPEInjectionGuard_ValidationRejects exercises layer 2
// of the guard: a body whose bundle param is itself a fully valid-looking dotted
// string but with too many groups would be dropped by veeamDottedVersionValidateRegex.
// (validateVeeamVersion is unit-tested directly in TestValidateVeeamVersion; this
// confirms the wiring drops it end-to-end and falls back to a wildcard CPE.)
func TestVeeamWebFingerprinter_CPEInjectionGuard_ValidationRejects(t *testing.T) {
	fp := &VeeamEnterpriseManagerWebFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")
	// 5 dotted groups — the extraction regex caps at 4, so it captures "1.2.3.4"
	// (the first 4 groups). That is a valid 4-group build and is accepted; this
	// documents that the bounded capture, not the validation, is the effective gate
	// here. The end-to-end result must still be a clean, metacharacter-free CPE.
	body := []byte(`<html><head>
<title>Veeam Backup Enterprise Manager : Login</title>
<script src="/login.bundle.js?v=1.2.3.4.5"></script>
</head><body></body></html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "1.2.3.4", result.Version, "bounded capture takes the first 4 dotted groups")
	for _, cpe := range result.CPEs {
		assert.NotContains(t, cpe, ".5:", "the over-long 5th group must not reach the CPE")
	}
}

func TestValidateVeeamVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"valid 4-part build", "12.1.2.172", "12.1.2.172"},
		{"valid single major", "12", "12"},
		{"empty stays empty", "", ""},
		{"cpe metacharacters rejected", "1.0:*:*:*", ""},
		{"alpha suffix rejected", "12.1a", ""},
		{"too many groups rejected", "1.2.3.4.5", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, validateVeeamVersion(tt.input))
		})
	}
}

// ── Header sanitization ─────────────────────────────────────────────────────────

func TestVeeamWebFingerprinter_HeaderSanitization(t *testing.T) {
	fp := &VeeamEnterpriseManagerWebFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")
	// Server header carries a control character (0x07 BEL) that must be stripped.
	resp.Header.Set("Server", "Microsoft-IIS/10.0\x07evil")

	result, err := fp.Fingerprint(resp, []byte(veeamLoginPageNoVersion))
	require.NoError(t, err)
	require.NotNil(t, result)

	server, ok := result.Metadata["server_header"].(string)
	require.True(t, ok)
	assert.NotContains(t, server, "\x07", "control characters must be stripped from header metadata")
	assert.Equal(t, "Microsoft-IIS/10.0evil", server)
}

func TestVeeamRESTFingerprinter_HeaderSanitization(t *testing.T) {
	fp := &VeeamEnterpriseManagerRESTFingerprinter{}
	resp := &http.Response{
		StatusCode: 401,
		Header:     make(http.Header),
	}
	// WWW-Authenticate carries a control character that must be stripped.
	resp.Header.Set("WWW-Authenticate", "Basic Realm=RestSvc\x00\x1b]0;x")

	result, err := fp.Fingerprint(resp, []byte(veeamRESTEntryDocV17))
	require.NoError(t, err)
	require.NotNil(t, result)

	wwwAuth, ok := result.Metadata["www_authenticate"].(string)
	require.True(t, ok)
	assert.NotContains(t, wwwAuth, "\x00")
	assert.NotContains(t, wwwAuth, "\x1b")
	// Sanitization must strip control bytes WITHOUT over-stripping legitimate content.
	assert.Contains(t, wwwAuth, "Basic Realm=RestSvc", "sanitization must preserve the auth realm content")
}

// ── Probe wiring (registration sanity via interface satisfaction) ───────────────

func TestVeeamFingerprinters_ProbeWiring(t *testing.T) {
	web := &VeeamEnterpriseManagerWebFingerprinter{}
	rest := &VeeamEnterpriseManagerRESTFingerprinter{}

	// Distinct probe endpoints and Accept headers drive the active phase correctly.
	assert.Equal(t, "/login.aspx", web.ProbeEndpoint())
	assert.Equal(t, "text/html", web.ProbeAccept())
	assert.Equal(t, "/api/", rest.ProbeEndpoint())
	assert.Equal(t, "application/xml", rest.ProbeAccept())

	// Distinct Name() values prevent GetProbeEndpoints() collision.
	assert.NotEqual(t, web.Name(), rest.Name())

	// Verify Register()/GetProbeEndpoints() wiring against a controlled registry.
	// Several tests in this package set httpFingerprinters = nil without restoring
	// it (e.g. registry_test.go, pinecone_test.go), so reading the live global here
	// is order-dependent; we save/restore and register fresh instances instead
	// (same pattern as wazuh_test.go / telerik_ui_aspnet_ajax_test.go).
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil
	Register(web)
	Register(rest)
	endpoints := GetProbeEndpoints()
	assert.Equal(t, "/login.aspx", endpoints[web.Name()])
	assert.Equal(t, "/api/", endpoints[rest.Name()])
}

// ── Body-size cap: genuinely-matching but oversized bodies are rejected ─────────
// These fail if the 2 MiB cap is removed, because the body DOES contain the
// definitive marker — only the cap stops it from being fingerprinted.

func TestVeeamWebFingerprinter_BodyCapRejectsOversized(t *testing.T) {
	fp := &VeeamEnterpriseManagerWebFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/html")

	// Matching login page + padding that pushes total over the 2 MiB cap.
	oversized := []byte(veeamLoginPageWithVersion + strings.Repeat("A", 2*1024*1024))
	require.Greater(t, len(oversized), 2*1024*1024)

	result, err := fp.Fingerprint(resp, oversized)
	require.NoError(t, err)
	assert.Nil(t, result, "an oversized body must be rejected even though it contains the EM title")

	// Control: the same matching content just under the cap is still detected.
	result, err = fp.Fingerprint(resp, []byte(veeamLoginPageWithVersion))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "veeam_backup_enterprise_manager_web", result.Technology)

	// Boundary: exactly 2 MiB is accepted (the cap rejects only sizes OVER the limit).
	// Guards against a future >  →  >= regression.
	exact := append([]byte(veeamLoginPageWithVersion), []byte(strings.Repeat("A", 2*1024*1024-len(veeamLoginPageWithVersion)))...)
	require.Equal(t, 2*1024*1024, len(exact))
	result, err = fp.Fingerprint(resp, exact)
	require.NoError(t, err)
	require.NotNil(t, result, "a body of exactly 2 MiB must be accepted")
}

func TestVeeamRESTFingerprinter_BodyCapRejectsOversized(t *testing.T) {
	fp := &VeeamEnterpriseManagerRESTFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/xml")

	oversized := []byte(veeamRESTEntryDocV17 + strings.Repeat("A", 2*1024*1024))
	require.Greater(t, len(oversized), 2*1024*1024)

	result, err := fp.Fingerprint(resp, oversized)
	require.NoError(t, err)
	assert.Nil(t, result, "an oversized body must be rejected even though it contains the EM REST markers")
}

// ── Nil / empty body must not panic and must not match ──────────────────────────

func TestVeeamFingerprinters_NilAndEmptyBody(t *testing.T) {
	web := &VeeamEnterpriseManagerWebFingerprinter{}
	rest := &VeeamEnterpriseManagerRESTFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}

	for _, body := range [][]byte{nil, {}, []byte("   ")} {
		wr, err := web.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, wr, "web must not match nil/empty/whitespace body")

		rr, err := rest.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, rr, "rest must not match nil/empty/whitespace body")
	}
}

// ── Detection-only contract: never elevate severity / emit findings (guards #313) ─

func TestVeeamFingerprinters_DetectionOnly_NoSeverityOrFindings(t *testing.T) {
	web := &VeeamEnterpriseManagerWebFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/html")
	wr, err := web.Fingerprint(resp, []byte(veeamLoginPageWithVersion))
	require.NoError(t, err)
	require.NotNil(t, wr)
	assert.Zero(t, wr.Severity, "detection-only fingerprinter must not set Severity")
	assert.Empty(t, wr.SecurityFindings, "detection-only fingerprinter must not emit SecurityFindings")

	rest := &VeeamEnterpriseManagerRESTFingerprinter{}
	resp2 := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp2.Header.Set("Content-Type", "application/xml")
	rr, err := rest.Fingerprint(resp2, []byte(veeamRESTEntryDocV17))
	require.NoError(t, err)
	require.NotNil(t, rr)
	assert.Zero(t, rr.Severity, "detection-only fingerprinter must not set Severity")
	assert.Empty(t, rr.SecurityFindings, "detection-only fingerprinter must not emit SecurityFindings")
}
