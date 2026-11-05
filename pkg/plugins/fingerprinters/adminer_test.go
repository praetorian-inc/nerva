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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Fixtures ─────────────────────────────────────────────────────────────────────

// Standard Adminer login page with version span.
const adminerLoginHTML = `<!DOCTYPE html>
<html>
<head><title>Login - Adminer</title></head>
<body>
<div id="version">
<a href="https://www.adminer.org">Adminer</a>
<span class="version">4.8.1</span>
</div>
<form>
<table>
<tr><th>System<td><select name="auth[driver]"><option value="server">MySQL</option></select>
<tr><th>Server<td><input name="auth[server]">
</table>
</form>
</body>
</html>`

// Adminer login page without a version span.
const adminerLoginNoVersionHTML = `<!DOCTYPE html>
<html>
<head><title>Login - Adminer</title></head>
<body>
<form>
<table>
<tr><th>System<td><select name="auth[driver]"><option value="server">MySQL</option></select>
</table>
</form>
</body>
</html>`

// AdminerEvo fork login page.
const adminerEvoLoginHTML = `<!DOCTYPE html>
<html>
<head><title>Login - AdminerEvo</title></head>
<body>
<div id="version">
<a href="https://adminerevo.org">AdminerEvo</a>
<span class="version">5.1.0</span>
</div>
<form>
<table>
<tr><th>System<td><select name="auth[driver]"></select>
</table>
</form>
</body>
</html>`

// Adminer Editor login page.
const adminerEditorLoginHTML = `<!DOCTYPE html>
<html>
<head><title>Login - Editor</title></head>
<body>
<div id="version">
<a href="https://www.adminer.org/editor/">Adminer Editor</a>
<span class="version">4.8.1</span>
</div>
<form>
<table>
<tr><th>System<td><select name="auth[driver]"></select>
</table>
</form>
</body>
</html>`

// Title tag with extra whitespace/attributes — must still match Signal 1.
const adminerTitleWhitespaceHTML = `<!DOCTYPE html>
<html>
<head><title lang="en">   Login   -   Adminer   </title></head>
<body></body>
</html>`

// Corroborated pair present but no title match (e.g. reverse-proxy rewrites the title).
const adminerCorroboratedOnlyHTML = `<!DOCTYPE html>
<html>
<head><title>Database Login</title></head>
<body>
<form>
<table>
<tr><th>System<td><select name="auth[driver]"><option value="server">MySQL</option></select>
</table>
</form>
</body>
</html>`

// Only the System<td> marker present, no auth[driver] — must NOT match (half-signal).
const adminerSystemOnlyHTML = `<!DOCTYPE html>
<html>
<head><title>Database Login</title></head>
<body>
<table>
<tr><th>System<td><span>MySQL</span>
</table>
</body>
</html>`

// Only the auth[driver] marker present, no System<td> — must NOT match (half-signal).
const adminerAuthDriverOnlyHTML = `<!DOCTYPE html>
<html>
<head><title>Database Login</title></head>
<body>
<form><select name="auth[driver]"></select></form>
</body>
</html>`

// A generic non-Adminer HTML login page — must NOT match (false-positive guard).
const genericLoginHTML = `<!DOCTYPE html>
<html>
<head><title>Login - Acme Portal</title></head>
<body><form><input name="username"><input name="password"></form></body>
</html>`

func newAdminerResp(status int, contentType string) *http.Response {
	h := http.Header{}
	if contentType != "" {
		h.Set("Content-Type", contentType)
	}
	return &http.Response{StatusCode: status, Header: h}
}

// ── AdminerFingerprinter: identity / wiring ─────────────────────────────────────

func TestAdminerFingerprinter_Identity(t *testing.T) {
	fp := &AdminerFingerprinter{}
	assert.Equal(t, "adminer", fp.Name())
	assert.Equal(t, "/adminer.php", fp.ProbeEndpoint())
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

// ── AdminerDirFingerprinter: identity / wiring ──────────────────────────────────

func TestAdminerDirFingerprinter_Identity(t *testing.T) {
	fp := &AdminerDirFingerprinter{}
	assert.Equal(t, "adminer_dir", fp.Name())
	assert.Equal(t, "/adminer/", fp.ProbeEndpoint())
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

// ── Match (shared matchAdminer) ─────────────────────────────────────────────────

func TestAdminerFingerprinter_Match(t *testing.T) {
	fp := &AdminerFingerprinter{}
	tests := []struct {
		name        string
		status      int
		contentType string
		want        bool
	}{
		{"200 html", 200, "text/html; charset=utf-8", true},
		{"200 json", 200, "application/json", false},
		{"404 html", 404, "text/html", true},
		{"499 html", 499, "text/html", true},
		{"500 html rejected", 500, "text/html", false},
		{"100 informational rejected", 100, "text/html", false},
		{"200 no content-type", 200, "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, fp.Match(newAdminerResp(tt.status, tt.contentType)))
		})
	}
}

func TestAdminerDirFingerprinter_Match(t *testing.T) {
	fp := &AdminerDirFingerprinter{}
	tests := []struct {
		name        string
		status      int
		contentType string
		want        bool
	}{
		{"200 html", 200, "text/html; charset=utf-8", true},
		{"200 json", 200, "application/json", false},
		{"500 html rejected", 500, "text/html", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, fp.Match(newAdminerResp(tt.status, tt.contentType)))
		})
	}
}

// ── Fingerprint: positive detection ─────────────────────────────────────────────

func TestAdminerFingerprinter_Fingerprint_TitleMatchWithVersion(t *testing.T) {
	fp := &AdminerFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(adminerLoginHTML))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "adminer", result.Technology)
	assert.Equal(t, "4.8.1", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:adminer:adminer:4.8.1:*:*:*:*:*:*:*")
	assert.Equal(t, "adminer", result.Metadata["variant"])
	assert.Equal(t, "title_match+corroborated_pair", result.Metadata["detection_method"])
	assert.Empty(t, result.Severity)
	assert.Empty(t, result.SecurityFindings)
}

func TestAdminerFingerprinter_Fingerprint_TitleMatchNoVersion(t *testing.T) {
	fp := &AdminerFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(adminerLoginNoVersionHTML))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "adminer", result.Technology)
	assert.Equal(t, "", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:adminer:adminer:*:*:*:*:*:*:*:*")
}

func TestAdminerFingerprinter_Fingerprint_AdminerEvoVariant(t *testing.T) {
	fp := &AdminerFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(adminerEvoLoginHTML))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "adminerevo", result.Metadata["variant"])
	assert.Equal(t, "5.1.0", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:adminerevo:adminerevo:5.1.0:*:*:*:*:*:*:*")
}

func TestAdminerFingerprinter_Fingerprint_EditorVariant(t *testing.T) {
	fp := &AdminerFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(adminerEditorLoginHTML))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "editor", result.Metadata["variant"])
	assert.Contains(t, result.CPEs, "cpe:2.3:a:adminer:adminer:4.8.1:*:*:*:*:*:*:*")
}

func TestAdminerFingerprinter_Fingerprint_TitleWithWhitespaceAndAttributes(t *testing.T) {
	fp := &AdminerFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(adminerTitleWhitespaceHTML))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "adminer", result.Technology)
	assert.Equal(t, "title_match", result.Metadata["detection_method"])
}

func TestAdminerFingerprinter_Fingerprint_CorroboratedPairOnly(t *testing.T) {
	fp := &AdminerFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(adminerCorroboratedOnlyHTML))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "adminer", result.Technology)
	assert.Equal(t, "corroborated_pair", result.Metadata["detection_method"])
}

// ── Fingerprint: negative / false-positive prevention ───────────────────────────

func TestAdminerFingerprinter_Fingerprint_HalfSignalsRejected(t *testing.T) {
	fp := &AdminerFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	for _, body := range []string{adminerSystemOnlyHTML, adminerAuthDriverOnlyHTML} {
		result, err := fp.Fingerprint(resp, []byte(body))
		require.NoError(t, err)
		assert.Nil(t, result)
	}
}

func TestAdminerFingerprinter_Fingerprint_GenericLoginRejected(t *testing.T) {
	fp := &AdminerFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(genericLoginHTML))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestAdminerFingerprinter_Fingerprint_EmptyBody(t *testing.T) {
	fp := &AdminerFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	for _, body := range [][]byte{nil, {}, []byte("   ")} {
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		assert.Nil(t, result)
	}
}

func TestAdminerFingerprinter_Fingerprint_StatusGate(t *testing.T) {
	fp := &AdminerFingerprinter{}

	result, err := fp.Fingerprint(newAdminerResp(500, "text/html"), []byte(adminerLoginHTML))
	require.NoError(t, err)
	assert.Nil(t, result)

	result, err = fp.Fingerprint(newAdminerResp(100, "text/html"), []byte(adminerLoginHTML))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestAdminerFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &AdminerFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	// Oversized (> 1 MiB cap) → nil.
	oversized := append([]byte(adminerLoginHTML), make([]byte, 1024*1024)...)
	result, err := fp.Fingerprint(resp, oversized)
	require.NoError(t, err)
	assert.Nil(t, result)

	// Exactly at the 1 MiB cap → accepted (guards against a >→>= regression).
	exact := append([]byte(adminerLoginHTML), []byte(strings.Repeat(" ", 1024*1024-len(adminerLoginHTML)))...)
	require.Equal(t, 1024*1024, len(exact))
	result, err = fp.Fingerprint(resp, exact)
	require.NoError(t, err)
	require.NotNil(t, result, "a body of exactly 1 MiB must be accepted")
}

// ── AdminerDirFingerprinter: shares the same detection logic ───────────────────

func TestAdminerDirFingerprinter_Fingerprint_TitleMatchWithVersion(t *testing.T) {
	fp := &AdminerDirFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(adminerLoginHTML))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "adminer", result.Technology)
	assert.Equal(t, "4.8.1", result.Version)
}

func TestAdminerDirFingerprinter_Fingerprint_GenericLoginRejected(t *testing.T) {
	fp := &AdminerDirFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(genericLoginHTML))
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ── AdminerRootFingerprinter: identity / wiring ─────────────────────────────────

func TestAdminerRootFingerprinter_Identity(t *testing.T) {
	fp := &AdminerRootFingerprinter{}
	assert.Equal(t, "adminer_root", fp.Name())
}

// Compile-time assertion: AdminerRootFingerprinter must implement
// HTTPFingerprinter. If this line stops compiling, the type's method set
// no longer satisfies the interface the registry requires.
var _ HTTPFingerprinter = (*AdminerRootFingerprinter)(nil)

// TestAdminerRootFingerprinter_MustStayPassive is the most important test in
// this file. AdminerRootFingerprinter must implement HTTPFingerprinter but
// must NOT implement ActiveHTTPFingerprinter. The engine's passive pass
// (RunFingerprinters) skips any ActiveHTTPFingerprinter whose ProbeEndpoint
// is neither "" nor "/" -- that's exactly why the two pre-existing active
// fingerprinters (/adminer.php and /adminer/) can never see Adminer served
// at the web root. If a future edit adds a ProbeEndpoint() method to
// AdminerRootFingerprinter, it would silently start being skipped by that
// same passive pass, and Adminer served at "/" would go undetected again --
// with every other test in this file still green, since none of them probe
// this specific invariant.
func TestAdminerRootFingerprinter_MustStayPassive(t *testing.T) {
	_, isActive := any(&AdminerRootFingerprinter{}).(ActiveHTTPFingerprinter)
	assert.False(t, isActive,
		"AdminerRootFingerprinter must not implement ActiveHTTPFingerprinter: "+
			"adding a ProbeEndpoint() method would make the engine's passive pass "+
			"(RunFingerprinters) skip it, since that pass skips any ActiveHTTPFingerprinter "+
			"whose ProbeEndpoint is neither \"\" nor \"/\" -- silently reintroducing the bug "+
			"where Adminer served at the web root is never detected")
}

func TestAdminerRootFingerprinter_NotInProbeEndpoints(t *testing.T) {
	saved := httpFingerprinters
	httpFingerprinters = nil
	defer func() { httpFingerprinters = saved }()

	Register(&AdminerRootFingerprinter{})

	endpoints := GetProbeEndpoints()
	_, ok := endpoints["adminer_root"]
	assert.False(t, ok, "adminer_root must not appear in GetProbeEndpoints(); it is passive by design and declares no probe endpoint")
}

// ── AdminerRootFingerprinter: detection ─────────────────────────────────────────

func TestAdminerRootFingerprinter_Fingerprint_TitleMatchWithVersion(t *testing.T) {
	fp := &AdminerRootFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(adminerLoginHTML))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "adminer", result.Technology)
	assert.Equal(t, "4.8.1", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:adminer:adminer:4.8.1:*:*:*:*:*:*:*")
}

func TestAdminerRootFingerprinter_Fingerprint_GenericLoginRejected(t *testing.T) {
	fp := &AdminerRootFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(genericLoginHTML))
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ── Version extraction ──────────────────────────────────────────────────────────

func TestExtractAdminerVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{"standard version", `<span class="version">4.8.1</span>`, "4.8.1"},
		{"pre-release suffix", `<span class="version">4.8.1-beta</span>`, "4.8.1-beta"},
		{"two-component rejected (no patch)", `<span class="version">4.8</span>`, ""},
		{"non-numeric suffix without hyphen rejected", `<span class="version">4.8.1abc</span>`, ""},
		{"missing span", `<div>no version here</div>`, ""},
		{"empty body", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractAdminerVersion([]byte(tt.body)))
		})
	}
}

func TestExtractAdminerVersion_CPEInjectionGuard(t *testing.T) {
	// The extraction regex's capture class ([0-9]+\.[0-9]+\.[0-9]+(?:-[a-z]+)?) cannot
	// itself capture CPE metacharacters, but the guard is exercised here as
	// defense-in-depth in case the regex is ever loosened.
	malicious := []string{
		`<span class="version">4.8.1:*:*:root</span>`,
		`<span class="version">*</span>`,
	}
	for _, body := range malicious {
		got := extractAdminerVersion([]byte(body))
		assert.NotContains(t, got, ":")
		assert.NotContains(t, got, "*")
		assert.NotContains(t, got, "?")
	}
}

// ── CPE builder ──────────────────────────────────────────────────────────────────

func TestBuildAdminerCPE(t *testing.T) {
	assert.Equal(t, "cpe:2.3:a:adminer:adminer:4.8.1:*:*:*:*:*:*:*", buildAdminerCPE("4.8.1", "adminer"))
	assert.Equal(t, "cpe:2.3:a:adminer:adminer:*:*:*:*:*:*:*:*", buildAdminerCPE("", "adminer"))
	assert.Equal(t, "cpe:2.3:a:adminerevo:adminerevo:5.1.0:*:*:*:*:*:*:*", buildAdminerCPE("5.1.0", "adminerevo"))
	assert.Equal(t, "cpe:2.3:a:adminerevo:adminerevo:*:*:*:*:*:*:*:*", buildAdminerCPE("", "adminerevo"))
	assert.Equal(t, "cpe:2.3:a:adminer:adminer:4.8.1:*:*:*:*:*:*:*", buildAdminerCPE("4.8.1", "editor"))
}

// ── Variant detection ────────────────────────────────────────────────────────────

func TestDetectAdminerVariant(t *testing.T) {
	tests := []struct {
		name         string
		body         string
		titleVariant string
		want         string
	}{
		{"adminerevo domain", `<a href="https://adminerevo.org">AdminerEvo</a>`, "AdminerEvo", "adminerevo"},
		{"editor path", `<a href="https://www.adminer.org/editor/">Editor</a>`, "", "editor"},
		{"editor title without path", ``, "Editor", "editor"},
		{"editor title case-insensitive", ``, "editor", "editor"},
		{"adminerevo title without domain", ``, "AdminerEvo", "adminerevo"},
		{"default adminer", `<a href="https://www.adminer.org">Adminer</a>`, "Adminer", "adminer"},
		{"no markers at all", ``, "", "adminer"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, detectAdminerVariant([]byte(tt.body), tt.titleVariant))
		})
	}
}

// ── Integration test ───────────────────────────────────────────────────────────

func TestAdminerFingerprinter_Integration(t *testing.T) {
	saved := httpFingerprinters
	httpFingerprinters = nil
	defer func() { httpFingerprinters = saved }()

	Register(&AdminerFingerprinter{})
	Register(&AdminerDirFingerprinter{})

	resp := newAdminerResp(200, "text/html")
	body := []byte(adminerLoginHTML)

	// AdminerFingerprinter and AdminerDirFingerprinter are ActiveHTTPFingerprinters
	// with dedicated non-"/" probe endpoints, so RunFingerprinters (the passive
	// phase) intentionally skips them; they run in the engine's active phase
	// against their specific ProbeEndpoint() response instead. Exercise that
	// active-phase flow directly via Match + Fingerprint.
	fp := GetFingerprinterByName("adminer")
	require.NotNil(t, fp)
	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "adminer", result.Technology)
	assert.Equal(t, "4.8.1", result.Version)

	dirFp := GetFingerprinterByName("adminer_dir")
	require.NotNil(t, dirFp)
	require.True(t, dirFp.Match(resp))

	dirResult, err := dirFp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, dirResult)
	assert.Equal(t, "adminer", dirResult.Technology)

	endpoints := GetProbeEndpoints()
	assert.Equal(t, "/adminer.php", endpoints["adminer"])
	assert.Equal(t, "/adminer/", endpoints["adminer_dir"])
}

// ── Registration / contract (order-independent) ─────────────────────────────────

func TestAdminerFingerprinters_Registered(t *testing.T) {
	saved := httpFingerprinters
	defer func() { httpFingerprinters = saved }()

	httpFingerprinters = nil
	Register(&AdminerFingerprinter{})
	Register(&AdminerDirFingerprinter{})
	Register(&AdminerRootFingerprinter{})

	assert.NotNil(t, GetFingerprinterByName("adminer"))
	assert.NotNil(t, GetFingerprinterByName("adminer_dir"))
	assert.NotNil(t, GetFingerprinterByName("adminer_root"))

	endpoints := GetProbeEndpoints()
	assert.Equal(t, "/adminer.php", endpoints["adminer"])
	assert.Equal(t, "/adminer/", endpoints["adminer_dir"])
	_, hasRoot := endpoints["adminer_root"]
	assert.False(t, hasRoot, "adminer_root must not appear in GetProbeEndpoints(); it is passive by design")
}

// ── Severity / SecurityFindings: pure fingerprinter, never sets either ─────────

func TestAdminerFingerprinter_NeverSetsSeverityOrFindings(t *testing.T) {
	fp := &AdminerFingerprinter{}
	dirFp := &AdminerDirFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	for _, body := range []string{adminerLoginHTML, adminerEvoLoginHTML, adminerEditorLoginHTML, adminerCorroboratedOnlyHTML} {
		result, err := fp.Fingerprint(resp, []byte(body))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Empty(t, result.Severity)
		assert.Empty(t, result.SecurityFindings)

		dirResult, err := dirFp.Fingerprint(resp, []byte(body))
		require.NoError(t, err)
		require.NotNil(t, dirResult)
		assert.Empty(t, dirResult.Severity)
		assert.Empty(t, dirResult.SecurityFindings)
	}
}

// ── False-positive prevention: standalone "Login - Editor" without Adminer markers ─

// A generic non-Adminer app with title "Login - Editor" — must NOT match
// because "Editor" alone is too generic without corroborating Adminer markers.
const editorTitleOnlyHTML = `<!DOCTYPE html>
<html>
<head><title>Login - Editor</title></head>
<body><form><input name="username"><input name="password"><button>Login</button></form></body>
</html>`

func TestAdminerFingerprinter_Fingerprint_EditorTitleAloneRejected(t *testing.T) {
	fp := &AdminerFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(editorTitleOnlyHTML))
	require.NoError(t, err)
	assert.Nil(t, result, "standalone 'Login - Editor' without Adminer markers must not match")
}

// Adminer Editor with corroboration — must still match.
func TestAdminerFingerprinter_Fingerprint_EditorWithCorroborationAccepted(t *testing.T) {
	fp := &AdminerFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(adminerEditorLoginHTML))
	require.NoError(t, err)
	require.NotNil(t, result, "Editor title with corroborated pair must match")
	assert.Equal(t, "editor", result.Metadata["variant"])
	assert.Equal(t, "title_match+corroborated_pair", result.Metadata["detection_method"])
}

// ── Single-quote auth[driver] variant (regression guard for Docker-discovered bug) ─

// Corroborated pair with single-quoted auth[driver] attribute (seen in Adminer 4.8.1 Docker).
const adminerCorroboratedSingleQuoteHTML = `<!DOCTYPE html>
<html>
<head><title>Database Login</title></head>
<body>
<form>
<table>
<tr><th>System<td><select name='auth[driver]'><option value="server">MySQL</option></select>
</table>
</form>
</body>
</html>`

func TestAdminerFingerprinter_Fingerprint_CorroboratedPairSingleQuote(t *testing.T) {
	fp := &AdminerFingerprinter{}
	resp := newAdminerResp(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(adminerCorroboratedSingleQuoteHTML))
	require.NoError(t, err)
	require.NotNil(t, result, "single-quoted auth[driver] must trigger corroborated pair detection")
	assert.Equal(t, "adminer", result.Technology)
	assert.Equal(t, "corroborated_pair", result.Metadata["detection_method"])
}
