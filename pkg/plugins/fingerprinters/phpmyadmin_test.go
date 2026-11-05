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

// ── Name / ProbeEndpoint / ProbeAccept ──────────────────────────────────────

func TestPhpMyAdminFingerprinter_Name(t *testing.T) {
	fp := &PhpMyAdminFingerprinter{}
	assert.Equal(t, "phpmyadmin", fp.Name())
}

func TestPhpMyAdminFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &PhpMyAdminFingerprinter{}
	assert.Equal(t, "/phpmyadmin/", fp.ProbeEndpoint())
}

func TestPhpMyAdminFingerprinter_ProbeAccept(t *testing.T) {
	fp := &PhpMyAdminFingerprinter{}
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

func TestPhpMyAdminPMAFingerprinter_Name(t *testing.T) {
	fp := &PhpMyAdminPMAFingerprinter{}
	assert.Equal(t, "phpmyadmin-pma", fp.Name())
}

func TestPhpMyAdminPMAFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &PhpMyAdminPMAFingerprinter{}
	assert.Equal(t, "/pma/", fp.ProbeEndpoint())
}

func TestPhpMyAdminPMAFingerprinter_ProbeAccept(t *testing.T) {
	fp := &PhpMyAdminPMAFingerprinter{}
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

func TestPhpMyAdminCasedFingerprinter_Name(t *testing.T) {
	fp := &PhpMyAdminCasedFingerprinter{}
	assert.Equal(t, "phpmyadmin-cased", fp.Name())
}

func TestPhpMyAdminCasedFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &PhpMyAdminCasedFingerprinter{}
	assert.Equal(t, "/phpMyAdmin/", fp.ProbeEndpoint())
}

func TestPhpMyAdminCasedFingerprinter_ProbeAccept(t *testing.T) {
	fp := &PhpMyAdminCasedFingerprinter{}
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

func TestPhpMyAdminSetupFingerprinter_Name(t *testing.T) {
	fp := &PhpMyAdminSetupFingerprinter{}
	assert.Equal(t, "phpmyadmin-setup", fp.Name())
}

func TestPhpMyAdminSetupFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &PhpMyAdminSetupFingerprinter{}
	assert.Equal(t, "/phpmyadmin/setup/", fp.ProbeEndpoint())
}

func TestPhpMyAdminSetupFingerprinter_ProbeAccept(t *testing.T) {
	fp := &PhpMyAdminSetupFingerprinter{}
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

// ── Match ────────────────────────────────────────────────────────────────────

func TestPhpMyAdminFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{name: "200 text/html → true", statusCode: 200, contentType: "text/html", want: true},
		{name: "200 text/html charset → true", statusCode: 200, contentType: "text/html; charset=utf-8", want: true},
		{name: "200 TEXT/HTML mixed case → true", statusCode: 200, contentType: "TEXT/HTML", want: true},
		{name: "401 text/html → true (auth-gated setup page)", statusCode: 401, contentType: "text/html", want: true},
		{name: "403 text/html → true", statusCode: 403, contentType: "text/html", want: true},
		{name: "404 text/html → true (some installs 404 on GET)", statusCode: 404, contentType: "text/html", want: true},
		{name: "499 text/html → true (upper bound inclusive)", statusCode: 499, contentType: "text/html", want: true},
		{name: "500 text/html → false (server error excluded)", statusCode: 500, contentType: "text/html", want: false},
		{name: "199 text/html → false (below lower bound)", statusCode: 199, contentType: "text/html", want: false},
		{name: "200 application/json → false", statusCode: 200, contentType: "application/json", want: false},
		{name: "200 text/plain → false", statusCode: 200, contentType: "text/plain", want: false},
		{name: "200 no content-type → false", statusCode: 200, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PhpMyAdminFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint ──────────────────────────────────────────────────────────────

const phpMyAdminLoginPage = `<!DOCTYPE html>
<html>
<head>
<title>phpMyAdmin</title>
<link rel="stylesheet" href="./phpmyadmin.css.php?nocache=abc123&amp;v=5.2.1" type="text/css">
</head>
<body>
<form method="post" id="login_form">
<input type="text" name="pma_username" id="input_username">
<input type="password" name="pma_password" id="input_password">
</form>
</body>
</html>`

const phpMyAdminSetupPage = `<!DOCTYPE html>
<html>
<head>
  <title>phpMyAdmin setup</title>
  <link rel="stylesheet" type="text/css" href="phpmyadmin.css.php?nocache=abc123&amp;v=5.2.1">
</head>
<body>
  <h1>
    <span class="blue">php</span><span class="orange">MyAdmin</span>
    setup
  </h1>
  <div id="page">
    <form id="setupForm" method="post" action="config.php">
      <input type="hidden" name="token" value="abc123">
    </form>
  </div>
</body>
</html>`

func TestPhpMyAdminFingerprinter_Fingerprint(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		cookies     []string
		wantNil     bool
		wantVersion string
		wantCPE     string
		wantMethod  string
		wantSource  string
	}{
		{
			name:        "title-based detection with version from asset URL",
			body:        phpMyAdminLoginPage,
			wantVersion: "5.2.1",
			wantCPE:     "cpe:2.3:a:phpmyadmin:phpmyadmin:5.2.1:*:*:*:*:*:*:*",
			wantMethod:  "title",
			wantSource:  "asset_url",
		},
		{
			name:        "title-based detection without version → wildcard CPE",
			body:        `<html><head><title>phpMyAdmin</title></head><body>no assets here</body></html>`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*",
			wantMethod:  "title",
		},
		{
			name: "cookie+form corroborated detection (no title)",
			body: `<html><head></head><body>
<form method="post"><input type="text" name="pma_username"></form>
</body></html>`,
			cookies:     []string{"phpMyAdmin=abc123; path=/"},
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*",
			wantMethod:  "cookie_form",
		},
		{
			name:    "cookie without form field → no detection",
			body:    `<html><head></head><body>generic page</body></html>`,
			cookies: []string{"phpMyAdmin=abc123; path=/"},
			wantNil: true,
		},
		{
			name:    "form field without cookie → no detection",
			body:    `<html><body><form><input type="text" name="pma_username"></form></body></html>`,
			wantNil: true,
		},
		{
			name:        "setup page title match with asset URL version extraction",
			body:        phpMyAdminSetupPage,
			wantVersion: "5.2.1",
			wantCPE:     "cpe:2.3:a:phpmyadmin:phpmyadmin:5.2.1:*:*:*:*:*:*:*",
			wantMethod:  "title",
			wantSource:  "asset_url",
		},
		{
			name:        "setup page title match with no cookie or form field present",
			body:        `<html><head><title>phpMyAdmin setup</title></head><body>no assets here</body></html>`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*",
			wantMethod:  "title",
		},
		{
			name: "asset URL version extraction via get_scripts.js.php",
			body: `<html><head><title>phpMyAdmin</title>
<link rel="stylesheet" href="get_scripts.js.php?v=5.1.0">
</head><body></body></html>`,
			wantVersion: "5.1.0",
			wantCPE:     "cpe:2.3:a:phpmyadmin:phpmyadmin:5.1.0:*:*:*:*:*:*:*",
			wantMethod:  "title",
			wantSource:  "asset_url",
		},
		{
			name: "4-component version from asset URL",
			body: `<html><head><title>phpMyAdmin</title>
<link rel="stylesheet" href="phpmyadmin.css.php?v=4.9.0.1">
</head><body></body></html>`,
			wantVersion: "4.9.0.1",
			wantCPE:     "cpe:2.3:a:phpmyadmin:phpmyadmin:4.9.0.1:*:*:*:*:*:*:*",
			wantMethod:  "title",
			wantSource:  "asset_url",
		},
		{
			name: "asset URL in unquoted HTML attribute terminated by >",
			body: `<html><head><title>phpMyAdmin</title>
<link rel=stylesheet href=phpmyadmin.css.php?v=5.2.1>
</head><body></body></html>`,
			wantVersion: "5.2.1",
			wantCPE:     "cpe:2.3:a:phpmyadmin:phpmyadmin:5.2.1:*:*:*:*:*:*:*",
			wantMethod:  "title",
			wantSource:  "asset_url",
		},
		{
			name:        "5-component version rejected",
			body:        `<html><head><title>phpMyAdmin</title><link href="messages.php?v=4.9.0.1.2"></head><body></body></html>`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*",
			wantMethod:  "title",
		},
		{
			name:        "version validation rejects invalid format",
			body:        `<html><head><title>phpMyAdmin</title><link href="messages.php?v=notaversion"></head><body></body></html>`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*",
			wantMethod:  "title",
		},
		{
			name:        "asset version param ordering: rev= before v= extracts v, not rev",
			body:        `<html><head><title>phpMyAdmin</title><link href="phpmyadmin.css.php?rev=1.0&amp;v=5.2.1"></head><body></body></html>`,
			wantVersion: "5.2.1",
			wantCPE:     "cpe:2.3:a:phpmyadmin:phpmyadmin:5.2.1:*:*:*:*:*:*:*",
			wantMethod:  "title",
			wantSource:  "asset_url",
		},
		{
			name:        "asset version rejects trailing non-numeric suffix",
			body:        `<html><head><title>phpMyAdmin</title><link href="messages.php?v=5.38abc"></head><body></body></html>`,
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*",
			wantMethod:  "title",
		},
		{
			name: "both signals true: title takes priority over cookie_form",
			body: `<html><head><title>phpMyAdmin</title></head><body>
<form method="post"><input type="text" name="pma_username"></form>
</body></html>`,
			cookies:     []string{"phpMyAdmin=abc123; path=/"},
			wantVersion: "",
			wantCPE:     "cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*",
			wantMethod:  "title",
		},
		{
			name:    "non-phpMyAdmin HTML → no detection",
			body:    `<html><head><title>Apache2 Debian Default Page</title></head><body>It works!</body></html>`,
			wantNil: true,
		},
		{
			name: "generic page with ?v= params but no PMA markers → no detection",
			body: `<html><head><title>My App</title>
<link rel="stylesheet" href="app.css.php?v=5.2.1"></head><body></body></html>`,
			wantNil: true,
		},
		{
			name:    "empty body → no detection",
			body:    "",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html")
			for _, c := range tt.cookies {
				resp.Header.Add("Set-Cookie", c)
			}

			result, err := fingerprintPhpMyAdmin(resp, []byte(tt.body))
			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, "phpmyadmin", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.wantCPE)
			assert.Equal(t, tt.wantMethod, result.Metadata["detection_method"])
			assert.Equal(t, "phpMyAdmin", result.Metadata["vendor"])
			assert.Equal(t, "phpMyAdmin", result.Metadata["product"])
			if tt.wantSource != "" {
				assert.Equal(t, tt.wantSource, result.Metadata["version_source"])
			} else {
				assert.NotContains(t, result.Metadata, "version_source")
			}
		})
	}
}

// TestPhpMyAdminFingerprinter_Fingerprint_CPEMetacharacterGuard verifies that
// version-like text embedding CPE metacharacters (":", "*", "?") immediately
// after the asset URL's v= parameter never produces a non-empty Version: the
// extraction regexes only capture \d+\.\d+(?:\.\d+)?, so the metacharacter
// breaks the match at the digit/dot boundary and no version is extracted.
// This exercises the real fingerprintPhpMyAdmin path end-to-end; the explicit
// strings.ContainsAny guard in extractPhpMyAdminVersion is defense-in-depth
// for this same invariant.
func TestPhpMyAdminFingerprinter_Fingerprint_CPEMetacharacterGuard(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "colon after v=",
			body: `<html><head><title>phpMyAdmin</title><link href="messages.php?v=5:2.1"></head><body></body></html>`,
		},
		{
			name: "asterisk after v=",
			body: `<html><head><title>phpMyAdmin</title><link href="messages.php?v=*5.2.1"></head><body></body></html>`,
		},
		{
			name: "question mark after v=",
			body: `<html><head><title>phpMyAdmin</title><link href="messages.php?v=?5.2.1"></head><body></body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html")

			result, err := fingerprintPhpMyAdmin(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, "", result.Version)
			assert.Contains(t, result.CPEs, "cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*")
			assert.NotContains(t, result.Metadata, "version_source")
		})
	}
}

func TestPhpMyAdminFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &PhpMyAdminFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	bigBody := []byte(strings.Repeat("x", 1*1024*1024+1))
	result, err := fp.Fingerprint(resp, bigBody)
	assert.Nil(t, result)
	assert.NoError(t, err)
}

// ── buildPhpMyAdminCPE ───────────────────────────────────────────────────────

func TestBuildPhpMyAdminCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{name: "with version", version: "5.2.1", expected: "cpe:2.3:a:phpmyadmin:phpmyadmin:5.2.1:*:*:*:*:*:*:*"},
		{name: "empty version → wildcard", version: "", expected: "cpe:2.3:a:phpmyadmin:phpmyadmin:*:*:*:*:*:*:*:*"},
		{name: "two-component version", version: "5.2", expected: "cpe:2.3:a:phpmyadmin:phpmyadmin:5.2:*:*:*:*:*:*:*"},
		{name: "four-component version", version: "4.9.0.1", expected: "cpe:2.3:a:phpmyadmin:phpmyadmin:4.9.0.1:*:*:*:*:*:*:*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildPhpMyAdminCPE(tt.version))
		})
	}
}

// ── Integration: Match + Fingerprint ─────────────────────────────────────────

func TestPhpMyAdminFingerprinter_Integration(t *testing.T) {
	fp := &PhpMyAdminFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(phpMyAdminLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "phpmyadmin", result.Technology)
	assert.Equal(t, "5.2.1", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:phpmyadmin:phpmyadmin:5.2.1:*:*:*:*:*:*:*")
}

func TestPhpMyAdminSetupFingerprinter_Integration(t *testing.T) {
	fp := &PhpMyAdminSetupFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(phpMyAdminSetupPage))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "phpmyadmin", result.Technology)
	assert.Equal(t, "5.2.1", result.Version)
	assert.Equal(t, "title", result.Metadata["detection_method"])
	assert.Equal(t, "asset_url", result.Metadata["version_source"])
}

func TestPhpMyAdminFingerprinter_Integration_NonPhpMyAdmin(t *testing.T) {
	fp := &PhpMyAdminFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(`<html><body>Hello</body></html>`))
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ── Severity / SecurityFindings ──────────────────────────────────────────────

func TestPhpMyAdminFingerprinter_NoSeverityOrFindings(t *testing.T) {
	fp := &PhpMyAdminFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(phpMyAdminLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "fingerprinter-only: Severity must be unset")
	assert.Nil(t, result.SecurityFindings, "fingerprinter-only: no SecurityFindings")
}

// ── All four fingerprinters registered ──────────────────────────────────────

func TestPhpMyAdminFingerprinters_Registered(t *testing.T) {
	names := map[string]bool{
		"phpmyadmin":       false,
		"phpmyadmin-pma":   false,
		"phpmyadmin-cased": false,
		"phpmyadmin-setup": false,
	}
	for _, fp := range GetFingerprinters() {
		if _, ok := names[fp.Name()]; ok {
			names[fp.Name()] = true
		}
	}
	for name, found := range names {
		assert.True(t, found, "fingerprinter %q not registered", name)
	}
}
