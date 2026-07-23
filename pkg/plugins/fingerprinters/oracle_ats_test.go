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

// realisticOLTLoginPage is a representative Oracle Load Testing login page
// that exercises all four detection signals.
const realisticOLTLoginPage = `<html><head><title>Oracle Load Testing</title></head><body>
<h2>Oracle Application Testing Suite</h2>
<form method="POST" action="/olt/LoginSubmit.do">
<input type="text" name="username"/>
<input type="password" name="password"/>
<input type="submit" value="Login"/>
</form>
<p>Version 13.3.0.1</p>
<a href="/otm">Oracle Test Manager</a>
</body></html>`

// ── Name / ProbeEndpoint / ProbeAccept ───────────────────────────────────────

func TestOracleATSFingerprinter_Name(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	assert.Equal(t, "oracle_ats", fp.Name())
}

func TestOracleATSFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	assert.Equal(t, "/olt", fp.ProbeEndpoint())
}

func TestOracleATSFingerprinter_ProbeAccept(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestOracleATSFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 text/html → true",
			statusCode:  200,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "200 TEXT/HTML mixed case → true",
			statusCode:  200,
			contentType: "TEXT/HTML",
			want:        true,
		},
		{
			name:        "200 text/html charset → true",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "302 text/html → true (login redirects are valid)",
			statusCode:  302,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "200 application/json → false",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "500 text/html → false",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
		{
			name:       "200 no content-type → false",
			statusCode: 200,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OracleATSFingerprinter{}
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

// ── Fingerprint — individual signals ─────────────────────────────────────────

func TestOracleATSFingerprinter_Fingerprint_OLTLoginAction(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	resp := makeOATSResponse(200, "text/html")

	body := `<form method="POST" action="/olt/LoginSubmit.do"><input type="submit"/></form>`
	result, err := fp.Fingerprint(resp, []byte(body))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "oracle_ats", result.Technology)
	assert.Contains(t, result.Metadata["detected_signals"], "olt_login_action")
}

func TestOracleATSFingerprinter_Fingerprint_OLTBranding(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	resp := makeOATSResponse(200, "text/html")

	body := `<html><body><h1>Oracle Load Testing</h1></body></html>`
	result, err := fp.Fingerprint(resp, []byte(body))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.Metadata["detected_signals"], "olt_branding")
}

func TestOracleATSFingerprinter_Fingerprint_OATSBranding(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	resp := makeOATSResponse(200, "text/html")

	body := `<html><body><h2>Oracle Application Testing Suite</h2></body></html>`
	result, err := fp.Fingerprint(resp, []byte(body))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.Metadata["detected_signals"], "oats_branding")
}

func TestOracleATSFingerprinter_Fingerprint_OTMReference(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	resp := makeOATSResponse(200, "text/html")

	body := `<html><body><a href="/otm">Test Manager</a></body></html>`
	result, err := fp.Fingerprint(resp, []byte(body))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.Metadata["detected_signals"], "otm_reference")

	components, ok := result.Metadata["components"].([]string)
	require.True(t, ok, "components should be []string")
	assert.Contains(t, components, "Oracle Test Manager")
}

func TestOracleATSFingerprinter_Fingerprint_AllSignals(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	resp := makeOATSResponse(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(realisticOLTLoginPage))

	require.NoError(t, err)
	require.NotNil(t, result)

	signals, ok := result.Metadata["detected_signals"].([]string)
	require.True(t, ok)
	assert.Contains(t, signals, "olt_login_action")
	assert.Contains(t, signals, "olt_branding")
	assert.Contains(t, signals, "oats_branding")
	assert.Contains(t, signals, "otm_reference")
}

func TestOracleATSFingerprinter_Fingerprint_NoSignals(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	resp := makeOATSResponse(200, "text/html")

	body := `<html><body><h1>Welcome</h1><p>Generic login page.</p></body></html>`
	result, err := fp.Fingerprint(resp, []byte(body))

	require.NoError(t, err)
	assert.Nil(t, result)
}

// ── Fingerprint — body cap ────────────────────────────────────────────────────

func TestOracleATSFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	resp := makeOATSResponse(200, "text/html")

	bigBody := []byte(strings.Repeat("x", 2*1024*1024+1))
	result, err := fp.Fingerprint(resp, bigBody)

	assert.Nil(t, result)
	assert.Nil(t, err)
}

// ── Fingerprint — version extraction ─────────────────────────────────────────

func TestOracleATSFingerprinter_Fingerprint_VersionExtraction(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	resp := makeOATSResponse(200, "text/html")

	body := `<html><body>
<h1>Oracle Load Testing</h1>
<p>Version 13.3.0.1</p>
</body></html>`
	result, err := fp.Fingerprint(resp, []byte(body))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "13.3.0.1", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:oracle:application_testing_suite:13.3.0.1:*:*:*:*:*:*:*")
}

func TestOracleATSFingerprinter_Fingerprint_NoVersion(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	resp := makeOATSResponse(200, "text/html")

	body := `<html><body><h1>Oracle Load Testing</h1></body></html>`
	result, err := fp.Fingerprint(resp, []byte(body))

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:oracle:application_testing_suite:*:*:*:*:*:*:*:*")
}

func TestOracleATSFingerprinter_Fingerprint_IPAddressNotExtractedAsVersion(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	resp := makeOATSResponse(200, "text/html")

	// Body has an IP address and a JS library version, but no "Version X.X.X" — must not extract a version.
	body := `<html><body>
<h1>Oracle Load Testing</h1>
<p>Server: 10.0.0.1</p>
<script src="jquery-3.6.0.0.js"></script>
</body></html>`
	result, err := fp.Fingerprint(resp, []byte(body))

	require.NoError(t, err)
	require.NotNil(t, result, "OATS detection must still fire via branding")
	assert.Empty(t, result.Version, "IP address or JS library version must not be extracted as OATS version")
	assert.Contains(t, result.CPEs[0], ":*:", "CPE must use wildcard when no Version prefix found")
}

func TestOracleATSFingerprinter_Fingerprint_CPEMetacharacterGuard(t *testing.T) {
	// The version regex only matches digit/dot sequences, so `:`, `*`, and `?`
	// cannot appear in the extracted string under normal input. The guard is
	// belt-and-suspenders. We verify it via extractOATSVersion by passing
	// strings that contain metacharacters directly (not via regex capture).
	tests := []struct {
		name    string
		rawBody string
	}{
		{name: "no Version prefix", rawBody: "13.3.0.1"},
		{name: "IP address", rawBody: "10.0.0.1"},
		{name: "colon in text", rawBody: "Version 13:3.0.1"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// None of these bodies produce a valid version — guard or regex prevents it.
			assert.Empty(t, extractOATSVersion(tt.rawBody))
		})
	}

	// End-to-end: confirm detection still works and wildcard CPE emitted when
	// the helper returns empty (simulated by a body with no parseable version).
	t.Run("end-to-end wildcard CPE when no version found", func(t *testing.T) {
		fp := &OracleATSFingerprinter{}
		resp := makeOATSResponse(200, "text/html")
		body := `<html><body><h1>Oracle Load Testing</h1></body></html>`
		result, err := fp.Fingerprint(resp, []byte(body))
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Empty(t, result.Version)
		assert.Contains(t, result.CPEs, "cpe:2.3:a:oracle:application_testing_suite:*:*:*:*:*:*:*:*")
	})
}

// ── buildOracleATSCPE ─────────────────────────────────────────────────────────

func TestBuildOracleATSCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with version",
			version:  "13.3.0.1",
			expected: "cpe:2.3:a:oracle:application_testing_suite:13.3.0.1:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version → wildcard",
			version:  "",
			expected: "cpe:2.3:a:oracle:application_testing_suite:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildOracleATSCPE(tt.version))
		})
	}
}

// ── Severity / SecurityFindings ──────────────────────────────────────────────

func TestOracleATSFingerprinter_NoSeverityOrFindings(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	resp := makeOATSResponse(200, "text/html")

	result, err := fp.Fingerprint(resp, []byte(realisticOLTLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "fingerprinter-only: Severity must be unset")
	assert.Nil(t, result.SecurityFindings, "fingerprinter-only: no SecurityFindings")
}

// ── Integration: Match + Fingerprint ─────────────────────────────────────────

func TestOracleATSFingerprinter_Integration(t *testing.T) {
	fp := &OracleATSFingerprinter{}
	resp := makeOATSResponse(200, "text/html")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(realisticOLTLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_ats", result.Technology)
	assert.Equal(t, "13.3.0.1", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:oracle:application_testing_suite:13.3.0.1:*:*:*:*:*:*:*")
	assert.Equal(t, "Oracle", result.Metadata["vendor"])
	assert.Equal(t, "Application Testing Suite", result.Metadata["product"])
	assert.Equal(t, "olt_login_page", result.Metadata["detection_method"])

	signals, ok := result.Metadata["detected_signals"].([]string)
	require.True(t, ok)
	assert.Contains(t, signals, "olt_login_action")
	assert.Contains(t, signals, "olt_branding")
	assert.Contains(t, signals, "oats_branding")
	assert.Contains(t, signals, "otm_reference")

	components, ok := result.Metadata["components"].([]string)
	require.True(t, ok)
	assert.Contains(t, components, "Oracle Load Testing")
	assert.Contains(t, components, "Oracle Test Manager")
}

// ── helpers ───────────────────────────────────────────────────────────────────

func makeOATSResponse(statusCode int, contentType string) *http.Response {
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
	}
	if contentType != "" {
		resp.Header.Set("Content-Type", contentType)
	}
	return resp
}
