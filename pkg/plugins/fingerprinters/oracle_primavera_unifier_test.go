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

// ── Name / ProbeEndpoint / ProbeAccept ───────────────────────────────────────

func TestOraclePrimaveraUnifierFingerprinter_Name(t *testing.T) {
	fp := &OraclePrimaveraUnifierFingerprinter{}
	assert.Equal(t, "oracle_primavera_unifier", fp.Name())
}

func TestOraclePrimaveraUnifierFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &OraclePrimaveraUnifierFingerprinter{}
	assert.Equal(t, "/bluedoor", fp.ProbeEndpoint())
}

func TestOraclePrimaveraUnifierFingerprinter_ProbeAccept(t *testing.T) {
	fp := &OraclePrimaveraUnifierFingerprinter{}
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestOraclePrimaveraUnifierFingerprinter_Match(t *testing.T) {
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
			name:        "200 text/html;charset → true",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 TEXT/HTML mixed case → true (lowercased)",
			statusCode:  200,
			contentType: "TEXT/HTML",
			want:        true,
		},
		{
			name:        "200 application/json → false",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:       "200 no content-type → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:        "401 text/html → true",
			statusCode:  401,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "500 text/html → false",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "199 text/html → false",
			statusCode:  199,
			contentType: "text/html",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OraclePrimaveraUnifierFingerprinter{}
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

// unifierFullLoginPage contains all three detection signals plus both version formats.
// The HTML version string is placed in the footer div so it appears on its own line,
// ensuring the unifierVersionRegex \S+ group terminates cleanly at end-of-line.
const unifierFullLoginPage = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Primavera Unifier Login</title>
  <script>
    var appConfig = {"codeVersion":"25.12.1-b-12242025-15"};
  </script>
</head>
<body>
  <div class="login-container">
    <h1>Primavera Unifier</h1>
    <form action="/bluedoor/j_security_check" method="post">
      <input type="text" name="j_username" />
      <input type="password" name="j_password" />
      <input type="submit" value="Sign In" />
    </form>
  </div>
  <div class="release">
    Version25.12.1 b-12242025-15
  </div>
</body>
</html>`

func TestOraclePrimaveraUnifierFingerprinter_Fingerprint_PositiveWithHTMLVersion(t *testing.T) {
	fp := &OraclePrimaveraUnifierFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(unifierFullLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_primavera_unifier", result.Technology)
	assert.Equal(t, "25.12.1", result.Version)
	assert.Equal(t, "12242025-15", result.Metadata["build"])
	require.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], "25.12.1")
}

func TestOraclePrimaveraUnifierFingerprinter_Fingerprint_TitleOnly(t *testing.T) {
	body := `<html><head><title>Primavera Unifier Login</title></head><body></body></html>`
	fp := &OraclePrimaveraUnifierFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_primavera_unifier", result.Technology)
	assert.Equal(t, "unifier_title", result.Metadata["detection_method"])
}

func TestOraclePrimaveraUnifierFingerprinter_Fingerprint_BrandingOnly(t *testing.T) {
	body := `<html><body><div>Welcome to Primavera Unifier project controls.</div></body></html>`
	fp := &OraclePrimaveraUnifierFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_primavera_unifier", result.Technology)
	assert.Equal(t, "unifier_branding", result.Metadata["detection_method"])
}

func TestOraclePrimaveraUnifierFingerprinter_Fingerprint_CodeVersionOnly(t *testing.T) {
	body := `<html><body><script>var c={"codeVersion":"1.0-b-test"};</script></body></html>`
	fp := &OraclePrimaveraUnifierFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_primavera_unifier", result.Technology)
	assert.Equal(t, "code_version", result.Metadata["detection_method"])
}

func TestOraclePrimaveraUnifierFingerprinter_Fingerprint_GenericCodeVersionNegative(t *testing.T) {
	// A generic SPA page with a "codeVersion" key that does NOT match the
	// Unifier-specific format must not trigger detection.
	body := `<html><body><script>var config={"codeVersion":"3.2.1","appName":"MyApp"};</script></body></html>`
	fp := &OraclePrimaveraUnifierFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	assert.Nil(t, result, "generic codeVersion without Unifier format must not detect")
}

func TestOraclePrimaveraUnifierFingerprinter_Fingerprint_JSONVersionFallback(t *testing.T) {
	// Body has codeVersion JSON but NO HTML version string — must fall back to JSON.
	body := `<html><head><title>Primavera Unifier Login</title></head>
<body>
  <script>var c={"codeVersion":"25.12.1-b-12242025-15"};</script>
</body></html>`
	fp := &OraclePrimaveraUnifierFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "25.12.1", result.Version)
	assert.Equal(t, "12242025-15", result.Metadata["build"])
}

func TestOraclePrimaveraUnifierFingerprinter_Fingerprint_Priority_TitleWins(t *testing.T) {
	// All three signals present — title must win.
	body := `<!DOCTYPE html>
<html><head><title>Primavera Unifier Login</title></head>
<body>
  <p>Primavera Unifier portal</p>
  <script>var c={"codeVersion":"25.12.1-b-test"};</script>
</body></html>`
	fp := &OraclePrimaveraUnifierFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "unifier_title", result.Metadata["detection_method"])
}

func TestOraclePrimaveraUnifierFingerprinter_Fingerprint_ReflectionSafe(t *testing.T) {
	// Body contains probe path only — no detection signal.
	body := `<html><body>/bluedoor not found</body></html>`
	fp := &OraclePrimaveraUnifierFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestOraclePrimaveraUnifierFingerprinter_Fingerprint_NoVersion(t *testing.T) {
	// Signal present but no version string in body.
	body := `<html><head><title>Primavera Unifier Login</title></head><body></body></html>`
	fp := &OraclePrimaveraUnifierFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "", result.Version)
	require.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], ":*:")
}

func TestOraclePrimaveraUnifierFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &OraclePrimaveraUnifierFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	signal := `<title>Primavera Unifier Login</title>`
	padding := strings.Repeat("x", 2*1024*1024+1)
	bigBody := []byte(signal + padding)

	result, err := fp.Fingerprint(resp, bigBody)
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ── buildPrimaveraUnifierCPE ──────────────────────────────────────────────────

func TestBuildPrimaveraUnifierCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "empty version → wildcard",
			version:  "",
			expected: "cpe:2.3:a:oracle:primavera_unifier:*:*:*:*:*:*:*:*",
		},
		{
			name:     "versioned CPE",
			version:  "25.12.1",
			expected: "cpe:2.3:a:oracle:primavera_unifier:25.12.1:*:*:*:*:*:*:*",
		},
		{
			name:     "colon in version → wildcard",
			version:  "25:12",
			expected: "cpe:2.3:a:oracle:primavera_unifier:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildPrimaveraUnifierCPE(tt.version))
		})
	}
}

// ── Severity / SecurityFindings ───────────────────────────────────────────────

func TestOraclePrimaveraUnifierFingerprinter_NoSeverityOrFindings(t *testing.T) {
	fp := &OraclePrimaveraUnifierFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(unifierFullLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "fingerprinter-only: Severity must be unset")
	assert.Nil(t, result.SecurityFindings, "fingerprinter-only: no SecurityFindings")
}
