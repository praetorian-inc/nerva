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

func TestOraclePrimaveraP6Fingerprinter_Name(t *testing.T) {
	fp := &OraclePrimaveraP6Fingerprinter{}
	assert.Equal(t, "oracle_primavera_p6", fp.Name())
}

func TestOraclePrimaveraP6Fingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &OraclePrimaveraP6Fingerprinter{}
	assert.Equal(t, "/p6/action/login", fp.ProbeEndpoint())
}

func TestOraclePrimaveraP6Fingerprinter_ProbeAccept(t *testing.T) {
	fp := &OraclePrimaveraP6Fingerprinter{}
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestOraclePrimaveraP6Fingerprinter_Match(t *testing.T) {
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
			fp := &OraclePrimaveraP6Fingerprinter{}
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

// p6FullLoginPage is a realistic P6 EPPM login page body with all three
// detection signals and a version string in the footer.
const p6FullLoginPage = `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Oracle Primavera P6 EPPM</title>
</head>
<body>
  <div class="login-header">
    <img src="/p6/icons/baseTheme/oracle-primavera-logo-cmyk.png" alt="Oracle Primavera">
    <h1>Primavera P6 EPPM</h1>
  </div>
  <form action="/p6/action/login" method="post">
    <input type="text" name="username" />
    <input type="password" name="password" />
    <input type="submit" value="Login" />
  </form>
  <div class="footer">
    Version 24.12.8.0 (B0109) 08.07.2025.2306
  </div>
</body>
</html>`

func TestOraclePrimaveraP6Fingerprinter_Fingerprint_PositiveWithVersion(t *testing.T) {
	fp := &OraclePrimaveraP6Fingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(p6FullLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_primavera_p6", result.Technology)
	assert.Equal(t, "24.12.8.0", result.Version)
	assert.Equal(t, "0109", result.Metadata["build"])
	require.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], "24.12.8.0")
}

func TestOraclePrimaveraP6Fingerprinter_Fingerprint_TitleOnly(t *testing.T) {
	body := `<html><head><title>Oracle Primavera P6 EPPM</title></head><body></body></html>`
	fp := &OraclePrimaveraP6Fingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_primavera_p6", result.Technology)
	assert.Equal(t, "p6_title", result.Metadata["detection_method"])
}

func TestOraclePrimaveraP6Fingerprinter_Fingerprint_LogoOnly(t *testing.T) {
	body := `<html><body><img src="/p6/icons/oracle-primavera-logo-cmyk.png"></body></html>`
	fp := &OraclePrimaveraP6Fingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_primavera_p6", result.Technology)
	assert.Equal(t, "p6_logo", result.Metadata["detection_method"])
}

func TestOraclePrimaveraP6Fingerprinter_Fingerprint_BrandingOnly(t *testing.T) {
	body := `<html><body><div>Primavera P6 Enterprise Portfolio Management EPPM</div></body></html>`
	fp := &OraclePrimaveraP6Fingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_primavera_p6", result.Technology)
	assert.Equal(t, "p6_branding", result.Metadata["detection_method"])
}

func TestOraclePrimaveraP6Fingerprinter_Fingerprint_Priority_TitleWins(t *testing.T) {
	// All three signals present — title must win.
	body := `<!DOCTYPE html>
<html><head><title>Oracle Primavera P6 EPPM</title></head>
<body>
  <img src="/p6/icons/oracle-primavera-logo-cmyk.png">
  <span>Primavera P6 EPPM</span>
</body></html>`
	fp := &OraclePrimaveraP6Fingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "p6_title", result.Metadata["detection_method"])
}

func TestOraclePrimaveraP6Fingerprinter_Fingerprint_NoVersion(t *testing.T) {
	// Title signal present but no version string in footer.
	body := `<html><head><title>Oracle Primavera P6 EPPM</title></head><body></body></html>`
	fp := &OraclePrimaveraP6Fingerprinter{}
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

func TestOraclePrimaveraP6Fingerprinter_Fingerprint_ReflectionSafe(t *testing.T) {
	// Body contains probe path text only — no real detection signal.
	body := `<html><body>/p6/action/login not found</body></html>`
	fp := &OraclePrimaveraP6Fingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestOraclePrimaveraP6Fingerprinter_Fingerprint_GenericHTML(t *testing.T) {
	body := `<html><head><title>Welcome</title></head><body><h1>Hello World</h1></body></html>`
	fp := &OraclePrimaveraP6Fingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestOraclePrimaveraP6Fingerprinter_Fingerprint_EmptyBody(t *testing.T) {
	fp := &OraclePrimaveraP6Fingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(""))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestOraclePrimaveraP6Fingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &OraclePrimaveraP6Fingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	// Body with a detection signal but exceeding the 2 MiB cap.
	signal := `<title>Oracle Primavera P6 EPPM</title>`
	padding := strings.Repeat("x", 2*1024*1024+1)
	bigBody := []byte(signal + padding)

	result, err := fp.Fingerprint(resp, bigBody)
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ── buildPrimaveraP6CPE ───────────────────────────────────────────────────────

func TestBuildPrimaveraP6CPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "empty version → wildcard",
			version:  "",
			expected: "cpe:2.3:a:oracle:primavera_p6_enterprise_project_portfolio_management:*:*:*:*:*:*:*:*",
		},
		{
			name:     "versioned CPE",
			version:  "24.12.8.0",
			expected: "cpe:2.3:a:oracle:primavera_p6_enterprise_project_portfolio_management:24.12.8.0:*:*:*:*:*:*:*",
		},
		{
			name:     "colon in version → wildcard",
			version:  "24:12",
			expected: "cpe:2.3:a:oracle:primavera_p6_enterprise_project_portfolio_management:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildPrimaveraP6CPE(tt.version))
		})
	}
}

// ── Severity / SecurityFindings ───────────────────────────────────────────────

func TestOraclePrimaveraP6Fingerprinter_NoSeverityOrFindings(t *testing.T) {
	fp := &OraclePrimaveraP6Fingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(p6FullLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "fingerprinter-only: Severity must be unset")
	assert.Nil(t, result.SecurityFindings, "fingerprinter-only: no SecurityFindings")
}
