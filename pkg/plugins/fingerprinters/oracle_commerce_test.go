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
	"encoding/base64"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Name / IsPassive ──────────────────────────────────────────────────────────

func TestOracleCommerceFingerprinter_Name(t *testing.T) {
	fp := &OracleCommerceFingerprinter{}
	assert.Equal(t, "oracle_commerce", fp.Name())
}

func TestOracleCommerceFingerprinter_IsPassive(t *testing.T) {
	fp := &OracleCommerceFingerprinter{}
	_, ok := any(fp).(ActiveHTTPFingerprinter)
	assert.False(t, ok, "OracleCommerceFingerprinter must not implement ActiveHTTPFingerprinter (it is passive)")
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestOracleCommerceFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		headers    map[string]string
		cookies    []string
		want       bool
	}{
		{
			name:       "200 with X-ATG-Version header → true",
			statusCode: 200,
			headers:    map[string]string{"X-Atg-Version": "QVRHUGxhdGZvcm0vMTEuMg=="},
			want:       true,
		},
		{
			name:       "200 with ATG_SESSION_ID cookie → true",
			statusCode: 200,
			cookies:    []string{"ATG_SESSION_ID=abc123; Path=/"},
			want:       true,
		},
		{
			name:       "200 with no ATG signals → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "500 with X-ATG-Version → false",
			statusCode: 500,
			headers:    map[string]string{"X-Atg-Version": "QVRHUGxhdGZvcm0vMTEuMg=="},
			want:       false,
		},
		{
			name:       "199 with X-ATG-Version → false",
			statusCode: 199,
			headers:    map[string]string{"X-Atg-Version": "QVRHUGxhdGZvcm0vMTEuMg=="},
			want:       false,
		},
		{
			name:       "301 with X-ATG-Version → true (redirects should match)",
			statusCode: 301,
			headers:    map[string]string{"X-Atg-Version": "QVRHUGxhdGZvcm0vMTEuMg=="},
			want:       true,
		},
		{
			name:       "200 with atg_session_id cookie (lowercase) → true (case-insensitive)",
			statusCode: 200,
			cookies:    []string{"atg_session_id=abc123; Path=/"},
			want:       true,
		},
		{
			name:       "200 with unrelated cookie containing atg_session_id substring → false",
			statusCode: 200,
			cookies:    []string{"UNRELATED_ATG_SESSION_ID=abc123; Path=/"},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OracleCommerceFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}
			for _, c := range tt.cookies {
				resp.Header.Add("Set-Cookie", c)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint tests ─────────────────────────────────────────────────────────

// TestOracleCommerceFingerprinter_Fingerprint_HeaderWithVersionPrefix verifies
// full detection when the X-ATG-Version header has a "version=" prefix.
// QVRHUGxhdGZvcm0vMTEuMg== decodes to "ATGPlatform/11.2".
func TestOracleCommerceFingerprinter_Fingerprint_HeaderWithVersionPrefix(t *testing.T) {
	fp := &OracleCommerceFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	// "version=" prefix + base64("ATGPlatform/11.2")
	resp.Header.Set("X-Atg-Version", "version=QVRHUGxhdGZvcm0vMTEuMg==")
	resp.Header.Add("Set-Cookie", "ATG_SESSION_ID=sess1; Path=/")
	resp.Header.Add("Set-Cookie", "DYN_USER_ID=user1; Path=/")

	result, err := fp.Fingerprint(resp, []byte(""))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_commerce", result.Technology)
	assert.Equal(t, "11.2", result.Version)
	require.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], "commerce_platform:11.2")
	assert.Equal(t, "atg_version_header", result.Metadata["detection_method"])
	assert.NotEmpty(t, result.Metadata["atg_version_raw"])
	assert.NotEmpty(t, result.Metadata["atg_version_decoded"])
	assert.NotEmpty(t, result.Metadata["version_note"])
	assert.NotNil(t, result.Metadata["cookies_found"])
}

// TestOracleCommerceFingerprinter_Fingerprint_HeaderWithoutPrefix verifies
// version extraction when there is no "version=" prefix.
// QVRHUGxhdGZvcm0vMTEuMy4y decodes to "ATGPlatform/11.3.2".
func TestOracleCommerceFingerprinter_Fingerprint_HeaderWithoutPrefix(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("ATGPlatform/11.3.2"))

	fp := &OracleCommerceFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-Atg-Version", encoded)

	result, err := fp.Fingerprint(resp, []byte(""))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "11.3.2", result.Version)
	require.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], "commerce_platform:11.3.2")
}

// TestOracleCommerceFingerprinter_Fingerprint_CookieOnly verifies detection
// via ATG_SESSION_ID cookie when no X-ATG-Version header is present.
func TestOracleCommerceFingerprinter_Fingerprint_CookieOnly(t *testing.T) {
	fp := &OracleCommerceFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Add("Set-Cookie", "ATG_SESSION_ID=session123; Path=/")

	result, err := fp.Fingerprint(resp, []byte(""))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_commerce", result.Technology)
	assert.Equal(t, "", result.Version, "version must be empty when only cookie is present")
	assert.Equal(t, "atg_session_cookie", result.Metadata["detection_method"])
	require.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], "commerce_platform:*", "CPE must use wildcard when version is unknown")
}

// TestOracleCommerceFingerprinter_Fingerprint_NoSignals verifies that nil is
// returned when neither header nor ATG cookies are present.
func TestOracleCommerceFingerprinter_Fingerprint_NoSignals(t *testing.T) {
	fp := &OracleCommerceFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte("<html></html>"))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestOracleCommerceFingerprinter_Fingerprint_DynUserIDOnlyNegative(t *testing.T) {
	fp := &OracleCommerceFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Add("Set-Cookie", "DYN_USER_ID=user1; Path=/")

	result, err := fp.Fingerprint(resp, []byte(""))
	require.NoError(t, err)
	assert.Nil(t, result, "DYN_USER_ID alone must not trigger detection (not a standalone signal)")
}

// TestOracleCommerceFingerprinter_Fingerprint_MalformedBase64 verifies that
// detection still fires when the header is present but the base64 is invalid.
// The header presence alone constitutes detection; version should be empty.
func TestOracleCommerceFingerprinter_Fingerprint_MalformedBase64(t *testing.T) {
	fp := &OracleCommerceFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-Atg-Version", "!!!notvalidbase64!!!")

	result, err := fp.Fingerprint(resp, []byte(""))
	require.NoError(t, err)
	require.NotNil(t, result, "result must be non-nil: header presence is enough for detection")
	assert.Equal(t, "", result.Version, "version must be empty when base64 decode fails")
	assert.Equal(t, "atg_version_header", result.Metadata["detection_method"])
}

func TestOracleCommerceFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &OracleCommerceFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-Atg-Version", "QVRHUGxhdGZvcm0vMTEuMg==")

	oversizedBody := []byte(strings.Repeat("A", 2*1024*1024+1))
	result, err := fp.Fingerprint(resp, oversizedBody)
	require.NoError(t, err)
	require.NotNil(t, result, "header/cookie detection must not be blocked by body cap")
	assert.Equal(t, "11.2", result.Version)
	_, hasBodySignals := result.Metadata["corroborating_paths"]
	assert.False(t, hasBodySignals, "body signals must be skipped for oversized body")
}

// TestOracleCommerceFingerprinter_Fingerprint_CPEMetacharGuard verifies that
// buildCommerceCPE uses a wildcard when the version string contains CPE
// metacharacters (":", "*", "?"). The atgVersionRegex only captures digits and
// dots, so the guard is exercised directly via buildCommerceCPE, which is the
// internal function that enforces the invariant.
func TestOracleCommerceFingerprinter_Fingerprint_CPEMetacharGuard(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantCPE string
	}{
		{
			name:    "version with colon → wildcard CPE",
			version: "11.2:patch1",
			wantCPE: "cpe:2.3:a:oracle:commerce_platform:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version with asterisk → wildcard CPE",
			version: "11.*",
			wantCPE: "cpe:2.3:a:oracle:commerce_platform:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version with question mark → wildcard CPE",
			version: "11.?",
			wantCPE: "cpe:2.3:a:oracle:commerce_platform:*:*:*:*:*:*:*:*",
		},
		{
			name:    "clean version → specific CPE",
			version: "11.2",
			wantCPE: "cpe:2.3:a:oracle:commerce_platform:11.2:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCommerceCPE(tt.version)
			assert.Equal(t, tt.wantCPE, got)
		})
	}
}

// TestOracleCommerceFingerprinter_NoSeverityOrFindings verifies that the
// fingerprinter never produces a non-zero Severity or SecurityFindings.
func TestOracleCommerceFingerprinter_NoSeverityOrFindings(t *testing.T) {
	fp := &OracleCommerceFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-Atg-Version", "QVRHUGxhdGZvcm0vMTEuMg==")

	result, err := fp.Fingerprint(resp, []byte(""))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "Severity must be zero (not set) for oracle_commerce fingerprinter")
	assert.Nil(t, result.SecurityFindings, "SecurityFindings must be nil for oracle_commerce fingerprinter")
}

// TestOracleCommerceFingerprinter_Fingerprint_AllCookiesCollected verifies that
// all three ATG cookie names are recorded in cookies_found metadata.
func TestOracleCommerceFingerprinter_Fingerprint_AllCookiesCollected(t *testing.T) {
	fp := &OracleCommerceFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Add("Set-Cookie", "ATG_SESSION_ID=s1; Path=/")
	resp.Header.Add("Set-Cookie", "DYN_USER_ID=u1; Path=/")
	resp.Header.Add("Set-Cookie", "DYN_USER_CONFIRM=c1; Path=/")

	result, err := fp.Fingerprint(resp, []byte(""))
	require.NoError(t, err)
	require.NotNil(t, result)

	cookiesFound, ok := result.Metadata["cookies_found"].([]string)
	require.True(t, ok, "cookies_found must be []string")
	assert.Contains(t, cookiesFound, "ATG_SESSION_ID")
	assert.Contains(t, cookiesFound, "DYN_USER_ID")
	assert.Contains(t, cookiesFound, "DYN_USER_CONFIRM")
}
