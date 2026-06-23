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

// ── Interface compliance ───────────────────────────────────────────────────────

var _ ActiveHTTPFingerprinter = (*SamsungMagicINFOFingerprinter)(nil)

// ── Name / ProbeEndpoint / ProbeAccept ────────────────────────────────────────

func TestSamsungMagicINFOFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	assert.Equal(t, "/MagicInfo/", fp.ProbeEndpoint())
}

func TestSamsungMagicINFOFingerprinter_Name(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	assert.Equal(t, "samsung-magicinfo", fp.Name())
}

func TestSamsungMagicINFOFingerprinter_ProbeAccept(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

// ── Match ──────────────────────────────────────────────────────────────────────

func TestSamsungMagicINFOFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		serverHdr   string
		contentType string
		want        bool
	}{
		{
			name:       "Server header 'MagicInfo Premium Server' → true (standalone)",
			statusCode: 200,
			serverHdr:  "MagicInfo Premium Server/21.1050",
			want:       true,
		},
		{
			name:       "Server header 'MagicInfo Lite Server' → true",
			statusCode: 200,
			serverHdr:  "MagicInfo Lite Server",
			want:       true,
		},
		{
			name:        "text/html content type → true",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "302 text/html → true",
			statusCode:  302,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "5xx → false",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "503 → false",
			statusCode:  503,
			contentType: "text/html",
			want:        false,
		},
		{
			name:       "200 image/png no server hdr → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:        "404 text/html → true",
			statusCode:  404,
			contentType: "text/html",
			want:        true,
		},
		{
			name:       "WebLogic server header → false",
			statusCode: 200,
			serverHdr:  "WebLogic Server 12.2.1.4.0",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SamsungMagicINFOFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.serverHdr != "" {
				resp.Header.Set("Server", tt.serverHdr)
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint: positive (standalone server header signal) ───────────────────

func TestSamsungMagicINFOFingerprinter_Fingerprint_ServerHeaderStandalone(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "MagicInfo Premium Server/21.1050")
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte(`<html><body>Hello</body></html>`))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "samsung-magicinfo", result.Technology)
	assert.Equal(t, "21.1050", result.Version)
	assert.Equal(t, "Premium", result.Metadata["edition"])
	assert.Contains(t, result.CPEs, "cpe:2.3:a:samsung:magicinfo_9_server:21.1050:*:*:*:*:*:*:*")
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_ServerHeaderLiteEdition(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "MagicInfo Lite Server/21.1052")

	result, err := fp.Fingerprint(resp, []byte{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "samsung-magicinfo", result.Technology)
	assert.Equal(t, "21.1052", result.Version)
	assert.Equal(t, "Lite", result.Metadata["edition"])
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_ServerHeaderNoVersion(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "MagicInfo Server")

	result, err := fp.Fingerprint(resp, []byte{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:samsung:magicinfo_9_server:*:*:*:*:*:*:*:*")
	// No edition determinable — field must be absent.
	_, hasEdition := result.Metadata["edition"]
	assert.False(t, hasEdition)
}

// ── Fingerprint: positive (corroborated body signal) ─────────────────────────

func TestSamsungMagicINFOFingerprinter_Fingerprint_BodyBrandPlusSamsung(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	body := []byte(`<!DOCTYPE html>
<html>
<head><title>MagicINFO Sign</title></head>
<body>
<p>Samsung MagicINFO Content Manager</p>
<p>version=21.1050</p>
</body>
</html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "samsung-magicinfo", result.Technology)
	assert.Equal(t, "21.1050", result.Version)
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_BodyBrandPlusPathRef(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	// Body includes a MagicINFO-branded <title> element (required by the corroboration
	// logic) along with a /MagicInfo/ path reference and the brand string.
	body := []byte(`<!DOCTYPE html>
<html>
<head><title>MagicINFO Sign Portal</title></head>
<body>
<script src="/MagicInfo/js/app.js"></script>
<p>Powered by MagicINFO</p>
</body>
</html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "samsung-magicinfo", result.Technology)
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_BodyBrandPlusTitleRef(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	body := []byte(`<html>
<head><title>Samsung MagicINFO Server</title></head>
<body>MagicINFO is running.</body>
</html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "samsung-magicinfo", result.Technology)
}

// ── Fingerprint: version extraction ───────────────────────────────────────────

func TestSamsungMagicINFOFingerprinter_Fingerprint_VersionFromServerHeader(t *testing.T) {
	tests := []struct {
		name          string
		serverHdr     string
		wantVersion   string
	}{
		{
			name:        "Premium edition version 21.1050",
			serverHdr:   "MagicInfo Premium Server/21.1050",
			wantVersion: "21.1050",
		},
		{
			name:        "Lite edition version 21.1052",
			serverHdr:   "MagicInfo Lite Server/21.1052",
			wantVersion: "21.1052",
		},
		{
			name:        "Base MagicInfo server with version",
			serverHdr:   "MagicInfo/9.0",
			wantVersion: "9.0",
		},
		{
			name:        "No version suffix → empty",
			serverHdr:   "MagicInfo Server",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SamsungMagicINFOFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Server", tt.serverHdr)

			result, err := fp.Fingerprint(resp, []byte{})
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.wantVersion, result.Version)
		})
	}
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_VersionFromBody(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantVersion string
	}{
		{
			name:        "version=21.1050 in body",
			body:        `<p>version=21.1050</p>`,
			wantVersion: "21.1050",
		},
		{
			name:        "Version: 21.1052 context",
			body:        `<span>Version: 21.1052</span>`,
			wantVersion: "21.1052",
		},
		{
			name:        "ver=9.0 context",
			body:        `ver=9.0`,
			wantVersion: "9.0",
		},
		{
			name:        "no version keyword → no version",
			body:        `<p>21.1050 is the build.</p>`,
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SamsungMagicINFOFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			// Use server header to trigger standalone signal so body-only version check is valid.
			resp.Header.Set("Server", "MagicInfo Server")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result)
			assert.Equal(t, tt.wantVersion, result.Version)
		})
	}
}

// ── Fingerprint: negative tests ───────────────────────────────────────────────

func TestSamsungMagicINFOFingerprinter_Fingerprint_WebLogicFalsePositive(t *testing.T) {
	// WebLogic on port 7001 must NOT be detected as MagicINFO.
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "WebLogic Server 12.2.1.4.0")
	resp.Header.Set("Content-Type", "text/html")

	body := []byte(`<!DOCTYPE html>
<html>
<head><title>Oracle WebLogic Server Administration Console</title></head>
<body>
<p>Welcome to WebLogic Server Administration Console.</p>
<p>Version: 12.2.1.4.0</p>
</body>
</html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result, "WebLogic response must not match MagicINFO fingerprinter")
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_GenericJavaApp(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Apache-Coyote/1.1")
	resp.Header.Set("Content-Type", "text/html")

	body := []byte(`<html><head><title>My Java App</title></head><body><p>Hello World</p></body></html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_SamsungTVPageNoMagicINFO(t *testing.T) {
	// A Samsung page that is NOT MagicINFO — Samsung brand alone is not sufficient.
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	body := []byte(`<html>
<head><title>Samsung Smart TV</title></head>
<body><p>Samsung television management portal. Version: 1234.5678</p></body>
</html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result, "Samsung TV page without MagicINFO markers must not match")
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_5xxRejected(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 500,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "MagicInfo Premium Server/21.1050")

	result, err := fp.Fingerprint(resp, []byte(`error`))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_BodyOverCapWithServerHeader(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")
	resp.Header.Set("Server", "MagicInfo Premium Server/21.1050")

	// Body over 1 MiB with a MagicInfo Server header must still detect — the server-header
	// standalone signal is evaluated before the body cap.
	bigBody := []byte(strings.Repeat("x", 1*1024*1024+1))

	result, err := fp.Fingerprint(resp, bigBody)
	require.NoError(t, err)
	require.NotNil(t, result, "MagicInfo Server header must trigger detection regardless of body size")
	assert.Equal(t, "samsung-magicinfo", result.Technology)
	assert.Equal(t, "21.1050", result.Version)
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_BodyOverCapNoServerHeader(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	// Body over 1 MiB without a MagicInfo Server header must be rejected; the body-based
	// detection path is gated by the 1 MiB cap.
	bigBody := []byte(strings.Repeat("x", 1*1024*1024+1))

	result, err := fp.Fingerprint(resp, bigBody)
	require.NoError(t, err)
	assert.Nil(t, result, "oversized body without MagicInfo Server header must not detect")
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_EmptyBodyNoServerHeader(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	result, err := fp.Fingerprint(resp, []byte{})
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_BodyBrandAloneNotSufficient(t *testing.T) {
	// Body with "magicinfo" but no title containing MagicINFO → no detection.
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	body := []byte(`<html><head><title>CMS</title></head><body><p>We integrate with magicinfo.</p></body></html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result, "body with 'magicinfo' mention only, without corroborating title marker, must not match")
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_ErrorPagePathEchoFalsePositive(t *testing.T) {
	// A non-MagicINFO server that echoes "/MagicInfo/" in a 404 body and incidentally
	// mentions "Samsung" must NOT detect. The \bmagicinfo\b regex matches within
	// "/MagicInfo/" (since "/" is not a word character), but the corroboration logic
	// requires a MagicINFO-branded <title> element — which a generic error page lacks.
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 404,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")
	resp.Header.Set("Server", "WebLogic Server 12.2.1.4.0")

	body := []byte(`<html><body>Error 404: /MagicInfo/ not found. Samsung WebLogic Portal.</body></html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result, "error page echoing /MagicInfo/ path and Samsung brand without a MagicINFO title must not detect")
}

// ── CPE validation ─────────────────────────────────────────────────────────────

func TestBuildMagicINFOCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "version 21.1050",
			version:  "21.1050",
			expected: "cpe:2.3:a:samsung:magicinfo_9_server:21.1050:*:*:*:*:*:*:*",
		},
		{
			name:     "version 21.1052",
			version:  "21.1052",
			expected: "cpe:2.3:a:samsung:magicinfo_9_server:21.1052:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version → wildcard CPE",
			version:  "",
			expected: "cpe:2.3:a:samsung:magicinfo_9_server:*:*:*:*:*:*:*:*",
		},
		{
			name:     "version with colon → wildcard (injection guard)",
			version:  "21:1050",
			expected: "cpe:2.3:a:samsung:magicinfo_9_server:*:*:*:*:*:*:*:*",
		},
		{
			name:     "version with asterisk → wildcard (injection guard)",
			version:  "21.*",
			expected: "cpe:2.3:a:samsung:magicinfo_9_server:*:*:*:*:*:*:*:*",
		},
		{
			name:     "version with question mark → wildcard (injection guard)",
			version:  "21.?",
			expected: "cpe:2.3:a:samsung:magicinfo_9_server:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildMagicINFOCPE(tt.version))
		})
	}
}

func TestSamsungMagicINFOFingerprinter_Fingerprint_CPEInjectionGuard(t *testing.T) {
	// Version string with CPE metacharacters in Server header must not appear in CPE output.
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "MagicInfo Server/21:1*0")

	result, err := fp.Fingerprint(resp, []byte{})
	require.NoError(t, err)
	require.NotNil(t, result)
	// Version with metacharacters must be rejected by validation.
	assert.Equal(t, "", result.Version)
	for _, cpe := range result.CPEs {
		assert.NotContains(t, cpe, "21:1*0", "CPE must not contain injected metacharacters")
	}
}

// ── Detection-only contract ────────────────────────────────────────────────────

func TestSamsungMagicINFOFingerprinter_NoSeverityNoSecurityFindings(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "MagicInfo Premium Server/21.1050")

	result, err := fp.Fingerprint(resp, []byte{})
	require.NoError(t, err)
	require.NotNil(t, result)

	// Fingerprinter-only ticket: Severity must be empty (zero value).
	assert.Empty(t, result.Severity, "Severity must not be set for a fingerprinter-only implementation")
	assert.Nil(t, result.SecurityFindings, "SecurityFindings must not be populated")
}

// ── Metadata structure ─────────────────────────────────────────────────────────

func TestSamsungMagicINFOFingerprinter_Fingerprint_MetadataFields(t *testing.T) {
	fp := &SamsungMagicINFOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "MagicInfo Premium Server/21.1050")

	result, err := fp.Fingerprint(resp, []byte{})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "Samsung", result.Metadata["vendor"])
	assert.Equal(t, "MagicINFO 9 Server", result.Metadata["product"])
	assert.Equal(t, "Premium", result.Metadata["edition"])
}
