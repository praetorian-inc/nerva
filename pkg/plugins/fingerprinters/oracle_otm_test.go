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

// otmLoginPage is a realistic fixture derived from a live OTM login page capture.
// It contains all five distinctive detection signals:
//   - glog.webserver.util.FrameGC3Servlet (frame_servlet)
//   - ORACLE TRANSPORTATION + GLOBAL TRADE MANAGEMENT (otm_heading)
//   - glogUrlContext + glogRawUrlContext (gc3_context)
//   - <title>Oracle Logistics</title> (oracle_logistics_title)
//   - Copyright &#169 2001&#44; 2016&#44; Oracle (copyright_year "2016")
const otmLoginPage = `<html><head><META http-equiv="Content-Type" content="text/html; charset=UTF-8">
<script>
        var glogUrlContext = '\x2FGC3\x2F';
        var glogRawUrlContext = 'GC3';
</script>
<title>Oracle Logistics</title>
</head>
<body onload="document.login.username.focus();">
<script language="javascript">
if (top.frames.length!=0){
    top.location = '/GC3/glog.webserver.servlet.umt.Login?redir=/GC3/glog.webserver.util.FrameGC3Servlet%3Fbody_frame%3D/GC3/glog.webserver.util.FrameGC3Servlet';
}
</script>
<table>
<tr><td>
  <span class="signInText">SIGN IN TO</span>
  <span class="otmText">ORACLE TRANSPORTATION &amp;</span>
  <span class="otmText">GLOBAL TRADE MANAGEMENT</span>
</td></tr>
<tr><td>
  <form method="post" action="/GC3/glog.webserver.servlet.umt.Login" name="login">
    <input value="GC3" name="namespace" type="hidden">
  </form>
</td></tr>
<tr><td>
  <div class="copyright">Copyright &#169 2001&#44; 2016&#44; Oracle and/or its affiliates. All rights reserved.</div>
</td></tr>
</table>
</body></html>`

// ── Name / ProbeEndpoint / ProbeAccept ────────────────────────────────────────

func TestOracleOTMFingerprinter_Name(t *testing.T) {
	fp := &OracleOTMFingerprinter{}
	assert.Equal(t, "oracle-otm", fp.Name())
}

func TestOracleOTMFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &OracleOTMFingerprinter{}
	assert.Equal(t, "/GC3/glog.webserver.servlet.umt.Login", fp.ProbeEndpoint())
}

func TestOracleOTMFingerprinter_ProbeAccept(t *testing.T) {
	fp := &OracleOTMFingerprinter{}
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestOracleOTMFingerprinter_Match(t *testing.T) {
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
			name:        "200 text/html with charset → true",
			statusCode:  200,
			contentType: "text/html; charset=UTF-8",
			want:        true,
		},
		{
			name:        "200 TEXT/HTML mixed case → true",
			statusCode:  200,
			contentType: "TEXT/HTML",
			want:        true,
		},
		{
			name:        "401 text/html (in-range) → true",
			statusCode:  401,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "403 text/html (in-range) → true",
			statusCode:  403,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "404 text/html (in-range) → true",
			statusCode:  404,
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
			name:        "503 text/html → false",
			statusCode:  503,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "200 application/json → false",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "200 text/plain → false",
			statusCode:  200,
			contentType: "text/plain",
			want:        false,
		},
		{
			name:       "200 no content-type → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:        "199 text/html (below range) → false",
			statusCode:  199,
			contentType: "text/html",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OracleOTMFingerprinter{}
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

func makeOTMResponse() *http.Response {
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html; charset=UTF-8")
	return resp
}

func TestOracleOTMFingerprinter_Fingerprint_FullPage(t *testing.T) {
	// Positive: realistic OTM login page containing all distinctive signals.
	// Expects: detected, Technology=="oracle_otm", Version=="", CPE wildcard,
	// detection_method=="frame_servlet" (highest priority signal present),
	// namespace=="GC3", copyright_year=="2016", version_note present.
	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(otmLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_otm", result.Technology)
	assert.Equal(t, "", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:oracle:transportation_management:*:*:*:*:*:*:*:*")

	assert.Equal(t, "Oracle", result.Metadata["vendor"])
	assert.Equal(t, "Oracle Transportation Management", result.Metadata["product"])
	assert.Equal(t, "GC3", result.Metadata["namespace"])
	assert.Equal(t, "frame_servlet", result.Metadata["detection_method"])
	assert.Equal(t, "2016", result.Metadata["copyright_year"])
	assert.NotEmpty(t, result.Metadata["version_note"])
}

func TestOracleOTMFingerprinter_Fingerprint_TitleOnly(t *testing.T) {
	// Positive: page with <title>Oracle Logistics</title> but none of the other signals.
	// Expects: detected, detection_method=="oracle_logistics_title".
	body := `<html><head><title>Oracle Logistics</title></head>
<body><p>Please sign in.</p></body></html>`

	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_otm", result.Technology)
	assert.Equal(t, "", result.Version)
	assert.Equal(t, "oracle_logistics_title", result.Metadata["detection_method"])
}

func TestOracleOTMFingerprinter_Fingerprint_TitleCaseInsensitive(t *testing.T) {
	// The title regex is case-insensitive; also tolerates extra whitespace.
	body := "<html><head><TITLE>  oracle logistics  </TITLE></head><body></body></html>"

	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "oracle_logistics_title", result.Metadata["detection_method"])
}

func TestOracleOTMFingerprinter_Fingerprint_OTMHeading(t *testing.T) {
	// Positive: body contains ORACLE TRANSPORTATION + GLOBAL TRADE MANAGEMENT
	// but no frame/integration servlet, no title, no gc3 context variables.
	body := `<html><head><title>Login</title></head>
<body>
  <span>ORACLE TRANSPORTATION &amp;</span>
  <span>GLOBAL TRADE MANAGEMENT</span>
</body></html>`

	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_otm", result.Technology)
	assert.Equal(t, "otm_heading", result.Metadata["detection_method"])
}

func TestOracleOTMFingerprinter_Fingerprint_GC3Context(t *testing.T) {
	// Positive: page has glogUrlContext only (no other signals).
	body := `<html><head><title>Sign In</title></head>
<body>
<script>var glogUrlContext = '/GC3/';</script>
</body></html>`

	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_otm", result.Technology)
	assert.Equal(t, "gc3_context", result.Metadata["detection_method"])
}

func TestOracleOTMFingerprinter_Fingerprint_GC3RawContext(t *testing.T) {
	// Positive: page has glogRawUrlContext only (no glogUrlContext, no other signals).
	body := `<html><body><script>var glogRawUrlContext = 'GC3';</script></body></html>`

	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "gc3_context", result.Metadata["detection_method"])
}

func TestOracleOTMFingerprinter_Fingerprint_IntegrationServlet(t *testing.T) {
	// Positive: body has glog.integration.servlet but no FrameGC3Servlet.
	// Expects detection_method=="integration_servlet".
	body := `<html><body>
<a href="/GC3/glog.integration.servlet/InboundAPI">Integration API</a>
</body></html>`

	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_otm", result.Technology)
	assert.Equal(t, "integration_servlet", result.Metadata["detection_method"])
}

func TestOracleOTMFingerprinter_Fingerprint_PriorityOrder(t *testing.T) {
	// Priority: frame_servlet > integration_servlet > otm_heading > gc3_context > oracle_logistics_title.
	// When frame_servlet + integration_servlet + heading all present, frame_servlet wins.
	body := `<html><head><title>Oracle Logistics</title></head>
<body>
<script>var glogUrlContext = '/GC3/';</script>
<a href="/GC3/glog.integration.servlet/API">API</a>
<span>ORACLE TRANSPORTATION &amp;</span>
<span>GLOBAL TRADE MANAGEMENT</span>
<script>top.location = '/GC3/glog.webserver.util.FrameGC3Servlet';</script>
</body></html>`

	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "frame_servlet", result.Metadata["detection_method"])
}

func TestOracleOTMFingerprinter_Fingerprint_ReflectionNegative(t *testing.T) {
	// REFLECTION GUARD: a server that echoes the probe path substring
	// "glog.webserver.servlet.umt.Login" must NOT be detected — that string
	// is intentionally not a detection signal.
	body := `<html><body>
<p>Path: /GC3/glog.webserver.servlet.umt.Login</p>
<p>Error: 404 Not Found</p>
</body></html>`

	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	assert.Nil(t, result, "probe path reflection must not trigger detection")
}

func TestOracleOTMFingerprinter_Fingerprint_GenericNegative(t *testing.T) {
	// Generic non-OTM page: no markers at all → nil.
	body := `<html><head><title>Welcome</title></head>
<body><p>Hello, world!</p></body></html>`

	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestOracleOTMFingerprinter_Fingerprint_EmptyBody(t *testing.T) {
	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(""))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestOracleOTMFingerprinter_Fingerprint_CopyrightExtraction(t *testing.T) {
	// Verify copyright_year and version_note keys when footer contains end-year 2016.
	// Body uses the HTML-entity form from the live capture.
	body := `<html><head><title>Oracle Logistics</title></head>
<body>
<div class="copyright">Copyright &#169 2001&#44; 2016&#44; Oracle and/or its affiliates.</div>
</body></html>`

	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "2016", result.Metadata["copyright_year"])
	assert.NotEmpty(t, result.Metadata["version_note"])
}

func TestOracleOTMFingerprinter_Fingerprint_CopyrightExtractionThreeYears(t *testing.T) {
	// Three comma-separated years — the regex must skip all leading years and
	// capture the last one (2016).
	body := `<html><head><title>Oracle Logistics</title></head>
<body>
<div class="copyright">Copyright &#169 2001&#44; 2010&#44; 2016&#44; Oracle and/or its affiliates.</div>
</body></html>`

	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "2016", result.Metadata["copyright_year"])
	assert.NotEmpty(t, result.Metadata["version_note"])
}

func TestOracleOTMFingerprinter_Fingerprint_NoCopyright(t *testing.T) {
	// Detection signal present but no copyright footer → no copyright_year / version_note keys.
	body := `<html><head><title>Oracle Logistics</title></head>
<body><p>Sign in.</p></body></html>`

	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	_, hasCopyrightYear := result.Metadata["copyright_year"]
	_, hasVersionNote := result.Metadata["version_note"]
	assert.False(t, hasCopyrightYear, "no copyright footer → copyright_year must be absent")
	assert.False(t, hasVersionNote, "no copyright footer → version_note must be absent")
}

func TestOracleOTMFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	// Body larger than 2 MiB → (nil, nil) even with valid markers present.
	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	// Build a body just over the 2 MiB cap that would otherwise match.
	// We place the frame_servlet marker at the very beginning, but the cap
	// check runs before any scanning, so the result must still be nil.
	marker := "glog.webserver.util.FrameGC3Servlet"
	bigBody := []byte(marker + strings.Repeat("x", 2*1024*1024+1))

	result, err := fp.Fingerprint(resp, bigBody)
	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestOracleOTMFingerprinter_Fingerprint_CPEFormat(t *testing.T) {
	// CPE sanity: the returned CPE must equal the wildcard string exactly.
	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(otmLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)

	require.Len(t, result.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:oracle:transportation_management:*:*:*:*:*:*:*:*", result.CPEs[0])
}

func TestOracleOTMFingerprinter_Fingerprint_VersionAlwaysEmpty(t *testing.T) {
	// OTM exposes no build number unauthenticated; Version is always "".
	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(otmLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "", result.Version)
}

func TestOracleOTMFingerprinter_Fingerprint_MetadataVendorProduct(t *testing.T) {
	// Metadata always contains vendor, product, namespace, detection_method.
	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(otmLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "Oracle", result.Metadata["vendor"])
	assert.Equal(t, "Oracle Transportation Management", result.Metadata["product"])
	assert.Equal(t, "GC3", result.Metadata["namespace"])
	assert.NotEmpty(t, result.Metadata["detection_method"])
}

// ── Severity / SecurityFindings ──────────────────────────────────────────────

func TestOracleOTMFingerprinter_NoSeverityOrFindings(t *testing.T) {
	// This fingerprinter does not set Severity or SecurityFindings.
	fp := &OracleOTMFingerprinter{}
	resp := makeOTMResponse()

	result, err := fp.Fingerprint(resp, []byte(otmLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "fingerprinter-only: Severity must be unset")
	assert.Nil(t, result.SecurityFindings, "fingerprinter-only: no SecurityFindings")
}

// ── buildOracleOTMCPE ────────────────────────────────────────────────────────

func TestBuildOracleOTMCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "empty version → wildcard",
			version:  "",
			expected: "cpe:2.3:a:oracle:transportation_management:*:*:*:*:*:*:*:*",
		},
		{
			name:     "colon in version → sanitized to wildcard",
			version:  "1:2",
			expected: "cpe:2.3:a:oracle:transportation_management:*:*:*:*:*:*:*:*",
		},
		{
			name:     "asterisk in version → sanitized to wildcard",
			version:  "1.*",
			expected: "cpe:2.3:a:oracle:transportation_management:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildOracleOTMCPE(tt.version))
		})
	}
}

// ── Integration: Match + Fingerprint ─────────────────────────────────────────

func TestOracleOTMFingerprinter_Integration_Positive(t *testing.T) {
	fp := &OracleOTMFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html; charset=UTF-8")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(otmLoginPage))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle_otm", result.Technology)
	assert.Equal(t, "", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:oracle:transportation_management:*:*:*:*:*:*:*:*")
}

func TestOracleOTMFingerprinter_Integration_NonOTM(t *testing.T) {
	fp := &OracleOTMFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte("<html><body><h1>Hello</h1></body></html>"))
	require.NoError(t, err)
	assert.Nil(t, result)
}
