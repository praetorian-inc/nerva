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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMikroTikFingerprinter_Name(t *testing.T) {
	fp := &MikroTikFingerprinter{}
	assert.Equal(t, "mikrotik-routeros", fp.Name())
}

func TestMikroTikFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		statusCode int
		expected   bool
	}{
		{
			name:       "matches HTML content type",
			headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "matches HTML with 302 redirect",
			headers:    map[string]string{"Content-Type": "text/html"},
			statusCode: 302,
			expected:   true,
		},
		{
			name:       "matches HTML with 401 auth required",
			headers:    map[string]string{"Content-Type": "text/html"},
			statusCode: 401,
			expected:   true,
		},
		{
			name:       "rejects 500 server error",
			headers:    map[string]string{"Content-Type": "text/html"},
			statusCode: 500,
			expected:   false,
		},
		{
			name:       "rejects non-HTML content type",
			headers:    map[string]string{"Content-Type": "application/json"},
			statusCode: 200,
			expected:   false,
		},
		{
			name:       "rejects binary content type",
			headers:    map[string]string{"Content-Type": "application/octet-stream"},
			statusCode: 200,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MikroTikFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     header,
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestMikroTikFingerprinter_Fingerprint_WebFigPage(t *testing.T) {
	body := []byte(`<html>
<head><title>RouterOS</title></head>
<body>
<script>var link = '/webfig/#';</script>
<div id="webfig">Loading...</div>
</body>
</html>`)

	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html; charset=utf-8")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "mikrotik-routeros", result.Technology)
	assert.Equal(t, "MikroTik", result.Metadata["vendor"])
	assert.Equal(t, "RouterOS", result.Metadata["product"])
	assert.Equal(t, "webfig", result.Metadata["management_interface"])
	assert.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], "mikrotik:routeros:")
}

func TestMikroTikFingerprinter_Fingerprint_RouterOSTitle(t *testing.T) {
	// Title "MikroTik RouterOS" triggers mikrotik + routeros + title (3 generic signals)
	// but no exclusive signal (no webfig, no data-defaultuser). Under the new logic,
	// generic signals alone are insufficient — an exclusive signal is required.
	body := []byte(`<html>
<head><title>MikroTik RouterOS</title></head>
<body>
<p>Please log in to manage your router.</p>
</body>
</html>`)

	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestMikroTikFingerprinter_Fingerprint_VersionExtraction(t *testing.T) {
	body := []byte(`<html>
<head><title>RouterOS</title></head>
<body>
<p>RouterOS v7.14.3</p>
<script src="/webfig/RouterOS.js"></script>
</body>
</html>`)

	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "7.14.3", result.Version)
	assert.Equal(t, "cpe:2.3:o:mikrotik:routeros:7.14.3:*:*:*:*:*:*:*", result.CPEs[0])
}

func TestMikroTikFingerprinter_Fingerprint_NoMatch(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		body    []byte
		status  int
	}{
		{
			name:    "generic HTML page",
			headers: map[string]string{"Content-Type": "text/html"},
			body:    []byte(`<html><body>Hello World</body></html>`),
			status:  200,
		},
		{
			name:    "FortiGate login page",
			headers: map[string]string{"Content-Type": "text/html"},
			body: []byte(`<html><head><title>FortiGate Login</title></head>
<body><div id="loginpage"></div></body></html>`),
			status: 200,
		},
		{
			name:    "OPNsense page",
			headers: map[string]string{"Content-Type": "text/html", "Server": "OPNsense"},
			body:    []byte(`<html><head><title>Login | OPNsense</title></head></html>`),
			status:  200,
		},
		{
			name:    "empty body",
			headers: map[string]string{"Content-Type": "text/html"},
			body:    []byte{},
			status:  200,
		},
		{
			name:    "500 error with RouterOS content",
			headers: map[string]string{"Content-Type": "text/html"},
			body:    []byte(`<html><head><title>RouterOS</title></head></html>`),
			status:  500,
		},
		{
			name:    "single signal mikrotik mention only",
			headers: map[string]string{"Content-Type": "text/html"},
			body:    []byte(`<html><body><p>Powered by MikroTik</p></body></html>`),
			status:  200,
		},
		{
			name:    "blog post mentioning mikrotik is rejected",
			headers: map[string]string{"Content-Type": "text/html"},
			body:    []byte(`<html><head><title>Best Routers 2024</title></head><body><p>MikroTik makes great routers.</p></body></html>`),
			status:  200,
		},
		{
			name:    "single routeros signal only is rejected",
			headers: map[string]string{"Content-Type": "text/html"},
			body:    []byte(`<html><body><p>RouterOS is an operating system.</p></body></html>`),
			status:  200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MikroTikFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{
				StatusCode: tt.status,
				Header:     header,
			}

			result, err := fp.Fingerprint(resp, tt.body)
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestMikroTikFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &MikroTikFingerprinter{}
	assert.Equal(t, "/webfig/", fp.ProbeEndpoint())
}

func TestBuildMikroTikRouterOSCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "empty version uses wildcard",
			version:  "",
			expected: "cpe:2.3:o:mikrotik:routeros:*:*:*:*:*:*:*:*",
		},
		{
			name:     "specific version",
			version:  "7.14.3",
			expected: "cpe:2.3:o:mikrotik:routeros:7.14.3:*:*:*:*:*:*:*",
		},
		{
			name:     "two-part version",
			version:  "6.49",
			expected: "cpe:2.3:o:mikrotik:routeros:6.49:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildMikroTikRouterOSCPE(tt.version)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestMikroTikFingerprinter_Fingerprint_LoginFormSignal(t *testing.T) {
	// data-defaultuser is MikroTik-specific and survives custom branding.
	// Combined with "mikrotik" in the body, this satisfies the 2-signal requirement.
	body := []byte(`<html><body><form data-defaultuser="admin"><input type="password"/></form><p>MikroTik</p></body></html>`)
	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "mikrotik-routeros", result.Technology)
}

func TestMikroTikFingerprinter_Fingerprint_CaseInsensitiveTitle(t *testing.T) {
	// Uppercase TITLE tag must be detected by the case-insensitive title extractor.
	body := []byte(`<html><head><TITLE>MikroTik RouterOS</TITLE></head><body><div id="webfig"></div></body></html>`)
	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "mikrotik-routeros", result.Technology)
}

func TestMikroTikFingerprinter_Fingerprint_HotspotPage(t *testing.T) {
	// Simulates a hotspot page with mikrotik + routeros (2 generic signals) but no
	// exclusive signal (no webfig, no data-defaultuser). Under the new logic, generic
	// signals alone are insufficient — an exclusive signal is required.
	body := []byte(`<html><head><title>internet hotspot > login</title></head>
<body><img alt="mikrotik"><p>Powered by MikroTik RouterOS</p></body></html>`)
	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestMikroTikFingerprinter_Fingerprint_OldAdminPage(t *testing.T) {
	// Title contains both "mikrotik" and "routeros" — hasTitle is true.
	// Body also contains "mikrotik" and "routeros" — hasMikroTik + hasRouterOS also true.
	// However, all signals are generic (no webfig, no data-defaultuser), so under the
	// exclusive-signal requirement, this page does not match.
	body := []byte(`<html><head><title>mikrotik routeros > administration</title></head>
<body><div class="top">mikrotik routeros 6.49.17 configuration page</div></body></html>`)
	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestMikroTikFingerprinter_Fingerprint_SingleDataDefaultuserRejected(t *testing.T) {
	// Only data-defaultuser signal present — 1 signal is below the 2-signal threshold.
	body := []byte(`<html><body><form id="login"><input id="name" data-defaultuser="admin"><input id="password"></form></body></html>`)
	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestMikroTikFingerprinter_Fingerprint_DataDefaultuserPlusMikroTikMatches(t *testing.T) {
	// data-defaultuser + "mikrotik" in body = 2 signals — meets threshold.
	body := []byte(`<html><body><img src="mikrotik_logo.png"><form id="login"><input id="name" data-defaultuser="admin"></form></body></html>`)
	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "mikrotik-routeros", result.Technology)
}

func TestMikroTikFingerprinter_Fingerprint_302RedirectMinimalBodyRejected(t *testing.T) {
	// 302 redirect with minimal body — 0 signals, no match.
	// Match() returns true for 302 + text/html, but Fingerprint() requires 2 signals.
	body := []byte(`<html><body>Redirecting...</body></html>`)
	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 302,
		Header:     header,
	}
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestMikroTikFingerprinter_Fingerprint_SecurityBlogPostAcceptedRisk(t *testing.T) {
	// A security blog post about MikroTik CVEs has mikrotik + routeros + title (3 generic
	// signals) but no exclusive signal (webfig or data-defaultuser). Under the new logic,
	// generic signals alone are insufficient — an exclusive signal is required.
	body := []byte(`<html><head><title>CVE-2018-14847: MikroTik RouterOS Vulnerability</title></head>
<body><p>MikroTik RouterOS versions before 6.49.7 are vulnerable...</p></body></html>`)
	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestMikroTikFingerprinter_Fingerprint_LowercaseRouterOSVersionExtraction(t *testing.T) {
	// The version regex is case-insensitive but version extraction must use the original-case
	// bodyStr (not bodyLower) so the extracted version string has correct digit formatting.
	body := []byte(`<html><head><title>RouterOS</title></head><body><p>routeros v7.14.3</p><div id="webfig"></div></body></html>`)
	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	// Version must be extracted correctly even though "routeros" is lowercase in the body.
	assert.Equal(t, "7.14.3", result.Version)
}

func TestMikroTikFingerprinter_Fingerprint_GenericSignalsOnlyRejected(t *testing.T) {
	body := []byte(`<html><head><title>MikroTik RouterOS > Administration</title></head>
<body><p>Welcome to MikroTik RouterOS management</p></body></html>`)
	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{StatusCode: 200, Header: header}
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	assert.Nil(t, result, "generic signals (mikrotik + routeros + title) without exclusive signal should not match")
}

func TestMikroTikFingerprinter_Fingerprint_WebFigExclusivePlusGeneric(t *testing.T) {
	body := []byte(`<html><body><script src="/webfig/app.js"></script><p>mikrotik device</p></body></html>`)
	fp := &MikroTikFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{StatusCode: 200, Header: header}
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result, "exclusive signal (webfig) + generic signal (mikrotik) should match")
	assert.Equal(t, "mikrotik-routeros", result.Technology)
}

func TestMikroTikFingerprinter_Integration(t *testing.T) {
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &MikroTikFingerprinter{}
	Register(fp)

	body := []byte(`<html>
<head><title>RouterOS</title></head>
<body>
<script>
var link = '/webfig/#';
</script>
</body>
</html>`)

	header := http.Header{}
	header.Set("Content-Type", "text/html")

	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "mikrotik-routeros", results[0].Technology)
	assert.Equal(t, "MikroTik", results[0].Metadata["vendor"])
	assert.Equal(t, "webfig", results[0].Metadata["management_interface"])
}
