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

func TestAPCNMCFingerprinter_Name(t *testing.T) {
	fp := &APCNMCFingerprinter{}
	assert.Equal(t, "apc-nmc", fp.Name())
}

func TestAPCNMCFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &APCNMCFingerprinter{}
	assert.Equal(t, "/logon.htm", fp.ProbeEndpoint())
}

func TestAPCNMCFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 text/html returns true",
			statusCode:  200,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "200 text/html;charset=utf-8 returns true",
			statusCode:  200,
			contentType: "text/html;charset=utf-8",
			want:        true,
		},
		{
			name:        "200 TEXT/HTML uppercase returns true",
			statusCode:  200,
			contentType: "TEXT/HTML",
			want:        true,
		},
		{
			name:        "200 application/json returns false",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "200 no content-type returns false",
			statusCode:  200,
			contentType: "",
			want:        false,
		},
		{
			name:        "404 text/html returns true",
			statusCode:  404,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "500 text/html returns false",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &APCNMCFingerprinter{}
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

func TestAPCNMCFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		body       string
	}{
		{
			name:       "title signal only, no cookie",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<html><head><title>APC | Log On</title></head><body>` +
				`<form name="frmLogin" method="POST" action="/Forms/login1"></form></body></html>`,
		},
		{
			name:       "title signal with whitespace/casing variance",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<html><head><title>apc  |  log on</title></head><body>Welcome</body></html>`,
		},
		{
			name:       "error page signal only, no title",
			statusCode: 404,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<html><body>The requested URL was not found on the APC Management Web Server.</body></html>`,
		},
		{
			name:       "cookie + brand corroborated signal, no title",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
				"Set-Cookie":   []string{"C0=apc; path=/"},
			},
			body: `<html><body>Welcome to the APC device management portal.</body></html>`,
		},
		{
			name:       "all signals present together",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
				"Set-Cookie":   []string{"C0=apc; path=/"},
			},
			body: `<html><head><title>APC | Log On</title></head><body>` +
				`APC Management Web Server. This is an APC device.` +
				`</body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &APCNMCFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.headers,
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "apc-nmc", result.Technology)
			assert.Empty(t, result.Version)
			assert.Nil(t, result.SecurityFindings)
			assert.Empty(t, result.Severity)

			assert.Equal(t, "APC", result.Metadata["vendor"])
			assert.Equal(t, "Network Management Card", result.Metadata["product"])
		})
	}
}

func TestAPCNMCFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		body       string
	}{
		{
			name:       "non-HTML body without markers",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"application/json"},
			},
			body: `{"status": "ok"}`,
		},
		{
			name:       "empty body",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: "",
		},
		{
			name:       "generic HTML without APC markers",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<html><head><title>Company Login</title></head><body><form action="/login">Login</form></body></html>`,
		},
		{
			name:       "cookie C0=apc alone without APC brand in body requires corroboration",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
				"Set-Cookie":   []string{"C0=apc; path=/"},
			},
			body: `<html><body>Welcome to the device management portal.</body></html>`,
		},
		{
			name:       "APC brand in body alone without title, cookie, or error page",
			statusCode: 200,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<html><body>APC routers were affected by a critical vulnerability.</body></html>`,
		},
		{
			name:       "500 server error rejected",
			statusCode: 500,
			headers: http.Header{
				"Content-Type": []string{"text/html"},
			},
			body: `<html><head><title>APC | Log On</title></head><body>Error</body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &APCNMCFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.headers,
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// TestAPCNMCFingerprinter_Fingerprint_BodyCapExceeded verifies that the title
// marker is not detected when it falls beyond the 1 MiB body truncation cap.
func TestAPCNMCFingerprinter_Fingerprint_BodyCapExceeded(t *testing.T) {
	fp := &APCNMCFingerprinter{}

	padding := strings.Repeat("A", apcNMCMaxBodySize+1024)
	body := padding + `<html><head><title>APC | Log On</title></head></html>`

	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/html"},
		},
	}

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestAPCNMCFingerprinter_BuildCPEs(t *testing.T) {
	cpes := buildAPCNMCCPEs()
	require.Len(t, cpes, 2)
	assert.Contains(t, cpes, "cpe:2.3:o:schneider-electric:network_management_card_2_firmware:*:*:*:*:*:*:*:*")
	assert.Contains(t, cpes, "cpe:2.3:o:schneider-electric:network_management_card_3_firmware:*:*:*:*:*:*:*:*")
}

func TestAPCNMCFingerprinter_MetadataCookieFingerprint(t *testing.T) {
	fp := &APCNMCFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/html"},
			"Set-Cookie":   []string{"C0=apc; path=/"},
		},
	}
	body := `<html><head><title>APC | Log On</title></head><body>APC device</body></html>`

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "C0=apc", result.Metadata["cookie_fingerprint"])
}

func TestAPCNMCFingerprinter_MetadataNoCookieFingerprintWhenAbsent(t *testing.T) {
	fp := &APCNMCFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/html"},
		},
	}
	body := `<html><head><title>APC | Log On</title></head><body>Welcome</body></html>`

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)
	_, ok := result.Metadata["cookie_fingerprint"]
	assert.False(t, ok)
}

// TestAPCNMCFingerprinter_ActiveInterface verifies that APCNMCFingerprinter
// implements the ActiveHTTPFingerprinter interface.
func TestAPCNMCFingerprinter_ActiveInterface(t *testing.T) {
	var _ ActiveHTTPFingerprinter = (*APCNMCFingerprinter)(nil)
}

// TestAPCNMCFingerprinter_Integration_MatchAndFingerprint exercises Match and
// Fingerprint together against a realistic APC NMC login page response.
func TestAPCNMCFingerprinter_Integration_MatchAndFingerprint(t *testing.T) {
	fp := &APCNMCFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type":  []string{"text/html"},
			"Cache-Control": []string{"no-cache"},
			"Set-Cookie":    []string{"C0=apc; path=/"},
		},
	}
	body := `<html><head><title>APC | Log On</title></head>
<body>
<form name="frmLogin" method="POST" action="/Forms/login1">
<input name="login_username" type="text">
<input name="login_password" type="password">
<input type="submit" value="Log On">
</form>
</body></html>`

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "apc-nmc", result.Technology)
	assert.Empty(t, result.Version)
	require.Len(t, result.CPEs, 2)
	assert.Contains(t, result.CPEs, "cpe:2.3:o:schneider-electric:network_management_card_2_firmware:*:*:*:*:*:*:*:*")
	assert.Contains(t, result.CPEs, "cpe:2.3:o:schneider-electric:network_management_card_3_firmware:*:*:*:*:*:*:*:*")
	assert.Equal(t, "C0=apc", result.Metadata["cookie_fingerprint"])
	assert.Nil(t, result.SecurityFindings)
	assert.Empty(t, result.Severity)
}

// TestAPCNMCFingerprinter_Integration_NonAPCHTML verifies that a generic,
// non-APC HTML response produces no detection.
func TestAPCNMCFingerprinter_Integration_NonAPCHTML(t *testing.T) {
	fp := &APCNMCFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header: http.Header{
			"Content-Type": []string{"text/html"},
		},
	}
	body := `<html><head><title>Generic Router Admin</title></head>
<body><form action="/login">Username: <input name="user"></form></body></html>`

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	assert.Nil(t, result)
}
