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

// ── Name ──────────────────────────────────────────────────────────────────────

func TestWebminFingerprinter_Name(t *testing.T) {
	fp := &WebminFingerprinter{}
	assert.Equal(t, "webmin", fp.Name())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestWebminFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		server      string
		contentType string
		want        bool
	}{
		{
			name:       "Server MiniServ/2.104 returns true",
			statusCode: 200,
			server:     "MiniServ/2.104",
			want:       true,
		},
		{
			name:       "Server MiniServ bare returns true",
			statusCode: 200,
			server:     "MiniServ",
			want:       true,
		},
		{
			name:       "Server miniserv/1.910 lowercase returns true",
			statusCode: 200,
			server:     "miniserv/1.910",
			want:       true,
		},
		{
			name:        "Server Apache/2.4 with text/html returns true (body fallback path)",
			statusCode:  200,
			server:      "Apache/2.4",
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "Server Apache/2.4 with application/json returns false",
			statusCode:  200,
			server:      "Apache/2.4",
			contentType: "application/json",
			want:        false,
		},
		{
			name:       "no Server no Content-Type returns false",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "status 500 with MiniServ returns false",
			statusCode: 500,
			server:     "MiniServ/2.104",
			want:       false,
		},
		{
			name:       "Server MiniServProxy without text/html returns false",
			statusCode: 200,
			server:     "MiniServProxy/1.0",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &WebminFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint: valid detections ────────────────────────────────────────────

const webminLoginBody = `<html><head><title>Login to Webmin</title></head>
<body>
<form action="/session_login.cgi" method="post">
<input name="user" type="text" size="20">
<input name="pass" type="password" size="20">
<input type="submit" value="Login">
<input type="hidden" name="page" value="/">
</form>
</body></html>`

const userminLoginBody = `<html><head><title>Login to Usermin</title></head>
<body>
<form action="/session_login.cgi" method="post">
<input name="user" type="text" size="20">
<input name="pass" type="password" size="20">
<input type="submit" value="Login">
<input type="hidden" name="page" value="/">
</form>
</body></html>`

func TestWebminFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		server      string
		body        string
		wantTech    string
		wantVersion string
	}{
		{
			name:        "MiniServ/2.104 with Webmin login body yields webmin 2.104",
			statusCode:  200,
			server:      "MiniServ/2.104",
			body:        webminLoginBody,
			wantTech:    "webmin",
			wantVersion: "2.104",
		},
		{
			name:        "MiniServ/1.910 with Usermin login body yields usermin 1.910",
			statusCode:  200,
			server:      "MiniServ/1.910",
			body:        userminLoginBody,
			wantTech:    "usermin",
			wantVersion: "1.910",
		},
		{
			name:        "MiniServ bare (no version) with Webmin login body yields webmin empty version",
			statusCode:  200,
			server:      "MiniServ",
			body:        webminLoginBody,
			wantTech:    "webmin",
			wantVersion: "",
		},
		{
			name:        "MiniServ/2.104 with no login title in body yields webmin default",
			statusCode:  200,
			server:      "MiniServ/2.104",
			body:        `<html><body>Some other content</body></html>`,
			wantTech:    "webmin",
			wantVersion: "2.104",
		},
		{
			name:       "body-only detection: no MiniServ header, Login to Webmin + session_login.cgi",
			statusCode: 200,
			body:       webminLoginBody,
			wantTech:   "webmin",
		},
		{
			name:       "body-only detection: no MiniServ header, Login to Usermin + session_login.cgi",
			statusCode: 200,
			body:       userminLoginBody,
			wantTech:   "usermin",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &WebminFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, tt.wantTech, result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)

			// Mandatory: no severity, no security findings for a fingerprinter-only capability.
			assert.Empty(t, result.Severity)
			assert.Empty(t, result.SecurityFindings)
		})
	}
}

// ── Fingerprint: invalid / negative cases ────────────────────────────────────

func TestWebminFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		server     string
		body       string
	}{
		{
			name:       "empty body, no MiniServ header",
			statusCode: 200,
			body:       "",
		},
		{
			name:       "generic HTML, no MiniServ header",
			statusCode: 200,
			body:       `<html><head><title>Welcome</title></head><body>Hello world</body></html>`,
		},
		{
			name:       "Login to Webmin present but no session_login.cgi (without MiniServ header)",
			statusCode: 200,
			body:       `<html><head><title>Login to Webmin</title></head><body>No form here</body></html>`,
		},
		{
			name:       "session_login.cgi present but no login title (without MiniServ header)",
			statusCode: 200,
			body:       `<html><body><form action="/session_login.cgi" method="post"></form></body></html>`,
		},
		{
			name:       "status 500 with MiniServ header and valid body",
			statusCode: 500,
			server:     "MiniServ/2.104",
			body:       webminLoginBody,
		},
		{
			name:       "Server header MiniServProxy (prefix match, not MiniServ) rejected",
			statusCode: 200,
			server:     "MiniServProxy/1.0",
			body:       `<html><body>Proxy landing page</body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &WebminFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ── Version extraction ───────────────────────────────────────────────────────

func TestWebminFingerprinter_VersionExtraction(t *testing.T) {
	tests := []struct {
		name         string
		serverHeader string
		want         string
	}{
		{
			name:         "MiniServ/2.104",
			serverHeader: "MiniServ/2.104",
			want:         "2.104",
		},
		{
			name:         "MiniServ/1.910",
			serverHeader: "MiniServ/1.910",
			want:         "1.910",
		},
		{
			name:         "MiniServ/2.104.1 three-part version",
			serverHeader: "MiniServ/2.104.1",
			want:         "2.104.1",
		},
		{
			name:         "MiniServ bare (no version)",
			serverHeader: "MiniServ",
			want:         "",
		},
		{
			name:         "MiniServ/2.104abc trailing chars rejected",
			serverHeader: "MiniServ/2.104abc",
			want:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractWebminVersion(tt.serverHeader))
		})
	}
}

// ── CPE building ──────────────────────────────────────────────────────────────

func TestBuildWebminCPE(t *testing.T) {
	tests := []struct {
		name    string
		product string
		version string
		want    string
	}{
		{
			name:    "webmin with version",
			product: "webmin",
			version: "2.104",
			want:    "cpe:2.3:a:webmin:webmin:2.104:*:*:*:*:*:*:*",
		},
		{
			name:    "usermin with version",
			product: "usermin",
			version: "1.910",
			want:    "cpe:2.3:a:webmin:usermin:1.910:*:*:*:*:*:*:*",
		},
		{
			name:    "webmin without version uses wildcard",
			product: "webmin",
			version: "",
			want:    "cpe:2.3:a:webmin:webmin:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version containing colon uses wildcard",
			product: "webmin",
			version: "2.104:injected",
			want:    "cpe:2.3:a:webmin:webmin:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version containing asterisk uses wildcard",
			product: "webmin",
			version: "2.104*",
			want:    "cpe:2.3:a:webmin:webmin:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version containing question mark uses wildcard",
			product: "webmin",
			version: "2.10?",
			want:    "cpe:2.3:a:webmin:webmin:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildWebminCPE(tt.product, tt.version))
		})
	}
}

// ── Body cap ──────────────────────────────────────────────────────────────────

func TestWebminFingerprinter_BodyCap(t *testing.T) {
	fp := &WebminFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	// Padding pushes the title marker beyond the 1 MiB cap so it must not be seen.
	padding := strings.Repeat("a", 1<<20)
	body := padding + webminLoginBody

	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ── Severity / SecurityFindings ──────────────────────────────────────────────

func TestWebminFingerprinter_SeverityAndFindingsUnset(t *testing.T) {
	fp := &WebminFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "MiniServ/2.104")

	result, err := fp.Fingerprint(resp, []byte(webminLoginBody))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Empty(t, result.Severity)
	assert.Empty(t, result.SecurityFindings)
}

// ── Passive interface check ──────────────────────────────────────────────────

func TestWebminFingerprinter_PassiveInterface(t *testing.T) {
	var _ HTTPFingerprinter = (*WebminFingerprinter)(nil)
}

// ── Integration: Match + Fingerprint round-trip ─────────────────────────────

func TestWebminFingerprinter_Integration(t *testing.T) {
	fp := &WebminFingerprinter{}

	t.Run("positive Webmin login page", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Server", "MiniServ/2.104")
		resp.Header.Set("Content-Type", "text/html; Charset=UTF-8")

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, []byte(webminLoginBody))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "webmin", result.Technology)
		assert.Equal(t, "2.104", result.Version)
		assert.Equal(t, "Webmin", result.Metadata["vendor"])
		assert.Equal(t, "Webmin", result.Metadata["product"])
		assert.Equal(t, "MiniServ/2.104", result.Metadata["server_header"])
		assert.NotEmpty(t, result.CPEs)
		assert.Equal(t, "cpe:2.3:a:webmin:webmin:2.104:*:*:*:*:*:*:*", result.CPEs[0])
		assert.Empty(t, result.Severity)
	})

	t.Run("positive Usermin login page", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Server", "MiniServ/1.910")

		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, []byte(userminLoginBody))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "usermin", result.Technology)
		assert.Equal(t, "1.910", result.Version)
		assert.Equal(t, "Usermin", result.Metadata["product"])
		assert.NotEmpty(t, result.CPEs)
		assert.Equal(t, "cpe:2.3:a:webmin:usermin:1.910:*:*:*:*:*:*:*", result.CPEs[0])
	})

	t.Run("negative generic server", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Server", "Apache/2.4.51")
		resp.Header.Set("Content-Type", "text/html")

		require.True(t, fp.Match(resp))

		body := `<html><head><title>Welcome to Apache</title></head><body>It works!</body></html>`
		result, err := fp.Fingerprint(resp, []byte(body))
		require.NoError(t, err)
		assert.Nil(t, result)
	})
}
