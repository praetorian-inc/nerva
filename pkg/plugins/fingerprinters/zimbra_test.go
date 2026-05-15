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
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// zimbraLoginPageBody is a realistic Zimbra login page HTML used across multiple tests.
const zimbraLoginPageBody = `<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html;charset=utf-8">
<title>Zimbra Web Client Sign In</title>
<script>
var zimbraCacheBusterVersion = "8.8.15";
</script>
<link rel="stylesheet" href="/zimbra/css/skin.css?v=8.8.15">
</head>
<body class="ZLoginForm">
<div id="ZLoginPanel">
<form id="loginForm" method="post" action="/zimbra/">
<input type="text" id="username" name="os_username">
<input type="password" id="password" name="os_password">
<input type="submit" value="Sign In">
</form>
<div class="footer">Copyright &copy; Zimbra, Inc. All rights reserved.</div>
</div>
</body>
</html>`

// makeZimbraResp constructs a minimal *http.Response for testing.
// headers values are set with Header.Set (last write wins per key).
// For multiple Set-Cookie values, use multiple "Set-Cookie" calls via
// resp.Header.Add after construction, or rely on the test body setting them.
func makeZimbraResp(statusCode int, headers map[string]string, body string) *http.Response {
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
	}
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	return resp
}

// ── Name ──────────────────────────────────────────────────────────────────────

func TestZimbraFingerprinter_Name(t *testing.T) {
	fp := &ZimbraFingerprinter{}
	assert.Equal(t, "zimbra", fp.Name())
}

// ── ProbeEndpoint ─────────────────────────────────────────────────────────────

func TestZimbraFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ZimbraFingerprinter{}
	assert.Equal(t, "/zimbra/", fp.ProbeEndpoint())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestZimbraFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		headers    map[string]string
		cookie     string // value for extra Set-Cookie header
		want       bool
	}{
		{
			name:       "200 with ZM_TEST cookie",
			statusCode: 200,
			cookie:     "ZM_TEST=true; Path=/",
			want:       true,
		},
		{
			name:       "200 with text/html Content-Type",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			want:       true,
		},
		{
			name:       "302 with ZM_AUTH_TOKEN cookie",
			statusCode: 302,
			cookie:     "ZM_AUTH_TOKEN=abc123; Path=/",
			want:       true,
		},
		{
			name:       "404 with text/html",
			statusCode: 404,
			headers:    map[string]string{"Content-Type": "text/html"},
			want:       true,
		},
		{
			name:       "500 rejected",
			statusCode: 500,
			headers:    map[string]string{"Content-Type": "text/html"},
			want:       false,
		},
		{
			name:       "100 informational rejected",
			statusCode: 100,
			headers:    map[string]string{"Content-Type": "text/html"},
			want:       false,
		},
		{
			name:       "200 application/json no Zimbra cookie",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "application/json"},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ZimbraFingerprinter{}
			resp := makeZimbraResp(tt.statusCode, tt.headers, "")
			if tt.cookie != "" {
				resp.Header.Add("Set-Cookie", tt.cookie)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint: positive (valid) ─────────────────────────────────────────────

func TestZimbraFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		headers       map[string]string
		cookies       []string // additional Set-Cookie values
		body          string
		probePath     string
		wantVersion   string
		wantCPE       string
		wantDetection string
		wantProbePath bool
		wantZMCookies bool
	}{
		{
			name:          "Full Zimbra login page with version and ZM_TEST cookie",
			statusCode:    200,
			headers:       map[string]string{"Content-Type": "text/html"},
			cookies:       []string{"ZM_TEST=true; Path=/"},
			body:          zimbraLoginPageBody,
			wantVersion:   "8.8.15",
			wantCPE:       "cpe:2.3:a:zimbra:collaboration:8.8.15:*:*:*:*:*:*:*",
			wantDetection: "body",
			wantZMCookies: true,
		},
		{
			name:       "Cookie-only detection — ZM_TEST present, generic zimbra HTML",
			statusCode: 200,
			cookies:    []string{"ZM_TEST=1"},
			body: `<html><head><title>Zimbra</title></head>
<body><p>Please login</p></body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:zimbra:collaboration:*:*:*:*:*:*:*:*",
			wantDetection: "cookie",
			wantZMCookies: true,
		},
		{
			name:          "Active probe — request URL path /zimbra/",
			statusCode:    200,
			body:          zimbraLoginPageBody,
			probePath:     "/zimbra/",
			wantVersion:   "8.8.15",
			wantCPE:       "cpe:2.3:a:zimbra:collaboration:8.8.15:*:*:*:*:*:*:*",
			wantDetection: "active_probe",
			wantProbePath: true,
		},
		{
			name:       "zimbraCacheBusterVersion JS variable — version extracted",
			statusCode: 200,
			body: `<html><head><title>Zimbra Web Client Sign In</title>
<script>var zimbraCacheBusterVersion = "9.0.0";</script>
</head><body class="ZLoginForm"></body></html>`,
			wantVersion:   "9.0.0",
			wantCPE:       "cpe:2.3:a:zimbra:collaboration:9.0.0:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "Script src with ?v= pattern — version extracted",
			statusCode: 200,
			body: `<html><head><title>Zimbra Web Client Sign In</title>
<link rel="stylesheet" href="/zimbra/css/skin.css?v=8.8.12">
</head><body class="ZLoginForm"></body></html>`,
			wantVersion:   "8.8.12",
			wantCPE:       "cpe:2.3:a:zimbra:collaboration:8.8.12:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "CLIENT_VERSION pattern — version extracted",
			statusCode: 200,
			body: `<html><head><title>Zimbra Web Client Sign In</title>
<script>var CLIENT_VERSION = "8.6.0";</script>
</head><body class="ZLoginForm"></body></html>`,
			wantVersion:   "8.6.0",
			wantCPE:       "cpe:2.3:a:zimbra:collaboration:8.6.0:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "Body with Zimbra Web Client text — detected",
			statusCode: 200,
			body: `<html><head><title>Zimbra Web Client Sign In</title>
</head><body><p>Zimbra Web Client</p></body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:zimbra:collaboration:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "Body with zimbramail JS reference — detected",
			statusCode: 200,
			body: `<html><head></head>
<body><script src="/zimbra/js/zimbraMail.js"></script></body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:zimbra:collaboration:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "zimbraCacheBusterVersion takes priority over script src version",
			statusCode: 200,
			body: `<html><head><title>Zimbra Web Client Sign In</title>
<script>var zimbraCacheBusterVersion = "8.8.15";</script>
<link href="/zimbra/css/skin.css?v=8.8.12">
</head><body class="ZLoginForm"></body></html>`,
			wantVersion:   "8.8.15",
			wantCPE:       "cpe:2.3:a:zimbra:collaboration:8.8.15:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ZimbraFingerprinter{}
			resp := makeZimbraResp(tt.statusCode, tt.headers, tt.body)
			for _, c := range tt.cookies {
				resp.Header.Add("Set-Cookie", c)
			}
			if tt.probePath != "" {
				resp.Request = &http.Request{URL: &url.URL{Path: tt.probePath}}
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result, "Fingerprint() should return a non-nil result")

			assert.Equal(t, "zimbra", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			require.NotEmpty(t, result.CPEs)
			assert.Equal(t, tt.wantCPE, result.CPEs[0])
			require.NotNil(t, result.Metadata)

			if tt.wantDetection != "" {
				assert.Equal(t, tt.wantDetection, result.Metadata["detection_method"])
			}
			if tt.wantProbePath {
				assert.Equal(t, "/zimbra/", result.Metadata["probe_path"])
			} else {
				assert.NotContains(t, result.Metadata, "probe_path",
					"probe_path should be absent for non-active-probe responses")
			}
			if tt.wantZMCookies {
				assert.Equal(t, true, result.Metadata["zm_cookies"])
			}
		})
	}
}

// ── Fingerprint: negative (invalid — must return nil) ─────────────────────────

func TestZimbraFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		headers    map[string]string
		cookies    []string
		body       string
	}{
		{
			name:       "Empty body, no cookies",
			statusCode: 200,
			body:       "",
		},
		{
			name:       "Body with just 'email' — no Zimbra",
			statusCode: 200,
			body: `<html><head><title>Sign In</title></head>
<body><form><input type="email" name="email"></form></body></html>`,
		},
		{
			name:       "Body > 2 MiB rejected",
			statusCode: 200,
			body:       "Zimbra Web Client" + string(make([]byte, 2*1024*1024+1)),
		},
		{
			name:       "CPE injection in body — :*: present",
			statusCode: 200,
			body:       `<html><head><title>Zimbra Web Client Sign In</title><script>var zimbraCacheBusterVersion = "8.8.15:*:malicious";</script></head><body class="ZLoginForm"></body></html>`,
		},
		{
			name:       "Status 500 rejected",
			statusCode: 500,
			body:       zimbraLoginPageBody,
		},
		{
			name:       "WordPress login page",
			statusCode: 200,
			body: `<html><head><title>Log In — WordPress</title></head>
<body id="login"><form name="loginform" action="/wp-login.php" method="post">
<input type="text" name="log" /><input type="password" name="pwd" />
</form></body></html>`,
		},
		{
			name:       "nginx default page",
			statusCode: 200,
			body: `<html>
<head><title>Welcome to nginx!</title></head>
<body><h1>Welcome to nginx!</h1>
<p>If you see this page, the nginx web server is successfully installed.</p>
</body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ZimbraFingerprinter{}
			resp := makeZimbraResp(tt.statusCode, tt.headers, tt.body)
			for _, c := range tt.cookies {
				resp.Header.Add("Set-Cookie", c)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result, "Fingerprint() should return nil for non-Zimbra response")
		})
	}
}

// ── TestExtractZimbraVersion ──────────────────────────────────────────────────

func TestExtractZimbraVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "zimbraCacheBusterVersion extraction",
			body: `var zimbraCacheBusterVersion = "8.8.15";`,
			want: "8.8.15",
		},
		{
			name: "zimbraCacheBusterVersion with single quotes",
			body: `var zimbraCacheBusterVersion = '9.0.0';`,
			want: "9.0.0",
		},
		{
			name: "Script src with ?v= extraction",
			body: `/zimbra/css/skin.css?v=8.8.12`,
			want: "8.8.12",
		},
		{
			name: "CLIENT_VERSION extraction",
			body: `var CLIENT_VERSION = "8.6.0";`,
			want: "8.6.0",
		},
		{
			name: "zimbraCacheBusterVersion takes priority over script src",
			body: `var zimbraCacheBusterVersion = "8.8.15"; /zimbra/js/zm.js?v=8.8.12`,
			want: "8.8.15",
		},
		{
			name: "Script src takes priority over CLIENT_VERSION",
			body: `/zimbra/js/zm.js?v=8.8.12 var CLIENT_VERSION = "8.6.0";`,
			want: "8.8.12",
		},
		{
			name: "No version in body",
			body: `<html><head><title>Zimbra Web Client Sign In</title></head></html>`,
			want: "",
		},
		{
			name: "GA suffix stripped by extraction regex — captures digits only",
			body: `var zimbraCacheBusterVersion = "8.8.15_GA_4179";`,
			want: "8.8.15",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractZimbraVersion([]byte(tt.body)))
		})
	}
}

// ── TestBuildZimbraCPE ────────────────────────────────────────────────────────

func TestBuildZimbraCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Version 8.8.15",
			version: "8.8.15",
			want:    "cpe:2.3:a:zimbra:collaboration:8.8.15:*:*:*:*:*:*:*",
		},
		{
			name:    "Version 9.0.0",
			version: "9.0.0",
			want:    "cpe:2.3:a:zimbra:collaboration:9.0.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:zimbra:collaboration:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildZimbraCPE(tt.version))
		})
	}
}

// ── TestHasZimbraCookie ───────────────────────────────────────────────────────

func TestHasZimbraCookie(t *testing.T) {
	tests := []struct {
		name    string
		cookies []string
		want    bool
	}{
		{
			name:    "ZM_TEST cookie present",
			cookies: []string{"ZM_TEST=true; Path=/"},
			want:    true,
		},
		{
			name:    "ZM_AUTH_TOKEN cookie present",
			cookies: []string{"ZM_AUTH_TOKEN=abc123; HttpOnly"},
			want:    true,
		},
		{
			name:    "Both cookies present",
			cookies: []string{"ZM_TEST=1", "ZM_AUTH_TOKEN=xyz"},
			want:    true,
		},
		{
			name:    "zm_test lowercase still matches (case-insensitive)",
			cookies: []string{"zm_test=1"},
			want:    true,
		},
		{
			name:    "No Zimbra cookies",
			cookies: []string{"PHPSESSID=abc123; Path=/"},
			want:    false,
		},
		{
			name:    "Empty cookies",
			cookies: nil,
			want:    false,
		},
		{
			name:    "Unrelated cookie with 'zimbra' in value but not name",
			cookies: []string{"session=zimbra_user"},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{Header: make(http.Header)}
			for _, c := range tt.cookies {
				resp.Header.Add("Set-Cookie", c)
			}
			assert.Equal(t, tt.want, hasZimbraCookie(resp))
		})
	}
}

// ── Integration test ──────────────────────────────────────────────────────────

func TestZimbraFingerprinter_Integration(t *testing.T) {
	// Save and restore global state to prevent test pollution.
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &ZimbraFingerprinter{}
	Register(fp)

	resp := makeZimbraResp(200, map[string]string{"Content-Type": "text/html"}, "")
	resp.Request = &http.Request{URL: &url.URL{Path: "/zimbra/"}}

	results := RunFingerprinters(resp, []byte(zimbraLoginPageBody))

	found := false
	for _, result := range results {
		if result.Technology == "zimbra" {
			found = true
			assert.Equal(t, "8.8.15", result.Version)
			require.NotEmpty(t, result.CPEs)
			assert.Equal(t, "cpe:2.3:a:zimbra:collaboration:8.8.15:*:*:*:*:*:*:*", result.CPEs[0])
			assert.Equal(t, "Zimbra", result.Metadata["vendor"])
			assert.Equal(t, "Collaboration", result.Metadata["product"])
		}
	}

	assert.True(t, found, "ZimbraFingerprinter not found in RunFingerprinters results")
}
