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

func TestOPNsenseFingerprinter_Name(t *testing.T) {
	fp := &OPNsenseFingerprinter{}
	assert.Equal(t, "opnsense", fp.Name())
}

func TestOPNsenseFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		statusCode int
		expected   bool
	}{
		{
			name:       "matches Server: OPNsense header",
			headers:    map[string]string{"Server": "OPNsense"},
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "matches Server header case-insensitive",
			headers:    map[string]string{"Server": "opnsense"},
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "matches HTML content type for body detection",
			headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "matches 302 redirect with OPNsense server",
			headers:    map[string]string{"Server": "OPNsense"},
			statusCode: 302,
			expected:   true,
		},
		{
			name:       "rejects 500 server error",
			headers:    map[string]string{"Server": "OPNsense"},
			statusCode: 500,
			expected:   false,
		},
		{
			name:       "rejects non-HTML without OPNsense server",
			headers:    map[string]string{"Server": "nginx", "Content-Type": "application/json"},
			statusCode: 200,
			expected:   false,
		},
		{
			name:       "rejects pfSense server header",
			headers:    map[string]string{"Server": "nginx"},
			statusCode: 200,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OPNsenseFingerprinter{}
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

func TestOPNsenseFingerprinter_Fingerprint_ServerHeader(t *testing.T) {
	// Server header alone is sufficient for detection.
	fp := &OPNsenseFingerprinter{}
	header := http.Header{}
	header.Set("Server", "OPNsense")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, []byte("<html></html>"))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "opnsense", result.Technology)
	assert.Equal(t, "OPNsense", result.Metadata["server_header"])
	assert.Equal(t, "Deciso B.V.", result.Metadata["vendor"])
	assert.NotEmpty(t, result.CPEs)
	assert.Contains(t, result.CPEs[0], "opnsense:opnsense:")
}

func TestOPNsenseFingerprinter_Fingerprint_LoginPage(t *testing.T) {
	body := []byte(`<html>
<head><title>Login | OPNsense</title></head>
<body class="page-login">
<div class="container">
  <main class="login-modal-container">
    <header class="login-modal-head" style="height:50px;">
      <div class="navbar-brand">
        <img src="/ui/themes/opnsense/build/images/default-logo.svg" height="30" alt="logo"/>
      </div>
    </header>
    <div class="login-modal-content">
      <form class="clearfix" id="iform" name="iform" method="post">
        <input id="usernamefld" type="text" name="usernamefld" class="form-control user"/>
        <input id="passwordfld" type="password" name="passwordfld" class="form-control pwd"/>
        <button type="submit" name="login" value="1" class="btn btn-primary pull-right">Login</button>
      </form>
    </div>
  </main>
  <div class="login-foot text-center">
    <a target="_blank" href="https://opnsense.org/">OPNsense</a> (c) 2014-2026
    <a target="_blank" href="https://www.deciso.com/">Deciso B.V.</a>
  </div>
</div>
</body>
</html>`)

	fp := &OPNsenseFingerprinter{}
	header := http.Header{}
	header.Set("Server", "OPNsense")
	header.Set("Content-Type", "text/html; charset=utf-8")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "opnsense", result.Technology)
	assert.Equal(t, "web-admin", result.Metadata["management_interface"])
	assert.Equal(t, "OPNsense", result.Metadata["server_header"])
}

func TestOPNsenseFingerprinter_Fingerprint_TitleOnly(t *testing.T) {
	body := []byte(`<html><head><title>Login | OPNsense</title></head><body></body></html>`)

	fp := &OPNsenseFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "opnsense", result.Technology)
}

func TestOPNsenseFingerprinter_Fingerprint_AssetPathOnly(t *testing.T) {
	body := []byte(`<html>
<head><link rel="stylesheet" href="/ui/themes/opnsense/build/css/main.css"/></head>
<body></body>
</html>`)

	fp := &OPNsenseFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "opnsense", result.Technology)
}

func TestOPNsenseFingerprinter_Fingerprint_JSPathOnly(t *testing.T) {
	body := []byte(`<html>
<head><script src="/ui/js/opnsense.js"></script></head>
<body></body>
</html>`)

	fp := &OPNsenseFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "opnsense", result.Technology)
}

func TestOPNsenseFingerprinter_Fingerprint_DecisoOnly(t *testing.T) {
	body := []byte(`<html><body>
<footer>OPNsense (c) 2014-2026 <a href="https://www.deciso.com/">Deciso B.V.</a></footer>
</body></html>`)

	fp := &OPNsenseFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "opnsense", result.Technology)
}

func TestOPNsenseFingerprinter_Fingerprint_CustomHostname(t *testing.T) {
	body := []byte(`<html><head><title>Login | fw01.corp.local</title></head>
<body class="page-login"><main class="login-modal-container"></main></body></html>`)

	fp := &OPNsenseFingerprinter{}
	header := http.Header{}
	header.Set("Server", "OPNsense")
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "fw01.corp.local", result.Metadata["hostname"])
}

func TestOPNsenseFingerprinter_Fingerprint_DefaultHostnameOmitted(t *testing.T) {
	body := []byte(`<html><head><title>Login | OPNsense</title></head>
<body><main class="login-modal-container"></main></body></html>`)

	fp := &OPNsenseFingerprinter{}
	header := http.Header{}
	header.Set("Server", "OPNsense")
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Nil(t, result.Metadata["hostname"])
}

func TestOPNsenseFingerprinter_Fingerprint_NoMatch(t *testing.T) {
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
			name:    "pfSense login page (must not match)",
			headers: map[string]string{"Content-Type": "text/html", "Server": "nginx"},
			body: []byte(`<html><head><title>pfSense - Login</title></head>
<body id="login"><div class="loginCont">
<input name="usernamefld"/><input name="passwordfld"/>
<svg id="pfsense-logo-svg"></svg>
</div></body></html>`),
			status: 200,
		},
		{
			name:    "500 error with OPNsense content",
			headers: map[string]string{"Server": "OPNsense", "Content-Type": "text/html"},
			body:    []byte(`<html><head><title>Login | OPNsense</title></head></html>`),
			status:  500,
		},
		{
			name:    "empty body with nginx server",
			headers: map[string]string{"Server": "nginx", "Content-Type": "text/html"},
			body:    []byte{},
			status:  200,
		},
		{
			name:    "other firewall product",
			headers: map[string]string{"Content-Type": "text/html"},
			body:    []byte(`<html><head><title>FortiGate Login</title></head></html>`),
			status:  200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OPNsenseFingerprinter{}
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

func TestBuildOPNsenseCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "empty version uses wildcard",
			version:  "",
			expected: "cpe:2.3:a:opnsense:opnsense:*:*:*:*:*:*:*:*",
		},
		{
			name:     "specific version",
			version:  "26.1.3",
			expected: "cpe:2.3:a:opnsense:opnsense:26.1.3:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildOPNsenseCPE(tt.version)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestOPNsenseFingerprinter_Integration(t *testing.T) {
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &OPNsenseFingerprinter{}
	Register(fp)

	body := []byte(`<html><head><title>Login | OPNsense</title></head>
<body class="page-login">
<main class="login-modal-container"></main>
<div class="login-foot">Deciso B.V.</div>
</body></html>`)

	header := http.Header{}
	header.Set("Server", "OPNsense")
	header.Set("Content-Type", "text/html")

	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "opnsense", results[0].Technology)
	assert.Equal(t, "Deciso B.V.", results[0].Metadata["vendor"])
	assert.Equal(t, "web-admin", results[0].Metadata["management_interface"])
}

func TestExtractOPNsenseHostname(t *testing.T) {
	tests := []struct {
		name     string
		body     string
		expected string
	}{
		{
			name:     "default OPNsense title returns empty",
			body:     `<title>Login | OPNsense</title>`,
			expected: "",
		},
		{
			name:     "custom hostname",
			body:     `<title>Login | fw01.corp.local</title>`,
			expected: "fw01.corp.local",
		},
		{
			name:     "dashboard page with hostname",
			body:     `<title>Dashboard | gateway.internal</title>`,
			expected: "gateway.internal",
		},
		{
			name:     "no title tag",
			body:     `<html><body></body></html>`,
			expected: "",
		},
		{
			name:     "title without pipe separator",
			body:     `<title>OPNsense Login</title>`,
			expected: "",
		},
		{
			name:     "case-insensitive OPNsense default",
			body:     `<title>Login | opnsense</title>`,
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractOPNsenseHostname(tt.body)
			assert.Equal(t, tt.expected, got)
		})
	}
}
