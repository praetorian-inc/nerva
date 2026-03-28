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
	require.NotNil(t, result)

	assert.Equal(t, "mikrotik-routeros", result.Technology)
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

func TestBuildMikroTikCPE(t *testing.T) {
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
			got := buildMikroTikCPE(tt.version)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestMikroTikFingerprinter_Fingerprint_MikroTikBodyOnly(t *testing.T) {
	body := []byte(`<html><body><p>Powered by MikroTik</p></body></html>`)
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
