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

func TestOracleServiceCloudFingerprinter_Name(t *testing.T) {
	fp := &OracleServiceCloudFingerprinter{}
	assert.Equal(t, "oracle-service-cloud", fp.Name())
}

func TestOracleServiceCloudFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &OracleServiceCloudFingerprinter{}
	assert.Equal(t, "/ci/about", fp.ProbeEndpoint())
}

func TestOracleServiceCloudFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		headers    map[string]string
		cookies    []*http.Cookie
		statusCode int
		expected   bool
	}{
		{
			name:       "matches HTML response",
			headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "matches cp_session cookie",
			headers:    map[string]string{"Content-Type": "application/json"},
			cookies:    []*http.Cookie{{Name: "cp_session", Value: "abc123"}},
			statusCode: 200,
			expected:   true,
		},
		{
			name:       "matches 302 redirect with cp_session",
			headers:    map[string]string{"Content-Type": "text/html"},
			cookies:    []*http.Cookie{{Name: "cp_session", Value: "xyz"}},
			statusCode: 302,
			expected:   true,
		},
		{
			name:       "rejects 500 server error",
			headers:    map[string]string{"Content-Type": "text/html"},
			statusCode: 500,
			expected:   false,
		},
		{
			name:       "rejects non-HTML without cp_session",
			headers:    map[string]string{"Content-Type": "application/json"},
			statusCode: 200,
			expected:   false,
		},
		{
			name:       "rejects unrelated cookie",
			headers:    map[string]string{"Content-Type": "application/octet-stream"},
			cookies:    []*http.Cookie{{Name: "JSESSIONID", Value: "abc"}},
			statusCode: 200,
			expected:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OracleServiceCloudFingerprinter{}
			header := http.Header{}
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			// Encode cookies via Set-Cookie headers so resp.Cookies() works.
			for _, c := range tt.cookies {
				header.Add("Set-Cookie", c.String())
			}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     header,
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestOracleServiceCloudFingerprinter_Fingerprint_AboutPage(t *testing.T) {
	body := []byte(`<html>
<head><title>About</title></head>
<body>
<p>RightNow Customer Portal version 3.9 (d-3.9 / s-3.9)</p>
<p>Oracle Service Cloud 25C (Build 3, CP 319) SP4</p>
<p>Copyright (c) [1998 - 2026], Oracle and/or its affiliates. All rights reserved.</p>
</body>
</html>`)

	fp := &OracleServiceCloudFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html; charset=utf-8")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle-service-cloud", result.Technology)
	assert.Equal(t, "25C", result.Version)
	assert.Equal(t, "3", result.Metadata["build"])
	assert.Equal(t, "319", result.Metadata["cp"])
	assert.Equal(t, "SP4", result.Metadata["servicePack"])
	assert.Equal(t, "25C", result.Metadata["release"])
	assert.NotEmpty(t, result.CPEs)
	assert.Equal(t, "cpe:2.3:a:oracle:service_cloud:25C:*:*:*:*:*:*:*", result.CPEs[0])
}

func TestOracleServiceCloudFingerprinter_Fingerprint_AboutPageNoSP(t *testing.T) {
	body := []byte(`<html><body>
Oracle Service Cloud 24C (Build 1, CP 300)
</body></html>`)

	fp := &OracleServiceCloudFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "24C", result.Version)
	assert.Equal(t, "1", result.Metadata["build"])
	assert.Equal(t, "300", result.Metadata["cp"])
	assert.Nil(t, result.Metadata["servicePack"])
}

func TestOracleServiceCloudFingerprinter_Fingerprint_RightNowJS(t *testing.T) {
	body := []byte(`<html>
<head>
<script>
var RightNow = {};
RightNow.Env = {"mode":"production"};
RightNow.Widgets = {};
</script>
<link rel="stylesheet" href="/euf/core/3.9/js/4.315/min/css/base.css"/>
</head>
<body>Welcome to Support</body>
</html>`)

	fp := &OracleServiceCloudFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html; charset=utf-8")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle-service-cloud", result.Technology)
	// Version from EUF core path since no /ci/about release.
	assert.Equal(t, "3.9", result.Version)
	assert.Equal(t, "3.9", result.Metadata["cpFrameworkVersion"])
	assert.Equal(t, "4.315", result.Metadata["jsBuild"])
	assert.Contains(t, result.CPEs[0], "service_cloud:3.9:")
}

func TestOracleServiceCloudFingerprinter_Fingerprint_EUFPathOnly(t *testing.T) {
	body := []byte(`<html>
<head>
<script src="/euf/core/3.11/js/5.100/min/modules/ui/treeview.js"></script>
</head>
<body></body>
</html>`)

	fp := &OracleServiceCloudFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "3.11", result.Version)
	assert.Equal(t, "5.100", result.Metadata["jsBuild"])
}

func TestOracleServiceCloudFingerprinter_Fingerprint_CPSessionCookie(t *testing.T) {
	// Body has RightNow.Env confirming the detection; cookie alone passes Match().
	body := []byte(`<html><script>RightNow.Env = {};</script></html>`)

	fp := &OracleServiceCloudFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	header.Add("Set-Cookie", "cp_session=encrypted_value; Secure; HttpOnly")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle-service-cloud", result.Technology)
}

func TestOracleServiceCloudFingerprinter_Fingerprint_RNNamespace(t *testing.T) {
	body := []byte(`<html xmlns:rn="http://schemas.rightnow.com/crm/document">
<body><rn:widget path="standard/input/FormSubmit"/></body>
</html>`)

	fp := &OracleServiceCloudFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "oracle-service-cloud", result.Technology)
}

func TestOracleServiceCloudFingerprinter_Fingerprint_NoMatch(t *testing.T) {
	tests := []struct {
		name   string
		body   []byte
		status int
	}{
		{
			name:   "generic HTML page",
			body:   []byte(`<html><body>Hello World</body></html>`),
			status: 200,
		},
		{
			name:   "nginx default page",
			body:   []byte(`<html><head><title>Welcome to nginx!</title></head></html>`),
			status: 200,
		},
		{
			name:   "500 error page",
			body:   []byte(`<html><body>Oracle Service Cloud 25C (Build 3, CP 319)</body></html>`),
			status: 500,
		},
		{
			name:   "empty body",
			body:   []byte{},
			status: 200,
		},
		{
			name:   "oracle but different product",
			body:   []byte(`<html><body>Oracle WebLogic Server</body></html>`),
			status: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OracleServiceCloudFingerprinter{}
			header := http.Header{}
			header.Set("Content-Type", "text/html")
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

func TestBuildOracleServiceCloudCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "release version",
			version:  "25C",
			expected: "cpe:2.3:a:oracle:service_cloud:25C:*:*:*:*:*:*:*",
		},
		{
			name:     "CP framework version",
			version:  "3.9",
			expected: "cpe:2.3:a:oracle:service_cloud:3.9:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version uses wildcard",
			version:  "",
			expected: "cpe:2.3:a:oracle:service_cloud:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildOracleServiceCloudCPE(tt.version)
			assert.Equal(t, tt.expected, got)
		})
	}
}

func TestOracleServiceCloudFingerprinter_Fingerprint_VersionPrecedence(t *testing.T) {
	// When both /ci/about release and EUF path are present, release takes precedence.
	body := []byte(`<html>
<body>
<p>Oracle Service Cloud 25C (Build 3, CP 319) SP4</p>
<script src="/euf/core/3.9/js/4.315/min/modules/base.js"></script>
</body>
</html>`)

	fp := &OracleServiceCloudFingerprinter{}
	header := http.Header{}
	header.Set("Content-Type", "text/html")
	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	// Release "25C" takes precedence over EUF "3.9".
	assert.Equal(t, "25C", result.Version)
	assert.Equal(t, "cpe:2.3:a:oracle:service_cloud:25C:*:*:*:*:*:*:*", result.CPEs[0])
	// But CP framework version is still in metadata.
	assert.Equal(t, "3.9", result.Metadata["cpFrameworkVersion"])
}

func TestOracleServiceCloudFingerprinter_Integration(t *testing.T) {
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &OracleServiceCloudFingerprinter{}
	Register(fp)

	body := []byte(`<html>
<script>RightNow.Env = {"mode":"production"};</script>
<script src="/euf/core/3.9/js/4.315/min/modules/ui/treeview.js"></script>
</html>`)

	header := http.Header{}
	header.Set("Content-Type", "text/html; charset=utf-8")

	resp := &http.Response{
		StatusCode: 200,
		Header:     header,
	}

	results := RunFingerprinters(resp, body)

	require.Len(t, results, 1)
	assert.Equal(t, "oracle-service-cloud", results[0].Technology)
	assert.Equal(t, "3.9", results[0].Version)
}
