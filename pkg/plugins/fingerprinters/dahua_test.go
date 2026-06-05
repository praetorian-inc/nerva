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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// ── Name / ProbeEndpoint / ProbeAccept ────────────────────────────────────────

func TestDahuaFingerprinter_Name(t *testing.T) {
	fp := &DahuaFingerprinter{}
	assert.Equal(t, "dahua", fp.Name())
}

func TestDahuaFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &DahuaFingerprinter{}
	assert.Equal(t, "/cgi-bin/magicBox.cgi?action=getDeviceType", fp.ProbeEndpoint())
}

func TestDahuaFingerprinter_ProbeAccept(t *testing.T) {
	fp := &DahuaFingerprinter{}
	assert.Equal(t, "text/plain", fp.ProbeAccept())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestDahuaFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		headers     map[string]string
		want        bool
	}{
		{
			name:       "200 text/html passes",
			statusCode: 200,
			contentType: "text/html; charset=utf-8",
			want:       true,
		},
		{
			name:       "200 text/plain passes (magicBox response)",
			statusCode: 200,
			contentType: "text/plain",
			want:       true,
		},
		{
			name:       "200 no content-type passes",
			statusCode: 200,
			contentType: "",
			want:       true,
		},
		{
			name:       "200 application/json rejected (not HTML or plain text)",
			statusCode: 200,
			contentType: "application/json",
			want:       false,
		},
		{
			name:       "200 image/png rejected",
			statusCode: 200,
			contentType: "image/png",
			want:       false,
		},
		{
			name:       "DH-prefixed header present causes match regardless of content-type",
			statusCode: 200,
			contentType: "application/json",
			headers:    map[string]string{"X-DH-State": "1"},
			want:       true,
		},
		{
			name:       "500 Internal Server Error rejected",
			statusCode: 500,
			contentType: "text/plain",
			want:       false,
		},
		{
			name:       "100 Informational rejected",
			statusCode: 100,
			contentType: "text/html",
			want:       false,
		},
		{
			name:       "404 text/html passes",
			statusCode: 404,
			contentType: "text/html",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &DahuaFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint: magicBox detection ──────────────────────────────────────────

func TestDahuaFingerprinter_Fingerprint_MagicBox(t *testing.T) {
	fp := &DahuaFingerprinter{}

	t.Run("magicBox response with device type", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/plain")
		body := []byte("type=IPC-HDW5831R-ZE\r\n")

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "dahua", result.Technology)
		assert.Equal(t, "IPC-HDW5831R-ZE", result.Metadata["model"])
		assert.Equal(t, true, result.Metadata["anonymous_access"])
		assert.Equal(t, "magicbox", result.Metadata["detection_method"])
		assert.Equal(t, plugins.SeverityHigh, result.Severity)
		require.Len(t, result.CPEs, 1)
		assert.Contains(t, result.CPEs[0], "dahuasecurity")
		assert.Contains(t, result.CPEs[0], "ipc-hdw5831r-ze")
	})

	t.Run("magicBox response with trailing whitespace and newline", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte("type=SD49425XB-HNR\n")

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "SD49425XB-HNR", result.Metadata["model"])
		assert.Equal(t, true, result.Metadata["anonymous_access"])
		assert.Equal(t, plugins.SeverityHigh, result.Severity)
	})
}

// ── Fingerprint: active probe detection ──────────────────────────────────────

func TestDahuaFingerprinter_Fingerprint_ActiveProbe(t *testing.T) {
	fp := &DahuaFingerprinter{}

	t.Run("request path matches magicBox probe endpoint — detection_method active_probe", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/cgi-bin/magicBox.cgi"},
			},
		}
		body := []byte("type=IPC-HDW4431EM-ASE\r\n")

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "active_probe", result.Metadata["detection_method"])
		assert.Equal(t, "/cgi-bin/magicBox.cgi?action=getDeviceType", result.Metadata["probe_path"])
		assert.Equal(t, true, result.Metadata["anonymous_access"])
		assert.Equal(t, plugins.SeverityHigh, result.Severity)
	})

	t.Run("nil Request does not panic and still detects via magicBox body", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    nil,
		}
		body := []byte("type=IPC-HDW5831R-ZE\r\n")

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "magicbox", result.Metadata["detection_method"])
	})
}

// ── Fingerprint: web UI (login page) detection ────────────────────────────────

func TestDahuaFingerprinter_Fingerprint_WebUI(t *testing.T) {
	fp := &DahuaFingerprinter{}

	t.Run("title containing Dahua is detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Content-Type", "text/html; charset=utf-8")
		body := []byte(`<html><head><title>Dahua Technology</title></head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "dahua", result.Technology)
		assert.Equal(t, "web_ui", result.Metadata["detection_method"])
		assert.Equal(t, true, result.Metadata["login_page_title"])
		assert.Equal(t, plugins.Severity(""), result.Severity, "login page only — no elevated severity")
	})

	t.Run("Dahua resource path in src attribute is detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<script src="/webpages/login.js"></script>
</head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "dahua", result.Technology)
		assert.Equal(t, "web_ui", result.Metadata["detection_method"])
		assert.Equal(t, true, result.Metadata["dahua_resource_path"])
	})

	t.Run("title with Dahua AND resource path — both flags set", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<title>Dahua Web Service</title>
<script src="/webpages/main.js"></script>
</head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, true, result.Metadata["login_page_title"])
		assert.Equal(t, true, result.Metadata["dahua_resource_path"])
	})

	t.Run("href attribute with /webpages/ path is detected", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := []byte(`<html><head>
<link href="/webpages/style.css" rel="stylesheet">
</head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "web_ui", result.Metadata["detection_method"])
	})
}

// ── Fingerprint: DH-header-only detection ────────────────────────────────────

func TestDahuaFingerprinter_Fingerprint_DHHeader(t *testing.T) {
	fp := &DahuaFingerprinter{}

	t.Run("X-DH-State header alone triggers header-only detection", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("X-DH-State", "active")
		body := []byte(`<html><head><title>Generic Router</title></head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "dahua", result.Technology)
		assert.Equal(t, "response_header", result.Metadata["detection_method"])
		assert.Equal(t, plugins.Severity(""), result.Severity, "header-only — no elevated severity")
	})

	t.Run("DH header included in web_ui result when title also matches", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("X-DH-State", "1")
		body := []byte(`<html><head><title>Dahua NVR Login</title></head><body></body></html>`)

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "web_ui", result.Metadata["detection_method"])
		assert.NotNil(t, result.Metadata["dh_header"])
	})
}

// ── Fingerprint: negative cases (must return nil) ─────────────────────────────

func TestDahuaFingerprinter_Fingerprint_Invalid(t *testing.T) {
	fp := &DahuaFingerprinter{}

	tests := []struct {
		name        string
		statusCode  int
		body        string
		contentType string
		headers     map[string]string
	}{
		{
			name:       "generic HTML page — no Dahua signals",
			statusCode: 200,
			body:       `<html><head><title>My Router</title></head><body><p>Welcome</p></body></html>`,
		},
		{
			name:       "generic plain text — no magicBox format",
			statusCode: 200,
			contentType: "text/plain",
			body:       "OK\n",
		},
		{
			name:       "prose mention of Dahua in paragraph — not structural",
			statusCode: 200,
			body:       `<html><head><title>Security Blog</title></head><body><p>We tested a Dahua camera.</p></body></html>`,
		},
		{
			name:       "500 status code rejected",
			statusCode: 500,
			body:       "type=IPC-HDW5831R-ZE\r\n",
		},
		{
			name:       "body larger than 2 MiB rejected",
			statusCode: 200,
			body:       "type=IPC-HDW5831R-ZE\r\n" + strings.Repeat("x", 2*1024*1024+1),
		},
		{
			name:       "magicBox with CPE metacharacters in model rejected",
			statusCode: 200,
			contentType: "text/plain",
			body:       "type=IPC:*:malicious\r\n",
		},
		{
			name:       "empty body with no DH header and no title",
			statusCode: 200,
			body:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result, "expected nil result for %q", tt.name)
		})
	}
}

// ── CPE building tests ────────────────────────────────────────────────────────

func TestBuildDahuaCPE(t *testing.T) {
	tests := []struct {
		name    string
		model   string
		version string
		want    string
	}{
		{
			name:    "known model, no version",
			model:   "IPC-HDW5831R-ZE",
			version: "",
			// cpe:2.3:o:dahuasecurity:<product>:<version>:update:edition:language:sw_edition:target_sw:target_hw:other
			want: "cpe:2.3:o:dahuasecurity:ipc-hdw5831r-ze:*:*:*:*:*:*:*:*",
		},
		{
			name:    "known model and version",
			model:   "IPC-HDW5831R-ZE",
			version: "2.820.0000000.2.R",
			want:    "cpe:2.3:o:dahuasecurity:ipc-hdw5831r-ze:2.820.0000000.2.R:*:*:*:*:*:*:*",
		},
		{
			name:    "no model, no version — full wildcard",
			model:   "",
			version: "",
			want:    "cpe:2.3:o:dahuasecurity:*:*:*:*:*:*:*:*:*",
		},
		{
			name:    "model with CPE metacharacters is sanitized to wildcard",
			model:   "bad:model*here",
			version: "",
			want:    "cpe:2.3:o:dahuasecurity:*:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version with CPE metacharacters is sanitized to wildcard",
			model:   "IPC-HX5831",
			version: "1.2.3:*:bad",
			want:    "cpe:2.3:o:dahuasecurity:ipc-hx5831:*:*:*:*:*:*:*:*",
		},
		{
			name:    "model is lowercased in CPE",
			model:   "SD49425XB-HNR",
			version: "",
			want:    "cpe:2.3:o:dahuasecurity:sd49425xb-hnr:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildDahuaCPE(tt.model, tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── extractDahuaMagicBoxInfo tests ────────────────────────────────────────────

func TestExtractDahuaMagicBoxInfo(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		wantModel   string
		wantVersion string
		wantFound   bool
	}{
		{
			name:      "standard magicBox response",
			body:      "type=IPC-HDW5831R-ZE\r\n",
			wantModel: "IPC-HDW5831R-ZE",
			wantFound: true,
		},
		{
			name:      "magicBox response with Unix newline",
			body:      "type=SD49425XB-HNR\n",
			wantModel: "SD49425XB-HNR",
			wantFound: true,
		},
		{
			name:      "magicBox response no newline",
			body:      "type=IPC-HX5831",
			wantModel: "IPC-HX5831",
			wantFound: true,
		},
		{
			name:      "empty body — not magicBox",
			body:      "",
			wantFound: false,
		},
		{
			name:      "generic text — not magicBox",
			body:      "OK",
			wantFound: false,
		},
		{
			name:      "CPE metacharacters in model are rejected",
			body:      "type=IPC:*:bad\r\n",
			wantFound: false,
		},
		{
			name:      "HTML body — not magicBox",
			body:      "<html><head><title>Dahua</title></head></html>",
			wantFound: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			model, version, found := extractDahuaMagicBoxInfo([]byte(tt.body))
			assert.Equal(t, tt.wantFound, found)
			assert.Equal(t, tt.wantModel, model)
			assert.Equal(t, tt.wantVersion, version)
		})
	}
}

// ── Integration test (Match + Fingerprint) ───────────────────────────────────

func TestDahuaFingerprinter_Integration_MagicBox(t *testing.T) {
	fp := &DahuaFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Request: &http.Request{
			URL: &url.URL{Path: "/cgi-bin/magicBox.cgi"},
		},
	}
	resp.Header.Set("Content-Type", "text/plain")
	body := []byte("type=IPC-HDW5831R-ZE\r\n")

	require.True(t, fp.Match(resp), "Match() should return true for text/plain response")

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "dahua", result.Technology)
	assert.Equal(t, "IPC-HDW5831R-ZE", result.Metadata["model"])
	assert.Equal(t, true, result.Metadata["anonymous_access"])
	assert.Equal(t, plugins.SeverityHigh, result.Severity)
	require.NotEmpty(t, result.CPEs)
	assert.Equal(t, "cpe:2.3:o:dahuasecurity:ipc-hdw5831r-ze:*:*:*:*:*:*:*:*", result.CPEs[0])
}

func TestDahuaFingerprinter_Integration_LoginPage(t *testing.T) {
	fp := &DahuaFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	body := []byte(`<!DOCTYPE html>
<html>
<head>
  <title>Dahua Web Service</title>
  <script src="/webpages/login.js"></script>
</head>
<body>
  <form id="loginForm">
    <input type="text" name="username"/>
    <input type="password" name="password"/>
  </form>
</body>
</html>`)

	require.True(t, fp.Match(resp), "Match() should return true for text/html response")

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "dahua", result.Technology)
	assert.Equal(t, "web_ui", result.Metadata["detection_method"])
	assert.Equal(t, "Dahua", result.Metadata["vendor"])
	assert.Equal(t, plugins.Severity(""), result.Severity)
	require.NotEmpty(t, result.CPEs)
	assert.Equal(t, "cpe:2.3:o:dahuasecurity:*:*:*:*:*:*:*:*:*", result.CPEs[0])
}
