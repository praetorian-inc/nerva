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
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// isapiDeviceInfoXML is a realistic ISAPI /ISAPI/System/deviceInfo response.
const isapiDeviceInfoXML = `<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo version="2.0" xmlns="http://www.isapi.org/ver20/XMLSchema">
  <deviceName>IP Camera</deviceName>
  <deviceID>48</deviceID>
  <model>DS-2CD2032-I</model>
  <serialNumber>DS-2CD2032-I20150101AAWRD12345678</serialNumber>
  <macAddress>aa:bb:cc:dd:ee:ff</macAddress>
  <firmwareVersion>V5.4.5</firmwareVersion>
  <firmwareReleasedDate>build 170124</firmwareReleasedDate>
  <deviceType>IPCamera</deviceType>
</DeviceInfo>`

// ── Name / ProbeEndpoint / ProbeAccept ────────────────────────────────────────

func TestHikvisionFingerprinter_Name(t *testing.T) {
	fp := &HikvisionFingerprinter{}
	assert.Equal(t, "hikvision", fp.Name())
}

func TestHikvisionFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &HikvisionFingerprinter{}
	assert.Equal(t, "/ISAPI/System/deviceInfo", fp.ProbeEndpoint())
}

func TestHikvisionFingerprinter_ProbeAccept(t *testing.T) {
	fp := &HikvisionFingerprinter{}
	assert.Equal(t, "application/xml", fp.ProbeAccept())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestHikvisionFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		server      string
		contentType string
		want        bool
	}{
		{
			name:       "DNVRS-Webs server header → true",
			statusCode: 200,
			server:     "DNVRS-Webs",
			want:       true,
		},
		{
			name:       "App-webs/ server header → true",
			statusCode: 200,
			server:     "App-webs/",
			want:       true,
		},
		{
			name:        "text/xml content-type → true (potential ISAPI response)",
			statusCode:  200,
			contentType: "text/xml; charset=UTF-8",
			want:        true,
		},
		{
			name:        "application/xml content-type → true (potential ISAPI response)",
			statusCode:  200,
			contentType: "application/xml",
			want:        true,
		},
		{
			name:        "text/html content-type → true (potential login page)",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "image/png → false (no relevant signal)",
			statusCode:  200,
			contentType: "image/png",
			want:        false,
		},
		{
			name:       "500 status code → false",
			statusCode: 500,
			server:     "DNVRS-Webs",
			want:       false,
		},
		{
			name:       "200 with no relevant headers → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "301 redirect with DNVRS-Webs → true",
			statusCode: 301,
			server:     "DNVRS-Webs",
			want:       true,
		},
		{
			name:       "401 with DNVRS-Webs → true (ISAPI returns 401 when auth required)",
			statusCode: 401,
			server:     "DNVRS-Webs",
			want:       true,
		},
		{
			name:       "DNVRS-Webs-Extended server header → false (exact match required)",
			statusCode: 200,
			server:     "DNVRS-Webs-Extended",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HikvisionFingerprinter{}
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

// ── Fingerprint: ISAPI XML (full response) ────────────────────────────────────

func TestHikvisionFingerprinter_Fingerprint_ISAPI(t *testing.T) {
	fp := &HikvisionFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/xml")

	result, err := fp.Fingerprint(resp, []byte(isapiDeviceInfoXML))
	require.NoError(t, err)
	require.NotNil(t, result, "expected non-nil result for ISAPI XML body")

	assert.Equal(t, "hikvision", result.Technology)
	assert.Equal(t, "5.4.5", result.Version, "V prefix should be stripped")
	require.NotEmpty(t, result.CPEs)
	assert.Equal(t, "cpe:2.3:o:hikvision:*:5.4.5:*:*:*:*:*:*:*", result.CPEs[0])

	assert.Equal(t, "Hikvision", result.Metadata["vendor"])
	assert.Equal(t, "DS-2CD2032-I", result.Metadata["model"])
	assert.Equal(t, "5.4.5", result.Metadata["firmware_version"])
	assert.Equal(t, "IPCamera", result.Metadata["device_type"])
	assert.Equal(t, true, result.Metadata["anonymous_access"])
	assert.Equal(t, plugins.SeverityHigh, result.Severity, "unauthenticated ISAPI should be SeverityHigh")

	dm, _ := result.Metadata["detection_method"].(string)
	assert.Contains(t, dm, "isapi")
}

// ── Fingerprint: active probe (request path = /ISAPI/System/deviceInfo) ───────

func TestHikvisionFingerprinter_Fingerprint_ActiveProbe(t *testing.T) {
	fp := &HikvisionFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
		Request:    &http.Request{URL: &url.URL{Path: "/ISAPI/System/deviceInfo"}},
	}
	resp.Header.Set("Content-Type", "application/xml")

	result, err := fp.Fingerprint(resp, []byte(isapiDeviceInfoXML))
	require.NoError(t, err)
	require.NotNil(t, result)

	dm, _ := result.Metadata["detection_method"].(string)
	assert.Contains(t, dm, "active_probe", "detection_method should include active_probe when path matches probe endpoint")
	assert.NotContains(t, dm, "isapi", "detection_method should not say 'isapi' separately when it is the active probe")

	assert.Equal(t, true, result.Metadata["anonymous_access"])
	assert.Equal(t, plugins.SeverityHigh, result.Severity)
}

// ── Fingerprint: web UI (title and App-Webs asset path) ───────────────────────

func TestHikvisionFingerprinter_Fingerprint_WebUI(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "title tag with Hikvision branding",
			body: `<html><head><title>Hikvision</title></head><body></body></html>`,
		},
		{
			name: "title tag with HIKVISION uppercase",
			body: `<html><head><title>HIKVISION - Login</title></head><body></body></html>`,
		},
		{
			name: "App-Webs asset in src attribute",
			body: `<html><head><script src="/doc/App-Webs/hikvision.js"></script></head><body></body></html>`,
		},
		{
			name: "App-Webs in href attribute",
			body: `<html><head><link href="/doc/App-Webs/style.css" rel="stylesheet"></head><body></body></html>`,
		},
	}

	fp := &HikvisionFingerprinter{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result, "expected non-nil result for web UI body: %s", tt.name)

			assert.Equal(t, "hikvision", result.Technology)
			assert.Equal(t, "Hikvision", result.Metadata["vendor"])

			dm, _ := result.Metadata["detection_method"].(string)
			assert.Contains(t, dm, "web_ui")

			// Web UI detection alone does not trigger SeverityHigh or anonymous_access.
			_, hasAnon := result.Metadata["anonymous_access"]
			assert.False(t, hasAnon, "anonymous_access should be absent for web_ui-only detection")
			assert.Empty(t, result.Severity, "web_ui detection alone should not set severity")
		})
	}
}

// ── Fingerprint: server header only (DNVRS-Webs) ─────────────────────────────

func TestHikvisionFingerprinter_Fingerprint_ServerHeaderOnly(t *testing.T) {
	fp := &HikvisionFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "DNVRS-Webs")
	resp.Header.Set("Content-Type", "text/html")

	body := []byte(`<html><body><h1>Device Login</h1></body></html>`)
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result, "expected detection via DNVRS-Webs server header")

	assert.Equal(t, "hikvision", result.Technology)
	serverHdr, _ := result.Metadata["server_header"].(string)
	assert.Equal(t, "DNVRS-Webs", serverHdr)

	dm, _ := result.Metadata["detection_method"].(string)
	assert.Contains(t, dm, "server_header")

	// Server header alone: no elevated severity, no anonymous_access.
	_, hasAnon := result.Metadata["anonymous_access"]
	assert.False(t, hasAnon)
	assert.Empty(t, result.Severity)
}

// ── Fingerprint: negative cases (must return nil) ─────────────────────────────

func TestHikvisionFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		server     string
		body       string
	}{
		{
			name:       "Status 500 → nil",
			statusCode: 500,
			server:     "DNVRS-Webs",
			body:       "",
		},
		{
			name:       "Body > 2 MiB → nil",
			statusCode: 200,
			body:       strings.Repeat("X", 2*1024*1024+1),
		},
		{
			name:       "Generic HTML page (no Hikvision signals) → nil",
			statusCode: 200,
			body:       "<html><body><h1>Welcome to the web interface</h1></body></html>",
		},
		{
			name:       "Generic XML (non-ISAPI) → nil",
			statusCode: 200,
			body:       `<?xml version="1.0"?><root><item>hello</item></root>`,
		},
		{
			name:       "Prose mention of Hikvision in paragraph → nil",
			statusCode: 200,
			body:       `<html><body><p>This camera supports Hikvision ISAPI protocol for integration.</p></body></html>`,
		},
		{
			name:       "Dahua device page (mentions Hikvision nowhere) → nil",
			statusCode: 200,
			server:     "webserver",
			body:       `<html><head><title>Dahua Web Service</title></head><body></body></html>`,
		},
		{
			name:       "DeviceInfo XML without ISAPI namespace → nil",
			statusCode: 200,
			body:       `<?xml version="1.0" encoding="UTF-8"?><DeviceInfo><model>SomeDevice</model><firmwareVersion>V1.0.0</firmwareVersion></DeviceInfo>`,
		},
		{
			name:       "DeviceInfo XML with non-ISAPI namespace → nil",
			statusCode: 200,
			body:       `<?xml version="1.0" encoding="UTF-8"?><DeviceInfo xmlns="http://www.example.com/schema"><model>SomeDevice</model></DeviceInfo>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HikvisionFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			assert.NoError(t, err)
			assert.Nil(t, result, "expected nil result for negative test case: %s", tt.name)
		})
	}
}

// ── Version extraction ────────────────────────────────────────────────────────

func TestExtractHikvisionFirmwareVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "V-prefixed version V5.4.5 → 5.4.5",
			body: `<firmwareVersion>V5.4.5</firmwareVersion>`,
			want: "5.4.5",
		},
		{
			name: "No V prefix 5.4.5 → 5.4.5 (as-is)",
			body: `<firmwareVersion>5.4.5</firmwareVersion>`,
			want: "5.4.5",
		},
		{
			name: "Build-appended version V5.4.5.170124 → 5.4.5.170124",
			body: `<firmwareVersion>V5.4.5.170124</firmwareVersion>`,
			want: "5.4.5.170124",
		},
		{
			name: "whitespace around tag value → trimmed correctly",
			body: `<firmwareVersion>  V5.3.0  </firmwareVersion>`,
			want: "5.3.0",
		},
		{
			name: "no firmwareVersion element → empty string",
			body: `<DeviceInfo><model>DS-2CD2032-I</model></DeviceInfo>`,
			want: "",
		},
		{
			name: "version with letter suffix rejected → empty string",
			body: `<firmwareVersion>5.4.5-beta</firmwareVersion>`,
			want: "",
		},
		{
			name: "empty body → empty string",
			body: ``,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractHikvisionFirmwareVersion([]byte(tt.body))
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── CPE building ──────────────────────────────────────────────────────────────

func TestBuildHikvisionCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "version 5.4.5",
			version: "5.4.5",
			want:    "cpe:2.3:o:hikvision:*:5.4.5:*:*:*:*:*:*:*",
		},
		{
			name:    "version 5.4.5.170124 (build-appended)",
			version: "5.4.5.170124",
			want:    "cpe:2.3:o:hikvision:*:5.4.5.170124:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version → wildcard CPE",
			version: "",
			want:    "cpe:2.3:o:hikvision:*:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildHikvisionCPE(tt.version))
		})
	}
}

// ── ISAPI XML model and device-type extraction ────────────────────────────────

func TestHikvisionFingerprinter_Fingerprint_ISAPIModelAndType(t *testing.T) {
	const dvr = `<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo xmlns="http://www.isapi.org/ver20/XMLSchema">
  <deviceName>DVR Device</deviceName>
  <model>DS-7208HUHI-F2/N</model>
  <firmwareVersion>V3.4.92</firmwareVersion>
  <deviceType>DVR</deviceType>
</DeviceInfo>`

	fp := &HikvisionFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/xml")

	result, err := fp.Fingerprint(resp, []byte(dvr))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "DS-7208HUHI-F2/N", result.Metadata["model"])
	assert.Equal(t, "DVR", result.Metadata["device_type"])
	assert.Equal(t, "3.4.92", result.Version)
}

// ── Fallback to deviceName when model element is absent ───────────────────────

func TestHikvisionFingerprinter_Fingerprint_DeviceNameFallback(t *testing.T) {
	const xml = `<?xml version="1.0" encoding="UTF-8"?>
<DeviceInfo xmlns="http://www.isapi.org/ver20/XMLSchema">
  <deviceName>IP Camera</deviceName>
  <firmwareVersion>V5.2.0</firmwareVersion>
  <deviceType>IPCamera</deviceType>
</DeviceInfo>`

	fp := &HikvisionFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	result, err := fp.Fingerprint(resp, []byte(xml))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "IP Camera", result.Metadata["model"], "should fall back to deviceName when model is absent")
}

// ── Integration tests (Match + Fingerprint round-trip) ───────────────────────

func TestHikvisionFingerprinter_Integration(t *testing.T) {
	fp := &HikvisionFingerprinter{}

	t.Run("ISAPI XML response triggers SeverityHigh with version and CPE", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/xml")
			fmt.Fprintln(w, isapiDeviceInfoXML)
		}))
		defer ts.Close()

		resp, err := http.Get(ts.URL)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, fp.Match(resp))
		result, err := fp.Fingerprint(resp, []byte(isapiDeviceInfoXML))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "hikvision", result.Technology)
		assert.Equal(t, "5.4.5", result.Version)
		assert.Equal(t, []string{"cpe:2.3:o:hikvision:*:5.4.5:*:*:*:*:*:*:*"}, result.CPEs)
		assert.Equal(t, "Hikvision", result.Metadata["vendor"])
		assert.Equal(t, "DS-2CD2032-I", result.Metadata["model"])
		assert.Equal(t, "IPCamera", result.Metadata["device_type"])
		assert.Equal(t, true, result.Metadata["anonymous_access"])
		assert.Equal(t, plugins.SeverityHigh, result.Severity)
	})

	t.Run("DNVRS-Webs header without ISAPI body → matched and fingerprinted", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "DNVRS-Webs")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintln(w, `<html><body>Login</body></html>`)
		}))
		defer ts.Close()

		resp, err := http.Get(ts.URL)
		require.NoError(t, err)
		defer resp.Body.Close()

		assert.True(t, fp.Match(resp))
		result, err := fp.Fingerprint(resp, []byte(`<html><body>Login</body></html>`))
		require.NoError(t, err)
		require.NotNil(t, result)

		assert.Equal(t, "hikvision", result.Technology)
		assert.Equal(t, "DNVRS-Webs", result.Metadata["server_header"])
	})
}
