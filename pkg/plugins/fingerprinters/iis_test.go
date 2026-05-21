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
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ── Name ──────────────────────────────────────────────────────────────────────

func TestIISFingerprinter_Name(t *testing.T) {
	fp := &IISFingerprinter{}
	assert.Equal(t, "iis", fp.Name())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestIISFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		server      string
		poweredBy   string
		aspNetVer   string
		contentType string
		want        bool
	}{
		{
			name:       "Server: Microsoft-IIS/10.0 on 200",
			statusCode: 200,
			server:     "Microsoft-IIS/10.0",
			want:       true,
		},
		{
			name:      "X-Powered-By: ASP.NET on 200",
			statusCode: 200,
			poweredBy:  "ASP.NET",
			want:       true,
		},
		{
			name:      "X-AspNet-Version present on 200",
			statusCode: 200,
			aspNetVer:  "4.0.30319",
			want:       true,
		},
		{
			name:        "Content-Type: text/html on 200",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        false,
		},
		{
			name:       "No IIS headers on 200",
			statusCode: 200,
			server:     "nginx/1.24.0",
			want:       false,
		},
		{
			name:       "Status 500 rejected",
			statusCode: 500,
			server:     "Microsoft-IIS/10.0",
			want:       false,
		},
		{
			name:       "Status 199 rejected",
			statusCode: 199,
			server:     "Microsoft-IIS/10.0",
			want:       false,
		},
		{
			name:       "302 redirect with Server: Microsoft-IIS/10.0",
			statusCode: 302,
			server:     "Microsoft-IIS/10.0",
			want:       true,
		},
		{
			name:       "Case-insensitive Server header match",
			statusCode: 200,
			server:     "microsoft-iis/8.5",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &IISFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.poweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.poweredBy)
			}
			if tt.aspNetVer != "" {
				resp.Header.Set("X-AspNet-Version", tt.aspNetVer)
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint: positive ─────────────────────────────────────────────────────

func TestIISFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name                string
		statusCode          int
		server              string
		poweredBy           string
		aspNetVer           string
		body                string
		wantVersion         string
		wantWindowsVersion  string
		wantCPE             string
		wantDetectionMethod string
		wantAspNetVersion   string
		wantDotNetVersion   string
		wantDefaultPage     bool
	}{
		{
			name:                "Server: Microsoft-IIS/10.0 only",
			statusCode:          200,
			server:              "Microsoft-IIS/10.0",
			wantVersion:         "10.0",
			wantWindowsVersion:  "Windows Server 2016/2019/2022",
			wantCPE:             "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*",
			wantDetectionMethod: "server_header",
		},
		{
			name:                "Server: Microsoft-IIS/8.5",
			statusCode:          200,
			server:              "Microsoft-IIS/8.5",
			wantVersion:         "8.5",
			wantWindowsVersion:  "Windows Server 2012 R2",
			wantCPE:             "cpe:2.3:a:microsoft:internet_information_services:8.5:*:*:*:*:*:*:*",
			wantDetectionMethod: "server_header",
		},
		{
			name:                "X-Powered-By: ASP.NET only (no IIS Server header)",
			statusCode:          200,
			poweredBy:           "ASP.NET",
			wantVersion:         "",
			wantCPE:             "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*",
			wantDetectionMethod: "header",
		},
		{
			name:              "X-AspNet-Version header extracts aspnet_version",
			statusCode:        200,
			server:            "Microsoft-IIS/10.0",
			aspNetVer:         "4.0.30319",
			wantVersion:       "10.0",
			wantAspNetVersion: "4.0.30319",
			wantDetectionMethod: "server_header",
		},
		{
			name:                "Full IIS response with all headers",
			statusCode:          200,
			server:              "Microsoft-IIS/10.0",
			poweredBy:           "ASP.NET",
			aspNetVer:           "4.0.30319",
			wantVersion:         "10.0",
			wantWindowsVersion:  "Windows Server 2016/2019/2022",
			wantAspNetVersion:   "4.0.30319",
			wantDetectionMethod: "server_header",
		},
		{
			name:                "Default page body with IIS branding",
			statusCode:          200,
			server:              "Microsoft-IIS/10.0",
			body:                "<html><head><title>IIS Windows Server</title></head><body>Welcome</body></html>",
			wantVersion:         "10.0",
			wantWindowsVersion:  "Windows Server 2016/2019/2022",
			wantDetectionMethod: "server_header",
			wantDefaultPage:     true,
		},
		{
			name:              ".NET CLR version in X-Powered-By",
			statusCode:        200,
			server:            "Microsoft-IIS/10.0",
			poweredBy:         "ASP.NET (.NET CLR 4.0.30319)",
			wantVersion:       "10.0",
			wantDotNetVersion: "4.0.30319",
			wantDetectionMethod: "server_header",
		},
		{
			name:                "Body with :*: does not block server header detection",
			statusCode:          200,
			server:              "Microsoft-IIS/10.0",
			body:                "some content :*: injection",
			wantVersion:         "10.0",
			wantWindowsVersion:  "Windows Server 2016/2019/2022",
			wantDetectionMethod: "server_header",
		},
		{
			name:                "Body with :*: in content does not block IIS detection",
			statusCode:          200,
			server:              "Microsoft-IIS/8.5",
			poweredBy:           "ASP.NET",
			body:                `<html><body>SELECT * FROM users WHERE role=:*:admin</body></html>`,
			wantVersion:         "8.5",
			wantWindowsVersion:  "Windows Server 2012 R2",
			wantCPE:             "cpe:2.3:a:microsoft:internet_information_services:8.5:*:*:*:*:*:*:*",
			wantDetectionMethod: "server_header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &IISFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.poweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.poweredBy)
			}
			if tt.aspNetVer != "" {
				resp.Header.Set("X-AspNet-Version", tt.aspNetVer)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result, "expected non-nil result")

			assert.Equal(t, "iis", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			require.NotEmpty(t, result.CPEs)
			if tt.wantCPE != "" {
				assert.Equal(t, tt.wantCPE, result.CPEs[0])
			}
			require.NotNil(t, result.Metadata)

			if tt.wantDetectionMethod != "" {
				assert.Equal(t, tt.wantDetectionMethod, result.Metadata["detection_method"])
			}
			if tt.wantWindowsVersion != "" {
				assert.Equal(t, tt.wantWindowsVersion, result.Metadata["windows_version"])
			}
			if tt.wantAspNetVersion != "" {
				assert.Equal(t, tt.wantAspNetVersion, result.Metadata["aspnet_version"])
			}
			if tt.wantDotNetVersion != "" {
				assert.Equal(t, tt.wantDotNetVersion, result.Metadata["dotnet_clr_version"])
			}
			if tt.wantDefaultPage {
				assert.Equal(t, true, result.Metadata["default_page"])
			} else {
				_, ok := result.Metadata["default_page"]
				assert.False(t, ok, "default_page should be absent when not detected")
			}
		})
	}
}

// ── Fingerprint: negative ─────────────────────────────────────────────────────

func TestIISFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		server     string
		poweredBy  string
		aspNetVer  string
		body       string
	}{
		{
			name:       "Status 500 returns nil",
			statusCode: 500,
			server:     "Microsoft-IIS/10.0",
		},
		{
			name:       "Body > 2 MiB returns nil",
			statusCode: 200,
			server:     "Microsoft-IIS/10.0",
			body:       strings.Repeat("x", 2*1024*1024+1),
		},
		{
			name:       "No IIS headers and no body brand returns nil",
			statusCode: 200,
			server:     "nginx/1.24.0",
			body:       "<html><head><title>Welcome</title></head></html>",
		},
		{
			name:       "Server: Apache, no IIS signals returns nil",
			statusCode: 200,
			server:     "Apache/2.4.54",
			body:       "<html><head><title>Apache Default Page</title></head></html>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &IISFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.poweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.poweredBy)
			}
			if tt.aspNetVer != "" {
				resp.Header.Set("X-AspNet-Version", tt.aspNetVer)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ── extractIISVersion ─────────────────────────────────────────────────────────

func TestExtractIISVersion(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
	}{
		{
			name:  "Standard IIS/10.0",
			input: "Microsoft-IIS/10.0",
			want:  "10.0",
		},
		{
			name:  "IIS/8.5",
			input: "Microsoft-IIS/8.5",
			want:  "8.5",
		},
		{
			name:  "IIS/7.0",
			input: "Microsoft-IIS/7.0",
			want:  "7.0",
		},
		{
			name:  "IIS/6.0",
			input: "Microsoft-IIS/6.0",
			want:  "6.0",
		},
		{
			name:  "Case-insensitive match",
			input: "microsoft-iis/10.0",
			want:  "10.0",
		},
		{
			name:  "Four-component version",
			input: "Microsoft-IIS/10.0.0.1",
			want:  "10.0.0.1",
		},
		{
			name:  "Empty header returns empty",
			input: "",
			want:  "",
		},
		{
			name:  "Non-IIS server header",
			input: "nginx/1.24.0",
			want:  "",
		},
		{
			name:  "Apache server header",
			input: "Apache/2.4.54",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractIISVersion(tt.input))
		})
	}
}

// ── extractASPNetVersion ──────────────────────────────────────────────────────

func TestExtractASPNetVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Standard ASP.NET version",
			input: "4.0.30319",
			want:  "4.0.30319",
		},
		{
			name:  "Two-component version",
			input: "2.0.50727",
			want:  "2.0.50727",
		},
		{
			name:  "Four-component version",
			input: "4.0.30319.42000",
			want:  "4.0.30319.42000",
		},
		{
			name:  "Empty header returns empty",
			input: "",
			want:  "",
		},
		{
			name:  "Non-version string returns empty",
			input: "ASP.NET",
			want:  "",
		},
		{
			name:  "Version with text prefix returns empty",
			input: "v4.0.30319",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractASPNetVersion(tt.input))
		})
	}
}

// ── extractDotNetCLRVersion ───────────────────────────────────────────────────

func TestExtractDotNetCLRVersion(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  ".NET CLR version extracted",
			input: "ASP.NET (.NET CLR 4.0.30319)",
			want:  "4.0.30319",
		},
		{
			name:  ".NET version without CLR keyword",
			input: "ASP.NET (.NET 8.0)",
			want:  "8.0",
		},
		{
			name:  "ASP.NET alone returns empty",
			input: "ASP.NET",
			want:  "",
		},
		{
			name:  "Empty header returns empty",
			input: "",
			want:  "",
		},
		{
			name:  ".NET CLR 2.0.50727 extracted",
			input: ".NET CLR 2.0.50727",
			want:  "2.0.50727",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractDotNetCLRVersion(tt.input))
		})
	}
}

// ── mapIISToWindowsVersion ────────────────────────────────────────────────────

func TestMapIISToWindowsVersion(t *testing.T) {
	tests := []struct {
		iisVersion string
		want       string
	}{
		{"6.0", "Windows Server 2003"},
		{"7.0", "Windows Server 2008"},
		{"7.5", "Windows Server 2008 R2"},
		{"8.0", "Windows Server 2012"},
		{"8.5", "Windows Server 2012 R2"},
		{"10.0", "Windows Server 2016/2019/2022"},
		{"9.0", ""},       // unknown version
		{"", ""},          // empty version
		{"5.1", ""},       // IIS 5.1 (Windows XP) — not in map
	}

	for _, tt := range tests {
		t.Run("iis-"+tt.iisVersion, func(t *testing.T) {
			assert.Equal(t, tt.want, mapIISToWindowsVersion(tt.iisVersion))
		})
	}
}

// ── isIISDefaultPage ──────────────────────────────────────────────────────────

func TestIsIISDefaultPage(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "IIS Windows Server title",
			body: "<html><head><title>IIS Windows Server</title></head></html>",
			want: true,
		},
		{
			name: "Internet Information Services title",
			body: "<html><head><title>Internet Information Services</title></head></html>",
			want: true,
		},
		{
			name: "IIS Windows Server with extra whitespace in title",
			body: "<html><head><title>  IIS Windows Server  </title></head></html>",
			want: true,
		},
		{
			name: "Case-insensitive title match",
			body: "<html><head><title>iis windows server</title></head></html>",
			want: true,
		},
		{
			name: "Non-IIS page",
			body: "<html><head><title>Welcome to nginx</title></head></html>",
			want: false,
		},
		{
			name: "Empty body",
			body: "",
			want: false,
		},
		{
			name: "Generic Windows page not IIS welcome",
			body: "<html><head><title>Windows Server 2019</title></head></html>",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isIISDefaultPage([]byte(tt.body)))
		})
	}
}

// ── buildIISCPE ───────────────────────────────────────────────────────────────

func TestBuildIISCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "10.0",
			want:    "cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*",
		},
		{
			version: "8.5",
			want:    "cpe:2.3:a:microsoft:internet_information_services:8.5:*:*:*:*:*:*:*",
		},
		{
			version: "7.0",
			want:    "cpe:2.3:a:microsoft:internet_information_services:7.0:*:*:*:*:*:*:*",
		},
		{
			version: "6.0",
			want:    "cpe:2.3:a:microsoft:internet_information_services:6.0:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:a:microsoft:internet_information_services:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version-"+tt.version, func(t *testing.T) {
			assert.Equal(t, tt.want, buildIISCPE(tt.version))
		})
	}
}

// ── sanitizeIISHeaderValue ────────────────────────────────────────────────────

func TestSanitizeIISHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Normal header value unchanged",
			input: "Microsoft-IIS/10.0",
			want:  "Microsoft-IIS/10.0",
		},
		{
			name:  "Control characters stripped",
			input: "Microsoft-IIS\x00\x01\x1f/10.0",
			want:  "Microsoft-IIS/10.0",
		},
		{
			name:  "DEL character stripped",
			input: "value\x7fafter",
			want:  "valueafter",
		},
		{
			name:  "Value > 256 chars truncated",
			input: strings.Repeat("A", 300),
			want:  strings.Repeat("A", 256),
		},
		{
			name:  "Printable ASCII preserved",
			input: "ASP.NET (.NET CLR 4.0.30319)",
			want:  "ASP.NET (.NET CLR 4.0.30319)",
		},
		{
			name:  "Empty string returns empty",
			input: "",
			want:  "",
		},
		{
			name:  "All control chars stripped gives empty",
			input: string([]byte{0x00, 0x01, 0x02, 0x1f}),
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, sanitizeIISHeaderValue(tt.input))
		})
	}
}

// ── Integration ───────────────────────────────────────────────────────────────

func TestIISFingerprinter_Integration(t *testing.T) {
	fp := &IISFingerprinter{}

	// Start an httptest server that responds with IIS-like headers.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Microsoft-IIS/10.0")
		w.Header().Set("X-Powered-By", "ASP.NET")
		w.Header().Set("X-AspNet-Version", "4.0.30319")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<html><head><title>Default Web Site</title></head><body></body></html>"))
	}))
	defer ts.Close()

	resp, err := http.Get(ts.URL) //nolint:noctx
	require.NoError(t, err)
	defer resp.Body.Close()

	body := []byte("<html><head><title>Default Web Site</title></head><body></body></html>")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "iis", result.Technology)
	assert.Equal(t, "10.0", result.Version)
	require.NotEmpty(t, result.CPEs)
	assert.Equal(t,
		"cpe:2.3:a:microsoft:internet_information_services:10.0:*:*:*:*:*:*:*",
		result.CPEs[0],
	)
	assert.Equal(t, "Microsoft", result.Metadata["vendor"])
	assert.Equal(t, "IIS", result.Metadata["product"])
	assert.Equal(t, "Windows Server 2016/2019/2022", result.Metadata["windows_version"])
	assert.Equal(t, "4.0.30319", result.Metadata["aspnet_version"])
}
