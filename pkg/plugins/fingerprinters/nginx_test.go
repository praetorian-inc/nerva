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
)

// ── Name / ProbeEndpoint ───────────────────────────────────────────────────────

func TestNginxFingerprinter_Name(t *testing.T) {
	fp := &NginxFingerprinter{}
	assert.Equal(t, "nginx", fp.Name())
}

func TestNginxFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &NginxFingerprinter{}
	assert.Equal(t, "/api/", fp.ProbeEndpoint())
}

// ── Match ──────────────────────────────────────────────────────────────────────

func TestNginxFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		server      string
		contentType string
		want        bool
	}{
		{
			name:       "200 with Server: nginx → true",
			statusCode: 200,
			server:     "nginx",
			want:       true,
		},
		{
			name:       "200 with Server: nginx/1.25.3 → true",
			statusCode: 200,
			server:     "nginx/1.25.3",
			want:       true,
		},
		{
			name:       "200 with Server: openresty/1.21.4.1 → true",
			statusCode: 200,
			server:     "openresty/1.21.4.1",
			want:       true,
		},
		{
			name:       "200 with Server: Tengine/2.3.3 → false (handled by TengineFingerprinter)",
			statusCode: 200,
			server:     "Tengine/2.3.3",
			want:       false,
		},
		{
			name:        "200 with text/html Content-Type → true",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:       "200 with no relevant headers → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "500 error → false",
			statusCode: 500,
			server:     "nginx",
			want:       false,
		},
		{
			name:       "302 with Server: nginx → true",
			statusCode: 302,
			server:     "nginx",
			want:       true,
		},
		{
			name:       "Server: NGINX uppercase → true",
			statusCode: 200,
			server:     "NGINX/1.24.0",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &NginxFingerprinter{}
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

// ── Fingerprint: positive (valid) ─────────────────────────────────────────────

func TestNginxFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name                 string
		statusCode           int
		server               string
		body                 string
		probePath            string
		wantVersion          string
		wantCPE              string
		wantVariant          string
		wantDetectionContains string
		wantNginxUIExposed   bool
		wantSeverityHigh     bool
		wantProbePathKey     bool
		wantServerHeaderKey  bool
	}{
		{
			name:                  "Server: nginx only (no version) → detects, variant=nginx, wildcard CPE",
			statusCode:            200,
			server:                "nginx",
			body:                  "",
			wantCPE:               "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
			wantVariant:           "nginx",
			wantDetectionContains: "server_header",
			wantServerHeaderKey:   true,
		},
		{
			name:                  "Server: nginx/1.25.3 → extracts version, CPE with version",
			statusCode:            200,
			server:                "nginx/1.25.3",
			body:                  "",
			wantVersion:           "1.25.3",
			wantCPE:               "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*",
			wantVariant:           "nginx",
			wantDetectionContains: "server_header",
			wantServerHeaderKey:   true,
		},
		{
			name:                  "Server: openresty/1.21.4.1 → variant=openresty, OpenResty CPE",
			statusCode:            200,
			server:                "openresty/1.21.4.1",
			body:                  "",
			wantVersion:           "1.21.4.1",
			wantCPE:               "cpe:2.3:a:openresty:openresty:1.21.4.1:*:*:*:*:*:*:*",
			wantVariant:           "openresty",
			wantDetectionContains: "server_header",
			wantServerHeaderKey:   true,
		},
		{
			name:                  "Default error page body → detects via error_page",
			statusCode:            200,
			server:                "",
			body:                  "<html><head><title>404 Not Found</title></head><body><center><h1>404 Not Found</h1></center><hr><center>nginx/1.24.0</center></body></html>",
			wantVersion:           "1.24.0",
			wantVariant:           "nginx",
			wantDetectionContains: "error_page",
		},
		{
			name:                  "Nginx UI body → nginx_ui_exposed=true, SeverityHigh",
			statusCode:            200,
			server:                "nginx",
			body:                  `<html><head><title>Nginx UI</title></head><body><div id="app" data-v-app>Login to Nginx UI</div></body></html>`,
			wantVariant:           "nginx",
			wantDetectionContains: "nginx_ui",
			wantNginxUIExposed:    true,
			wantSeverityHigh:      true,
			wantServerHeaderKey:   true,
		},
		{
			name:                  "Active probe /api/ with Nginx UI → detection_method contains active_probe",
			statusCode:            200,
			server:                "nginx",
			probePath:             "/api/",
			body:                  `{"msg":"pong","nginx_ui":"yes"}`,
			wantVariant:           "nginx",
			wantDetectionContains: "active_probe",
			wantNginxUIExposed:    true,
			wantSeverityHigh:      true,
			wantProbePathKey:      true,
			wantServerHeaderKey:   true,
		},
		{
			name:                  "Body with :*: does not reject fingerprint",
			statusCode:            200,
			server:                "nginx/1.25.3",
			body:                  "some body with :*: cpe metacharacters",
			wantVersion:           "1.25.3",
			wantCPE:               "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*",
			wantVariant:           "nginx",
			wantDetectionContains: "server_header",
			wantServerHeaderKey:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &NginxFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.probePath != "" {
				resp.Request = &http.Request{URL: &url.URL{Path: tt.probePath}}
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			assert.NoError(t, err)
			assert.NotNil(t, result, "expected non-nil result")

			if result == nil {
				return
			}

			assert.Equal(t, "nginx", result.Technology)
			assert.NotEmpty(t, result.CPEs)
			assert.NotNil(t, result.Metadata)

			if tt.wantVersion != "" {
				assert.Equal(t, tt.wantVersion, result.Version)
			}
			if tt.wantCPE != "" {
				assert.Equal(t, tt.wantCPE, result.CPEs[0])
			}
			if tt.wantVariant != "" {
				assert.Equal(t, tt.wantVariant, result.Metadata["variant"])
			}
			if tt.wantDetectionContains != "" {
				dm, _ := result.Metadata["detection_method"].(string)
				assert.Contains(t, dm, tt.wantDetectionContains, "detection_method should contain expected method")
			}
			if tt.wantNginxUIExposed {
				exposed, ok := result.Metadata["nginx_ui_exposed"].(bool)
				assert.True(t, ok, "nginx_ui_exposed should be bool")
				assert.True(t, exposed, "nginx_ui_exposed should be true")
			}
			if tt.wantSeverityHigh {
				assert.NotEmpty(t, result.Severity, "expected severity to be set")
			}
			if tt.wantProbePathKey {
				assert.Equal(t, "/api/", result.Metadata["probe_path"])
			} else {
				_, hasProbePath := result.Metadata["probe_path"]
				assert.False(t, hasProbePath, "probe_path should be absent for non-active-probe responses")
			}
			if tt.wantServerHeaderKey {
				_, hasServerHeader := result.Metadata["server_header"]
				assert.True(t, hasServerHeader, "server_header should be present when Server header is set")
			}
		})
	}
}

// ── Fingerprint: negative (invalid — must return nil) ─────────────────────────

func TestNginxFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		server     string
		body       string
	}{
		{
			name:       "Status 500 → nil",
			statusCode: 500,
			server:     "nginx",
			body:       "",
		},
		{
			name:       "Body > 2 MiB → nil",
			statusCode: 200,
			server:     "nginx",
			body:       strings.Repeat("A", 2*1024*1024+1),
		},
		{
			name:       "Server: Tengine → nil (excluded)",
			statusCode: 200,
			server:     "Tengine/2.3.3",
			body:       "",
		},
		{
			name:       "No nginx headers, no body brand → nil",
			statusCode: 200,
			server:     "",
			body:       "<html><body><h1>Welcome</h1></body></html>",
		},
		{
			name:       "Server: Apache → nil",
			statusCode: 200,
			server:     "Apache/2.4.57",
			body:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &NginxFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			assert.NoError(t, err)
			assert.Nil(t, result, "expected nil result for negative test case")
		})
	}
}

// ── TestExtractNginxVersion ────────────────────────────────────────────────────

func TestExtractNginxVersion(t *testing.T) {
	tests := []struct {
		name   string
		server string
		body   string
		want   string
	}{
		{
			name:   "Server header nginx/1.25.3",
			server: "nginx/1.25.3",
			want:   "1.25.3",
		},
		{
			name:   "Server header openresty/1.21.4.1",
			server: "openresty/1.21.4.1",
			want:   "1.21.4.1",
		},
		{
			name:   "Server header NGINX/1.24.0 (uppercase)",
			server: "NGINX/1.24.0",
			want:   "1.24.0",
		},
		{
			name:   "Server header nginx (no version)",
			server: "nginx",
			want:   "",
		},
		{
			name:   "Version in error page body when no server header version",
			server: "nginx",
			body:   "<html><body><center>nginx/1.24.0</center></body></html>",
			want:   "1.24.0",
		},
		{
			name:   "Server header takes priority over body",
			server: "nginx/1.25.3",
			body:   "<html><body><center>nginx/1.18.0</center></body></html>",
			want:   "1.25.3",
		},
		{
			name:   "No version anywhere",
			server: "nginx",
			body:   "<html><body><center>nginx</center></body></html>",
			want:   "",
		},
		{
			name:   "Empty server header and body",
			server: "",
			body:   "",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractNginxVersion(tt.server, []byte(tt.body))
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── TestIsOpenResty ────────────────────────────────────────────────────────────

func TestIsOpenResty(t *testing.T) {
	tests := []struct {
		name         string
		serverHeader string
		want         bool
	}{
		{
			name:         "openresty/1.21.4.1 → true",
			serverHeader: "openresty/1.21.4.1",
			want:         true,
		},
		{
			name:         "OpenResty/1.21.4.1 uppercase → true",
			serverHeader: "OpenResty/1.21.4.1",
			want:         true,
		},
		{
			name:         "nginx/1.25.3 → false",
			serverHeader: "nginx/1.25.3",
			want:         false,
		},
		{
			name:         "empty → false",
			serverHeader: "",
			want:         false,
		},
		{
			name:         "Tengine/2.3.3 → false",
			serverHeader: "Tengine/2.3.3",
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isOpenResty(tt.serverHeader))
		})
	}
}

// ── TestIsNginxUI ──────────────────────────────────────────────────────────────

func TestIsNginxUI(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "nginx-ui in body → true",
			body: `<div class="nginx-ui-app"></div>`,
			want: true,
		},
		{
			name: "Nginx UI in body → true",
			body: `<title>Nginx UI</title>`,
			want: true,
		},
		{
			name: "nginxui in body → true",
			body: `<meta name="application" content="nginxui">`,
			want: true,
		},
		{
			name: "NGINX UI uppercase → true",
			body: `<h1>NGINX UI Login</h1>`,
			want: true,
		},
		{
			name: "plain nginx without UI marker → false",
			body: `<center>nginx/1.25.3</center>`,
			want: false,
		},
		{
			name: "empty body → false",
			body: ``,
			want: false,
		},
		{
			name: "unrelated body → false",
			body: `<html><body><h1>Welcome to Apache</h1></body></html>`,
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isNginxUI([]byte(tt.body)))
		})
	}
}

// ── TestIsNginxErrorPage ───────────────────────────────────────────────────────

func TestIsNginxErrorPage(t *testing.T) {
	tests := []struct {
		name string
		body string
		want bool
	}{
		{
			name: "default nginx error page no version → true",
			body: `<html><head><title>404 Not Found</title></head><body><center><h1>404</h1></center><hr><center>nginx</center></body></html>`,
			want: true,
		},
		{
			name: "default nginx error page with version → true",
			body: `<html><head><title>404 Not Found</title></head><body><center><h1>404</h1></center><hr><center>nginx/1.24.0</center></body></html>`,
			want: true,
		},
		{
			name: "nginx in body but not centered footer → false",
			body: `<html><body><p>Powered by nginx</p></body></html>`,
			want: false,
		},
		{
			name: "empty body → false",
			body: ``,
			want: false,
		},
		{
			name: "Apache error page → false",
			body: `<html><body><center>Apache/2.4.57</center></body></html>`,
			want: false,
		},
		{
			name: "NGINX uppercase in center → true",
			body: `<html><body><center>NGINX/1.25.0</center></body></html>`,
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isNginxErrorPage([]byte(tt.body)))
		})
	}
}

// ── TestBuildNginxCPE ──────────────────────────────────────────────────────────

func TestBuildNginxCPE(t *testing.T) {
	tests := []struct {
		name       string
		version    string
		isOpenResty bool
		want       string
	}{
		{
			name:       "Nginx with version 1.25.3",
			version:    "1.25.3",
			isOpenResty: false,
			want:       "cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*",
		},
		{
			name:       "Nginx wildcard (empty version)",
			version:    "",
			isOpenResty: false,
			want:       "cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*",
		},
		{
			name:       "OpenResty with version 1.21.4.1",
			version:    "1.21.4.1",
			isOpenResty: true,
			want:       "cpe:2.3:a:openresty:openresty:1.21.4.1:*:*:*:*:*:*:*",
		},
		{
			name:       "OpenResty wildcard (empty version)",
			version:    "",
			isOpenResty: true,
			want:       "cpe:2.3:a:openresty:openresty:*:*:*:*:*:*:*:*",
		},
		{
			name:       "Nginx four-component version 1.25.3.1",
			version:    "1.25.3.1",
			isOpenResty: false,
			want:       "cpe:2.3:a:f5:nginx:1.25.3.1:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildNginxCPE(tt.version, tt.isOpenResty))
		})
	}
}

// ── Integration test ──────────────────────────────────────────────────────────

func TestNginxFingerprinter_Integration(t *testing.T) {
	// Save and restore global state to prevent test pollution.
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &NginxFingerprinter{}
	Register(fp)

	t.Run("server header with version triggers detection", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "nginx/1.25.3")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintln(w, "<html><body>Hello</body></html>")
		}))
		defer ts.Close()

		resp, err := http.Get(ts.URL)
		assert.NoError(t, err)
		defer resp.Body.Close()

		body := []byte("<html><body>Hello</body></html>")
		results := RunFingerprinters(resp, body)

		found := false
		for _, result := range results {
			if result.Technology == "nginx" {
				found = true
				assert.Equal(t, "1.25.3", result.Version)
				assert.Equal(t, []string{"cpe:2.3:a:f5:nginx:1.25.3:*:*:*:*:*:*:*"}, result.CPEs)
				assert.Equal(t, "F5", result.Metadata["vendor"])
				assert.Equal(t, "Nginx", result.Metadata["product"])
				assert.Equal(t, "nginx", result.Metadata["variant"])
			}
		}
		assert.True(t, found, "NginxFingerprinter not found in RunFingerprinters results")
	})

	t.Run("nginx UI body triggers high severity", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "nginx")
			w.Header().Set("Content-Type", "text/html")
			fmt.Fprintln(w, `<html><head><title>Nginx UI</title></head><body>Login to Nginx UI</body></html>`)
		}))
		defer ts.Close()

		resp, err := http.Get(ts.URL)
		assert.NoError(t, err)
		defer resp.Body.Close()

		body := []byte(`<html><head><title>Nginx UI</title></head><body>Login to Nginx UI</body></html>`)
		results := RunFingerprinters(resp, body)

		found := false
		for _, result := range results {
			if result.Technology == "nginx" {
				found = true
				assert.Equal(t, true, result.Metadata["nginx_ui_exposed"])
				assert.NotEmpty(t, result.Severity)
			}
		}
		assert.True(t, found, "NginxFingerprinter not found in RunFingerprinters results for Nginx UI")
	})
}
