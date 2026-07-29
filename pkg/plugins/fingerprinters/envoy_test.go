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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ── EnvoyServerInfoFingerprinter: Name / ProbeEndpoint ─────────────────────────

func TestEnvoyServerInfoFingerprinter_Name(t *testing.T) {
	fp := &EnvoyServerInfoFingerprinter{}
	assert.Equal(t, "envoy-admin-api", fp.Name())
}

func TestEnvoyServerInfoFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &EnvoyServerInfoFingerprinter{}
	assert.Equal(t, "/server_info", fp.ProbeEndpoint())
}

// ── EnvoyServerInfoFingerprinter: Match ─────────────────────────────────────────

func TestEnvoyServerInfoFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		server      string
		contentType string
		want        bool
	}{
		{name: "200 + server: envoy → true", statusCode: 200, server: "envoy", want: true},
		{name: "200 + server: Envoy (mixed case) → true", statusCode: 200, server: "Envoy", want: true},
		{name: "200 + server: ENVOY (upper case) → true", statusCode: 200, server: "ENVOY", want: true},
		{name: "200 + application/json content-type → true", statusCode: 200, contentType: "application/json", want: true},
		{name: "200 + application/json;charset=utf-8 → true", statusCode: 200, contentType: "application/json; charset=utf-8", want: true},
		{name: "200 + server: nginx + text/plain → false", statusCode: 200, server: "nginx", contentType: "text/plain", want: false},
		{name: "200 + no headers → false", statusCode: 200, want: false},
		{name: "404 + server: envoy → false (non-200 rejected)", statusCode: 404, server: "envoy", want: false},
		{name: "500 + server: envoy → false (non-200 rejected)", statusCode: 500, server: "envoy", want: false},
		{name: "302 + application/json → false (non-200 rejected)", statusCode: 302, contentType: "application/json", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &EnvoyServerInfoFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
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

// ── EnvoyServerInfoFingerprinter: Fingerprint (positive) ───────────────────────

func TestEnvoyServerInfoFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name              string
		body              string
		wantVersion       string
		wantCPE           string
		wantState         string
		wantHotRestart    string
		wantBuildType     string
		wantTLSLibrary    string
		wantVersionRawKey bool
		wantVersionRaw    string
	}{
		{
			name:              "hash-prefixed version with -dev suffix → confirmed via hot_restart_version, clean version for CPE",
			body:              `{"version":"c93f9f6c1e5adddd10a3e3646c7e049c649ae177/1.9.0-dev/Clean/RELEASE/BoringSSL","state":"LIVE","hot_restart_version":"11.104","node":{"user_agent_name":"envoy"}}`,
			wantVersion:       "1.9.0",
			wantCPE:           "cpe:2.3:a:envoyproxy:envoy:1.9.0:*:*:*:*:*:*:*",
			wantState:         "LIVE",
			wantHotRestart:    "11.104",
			wantBuildType:     "RELEASE",
			wantTLSLibrary:    "BoringSSL",
			wantVersionRawKey: true,
			wantVersionRaw:    "1.9.0-dev",
		},
		{
			name:           "no-hash version segment, confirmed via node.user_agent_name only",
			body:           `{"version":"1.28.0/Clean/RELEASE/BoringSSL","state":"LIVE","node":{"user_agent_name":"envoy"}}`,
			wantVersion:    "1.28.0",
			wantCPE:        "cpe:2.3:a:envoyproxy:envoy:1.28.0:*:*:*:*:*:*:*",
			wantState:      "LIVE",
			wantBuildType:  "RELEASE",
			wantTLSLibrary: "BoringSSL",
		},
		{
			name:           "DEBUG build type extracted",
			body:           `{"version":"deadbeef/1.30.1/Clean/DEBUG/BoringSSL","hot_restart_version":"11.104","node":{"user_agent_name":"envoy"}}`,
			wantVersion:    "1.30.1",
			wantCPE:        "cpe:2.3:a:envoyproxy:envoy:1.30.1:*:*:*:*:*:*:*",
			wantHotRestart: "11.104",
			wantBuildType:  "DEBUG",
			wantTLSLibrary: "BoringSSL",
		},
		{
			name:           "missing/unparseable version field but hot_restart_version present → still confirmed, wildcard CPE",
			body:           `{"version":"","state":"LIVE","hot_restart_version":"11.104"}`,
			wantVersion:    "",
			wantCPE:        "cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*",
			wantState:      "LIVE",
			wantHotRestart: "11.104",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &EnvoyServerInfoFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			assert.NoError(t, err)
			assert.NotNil(t, result, "expected non-nil result")
			if result == nil {
				return
			}

			assert.Equal(t, "envoy", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			assert.NotEmpty(t, result.CPEs)
			assert.Equal(t, tt.wantCPE, result.CPEs[0])
			assert.Empty(t, result.Severity, "severity must remain unset for fingerprinter-only ticket")

			if tt.wantState != "" {
				assert.Equal(t, tt.wantState, result.Metadata["state"])
			}
			if tt.wantHotRestart != "" {
				assert.Equal(t, tt.wantHotRestart, result.Metadata["hot_restart_version"])
			}
			if tt.wantBuildType != "" {
				assert.Equal(t, tt.wantBuildType, result.Metadata["build_type"])
			}
			if tt.wantTLSLibrary != "" {
				assert.Equal(t, tt.wantTLSLibrary, result.Metadata["tls_library"])
			}
			if tt.wantVersionRawKey {
				assert.Equal(t, tt.wantVersionRaw, result.Metadata["version_raw"])
			} else {
				_, has := result.Metadata["version_raw"]
				assert.False(t, has, "version_raw should be absent when raw equals clean version")
			}
		})
	}
}

// ── EnvoyServerInfoFingerprinter: Fingerprint (negative / false-positive guards) ─

func TestEnvoyServerInfoFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "non-200 status → nil",
			statusCode: 404,
			body:       `{"version":"1.28.0/Clean/RELEASE/BoringSSL","hot_restart_version":"11.104","node":{"user_agent_name":"envoy"}}`,
		},
		{
			name:       "500 status → nil",
			statusCode: 500,
			body:       `{"version":"1.28.0/Clean/RELEASE/BoringSSL","hot_restart_version":"11.104","node":{"user_agent_name":"envoy"}}`,
		},
		{
			name:       "generic JSON API (no hot_restart_version, no envoy user_agent_name) → nil",
			statusCode: 200,
			body:       `{"version":"1.2.3","status":"ok","node":{"user_agent_name":"generic-api"}}`,
		},
		{
			name:       "malformed JSON → nil",
			statusCode: 200,
			body:       `{not valid json`,
		},
		{
			name:       "empty body → nil",
			statusCode: 200,
			body:       ``,
		},
		{
			name:       "body exceeds 2 MiB cap → nil",
			statusCode: 200,
			body:       `{"hot_restart_version":"11.104","padding":"` + strings.Repeat("A", 2*1024*1024+1) + `"}`,
		},
		{
			name:       "user_agent_name present but not envoy, no hot_restart_version → nil",
			statusCode: 200,
			body:       `{"version":"1.2.3","node":{"user_agent_name":"some-other-proxy"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &EnvoyServerInfoFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			result, err := fp.Fingerprint(resp, []byte(tt.body))
			assert.NoError(t, err)
			assert.Nil(t, result, "expected nil result for negative test case")
		})
	}
}

// ── parseEnvoyVersionField ──────────────────────────────────────────────────────

func TestParseEnvoyVersionField(t *testing.T) {
	tests := []struct {
		name           string
		field          string
		wantVersion    string
		wantRawVersion string
		wantBuildType  string
		wantTLSLibrary string
	}{
		{
			name:           "full hash/version/status/buildtype/tls string",
			field:          "c93f9f6c1e5adddd10a3e3646c7e049c649ae177/1.9.0-dev/Clean/RELEASE/BoringSSL",
			wantVersion:    "1.9.0",
			wantRawVersion: "1.9.0-dev",
			wantBuildType:  "RELEASE",
			wantTLSLibrary: "BoringSSL",
		},
		{
			name:           "version without hash prefix",
			field:          "1.28.0/Clean/RELEASE/BoringSSL",
			wantVersion:    "1.28.0",
			wantRawVersion: "1.28.0",
			wantBuildType:  "RELEASE",
			wantTLSLibrary: "BoringSSL",
		},
		{
			name:           "version with -rc suffix",
			field:          "abc123/2.0.0-rc1/Modified/DEBUG/wolfSSL",
			wantVersion:    "2.0.0",
			wantRawVersion: "2.0.0-rc1",
			wantBuildType:  "DEBUG",
			wantTLSLibrary: "wolfSSL",
		},
		{
			name:        "invalid version segment (no semver anywhere) → all empty",
			field:       "deadbeef/Clean/RELEASE/BoringSSL",
			wantVersion: "",
		},
		{
			name:        "partial semver match rejected (5.38abc)",
			field:       "hash/5.38abc/Clean/RELEASE/BoringSSL",
			wantVersion: "",
		},
		{
			name:        "empty field",
			field:       "",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseEnvoyVersionField(tt.field)
			assert.Equal(t, tt.wantVersion, got.Version)
			assert.Equal(t, tt.wantRawVersion, got.RawVersion)
			assert.Equal(t, tt.wantBuildType, got.BuildType)
			assert.Equal(t, tt.wantTLSLibrary, got.TLSLibrary)
		})
	}
}

// ── buildEnvoyCPE ────────────────────────────────────────────────────────────────

func TestBuildEnvoyCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{name: "valid version", version: "1.9.0", want: "cpe:2.3:a:envoyproxy:envoy:1.9.0:*:*:*:*:*:*:*"},
		{name: "valid version with dev suffix → suffix stripped", version: "1.9.0-dev", want: "cpe:2.3:a:envoyproxy:envoy:1.9.0:*:*:*:*:*:*:*"},
		{name: "empty version → wildcard", version: "", want: "cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*"},
		{name: "invalid version (metacharacters) → wildcard", version: "1.9.0:*", want: "cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*"},
		{name: "invalid version (V-prefix) → wildcard", version: "V1.9.0", want: "cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildEnvoyCPE(tt.version))
		})
	}
}

// ── EnvoyAdminFingerprinter: Name ────────────────────────────────────────────────

func TestEnvoyAdminFingerprinter_Name(t *testing.T) {
	fp := &EnvoyAdminFingerprinter{}
	assert.Equal(t, "envoy-admin", fp.Name())
}

// ── EnvoyAdminFingerprinter: Match ───────────────────────────────────────────────

func TestEnvoyAdminFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		server      string
		contentType string
		want        bool
	}{
		{name: "200 + server: envoy → true", statusCode: 200, server: "envoy", want: true},
		{name: "200 + server: ENVOY → true", statusCode: 200, server: "ENVOY", want: true},
		{name: "403 + server: envoy → true (403 in 200-499 range)", statusCode: 403, server: "envoy", want: true},
		{name: "499 + server: envoy → true (boundary)", statusCode: 499, server: "envoy", want: true},
		{name: "200 + text/html content-type → true", statusCode: 200, contentType: "text/html; charset=utf-8", want: true},
		{name: "200 + server: nginx + text/html → true (candidate via content-type)", statusCode: 200, server: "nginx", contentType: "text/html", want: true},
		{name: "200 + server: nginx + application/json → false", statusCode: 200, server: "nginx", contentType: "application/json", want: false},
		{name: "200 + no headers → false", statusCode: 200, want: false},
		{name: "500 + server: envoy → false (5xx rejected)", statusCode: 500, server: "envoy", want: false},
		{name: "503 + text/html → false (5xx rejected)", statusCode: 503, contentType: "text/html", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &EnvoyAdminFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
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

// ── EnvoyAdminFingerprinter: Fingerprint (positive) ─────────────────────────────

func TestEnvoyAdminFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name                string
		statusCode          int
		server              string
		body                string
		wantDetectionMethod string
	}{

		{
			name:                "title only, no server header → admin_ui",
			statusCode:          200,
			body:                `<html><head><title>Envoy Admin</title></head><body><table><tr><td>/stats</td></tr></table></body></html>`,
			wantDetectionMethod: "admin_ui",
		},
		{
			name:                "case-insensitive title match → admin_ui",
			statusCode:          200,
			body:                `<html><head><title>envoy admin</title></head><body></body></html>`,
			wantDetectionMethod: "admin_ui",
		},
		{
			name:                "both server header and title present → server_header+admin_ui",
			statusCode:          200,
			server:              "envoy",
			body:                `<html><head><title>Envoy Admin</title></head><body></body></html>`,
			wantDetectionMethod: "server_header+admin_ui",
		},
		{
			name:                "403 status with server header + title → still detected (200-499 accepted)",
			statusCode:          403,
			server:              "envoy",
			body:                `<html><head><title>Envoy Admin</title></head><body></body></html>`,
			wantDetectionMethod: "server_header+admin_ui",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &EnvoyAdminFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			assert.NoError(t, err)
			assert.NotNil(t, result, "expected non-nil result")
			if result == nil {
				return
			}

			assert.Equal(t, "envoy-admin", result.Technology)
			assert.Equal(t, "", result.Version, "no version available from header/HTML alone")
			assert.Equal(t, []string{"cpe:2.3:a:envoyproxy:envoy:*:*:*:*:*:*:*:*"}, result.CPEs)
			assert.Empty(t, result.Severity, "severity must remain unset for fingerprinter-only ticket")
			assert.Equal(t, tt.wantDetectionMethod, result.Metadata["detection_method"])
		})
	}
}

// ── EnvoyAdminFingerprinter: Fingerprint (negative / false-positive guards) ─────

func TestEnvoyAdminFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		server     string
		body       string
	}{
		{
			name:       "server: envoy header only, no admin title → nil (data-plane proxy FP guard)",
			statusCode: 200,
			server:     "envoy",
			body:       `<html><head><title>Not Envoy</title></head><body></body></html>`,
		},
		{
			name:       "generic nginx HTML page, no envoy signals → nil",
			statusCode: 200,
			server:     "nginx",
			body:       `<html><head><title>Welcome to nginx!</title></head><body></body></html>`,
		},
		{
			name:       "prose mention of 'Envoy Admin' outside title → nil",
			statusCode: 200,
			body:       `<html><head><title>Dashboard</title></head><body><p>This is the Envoy Admin interface documentation.</p></body></html>`,
		},
		{
			name:       "5xx status with server: envoy → nil",
			statusCode: 502,
			server:     "envoy",
			body:       `<html><head><title>Envoy Admin</title></head><body></body></html>`,
		},
		{
			name:       "generic HTML, no title, no server header → nil",
			statusCode: 200,
			body:       `<html><body><h1>Hello World</h1></body></html>`,
		},
		{
			name:       "body exceeds 2 MiB cap → nil",
			statusCode: 200,
			server:     "envoy",
			body:       strings.Repeat("A", 2*1024*1024+1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &EnvoyAdminFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			result, err := fp.Fingerprint(resp, []byte(tt.body))
			assert.NoError(t, err)
			assert.Nil(t, result, "expected nil result for negative test case")
		})
	}
}

// ── Integration tests ────────────────────────────────────────────────────────────

func TestEnvoyFingerprinters_Integration(t *testing.T) {
	t.Run("EnvoyAdminFingerprinter detects real HTTP response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "envoy")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintln(w, `<html><head><title>Envoy Admin</title></head><body></body></html>`)
		}))
		defer ts.Close()

		fp := &EnvoyAdminFingerprinter{}
		resp, err := http.Get(ts.URL)
		assert.NoError(t, err)
		defer resp.Body.Close()

		body := []byte(`<html><head><title>Envoy Admin</title></head><body></body></html>`)
		assert.True(t, fp.Match(resp))
		result, err := fp.Fingerprint(resp, body)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		if result != nil {
			assert.Equal(t, "envoy-admin", result.Technology)
			assert.Empty(t, result.Severity)
		}
	})

	t.Run("EnvoyServerInfoFingerprinter detects real HTTP response", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Server", "envoy")
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"version":"hash/1.28.0/Clean/RELEASE/BoringSSL","state":"LIVE","hot_restart_version":"11.104","node":{"user_agent_name":"envoy"}}`)
		}))
		defer ts.Close()

		fp := &EnvoyServerInfoFingerprinter{}
		resp, err := http.Get(ts.URL)
		assert.NoError(t, err)
		defer resp.Body.Close()

		body := []byte(`{"version":"hash/1.28.0/Clean/RELEASE/BoringSSL","state":"LIVE","hot_restart_version":"11.104","node":{"user_agent_name":"envoy"}}`)
		assert.True(t, fp.Match(resp))
		result, err := fp.Fingerprint(resp, body)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		if result != nil {
			assert.Equal(t, "envoy", result.Technology)
			assert.Equal(t, "1.28.0", result.Version)
			assert.Empty(t, result.Severity)
		}
	})
}
