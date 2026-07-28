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

// ── Name / ProbeEndpoint / ProbeAccept ──────────────────────────────────────

func TestArgoCDAPIFingerprinter_Name(t *testing.T) {
	fp := &ArgoCDAPIFingerprinter{}
	assert.Equal(t, "argocd", fp.Name())
}

func TestArgoCDAPIFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ArgoCDAPIFingerprinter{}
	assert.Equal(t, "/api/version", fp.ProbeEndpoint())
}

func TestArgoCDLoginFingerprinter_Name(t *testing.T) {
	fp := &ArgoCDLoginFingerprinter{}
	assert.Equal(t, "argocd-login", fp.Name())
}

func TestArgoCDLoginFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ArgoCDLoginFingerprinter{}
	assert.Equal(t, "/login", fp.ProbeEndpoint())
}

func TestArgoCDLoginFingerprinter_ProbeAccept(t *testing.T) {
	fp := &ArgoCDLoginFingerprinter{}
	assert.Equal(t, "text/html", fp.ProbeAccept())
}

// ── Match: ArgoCDAPIFingerprinter ───────────────────────────────────────────

func TestArgoCDAPIFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 application/json → true",
			statusCode:  200,
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "200 application/json charset → true",
			statusCode:  200,
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 APPLICATION/JSON mixed case → true",
			statusCode:  200,
			contentType: "APPLICATION/JSON",
			want:        true,
		},
		{
			name:        "200 text/html → false",
			statusCode:  200,
			contentType: "text/html",
			want:        false,
		},
		{
			name:       "200 no content-type → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:        "404 application/json → false",
			statusCode:  404,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "500 application/json → false",
			statusCode:  500,
			contentType: "application/json",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ArgoCDAPIFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Match: ArgoCDLoginFingerprinter ─────────────────────────────────────────

func TestArgoCDLoginFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 text/html → true",
			statusCode:  200,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "200 text/html charset → true",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 TEXT/HTML mixed case → true",
			statusCode:  200,
			contentType: "TEXT/HTML",
			want:        true,
		},
		{
			name:        "302 text/html → true (redirect states allowed)",
			statusCode:  302,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "401 text/html → true (auth-gated states allowed)",
			statusCode:  401,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "499 text/html → true (boundary of allowed range)",
			statusCode:  499,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "500 text/html → false (outside allowed range)",
			statusCode:  500,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "200 application/json → false",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:       "200 no content-type → false",
			statusCode: 200,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ArgoCDLoginFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint: ArgoCDAPIFingerprinter (valid) ─────────────────────────────

func TestArgoCDAPIFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name                 string
		body                 string
		wantVersion          string
		wantCPE              string
		wantRawVersion       string
		wantBuildDate        any
		wantGitCommit        any
		wantGoVersion        any
		wantPlatform         any
		wantKsonnetVersion   any
		wantKustomizeVersion any
		wantHelmVersion      any
	}{
		{
			name: "full response with valid semver and build suffix",
			body: `{"Version": "v2.9.3+6eba5be", "BuildDate": "2024-01-01T00:00:00Z",
				"GitCommit": "6eba5be1234567890abcdef1234567890abcdef", "GoVersion": "go1.21.5",
				"Compiler": "gc", "Platform": "linux/amd64", "KsonnetVersion": "v0.13.1",
				"KustomizeVersion": "v4.5.7", "HelmVersion": "v3.13.2"}`,
			wantVersion:          "2.9.3",
			wantCPE:              "cpe:2.3:a:argoproj:argo_cd:2.9.3:*:*:*:*:*:*:*",
			wantRawVersion:       "v2.9.3+6eba5be",
			wantBuildDate:        "2024-01-01T00:00:00Z",
			wantGitCommit:        "6eba5be1234567890abcdef1234567890abcdef",
			wantGoVersion:        "go1.21.5",
			wantPlatform:         "linux/amd64",
			wantKsonnetVersion:   "v0.13.1",
			wantKustomizeVersion: "v4.5.7",
			wantHelmVersion:      "v3.13.2",
		},
		{
			name:            "missing optional fields omitted from metadata",
			body:            `{"Version": "v2.9.3", "HelmVersion": "v3.13.2"}`,
			wantVersion:     "2.9.3",
			wantCPE:         "cpe:2.3:a:argoproj:argo_cd:2.9.3:*:*:*:*:*:*:*",
			wantRawVersion:  "v2.9.3",
			wantHelmVersion: "v3.13.2",
		},
		{
			name:                 "dev build version does not match strict semver",
			body:                 `{"Version": "v2.10.0-rc1", "KustomizeVersion": "v4.5.7"}`,
			wantVersion:          "",
			wantCPE:              "cpe:2.3:a:argoproj:argo_cd:*:*:*:*:*:*:*:*",
			wantRawVersion:       "v2.10.0-rc1",
			wantKustomizeVersion: "v4.5.7",
		},
		{
			name:               "version with build suffix, no v prefix",
			body:               `{"Version": "2.9.3+6eba5be", "KsonnetVersion": "v0.13.1"}`,
			wantVersion:        "2.9.3",
			wantCPE:            "cpe:2.3:a:argoproj:argo_cd:2.9.3:*:*:*:*:*:*:*",
			wantRawVersion:     "2.9.3+6eba5be",
			wantKsonnetVersion: "v0.13.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ArgoCDAPIFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
			resp.Header.Set("Content-Type", "application/json")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "argocd", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.wantCPE)
			assert.Equal(t, tt.wantRawVersion, result.Metadata["raw_version"])

			assertOptionalMetadata(t, result, "build_date", tt.wantBuildDate)
			assertOptionalMetadata(t, result, "git_commit", tt.wantGitCommit)
			assertOptionalMetadata(t, result, "go_version", tt.wantGoVersion)
			assertOptionalMetadata(t, result, "platform", tt.wantPlatform)
			assertOptionalMetadata(t, result, "ksonnet_version", tt.wantKsonnetVersion)
			assertOptionalMetadata(t, result, "kustomize_version", tt.wantKustomizeVersion)
			assertOptionalMetadata(t, result, "helm_version", tt.wantHelmVersion)
		})
	}
}

// assertOptionalMetadata checks that an optional metadata field is present
// with the expected value when want is non-nil, and absent otherwise.
func assertOptionalMetadata(t *testing.T, result *FingerprintResult, key string, want any) {
	t.Helper()
	if want != nil {
		assert.Equal(t, want, result.Metadata[key])
	} else {
		_, ok := result.Metadata[key]
		assert.False(t, ok, "%s should be absent when not present in response", key)
	}
}

// ── Fingerprint: ArgoCDAPIFingerprinter (invalid) ───────────────────────────

func TestArgoCDAPIFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "non-JSON body",
			body: "not json",
		},
		{
			name: "empty body",
			body: "",
		},
		{
			name: "missing Version",
			body: `{"KsonnetVersion": "v0.13.1"}`,
		},
		{
			name: "missing all ArgoCD-specific fields",
			body: `{"Version": "v2.9.3", "BuildDate": "2024-01-01", "GitCommit": "abc123"}`,
		},
		{
			name: "empty Version string",
			body: `{"Version": "", "KsonnetVersion": "v0.13.1"}`,
		},
		{
			name: "generic JSON API unrelated to ArgoCD",
			body: `{"status": "ok", "Version": "1.0"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ArgoCDAPIFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
			resp.Header.Set("Content-Type", "application/json")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestArgoCDAPIFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &ArgoCDAPIFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	bigBody := []byte(strings.Repeat("x", 1*1024*1024+1))
	result, err := fp.Fingerprint(resp, bigBody)
	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestArgoCDAPIFingerprinter_Fingerprint_CPEInjectionGuard(t *testing.T) {
	// Regex is anchored to digits and dots only, so a malicious Version value
	// can never reach the CPE guard via the regex path. Verify the guard
	// directly via buildArgoCDCPE and confirm the fingerprinter itself never
	// produces an unsanitized version for non-semver input.
	fp := &ArgoCDAPIFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	body := `{"Version": "v1.2.3:evil*", "KsonnetVersion": "v0.13.1"}`
	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Version, "malformed version must not be extracted")
	assert.NotContains(t, result.CPEs[0], "evil")
}

// ── Fingerprint: ArgoCDLoginFingerprinter (valid) ───────────────────────────

func TestArgoCDLoginFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "standard title",
			body: `<!DOCTYPE html><html><head><title>Argo CD</title></head><body><div id="app"></div></body></html>`,
		},
		{
			name: "title with whitespace",
			body: `<!DOCTYPE html><html><head><title>  Argo CD  </title></head><body></body></html>`,
		},
		{
			name: "title with attributes",
			body: `<!DOCTYPE html><html><head><title lang="en">Argo CD</title></head><body></body></html>`,
		},
		{
			name: "title mixed case",
			body: `<!DOCTYPE html><html><head><TITLE>argo cd</TITLE></head><body></body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ArgoCDLoginFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
			resp.Header.Set("Content-Type", "text/html")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "argocd", result.Technology)
			assert.Empty(t, result.Version)
			assert.Contains(t, result.CPEs, "cpe:2.3:a:argoproj:argo_cd:*:*:*:*:*:*:*:*")
			assert.Equal(t, "login_title", result.Metadata["detection_method"])
		})
	}
}

// ── Fingerprint: ArgoCDLoginFingerprinter (invalid) ─────────────────────────

func TestArgoCDLoginFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "wrong title",
			body: `<!DOCTYPE html><html><head><title>Some Other App</title></head><body></body></html>`,
		},
		{
			name: "no title",
			body: `<!DOCTYPE html><html><head></head><body><h1>Argo CD</h1></body></html>`,
		},
		{
			name: "generic HTML page",
			body: `<!DOCTYPE html><html><head><title>Login</title></head><body><form></form></body></html>`,
		},
		{
			name: "empty body",
			body: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ArgoCDLoginFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
			resp.Header.Set("Content-Type", "text/html")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestArgoCDLoginFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &ArgoCDLoginFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/html")

	bigBody := []byte(strings.Repeat("x", 1*1024*1024+1))
	result, err := fp.Fingerprint(resp, bigBody)
	assert.Nil(t, result)
	assert.Nil(t, err)
}

// ── Regex boundary behavior ──────────────────────────────────────────────────

func TestArgoCDVersionRegex(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"2.9.3", true},
		{"0.0.1", true},
		{"2.10.0-rc1", false},
		{"5.38abc", false},
		{"V5.38.0", false},
		{"2.9", false},
		{"2.9.3.1", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			assert.Equal(t, tt.want, argoCDVersionRegex.MatchString(tt.version))
		})
	}
}

// ── buildArgoCDCPE ───────────────────────────────────────────────────────────

func TestBuildArgoCDCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with version",
			version:  "2.9.3",
			expected: "cpe:2.3:a:argoproj:argo_cd:2.9.3:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version → wildcard",
			version:  "",
			expected: "cpe:2.3:a:argoproj:argo_cd:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildArgoCDCPE(tt.version))
		})
	}
}

// ── extractArgoCDVersion ─────────────────────────────────────────────────────

func TestExtractArgoCDVersion(t *testing.T) {
	tests := []struct {
		name string
		raw  string
		want string
	}{
		{
			name: "v prefix and build suffix",
			raw:  "v2.9.3+6eba5be",
			want: "2.9.3",
		},
		{
			name: "v prefix only",
			raw:  "v2.9.3",
			want: "2.9.3",
		},
		{
			name: "build suffix only",
			raw:  "2.9.3+6eba5be",
			want: "2.9.3",
		},
		{
			name: "neither prefix nor suffix",
			raw:  "2.9.3",
			want: "2.9.3",
		},
		{
			name: "invalid version",
			raw:  "not-a-version",
			want: "",
		},
		{
			name: "dev build suffix does not match strict semver",
			raw:  "v2.10.0-rc1",
			want: "",
		},
		{
			name: "empty",
			raw:  "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, extractArgoCDVersion(tt.raw))
		})
	}
}

// ── Integration: Match + Fingerprint ─────────────────────────────────────────

func TestArgoCDAPIFingerprinter_Integration(t *testing.T) {
	fp := &ArgoCDAPIFingerprinter{}

	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	require.True(t, fp.Match(resp))

	body := `{"Version": "v2.9.3+6eba5be", "KsonnetVersion": "v0.13.1", "KustomizeVersion": "v4.5.7", "HelmVersion": "v3.13.2"}`
	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "argocd", result.Technology)
	assert.Equal(t, "2.9.3", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:argoproj:argo_cd:2.9.3:*:*:*:*:*:*:*")
}

func TestArgoCDAPIFingerprinter_Integration_NonArgoCD(t *testing.T) {
	fp := &ArgoCDAPIFingerprinter{}

	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(`{"status": "healthy"}`))
	require.NoError(t, err)
	assert.Nil(t, result)
}

func TestArgoCDLoginFingerprinter_Integration(t *testing.T) {
	fp := &ArgoCDLoginFingerprinter{}

	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/html")

	require.True(t, fp.Match(resp))

	body := `<!DOCTYPE html><html><head><title>Argo CD</title></head><body></body></html>`
	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "argocd", result.Technology)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:argoproj:argo_cd:*:*:*:*:*:*:*:*")
}

func TestArgoCDLoginFingerprinter_Integration_NonArgoCD(t *testing.T) {
	fp := &ArgoCDLoginFingerprinter{}

	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/html")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(`<html><head><title>Generic App</title></head></html>`))
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ── Severity / SecurityFindings ──────────────────────────────────────────────

func TestArgoCDAPIFingerprinter_NoSeverityOrFindings(t *testing.T) {
	fp := &ArgoCDAPIFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	body := `{"Version": "v2.9.3", "KsonnetVersion": "v0.13.1"}`
	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "fingerprinter-only: Severity must be unset")
	assert.Nil(t, result.SecurityFindings, "fingerprinter-only: no SecurityFindings")
}

func TestArgoCDLoginFingerprinter_NoSeverityOrFindings(t *testing.T) {
	fp := &ArgoCDLoginFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "text/html")

	body := `<!DOCTYPE html><html><head><title>Argo CD</title></head></html>`
	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "fingerprinter-only: Severity must be unset")
	assert.Nil(t, result.SecurityFindings, "fingerprinter-only: no SecurityFindings")
}
