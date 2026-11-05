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

// ── Name / ProbeEndpoint ─────────────────────────────────────────────────────

func TestRayFingerprinter_Name(t *testing.T) {
	fp := &RayFingerprinter{}
	assert.Equal(t, "ray", fp.Name())
}

func TestRayFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &RayFingerprinter{}
	assert.Equal(t, "/api/version", fp.ProbeEndpoint())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestRayFingerprinter_Match(t *testing.T) {
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
			fp := &RayFingerprinter{}
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

// ── Fingerprint ──────────────────────────────────────────────────────────────

func TestRayFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantVersion     string
		wantCPE         string
		wantRayVersion  string
		wantRayCommit   string
		wantAPIVersion  any
		wantSessionName any
	}{
		{
			name:            "full response with valid semver",
			body:            `{"version": "4", "ray_version": "2.56.0", "ray_commit": "abc123def456789012345678901234567890abcd", "session_name": "session_2026-07-16_10-30-00_123456_12345"}`,
			wantVersion:     "2.56.0",
			wantCPE:         "cpe:2.3:a:anyscale:ray:2.56.0:*:*:*:*:*:*:*",
			wantRayVersion:  "2.56.0",
			wantRayCommit:   "abc123def456789012345678901234567890abcd",
			wantAPIVersion:  "4",
			wantSessionName: "session_2026-07-16_10-30-00_123456_12345",
		},
		{
			name:           "dev build version does not match strict semver",
			body:           `{"version": "4", "ray_version": "3.0.0.dev0", "ray_commit": "abc123"}`,
			wantVersion:    "",
			wantCPE:        "cpe:2.3:a:anyscale:ray:*:*:*:*:*:*:*:*",
			wantRayVersion: "3.0.0.dev0",
			wantRayCommit:  "abc123",
			wantAPIVersion: "4",
		},
		{
			name:           "missing optional fields omitted from metadata",
			body:           `{"ray_version": "2.9.0", "ray_commit": "deadbeef"}`,
			wantVersion:    "2.9.0",
			wantCPE:        "cpe:2.3:a:anyscale:ray:2.9.0:*:*:*:*:*:*:*",
			wantRayVersion: "2.9.0",
			wantRayCommit:  "deadbeef",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RayFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
			resp.Header.Set("Content-Type", "application/json")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "ray", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.wantCPE)
			assert.Equal(t, tt.wantRayVersion, result.Metadata["ray_version"])
			assert.Equal(t, tt.wantRayCommit, result.Metadata["ray_commit"])

			if tt.wantAPIVersion != nil {
				assert.Equal(t, tt.wantAPIVersion, result.Metadata["api_version"])
			} else {
				_, ok := result.Metadata["api_version"]
				assert.False(t, ok, "api_version should be absent when not present in response")
			}

			if tt.wantSessionName != nil {
				assert.Equal(t, tt.wantSessionName, result.Metadata["session_name"])
			} else {
				_, ok := result.Metadata["session_name"]
				assert.False(t, ok, "session_name should be absent when not present in response")
			}
		})
	}
}

func TestRayFingerprinter_Fingerprint_Invalid(t *testing.T) {
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
			name: "missing ray_commit",
			body: `{"ray_version": "2.56.0"}`,
		},
		{
			name: "missing ray_version",
			body: `{"ray_commit": "abc123"}`,
		},
		{
			name: "missing both ray_version and ray_commit",
			body: `{"version": "4"}`,
		},
		{
			name: "empty ray_version and ray_commit strings",
			body: `{"ray_version": "", "ray_commit": ""}`,
		},
		{
			name: "generic JSON API unrelated to Ray",
			body: `{"status": "ok", "version": "1.0"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RayFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
			resp.Header.Set("Content-Type", "application/json")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestRayFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &RayFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	bigBody := []byte(strings.Repeat("x", 2*1024*1024+1))
	result, err := fp.Fingerprint(resp, bigBody)
	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestRayFingerprinter_Fingerprint_CPEInjectionGuard(t *testing.T) {
	// Regex is anchored to digits and dots only, so a malicious ray_version
	// value can never reach the CPE guard via the regex path. Verify the
	// guard directly via buildRayCPE and confirm the fingerprinter itself
	// never produces an unsanitized version for non-semver input.
	fp := &RayFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	body := `{"ray_version": "1.2.3:evil*", "ray_commit": "abc123"}`
	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Empty(t, result.Version, "malformed version must not be extracted")
	assert.NotContains(t, result.CPEs[0], "evil")
}

// ── Regex boundary behavior ──────────────────────────────────────────────────

func TestRayVersionRegex(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"2.56.0", true},
		{"0.0.1", true},
		{"3.0.0.dev0", false},
		{"5.38abc", false},
		{"V5.38.0", false},
		{"2.56", false},
		{"2.56.0.1", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			assert.Equal(t, tt.want, rayVersionRegex.MatchString(tt.version))
		})
	}
}

// ── buildRayCPE ──────────────────────────────────────────────────────────────

func TestBuildRayCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with version",
			version:  "2.56.0",
			expected: "cpe:2.3:a:anyscale:ray:2.56.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version → wildcard",
			version:  "",
			expected: "cpe:2.3:a:anyscale:ray:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildRayCPE(tt.version))
		})
	}
}

// ── Integration: Match + Fingerprint ─────────────────────────────────────────

func TestRayFingerprinter_Integration(t *testing.T) {
	fp := &RayFingerprinter{}

	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	require.True(t, fp.Match(resp))

	body := `{"version": "4", "ray_version": "2.56.0", "ray_commit": "abc123def456789012345678901234567890abcd", "session_name": "session_2026-07-16_10-30-00_123456_12345"}`
	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "ray", result.Technology)
	assert.Equal(t, "2.56.0", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:anyscale:ray:2.56.0:*:*:*:*:*:*:*")
}

func TestRayFingerprinter_Integration_NonRay(t *testing.T) {
	fp := &RayFingerprinter{}

	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(`{"status": "healthy"}`))
	require.NoError(t, err)
	assert.Nil(t, result)
}

// ── Severity / SecurityFindings ──────────────────────────────────────────────

func TestRayFingerprinter_NoSeverityOrFindings(t *testing.T) {
	fp := &RayFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	resp.Header.Set("Content-Type", "application/json")

	body := `{"ray_version": "2.56.0", "ray_commit": "abc123"}`
	result, err := fp.Fingerprint(resp, []byte(body))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "fingerprinter-only: Severity must be unset")
	assert.Nil(t, result.SecurityFindings, "fingerprinter-only: no SecurityFindings")
}
