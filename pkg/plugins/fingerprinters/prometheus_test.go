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

func TestPrometheusFingerprinter_Name(t *testing.T) {
	fp := &PrometheusFingerprinter{}
	assert.Equal(t, "prometheus", fp.Name())
}

func TestPrometheusFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &PrometheusFingerprinter{}
	assert.Equal(t, "/api/v1/status/buildinfo", fp.ProbeEndpoint())
}

func TestPrometheusFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "Content-Type: application/json returns true",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "Content-Type: application/json; charset=utf-8 returns true",
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "Content-Type: text/html returns false",
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "No Content-Type header returns false",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PrometheusFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}

			got := fp.Match(resp)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPrometheusFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name                 string
		body                 string
		wantVersion          string
		wantRevision         string
		wantBranch           string
		wantBuildDate        string
		wantGoVersion        string
		wantBuildUserPresent bool
	}{
		{
			name: "Full buildinfo response (v2.45.0 with all fields)",
			body: `{
				"status": "success",
				"data": {
					"version": "2.45.0",
					"revision": "abc123def456",
					"branch": "HEAD",
					"buildUser": "root@buildhost",
					"buildDate": "20231215-08:42:32",
					"goVersion": "go1.21.5"
				}
			}`,
			wantVersion:          "2.45.0",
			wantRevision:         "abc123def456",
			wantBranch:           "HEAD",
			wantBuildDate:        "20231215-08:42:32",
			wantGoVersion:        "go1.21.5",
			wantBuildUserPresent: true,
		},
		{
			name: "Older version (v2.37.0)",
			body: `{
				"status": "success",
				"data": {
					"version": "2.37.0",
					"revision": "b58e00a49055",
					"branch": "HEAD",
					"buildUser": "root@localhost",
					"buildDate": "20230401-12:34:56",
					"goVersion": "go1.20.3"
				}
			}`,
			wantVersion:          "2.37.0",
			wantRevision:         "b58e00a49055",
			wantBranch:           "HEAD",
			wantBuildDate:        "20230401-12:34:56",
			wantGoVersion:        "go1.20.3",
			wantBuildUserPresent: true,
		},
		{
			name: "Pre-release version (v2.50.0-rc.0)",
			body: `{
				"status": "success",
				"data": {
					"version": "2.50.0-rc.0",
					"revision": "def789abc012",
					"branch": "release-2.50",
					"buildUser": "jenkins@ci",
					"buildDate": "20240101-10:00:00",
					"goVersion": "go1.22.0"
				}
			}`,
			wantVersion:          "2.50.0-rc.0",
			wantRevision:         "def789abc012",
			wantBranch:           "release-2.50",
			wantBuildDate:        "20240101-10:00:00",
			wantGoVersion:        "go1.22.0",
			wantBuildUserPresent: true,
		},
		{
			name: "Minimal response (only version, goVersion, status)",
			body: `{
				"status": "success",
				"data": {
					"version": "2.40.0",
					"goVersion": "go1.21.0"
				}
			}`,
			wantVersion:          "2.40.0",
			wantGoVersion:        "go1.21.0",
			wantBuildUserPresent: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PrometheusFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "prometheus", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)

			// Check metadata
			if tt.wantRevision != "" {
				assert.Equal(t, tt.wantRevision, result.Metadata["revision"])
			}
			if tt.wantBranch != "" {
				assert.Equal(t, tt.wantBranch, result.Metadata["branch"])
			}
			if tt.wantBuildDate != "" {
				assert.Equal(t, tt.wantBuildDate, result.Metadata["build_date"])
			}
			if tt.wantGoVersion != "" {
				assert.Equal(t, tt.wantGoVersion, result.Metadata["go_version"])
			}
			if tt.wantBuildUserPresent {
				_, exists := result.Metadata["build_user"]
				assert.True(t, exists, "Expected buildUser in metadata")
			}

			// Check CPE
			require.NotEmpty(t, result.CPEs)
			expectedCPE := "cpe:2.3:a:prometheus:prometheus:" + tt.wantVersion + ":*:*:*:*:*:*:*"
			assert.Contains(t, result.CPEs, expectedCPE)

		})
	}
}

func TestPrometheusFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Non-JSON body",
			body: "OK",
		},
		{
			name: "JSON without status field",
			body: `{"data": {"version": "2.45.0", "goVersion": "go1.21.5"}}`,
		},
		{
			name: "JSON with status != success",
			body: `{"status": "error", "data": {"version": "2.45.0", "goVersion": "go1.21.5"}}`,
		},
		{
			name: "JSON without version in data",
			body: `{"status": "success", "data": {"goVersion": "go1.21.5"}}`,
		},
		{
			name: "JSON without goVersion in data (distinguishes from other APIs)",
			body: `{"status": "success", "data": {"version": "2.45.0"}}`,
		},
		{
			name: "Empty JSON",
			body: `{}`,
		},
		{
			name: "Empty string",
			body: "",
		},
		{
			name: "CPE injection attempt in version",
			body: `{"status": "success", "data": {"version": "2.0.0:*:*:*:*:*:*:*", "goVersion": "go1.21.5"}}`,
		},
		{
			name: "JSON with different envelope structure (not Prometheus)",
			body: `{"version": "2.45.0", "goVersion": "go1.21.5"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PrometheusFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestBuildPrometheusCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "2.45.0",
			want:    "cpe:2.3:a:prometheus:prometheus:2.45.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:prometheus:prometheus:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildPrometheusCPE(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPrometheusFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter
	fp := &PrometheusFingerprinter{}
	Register(fp)

	// Create a valid Prometheus buildinfo response
	body := []byte(`{
		"status": "success",
		"data": {
			"version": "2.45.0",
			"revision": "abc123def456",
			"branch": "HEAD",
			"buildUser": "root@buildhost",
			"buildDate": "20231215-08:42:32",
			"goVersion": "go1.21.5"
		}
	}`)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	results := RunFingerprinters(resp, body)

	// Should find at least the Prometheus fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "prometheus" {
			found = true
			assert.Equal(t, "2.45.0", result.Version)
		}
	}

	assert.True(t, found, "PrometheusFingerprinter not found in results")
}
