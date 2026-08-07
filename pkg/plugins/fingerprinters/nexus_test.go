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

// ── NexusAPIFingerprinter: Name / ProbeEndpoint ─────────────────────────────

func TestNexusAPIFingerprinter_Name(t *testing.T) {
	fp := &NexusAPIFingerprinter{}
	assert.Equal(t, "nexus-repository", fp.Name())
}

func TestNexusAPIFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &NexusAPIFingerprinter{}
	assert.Equal(t, "/service/rest/v1/status", fp.ProbeEndpoint())
}

// ── NexusAPIFingerprinter: Match ─────────────────────────────────────────────

func TestNexusAPIFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		server     string
		want       bool
	}{
		{
			name:       "200 with Nexus server header → true",
			statusCode: 200,
			server:     "Nexus/3.63.0-01 (PRO)",
			want:       true,
		},
		{
			name:       "200 with mixed-case Nexus server header → true",
			statusCode: 200,
			server:     "nexus/3.63.0-01 (pro)",
			want:       true,
		},
		{
			name:       "200 with no server header → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "200 with unrelated server header → false",
			statusCode: 200,
			server:     "Apache/2.4.29",
			want:       false,
		},
		{
			name:       "404 with Nexus server header → false",
			statusCode: 404,
			server:     "Nexus/3.63.0-01 (PRO)",
			want:       false,
		},
		{
			name:       "500 with Nexus server header → false",
			statusCode: 500,
			server:     "Nexus/3.63.0-01 (PRO)",
			want:       false,
		},
		{
			name:       "503 with Nexus server header → true",
			statusCode: 503,
			server:     "Nexus/3.63.0-01 (PRO)",
			want:       true,
		},
		{
			name:       "503 with no server header → false",
			statusCode: 503,
			want:       false,
		},
		{
			name:       "503 with unrelated server header → false",
			statusCode: 503,
			server:     "Apache/2.4.29",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &NexusAPIFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── NexusAPIFingerprinter: Fingerprint ───────────────────────────────────────

func TestNexusAPIFingerprinter_Fingerprint(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		server      string
		wantNil     bool
		wantVersion string
		wantEdition string
		wantMajor   string
		wantCPE     string
	}{
		{
			name:        "Nexus 3 PRO",
			statusCode:  200,
			server:      "Nexus/3.63.0-01 (PRO)",
			wantVersion: "3.63.0",
			wantEdition: "pro",
			wantMajor:   "3",
			wantCPE:     "cpe:2.3:a:sonatype:nexus_repository_manager:3.63.0:*:*:*:*:*:*:*",
		},
		{
			name:        "Nexus 3 OSS",
			statusCode:  200,
			server:      "Nexus/3.70.4-02 (OSS)",
			wantVersion: "3.70.4",
			wantEdition: "oss",
			wantMajor:   "3",
			wantCPE:     "cpe:2.3:a:sonatype:nexus_repository_manager:3.70.4:*:*:*:*:*:*:*",
		},
		{
			name:        "Nexus 2 Restlet",
			statusCode:  200,
			server:      "Nexus/2.15.1-02 Noelios-Restlet-Engine/1.1.6",
			wantVersion: "2.15.1",
			wantEdition: "",
			wantMajor:   "2",
			wantCPE:     "cpe:2.3:a:sonatype:nexus_repository_manager:2.15.1:*:*:*:*:*:*:*",
		},
		{
			name:       "500 → nil",
			statusCode: 500,
			server:     "Nexus/3.63.0-01 (PRO)",
			wantNil:    true,
		},
		{
			name:       "no Nexus server header → nil",
			statusCode: 200,
			server:     "Apache/2.4.29",
			wantNil:    true,
		},
		{
			name:        "503 with Nexus server header",
			statusCode:  503,
			server:      "Nexus/3.63.0-01 (PRO)",
			wantVersion: "3.63.0",
			wantEdition: "pro",
			wantMajor:   "3",
			wantCPE:     "cpe:2.3:a:sonatype:nexus_repository_manager:3.63.0:*:*:*:*:*:*:*",
		},
		{
			name:       "503 with no Nexus server header → nil",
			statusCode: 503,
			server:     "Apache/2.4.29",
			wantNil:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &NexusAPIFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, []byte(""))
			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, "nexus-repository", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			assert.Contains(t, result.CPEs, tt.wantCPE)
			assert.Equal(t, "server_header", result.Metadata["detection_method"])
			if tt.wantEdition != "" {
				assert.Equal(t, tt.wantEdition, result.Metadata["edition"])
			} else {
				assert.NotContains(t, result.Metadata, "edition")
			}
			assert.Equal(t, tt.wantMajor, result.Metadata["nexus_major_version"])
		})
	}
}

// ── NexusLoginFingerprinter: Name ────────────────────────────────────────────

func TestNexusLoginFingerprinter_Name(t *testing.T) {
	fp := &NexusLoginFingerprinter{}
	assert.Equal(t, "nexus-repository-login", fp.Name())
}

// ── NexusLoginFingerprinter: Match ───────────────────────────────────────────

func TestNexusLoginFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		server      string
		contentType string
		want        bool
	}{
		{
			name:       "200 with Nexus server header, no content-type → true",
			statusCode: 200,
			server:     "Nexus/3.63.0-01 (PRO)",
			want:       true,
		},
		{
			name:       "401 with Nexus server header → true",
			statusCode: 401,
			server:     "Nexus/3.63.0-01 (PRO)",
			want:       true,
		},
		{
			name:       "404 with Nexus server header → true",
			statusCode: 404,
			server:     "Nexus/3.63.0-01 (PRO)",
			want:       true,
		},
		{
			name:       "500 with Nexus server header → false",
			statusCode: 500,
			server:     "Nexus/3.63.0-01 (PRO)",
			want:       false,
		},
		{
			name:        "200 text/html, no server header → true",
			statusCode:  200,
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "200 text/html charset, no server header → true",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 application/json, no server header → false",
			statusCode:  200,
			contentType: "application/json",
			want:        false,
		},
		{
			name:       "200 no server header, no content-type → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "200 unrelated server header, no content-type → false",
			statusCode: 200,
			server:     "nginx/1.14.0",
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &NexusLoginFingerprinter{}
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

// ── NexusLoginFingerprinter: Fingerprint ─────────────────────────────────────

func TestNexusLoginFingerprinter_Fingerprint(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		body        string
		wantNil     bool
		wantVersion string
		wantEdition string
		wantMajor   string
		wantMethod  string
	}{
		{
			name:        "Nexus 3 Server header with version+edition",
			server:      "Nexus/3.63.0-01 (PRO)",
			wantVersion: "3.63.0",
			wantEdition: "pro",
			wantMajor:   "3",
			wantMethod:  "server_header",
		},
		{
			name:        "Nexus 3 Server header OSS",
			server:      "Nexus/3.70.4-02 (OSS)",
			wantVersion: "3.70.4",
			wantEdition: "oss",
			wantMajor:   "3",
			wantMethod:  "server_header",
		},
		{
			name:        "Nexus 2 Server header with Restlet",
			server:      "Nexus/2.15.1-02 Noelios-Restlet-Engine/1.1.6",
			wantVersion: "2.15.1",
			wantMajor:   "2",
			wantMethod:  "server_header",
		},
		{
			name:       "Server header missing version",
			server:     "Nexus/",
			wantMethod: "server_header",
		},
		{
			name:       "HTML title Nexus 3, no server header",
			body:       `<html><head><title>Sonatype Nexus Repository</title></head></html>`,
			wantMajor:  "3",
			wantMethod: "html_title",
		},
		{
			name:       "HTML title Nexus 2, no server header",
			body:       `<html><head><title>Sonatype Nexus</title></head></html>`,
			wantMajor:  "2",
			wantMethod: "html_title",
		},
		{
			name:    "generic HTML, no server header → nil",
			body:    `<html><head><title>Welcome</title></head></html>`,
			wantNil: true,
		},
		{
			name:    "empty body, no server header → nil",
			body:    "",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &NexusLoginFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, "nexus-repository-login", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			assert.Equal(t, tt.wantMethod, result.Metadata["detection_method"])
			if tt.wantMajor != "" {
				assert.Equal(t, tt.wantMajor, result.Metadata["nexus_major_version"])
			} else {
				assert.NotContains(t, result.Metadata, "nexus_major_version")
			}
			if tt.wantEdition != "" {
				assert.Equal(t, tt.wantEdition, result.Metadata["edition"])
			} else {
				assert.NotContains(t, result.Metadata, "edition")
			}
		})
	}
}

func TestNexusLoginFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &NexusLoginFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	// Body larger than 1 MiB cap, but with the Nexus 3 title placed within the
	// first 1 MiB so truncation (not rejection) is verified.
	title := `<html><head><title>Sonatype Nexus Repository</title></head><body>`
	padding := strings.Repeat("x", 2*1024*1024)
	body := []byte(title + padding + "</body></html>")

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result, "detection signal within the first 1 MiB must still fire after truncation")
	assert.Equal(t, "3", result.Metadata["nexus_major_version"])
}

func TestNexusLoginFingerprinter_Fingerprint_Status500(t *testing.T) {
	fp := &NexusLoginFingerprinter{}
	resp := &http.Response{
		StatusCode: 500,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Nexus/3.63.0-01 (PRO)")

	result, err := fp.Fingerprint(resp, []byte(""))
	require.NoError(t, err)
	assert.Nil(t, result, "Fingerprint must return nil for status >= 500")
}

// ── False-positive guards ────────────────────────────────────────────────────

func TestNexusLoginFingerprinter_FalsePositives(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		contentType string
		body        string
	}{
		{
			name:   "generic Apache server header",
			server: "Apache/2.4.29 (Ubuntu)",
			body:   `<html><head><title>Apache2 Default Page</title></head></html>`,
		},
		{
			name:   "generic nginx server header",
			server: "nginx/1.14.0",
			body:   `<html><head><title>Welcome to nginx!</title></head></html>`,
		},
		{
			name:        "generic HTML title, text/html content-type",
			contentType: "text/html",
			body:        `<html><head><title>Example Domain</title></head></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &NexusLoginFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestNexusAPIFingerprinter_FalsePositives(t *testing.T) {
	tests := []struct {
		name   string
		server string
	}{
		{name: "generic Apache server header", server: "Apache/2.4.29 (Ubuntu)"},
		{name: "generic nginx server header", server: "nginx/1.14.0"},
		{name: "prefix false positive: word containing Nexus but no slash", server: "SonatypeNexusProxy/1.0"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &NexusAPIFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Server", tt.server)

			assert.False(t, fp.Match(resp))

			result, err := fp.Fingerprint(resp, []byte(""))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ── Integration: Match + Fingerprint ─────────────────────────────────────────

func TestNexusAPIFingerprinter_Integration(t *testing.T) {
	fp := &NexusAPIFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Nexus/3.63.0-01 (PRO)")

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, []byte(""))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "nexus-repository", result.Technology)
	assert.Equal(t, "3.63.0", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:sonatype:nexus_repository_manager:3.63.0:*:*:*:*:*:*:*")
}

func TestNexusLoginFingerprinter_Integration(t *testing.T) {
	fp := &NexusLoginFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")
	body := []byte(`<html><head><title>Sonatype Nexus Repository</title></head></html>`)

	require.True(t, fp.Match(resp))

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "nexus-repository-login", result.Technology)
	assert.Equal(t, "3", result.Metadata["nexus_major_version"])
}

// ── Severity / SecurityFindings ──────────────────────────────────────────────

func TestNexusAPIFingerprinter_NoSeverityOrFindings(t *testing.T) {
	fp := &NexusAPIFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Server", "Nexus/3.63.0-01 (PRO)")

	result, err := fp.Fingerprint(resp, []byte(""))
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "fingerprinter-only: Severity must be unset")
	assert.Nil(t, result.SecurityFindings, "fingerprinter-only: no SecurityFindings")
}

func TestNexusLoginFingerprinter_NoSeverityOrFindings(t *testing.T) {
	fp := &NexusLoginFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	body := []byte(`<html><head><title>Sonatype Nexus Repository</title></head></html>`)

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Zero(t, result.Severity, "fingerprinter-only: Severity must be unset")
	assert.Nil(t, result.SecurityFindings, "fingerprinter-only: no SecurityFindings")
}

// ── buildNexusCPE ────────────────────────────────────────────────────────────

func TestBuildNexusCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "with version",
			version:  "3.63.0",
			expected: "cpe:2.3:a:sonatype:nexus_repository_manager:3.63.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version → wildcard",
			version:  "",
			expected: "cpe:2.3:a:sonatype:nexus_repository_manager:*:*:*:*:*:*:*:*",
		},
		{
			name:     "version with CPE metacharacter rejected → wildcard",
			version:  "3.63.0:evil",
			expected: "cpe:2.3:a:sonatype:nexus_repository_manager:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildNexusCPE(tt.version))
		})
	}
}

// ── extractNexusServerInfo ───────────────────────────────────────────────────

func TestExtractNexusServerInfo(t *testing.T) {
	tests := []struct {
		name           string
		server         string
		wantVersion    string
		wantEdition    string
		wantGeneration string
	}{
		{
			name:           "Nexus 3 PRO with build suffix",
			server:         "Nexus/3.63.0-01 (PRO)",
			wantVersion:    "3.63.0",
			wantEdition:    "pro",
			wantGeneration: "3",
		},
		{
			name:           "Nexus 3 OSS with build suffix",
			server:         "Nexus/3.70.4-02 (OSS)",
			wantVersion:    "3.70.4",
			wantEdition:    "oss",
			wantGeneration: "3",
		},
		{
			name:           "Nexus 2 with Restlet engine",
			server:         "Nexus/2.15.1-02 Noelios-Restlet-Engine/1.1.6",
			wantVersion:    "2.15.1",
			wantEdition:    "",
			wantGeneration: "2",
		},
		{
			name:           "missing version",
			server:         "Nexus/",
			wantVersion:    "",
			wantEdition:    "",
			wantGeneration: "",
		},
		{
			name:           "partial version match rejected: 5.38abc",
			server:         "Nexus/5.38abc (PRO)",
			wantVersion:    "",
			wantEdition:    "pro",
			wantGeneration: "",
		},
		{
			name:           "empty server header",
			server:         "",
			wantVersion:    "",
			wantEdition:    "",
			wantGeneration: "",
		},
		{
			name:           "lowercase edition in parens still matched and lowercased",
			server:         "Nexus/3.63.0-01 (pro)",
			wantVersion:    "3.63.0",
			wantEdition:    "pro",
			wantGeneration: "3",
		},
		{
			name:           "trailing alphabetic garbage rejected",
			server:         "Nexus/5.38.0abc (PRO)",
			wantVersion:    "",
			wantEdition:    "pro",
			wantGeneration: "",
		},
		{
			name:           "four-component version rejected",
			server:         "Nexus/3.63.0.1-01 (PRO)",
			wantVersion:    "",
			wantEdition:    "pro",
			wantGeneration: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, edition, generation := extractNexusServerInfo(tt.server)
			assert.Equal(t, tt.wantVersion, version)
			assert.Equal(t, tt.wantEdition, edition)
			assert.Equal(t, tt.wantGeneration, generation)
		})
	}
}
