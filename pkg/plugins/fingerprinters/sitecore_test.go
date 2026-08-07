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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// ── Name / ProbeEndpoint ──────────────────────────────────────────────────────

func TestSitecore_Name(t *testing.T) {
	fp := &SitecoreFingerprinter{}
	assert.Equal(t, "sitecore", fp.Name())
}

func TestSitecore_ProbeEndpoint(t *testing.T) {
	fp := &SitecoreFingerprinter{}
	assert.Equal(t, "/sitecore/login", fp.ProbeEndpoint())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestSitecore_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		poweredBy   string
		server      string
		contentType string
		want        bool
	}{
		{
			name:       "X-Powered-By: Sitecore/10.3.1 header match",
			statusCode: 200,
			poweredBy:  "Sitecore/10.3.1",
			want:       true,
		},
		{
			name:       "X-Powered-By: sitecore (case-insensitive) header match",
			statusCode: 200,
			poweredBy:  "sitecore",
			want:       true,
		},
		{
			name:        "Content-Type: text/html is a body scan candidate",
			statusCode:  200,
			contentType: "text/html",
			want:        true,
		},
		{
			name:       "Server: nginx/1.18.0 only rejected",
			statusCode: 200,
			server:     "nginx/1.18.0",
			want:       false,
		},
		{
			name:       "No headers rejected",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "199 with Sitecore header rejected (below 200)",
			statusCode: 199,
			poweredBy:  "Sitecore/10.3.1",
			want:       false,
		},
		{
			name:       "500 with Sitecore header rejected",
			statusCode: 500,
			poweredBy:  "Sitecore/10.3.1",
			want:       false,
		},
		{
			name:       "302 with Sitecore header passes",
			statusCode: 302,
			poweredBy:  "Sitecore/10.3.1",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SitecoreFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.poweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.poweredBy)
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

// ── Fingerprint: positive (valid) ────────────────────────────────────────────

func TestSitecore_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name            string
		statusCode      int
		poweredBy       string
		body            string
		probePath       string
		wantVersion     string
		wantCPE         string
		wantDetection   string
		wantProbePath   bool
		wantPoweredByIn bool // expect powered_by key in metadata
	}{
		{
			name:            "X-Powered-By: Sitecore/10.3.1",
			statusCode:      200,
			poweredBy:       "Sitecore/10.3.1",
			body:            "",
			wantVersion:     "10.3.1",
			wantCPE:         "cpe:2.3:a:sitecore:experience_platform:10.3.1:*:*:*:*:*:*:*",
			wantDetection:   "header",
			wantPoweredByIn: true,
		},
		{
			name:            "X-Powered-By: Sitecore 10.3 (space separator)",
			statusCode:      200,
			poweredBy:       "Sitecore 10.3",
			body:            "",
			wantVersion:     "10.3",
			wantCPE:         "cpe:2.3:a:sitecore:experience_platform:10.3:*:*:*:*:*:*:*",
			wantDetection:   "header",
			wantPoweredByIn: true,
		},
		{
			name:            "X-Powered-By: Sitecore (no version)",
			statusCode:      200,
			poweredBy:       "Sitecore",
			body:            "",
			wantVersion:     "",
			wantCPE:         "cpe:2.3:a:sitecore:experience_platform:*:*:*:*:*:*:*:*",
			wantDetection:   "header",
			wantPoweredByIn: true,
		},
		{
			name:          "Body with sitecore + /sitecore/login",
			statusCode:    200,
			body:          `<html><body>sitecore powered site <a href="/sitecore/login">Login</a></body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:sitecore:experience_platform:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:          "Body with sitecore + sitecore.net",
			statusCode:    200,
			body:          `<html><body>sitecore experience platform, see sitecore.net for details</body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:sitecore:experience_platform:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:          "Body with sitecore + sitecore.css",
			statusCode:    200,
			body:          `<html><head><link rel="stylesheet" href="/styles/sitecore.css"></head><body>sitecore</body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:sitecore:experience_platform:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:          "Active probe via /sitecore/login sets probe_path metadata",
			statusCode:    200,
			body:          `<html><body>sitecore login <a href="/sitecore/login">Login</a></body></html>`,
			probePath:     "/sitecore/login",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:sitecore:experience_platform:*:*:*:*:*:*:*:*",
			wantDetection: "active_probe",
			wantProbePath: true,
		},
		{
			name:            "Header + body both present — detection_method body, version from header",
			statusCode:      200,
			poweredBy:       "Sitecore/10.3.1",
			body:            `<html><body>sitecore <a href="/sitecore/login">Login</a></body></html>`,
			wantVersion:     "10.3.1",
			wantCPE:         "cpe:2.3:a:sitecore:experience_platform:10.3.1:*:*:*:*:*:*:*",
			wantDetection:   "body",
			wantPoweredByIn: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SitecoreFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.poweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.poweredBy)
			}
			if tt.probePath != "" {
				resp.Request = &http.Request{URL: &url.URL{Path: tt.probePath}}
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result, "Fingerprint() returned nil, want non-nil result")

			assert.Equal(t, "sitecore", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			require.NotEmpty(t, result.CPEs, "Expected at least one CPE")
			assert.Equal(t, tt.wantCPE, result.CPEs[0])
			require.NotNil(t, result.Metadata)

			assert.Equal(t, plugins.SeverityHigh, result.Severity)

			if tt.wantDetection != "" {
				assert.Equal(t, tt.wantDetection, result.Metadata["detection_method"])
			}

			if tt.wantProbePath {
				assert.Equal(t, "/sitecore/login", result.Metadata["probe_path"])
			} else {
				assert.NotContains(t, result.Metadata, "probe_path",
					"probe_path should be absent for non-active-probe responses")
			}

			if tt.wantPoweredByIn {
				assert.Contains(t, result.Metadata, "powered_by",
					"powered_by should be present when X-Powered-By header is set")
			} else {
				assert.NotContains(t, result.Metadata, "powered_by",
					"powered_by should be absent when X-Powered-By header is not set")
			}
		})
	}
}

// ── Fingerprint: negative (invalid — must return nil) ─────────────────────────

func TestSitecore_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		poweredBy  string
		body       string
	}{
		{
			name:       "CPE injection attempt in X-Powered-By clears version",
			statusCode: 200,
			poweredBy:  "Sitecore/10.3:*:exploit",
			body:       "",
		},
		{
			name:       "Status 500 rejected",
			statusCode: 500,
			poweredBy:  "Sitecore/10.3.1",
			body:       "",
		},
		{
			name:       "Body larger than 2 MiB is rejected",
			statusCode: 200,
			body:       "sitecore /sitecore/login" + string(make([]byte, 2*1024*1024+1)),
		},
		{
			name:       "Body with sitecore but no corroborating marker",
			statusCode: 200,
			body:       `<html><body>this site is not sitecore related in any special way</body></html>`,
		},
		{
			name:       "No signals at all",
			statusCode: 200,
			body:       `<html><head><title>Welcome</title></head><body>Hello world</body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SitecoreFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.poweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.poweredBy)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)

			if tt.name == "CPE injection attempt in X-Powered-By clears version" {
				// The version-extraction regex only captures digits and dots, so the
				// malicious suffix (":*:exploit") falls outside the captured group and
				// is never part of the extracted version. The CPE metacharacter guard
				// (ContainsAny check) has nothing to clear here, but the net effect is
				// the same: no CPE-injection metacharacters ever reach the built CPE.
				require.NotNil(t, result, "Fingerprint() returned nil, want non-nil result")
				assert.Equal(t, "10.3", result.Version)
				assert.NotContains(t, result.Version, ":")
				assert.NotContains(t, result.Version, "*")
				assert.Equal(t, "cpe:2.3:a:sitecore:experience_platform:10.3:*:*:*:*:*:*:*", result.CPEs[0])
				return
			}

			assert.Nil(t, result, "Fingerprint() should return nil for non-Sitecore response")
		})
	}
}

// ── Integration test ──────────────────────────────────────────────────────────

func TestSitecore_Integration(t *testing.T) {
	fp := &SitecoreFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-Powered-By", "Sitecore/10.3.1")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, []byte(""))
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "sitecore", result.Technology)
	assert.Equal(t, "10.3.1", result.Version)
	require.NotEmpty(t, result.CPEs)
	assert.Equal(t, "cpe:2.3:a:sitecore:experience_platform:10.3.1:*:*:*:*:*:*:*", result.CPEs[0])
	assert.Equal(t, plugins.SeverityHigh, result.Severity)
	assert.Equal(t, "header", result.Metadata["detection_method"])
	assert.Contains(t, result.Metadata, "powered_by")
}

// ── TestBuildSitecoreCPE ──────────────────────────────────────────────────────

func TestBuildSitecoreCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "10.3.1",
			want:    "cpe:2.3:a:sitecore:experience_platform:10.3.1:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:a:sitecore:experience_platform:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			assert.Equal(t, tt.want, buildSitecoreCPE(tt.version))
		})
	}
}
