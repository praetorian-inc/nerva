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

func TestCraftCMS_Name(t *testing.T) {
	fp := &CraftCMSFingerprinter{}
	assert.Equal(t, "craftcms", fp.Name())
}

func TestCraftCMS_ProbeEndpoint(t *testing.T) {
	fp := &CraftCMSFingerprinter{}
	assert.Equal(t, "/admin/login", fp.ProbeEndpoint())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestCraftCMS_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		poweredBy   string
		server      string
		contentType string
		want        bool
	}{
		{
			name:       "X-Powered-By: Craft CMS/5.6.17 header match",
			statusCode: 200,
			poweredBy:  "Craft CMS/5.6.17",
			want:       true,
		},
		{
			name:       "X-Powered-By: craft cms case-insensitive match",
			statusCode: 200,
			poweredBy:  "craft cms",
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
			name:       "199 rejected (below 200) even with Craft CMS header",
			statusCode: 199,
			poweredBy:  "Craft CMS/5.6.17",
			want:       false,
		},
		{
			name:       "500 rejected even with Craft CMS header",
			statusCode: 500,
			poweredBy:  "Craft CMS/5.6.17",
			want:       false,
		},
		{
			name:       "302 redirect passes with Craft CMS header",
			statusCode: 302,
			poweredBy:  "Craft CMS/5.6.17",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CraftCMSFingerprinter{}
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

func TestCraftCMS_Fingerprint_Valid(t *testing.T) {
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
		wantPoweredByIn bool
	}{
		{
			name:            "X-Powered-By: Craft CMS/5.6.17 slash separator",
			statusCode:      200,
			poweredBy:       "Craft CMS/5.6.17",
			wantVersion:     "5.6.17",
			wantCPE:         "cpe:2.3:a:craftcms:craft_cms:5.6.17:*:*:*:*:*:*:*",
			wantDetection:   "header",
			wantPoweredByIn: true,
		},
		{
			name:            "X-Powered-By: Craft CMS 4.14.15 space separator",
			statusCode:      200,
			poweredBy:       "Craft CMS 4.14.15",
			wantVersion:     "4.14.15",
			wantCPE:         "cpe:2.3:a:craftcms:craft_cms:4.14.15:*:*:*:*:*:*:*",
			wantDetection:   "header",
			wantPoweredByIn: true,
		},
		{
			name:            "X-Powered-By: Craft CMS with no version",
			statusCode:      200,
			poweredBy:       "Craft CMS",
			wantVersion:     "",
			wantCPE:         "cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*",
			wantDetection:   "header",
			wantPoweredByIn: true,
		},
		{
			name:          "Body with Craft CMS + craftcms corroborating marker",
			statusCode:    200,
			body:          `<html><head><title>Craft CMS</title></head><body>Powered by craftcms</body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:          "Body with Craft CMS + /admin/login corroborating marker",
			statusCode:    200,
			body:          `<html><head><title>Craft CMS</title></head><body><a href="/admin/login">Login</a></body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:          "Body with Craft CMS + craft-cms corroborating marker",
			statusCode:    200,
			body:          `<html><head><title>Craft CMS</title></head><body class="craft-cms">Login</body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:          "Active probe /admin/login with body match sets probe_path",
			statusCode:    200,
			body:          `<html><head><title>Craft CMS</title></head><body>Powered by craftcms</body></html>`,
			probePath:     "/admin/login",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*",
			wantDetection: "active_probe",
			wantProbePath: true,
		},
		{
			name:            "Header + body both present — version from header wins",
			statusCode:      200,
			poweredBy:       "Craft CMS/5.6.17",
			body:            `<html><head><title>Craft CMS</title></head><body>Powered by craftcms</body></html>`,
			wantVersion:     "5.6.17",
			wantCPE:         "cpe:2.3:a:craftcms:craft_cms:5.6.17:*:*:*:*:*:*:*",
			wantDetection:   "body",
			wantPoweredByIn: true,
		},
		{
			// The version regex only ever captures digit/dot runs, so an
			// injection payload trailing the version never makes it into
			// the captured group — extraction naturally stops at "5.6".
			name:            "CPE injection attempt in X-Powered-By yields clean extracted version",
			statusCode:      200,
			poweredBy:       "Craft CMS/5.6:*:exploit",
			wantVersion:     "5.6",
			wantCPE:         "cpe:2.3:a:craftcms:craft_cms:5.6:*:*:*:*:*:*:*",
			wantDetection:   "header",
			wantPoweredByIn: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CraftCMSFingerprinter{}
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

			assert.Equal(t, "craftcms", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			require.NotEmpty(t, result.CPEs, "Expected at least one CPE")
			assert.Equal(t, tt.wantCPE, result.CPEs[0])
			require.NotNil(t, result.Metadata)

			assert.Equal(t, plugins.SeverityHigh, result.Severity)

			if tt.wantDetection != "" {
				assert.Equal(t, tt.wantDetection, result.Metadata["detection_method"])
			}

			if tt.wantProbePath {
				assert.Equal(t, "/admin/login", result.Metadata["probe_path"])
			} else {
				assert.NotContains(t, result.Metadata, "probe_path",
					"probe_path should be absent for non-active-probe responses")
			}

			if tt.wantPoweredByIn {
				assert.Contains(t, result.Metadata, "powered_by",
					"powered_by should be present when X-Powered-By header is set")
			}
		})
	}
}

// ── Fingerprint: negative (invalid — must return nil) ─────────────────────────

func TestCraftCMS_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		poweredBy  string
		body       string
	}{
		{
			name:       "Status 500 rejected",
			statusCode: 500,
			poweredBy:  "Craft CMS/5.6.17",
		},
		{
			name:       "Body larger than 2 MiB is rejected",
			statusCode: 200,
			body:       "craft cms craftcms" + string(make([]byte, 3*1024*1024)),
		},
		{
			name:       "Body with 'craft cms' but no corroborating marker rejected",
			statusCode: 200,
			body:       `<html><head><title>Login</title></head><body>This is not craft cms related.</body></html>`,
		},
		{
			name:       "No signals at all rejected",
			statusCode: 200,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CraftCMSFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.poweredBy != "" {
				resp.Header.Set("X-Powered-By", tt.poweredBy)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result, "Fingerprint() should return nil for non-Craft-CMS response")
		})
	}
}

// ── Integration test ──────────────────────────────────────────────────────────

func TestCraftCMS_Integration(t *testing.T) {
	fp := &CraftCMSFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("X-Powered-By", "Craft CMS/5.6.17")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, []byte{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "craftcms", result.Technology)
	assert.Equal(t, "5.6.17", result.Version)
	require.NotEmpty(t, result.CPEs)
	assert.Equal(t, "cpe:2.3:a:craftcms:craft_cms:5.6.17:*:*:*:*:*:*:*", result.CPEs[0])
	assert.Equal(t, plugins.SeverityHigh, result.Severity)
	assert.Equal(t, "header", result.Metadata["detection_method"])
}

// ── TestBuildCraftCMSCPE ────────────────────────────────────────────────────

func TestBuildCraftCMSCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "5.6.17",
			want:    "cpe:2.3:a:craftcms:craft_cms:5.6.17:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:a:craftcms:craft_cms:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			assert.Equal(t, tt.want, buildCraftCMSCPE(tt.version))
		})
	}
}
