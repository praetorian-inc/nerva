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

func TestSharePoint_Name(t *testing.T) {
	fp := &SharePointFingerprinter{}
	assert.Equal(t, "sharepoint", fp.Name())
}

func TestSharePoint_ProbeEndpoint(t *testing.T) {
	fp := &SharePointFingerprinter{}
	assert.Equal(t, "/_layouts/", fp.ProbeEndpoint())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestSharePoint_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		spHeader    string
		server      string
		contentType string
		want        bool
	}{
		{
			name:       "MicrosoftSharePointTeamServices header present",
			statusCode: 200,
			spHeader:   "16.0.0.10416",
			want:       true,
		},
		{
			name:        "Content-Type text/html is a body scan candidate",
			statusCode:  200,
			contentType: "text/html",
			want:        true,
		},
		{
			name:       "Server nginx only returns false",
			statusCode: 200,
			server:     "nginx/1.18.0",
			want:       false,
		},
		{
			name:       "No headers returns false",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "StatusCode 199 with SharePoint header rejected",
			statusCode: 199,
			spHeader:   "16.0.0.10416",
			want:       false,
		},
		{
			name:       "StatusCode 500 with SharePoint header rejected",
			statusCode: 500,
			spHeader:   "16.0.0.10416",
			want:       false,
		},
		{
			name:       "StatusCode 302 with SharePoint header accepted",
			statusCode: 302,
			spHeader:   "16.0.0.10416",
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SharePointFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.spHeader != "" {
				resp.Header.Set("MicrosoftSharePointTeamServices", tt.spHeader)
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

func TestSharePoint_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name             string
		spHeader         string
		body             string
		probePath        string
		wantVersion      string
		wantDetection    string
		wantEdition      string
		wantProbePath    bool
		wantHeaderInMeta bool
	}{
		{
			name:             "SharePoint 2016/2019/SE header (16.0.0.10416)",
			spHeader:         "16.0.0.10416",
			wantVersion:      "16.0.0.10416",
			wantDetection:    "header",
			wantEdition:      "SharePoint Server 2016/2019/SE",
			wantHeaderInMeta: true,
		},
		{
			name:             "SharePoint 2013 header (15.0.0.4571)",
			spHeader:         "15.0.0.4571",
			wantVersion:      "15.0.0.4571",
			wantDetection:    "header",
			wantEdition:      "SharePoint Server 2013",
			wantHeaderInMeta: true,
		},
		{
			name:             "SharePoint 2010 header (14.0.0.7116)",
			spHeader:         "14.0.0.7116",
			wantVersion:      "14.0.0.7116",
			wantDetection:    "header",
			wantEdition:      "SharePoint Server 2010",
			wantHeaderInMeta: true,
		},
		{
			name:          "Body with sharepoint and /_layouts/",
			body:          `<html><body>Welcome to sharepoint. Try /_layouts/15/start.aspx</body></html>`,
			wantVersion:   "",
			wantDetection: "body",
		},
		{
			name:          "Body with sharepoint and microsoft.sharepoint",
			body:          `<html><body>Powered by microsoft.sharepoint services, sharepoint edition</body></html>`,
			wantVersion:   "",
			wantDetection: "body",
		},
		{
			name:          "Body with sharepoint and sharepoint.css",
			body:          `<html><head><link rel="stylesheet" href="/sharepoint.css"></head><body>sharepoint site</body></html>`,
			wantVersion:   "",
			wantDetection: "body",
		},
		{
			name:          "Active probe path /_layouts/ with body match",
			body:          `<html><body>sharepoint site with /_layouts/ path</body></html>`,
			probePath:     "/_layouts/",
			wantVersion:   "",
			wantDetection: "active_probe",
			wantProbePath: true,
		},
		{
			name:             "Header and body both present prefers body detection",
			spHeader:         "16.0.0.10416",
			body:             `<html><body>sharepoint site at /_layouts/</body></html>`,
			wantVersion:      "16.0.0.10416",
			wantDetection:    "body",
			wantEdition:      "SharePoint Server 2016/2019/SE",
			wantHeaderInMeta: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SharePointFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			if tt.spHeader != "" {
				resp.Header.Set("MicrosoftSharePointTeamServices", tt.spHeader)
			}
			if tt.probePath != "" {
				resp.Request = &http.Request{URL: &url.URL{Path: tt.probePath}}
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result, "Fingerprint() returned nil, want non-nil result")

			assert.Equal(t, "sharepoint", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			require.NotEmpty(t, result.CPEs, "Expected at least one CPE")

			expectedCPE := buildSharePointCPE(tt.wantVersion)
			assert.Equal(t, expectedCPE, result.CPEs[0])

			require.NotNil(t, result.Metadata)
			assert.Equal(t, tt.wantDetection, result.Metadata["detection_method"])
			assert.Equal(t, plugins.SeverityHigh, result.Severity)

			if tt.wantProbePath {
				assert.Equal(t, "/_layouts/", result.Metadata["probe_path"])
			} else {
				assert.NotContains(t, result.Metadata, "probe_path",
					"probe_path should be absent for non-active-probe responses")
			}

			if tt.wantHeaderInMeta {
				assert.Contains(t, result.Metadata, "sharepoint_header",
					"sharepoint_header should be present when the SharePoint header is set")
			}

			if tt.wantEdition != "" {
				assert.Equal(t, tt.wantEdition, result.Metadata["sharepoint_edition"])
			}
		})
	}
}

// ── Fingerprint: negative (invalid — must return nil or sanitized) ───────────

func TestSharePoint_Fingerprint_Invalid(t *testing.T) {
	t.Run("CPE injection attempt clears version", func(t *testing.T) {
		fp := &SharePointFingerprinter{}
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("MicrosoftSharePointTeamServices", "16.0.0:*:")

		result, err := fp.Fingerprint(resp, []byte{})
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "", result.Version)
	})

	tests := []struct {
		name       string
		statusCode int
		spHeader   string
		body       string
	}{
		{
			name:       "Status 500 rejected",
			statusCode: 500,
			spHeader:   "16.0.0.10416",
		},
		{
			name:       "Oversized body rejected",
			statusCode: 200,
			body:       "sharepoint /_layouts/ " + string(make([]byte, 3*1024*1024)),
		},
		{
			name:       "Body with sharepoint but no corroborating marker",
			statusCode: 200,
			body:       `<html><body>This mentions sharepoint but nothing else.</body></html>`,
		},
		{
			name:       "No signals at all",
			statusCode: 200,
			body:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SharePointFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.spHeader != "" {
				resp.Header.Set("MicrosoftSharePointTeamServices", tt.spHeader)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result, "Fingerprint() should return nil for non-SharePoint response")
		})
	}
}

// ── Integration test ──────────────────────────────────────────────────────────

func TestSharePoint_Integration(t *testing.T) {
	fp := &SharePointFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("MicrosoftSharePointTeamServices", "16.0.0.10416")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, []byte{})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, "sharepoint", result.Technology)
	assert.Equal(t, "16.0.0.10416", result.Version)
	require.NotEmpty(t, result.CPEs)
	assert.Equal(t, "cpe:2.3:a:microsoft:sharepoint_server:16.0.0.10416:*:*:*:*:*:*:*", result.CPEs[0])
	assert.Equal(t, plugins.SeverityHigh, result.Severity)
	assert.Equal(t, "SharePoint Server 2016/2019/SE", result.Metadata["sharepoint_edition"])
}

// ── TestBuildSharePointCPE ────────────────────────────────────────────────────

func TestBuildSharePointCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "16.0.0.10416",
			want:    "cpe:2.3:a:microsoft:sharepoint_server:16.0.0.10416:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:microsoft:sharepoint_server:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildSharePointCPE(tt.version))
		})
	}
}

// ── TestMapSharePointEdition ──────────────────────────────────────────────────

func TestMapSharePointEdition(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "16.0 maps to SharePoint Server 2016/2019/SE",
			version: "16.0.0.10416",
			want:    "SharePoint Server 2016/2019/SE",
		},
		{
			name:    "15.0 maps to SharePoint Server 2013",
			version: "15.0.0.4571",
			want:    "SharePoint Server 2013",
		},
		{
			name:    "14.0 maps to SharePoint Server 2010",
			version: "14.0.0.7116",
			want:    "SharePoint Server 2010",
		},
		{
			name:    "Unknown version returns empty",
			version: "17.0.0.1",
			want:    "",
		},
		{
			name:    "Malformed version returns empty",
			version: "invalid",
			want:    "",
		},
		{
			name:    "Empty version returns empty",
			version: "",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, mapSharePointEdition(tt.version))
		})
	}
}
