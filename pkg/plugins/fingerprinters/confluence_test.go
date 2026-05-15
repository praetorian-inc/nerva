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
	"bytes"
	"io"
	"net/http"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// makeConfluenceResp builds a minimal *http.Response with the given status, headers, and body.
func makeConfluenceResp(statusCode int, headers map[string]string, body string) *http.Response {
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
		Body:       io.NopCloser(bytes.NewReader([]byte(body))),
	}
	for k, v := range headers {
		resp.Header.Set(k, v)
	}
	return resp
}

// ── Name / ProbeEndpoint ──────────────────────────────────────────────────────

func TestConfluenceFingerprinter_Name(t *testing.T) {
	fp := &ConfluenceFingerprinter{}
	assert.Equal(t, "confluence", fp.Name())
}

func TestConfluenceFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ConfluenceFingerprinter{}
	assert.Equal(t, "/login.action", fp.ProbeEndpoint())
}

// ── Match ─────────────────────────────────────────────────────────────────────

func TestConfluenceFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		headers    map[string]string
		want       bool
	}{
		{
			name:       "200 with X-Confluence-Request-Time header",
			statusCode: 200,
			headers:    map[string]string{"X-Confluence-Request-Time": "1710000000000"},
			want:       true,
		},
		{
			name:       "200 with text/html Content-Type",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html; charset=utf-8"},
			want:       true,
		},
		{
			name:       "302 with X-Confluence-Request-Time header",
			statusCode: 302,
			headers:    map[string]string{"X-Confluence-Request-Time": "1710000000000"},
			want:       true,
		},
		{
			name:       "404 with text/html",
			statusCode: 404,
			headers:    map[string]string{"Content-Type": "text/html"},
			want:       true,
		},
		{
			name:       "500 rejected",
			statusCode: 500,
			headers:    map[string]string{"Content-Type": "text/html"},
			want:       false,
		},
		{
			name:       "100 informational rejected",
			statusCode: 100,
			headers:    map[string]string{"Content-Type": "text/html"},
			want:       false,
		},
		{
			name:       "200 application/json without Confluence header",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "application/json"},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ConfluenceFingerprinter{}
			resp := makeConfluenceResp(tt.statusCode, tt.headers, "")
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint: positive (valid) ────────────────────────────────────────────

const confluenceLoginBody = `<html><head>
<meta name="ajs-version-number" content="8.5.4">
<meta name="ajs-build-number" content="9802">
<title>Log In - Confluence</title>
</head><body>
<div id="login">Powered by <a href="https://www.atlassian.com/software/confluence">Atlassian Confluence</a> 8.5.4</div>
</body></html>`

const confluenceDataCenterBody = `<html><head>
<meta name="ajs-version-number" content="8.5.4">
<meta name="ajs-build-number" content="9802">
<meta name="ajs-data-center-id" content="abc123-def456">
<title>Log In - Confluence</title>
</head><body>
<div id="login">Powered by <a href="https://www.atlassian.com/software/confluence">Atlassian Confluence</a> 8.5.4</div>
</body></html>`

func TestConfluenceFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name            string
		statusCode      int
		headers         map[string]string
		body            string
		probePath       string
		wantVersion     string
		wantBuildNumber string
		wantDeployment  string
		wantDetection   string
		wantProbePath   bool
		wantSecondCPE   bool
		wantAsen        bool
		wantRequestTime bool
	}{
		{
			name:            "full login page with version meta and brand text — server deployment",
			statusCode:      200,
			headers:         map[string]string{"Content-Type": "text/html"},
			body:            confluenceLoginBody,
			wantVersion:     "8.5.4",
			wantBuildNumber: "9802",
			wantDeployment:  "server",
			wantDetection:   "body",
			wantSecondCPE:   false,
		},
		{
			name:            "login page with Data Center ID meta tag — data_center deployment, both CPEs",
			statusCode:      200,
			headers:         map[string]string{"Content-Type": "text/html"},
			body:            confluenceDataCenterBody,
			wantVersion:     "8.5.4",
			wantBuildNumber: "9802",
			wantDeployment:  "data_center",
			wantDetection:   "body",
			wantSecondCPE:   true,
		},
		{
			name:       "reversed attribute order meta tags — version still extracted",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html><head>
<meta content="7.19.1" name="ajs-version-number">
<meta content="8803" name="ajs-build-number">
<title>Log In - Confluence</title>
</head><body>Atlassian Confluence login</body></html>`,
			wantVersion:     "7.19.1",
			wantBuildNumber: "8803",
			wantDeployment:  "server",
			wantDetection:   "body",
		},
		{
			name:           "header-only detection via X-Confluence-Request-Time",
			statusCode:     200,
			headers:        map[string]string{"X-Confluence-Request-Time": "1710000000000"},
			body:           "<html><body>generic page</body></html>",
			wantDetection:  "header",
			wantDeployment: "server",
		},
		{
			name:           "active probe detection — path /login.action sets active_probe method",
			statusCode:     200,
			headers:        map[string]string{"Content-Type": "text/html"},
			body:           confluenceLoginBody,
			probePath:      "/login.action",
			wantVersion:    "8.5.4",
			wantDeployment: "server",
			wantDetection:  "active_probe",
			wantProbePath:  true,
		},
		{
			name:       "version meta tag only — no brand text but ajs-version-number detected",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html><head>
<meta name="ajs-version-number" content="8.0.0">
<title>Page</title>
</head><body>Some content</body></html>`,
			wantVersion:    "8.0.0",
			wantDeployment: "server",
			wantDetection:  "body",
		},
		{
			name:       "X-ASEN header present — asen in metadata",
			statusCode: 200,
			headers: map[string]string{
				"Content-Type":              "text/html",
				"X-ASEN":                    "SEN-12345678",
				"X-Confluence-Request-Time": "1710000000000",
			},
			body:            confluenceLoginBody,
			wantVersion:     "8.5.4",
			wantDetection:   "body",
			wantAsen:        true,
			wantRequestTime: true,
		},
		{
			name:       "body with :*: CPE injection attempt — brand detected, version empty (regex won't match)",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html><head>
<meta name="ajs-version-number" content="8.5.4:*:malicious">
<title>Atlassian Confluence</title>
</head></html>`,
			wantVersion:    "",
			wantDeployment: "server",
			wantDetection:  "body",
		},
		{
			name:       "body with :*: in wiki content does not block detection",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body: `<html><head>
<meta name="ajs-version-number" content="8.5.4">
<meta name="ajs-build-number" content="9802">
<title>Log In - Confluence</title>
</head><body>
<div>Atlassian Confluence</div>
<p>Example: SELECT * FROM users WHERE id=:*:placeholder</p>
</body></html>`,
			wantVersion:     "8.5.4",
			wantBuildNumber: "9802",
			wantDeployment:  "server",
			wantDetection:   "body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ConfluenceFingerprinter{}
			resp := makeConfluenceResp(tt.statusCode, tt.headers, tt.body)
			if tt.probePath != "" {
				resp.Request = &http.Request{URL: &url.URL{Path: tt.probePath}}
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result, "expected non-nil result")

			assert.Equal(t, "confluence", result.Technology)
			assert.NotEmpty(t, result.CPEs, "expected at least one CPE")
			assert.NotNil(t, result.Metadata)

			if tt.wantVersion != "" {
				assert.Equal(t, tt.wantVersion, result.Version)
			}
			if tt.wantBuildNumber != "" {
				assert.Equal(t, tt.wantBuildNumber, result.Metadata["build_number"])
			}
			if tt.wantDeployment != "" {
				assert.Equal(t, tt.wantDeployment, result.Metadata["deployment_type"])
			}
			if tt.wantDetection != "" {
				assert.Equal(t, tt.wantDetection, result.Metadata["detection_method"])
			}
			if tt.wantProbePath {
				assert.Equal(t, "/login.action", result.Metadata["probe_path"])
			} else {
				assert.NotContains(t, result.Metadata, "probe_path")
			}
			if tt.wantSecondCPE {
				assert.Len(t, result.CPEs, 2, "data_center should emit two CPEs")
			}
			if tt.wantAsen {
				assert.Contains(t, result.Metadata, "asen")
			}
			if tt.wantRequestTime {
				assert.Contains(t, result.Metadata, "confluence_request_time")
			}
		})
	}
}

// ── Fingerprint: negative (invalid — must return nil) ─────────────────────────

func TestConfluenceFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		headers    map[string]string
		body       string
	}{
		{
			name:       "empty body and no Confluence headers",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       "",
		},
		{
			name:       "body with just 'confluence' without 'atlassian' prefix",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       "<html><head><title>confluence admin</title></head><body>confluence</body></html>",
		},
		{
			name:       "Atlassian Jira page — not Confluence",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       "<html><head><title>Jira</title></head><body>Atlassian Jira Software</body></html>",
		},
		{
			name:       "body > 2 MiB rejected",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       "atlassian confluence" + string(make([]byte, 2*1024*1024+1)),
		},
		{
			name:       "status 500 rejected",
			statusCode: 500,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       confluenceLoginBody,
		},
		{
			name:       "non-Confluence HTML — WordPress default page",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       "<html><head><title>Just another WordPress site</title></head><body>Hello World</body></html>",
		},
		{
			name:       "nginx default page",
			statusCode: 200,
			headers:    map[string]string{"Content-Type": "text/html"},
			body:       "<html><head><title>Welcome to nginx!</title></head><body><p>If you see this page, the nginx web server is successfully installed.</p></body></html>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ConfluenceFingerprinter{}
			resp := makeConfluenceResp(tt.statusCode, tt.headers, tt.body)

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result, "expected nil result for non-Confluence response")
		})
	}
}

// ── Unit: extractConfluenceVersion ───────────────────────────────────────────

func TestExtractConfluenceVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "standard name-before-content meta tag",
			body: `<meta name="ajs-version-number" content="8.5.4">`,
			want: "8.5.4",
		},
		{
			name: "reversed content-before-name attribute order",
			body: `<meta content="7.19.1" name="ajs-version-number">`,
			want: "7.19.1",
		},
		{
			name: "quoted with single quotes",
			body: `<meta name='ajs-version-number' content='8.0.0'>`,
			want: "8.0.0",
		},
		{
			name: "no version meta tag",
			body: `<html><body>Atlassian Confluence</body></html>`,
			want: "",
		},
		{
			name: "version with extra dotted segment",
			body: `<meta name="ajs-version-number" content="8.5.4.1">`,
			want: "8.5.4.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractConfluenceVersion([]byte(tt.body))
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── Unit: extractConfluenceBuildNumber ───────────────────────────────────────

func TestExtractConfluenceBuildNumber(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "standard name-before-content",
			body: `<meta name="ajs-build-number" content="9802">`,
			want: "9802",
		},
		{
			name: "reversed content-before-name",
			body: `<meta content="8803" name="ajs-build-number">`,
			want: "8803",
		},
		{
			name: "no build number",
			body: `<html><body>Atlassian Confluence</body></html>`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractConfluenceBuildNumber([]byte(tt.body))
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── Unit: detectConfluenceDeploymentType ─────────────────────────────────────

func TestDetectConfluenceDeploymentType(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "data-center-id meta tag present — data_center",
			body: `<meta name="ajs-data-center-id" content="abc123-def456">`,
			want: "data_center",
		},
		{
			name: "no data-center-id meta tag — server",
			body: `<html><head><title>Confluence</title></head></html>`,
			want: "server",
		},
		{
			name: "empty body — server",
			body: ``,
			want: "server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectConfluenceDeploymentType([]byte(tt.body))
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── Unit: buildConfluenceCPEs ─────────────────────────────────────────────────

func TestBuildConfluenceCPEs(t *testing.T) {
	tests := []struct {
		name           string
		version        string
		deploymentType string
		wantLen        int
		wantFirst      string
		wantSecond     string
	}{
		{
			name:           "server with version",
			version:        "8.5.4",
			deploymentType: "server",
			wantLen:        1,
			wantFirst:      "cpe:2.3:a:atlassian:confluence_server:8.5.4:*:*:*:*:*:*:*",
		},
		{
			name:           "data_center with version — two CPEs",
			version:        "8.5.4",
			deploymentType: "data_center",
			wantLen:        2,
			wantFirst:      "cpe:2.3:a:atlassian:confluence_server:8.5.4:*:*:*:*:*:*:*",
			wantSecond:     "cpe:2.3:a:atlassian:confluence_data_center:8.5.4:*:*:*:*:*:*:*",
		},
		{
			name:           "server with empty version — wildcard CPE",
			version:        "",
			deploymentType: "server",
			wantLen:        1,
			wantFirst:      "cpe:2.3:a:atlassian:confluence_server:*:*:*:*:*:*:*:*",
		},
		{
			name:           "data_center with empty version — two wildcard CPEs",
			version:        "",
			deploymentType: "data_center",
			wantLen:        2,
			wantFirst:      "cpe:2.3:a:atlassian:confluence_server:*:*:*:*:*:*:*:*",
			wantSecond:     "cpe:2.3:a:atlassian:confluence_data_center:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpes := buildConfluenceCPEs(tt.version, tt.deploymentType)
			require.Len(t, cpes, tt.wantLen)
			assert.Equal(t, tt.wantFirst, cpes[0])
			if tt.wantSecond != "" {
				assert.Equal(t, tt.wantSecond, cpes[1])
			}
		})
	}
}

// ── Unit: sanitizeConfluenceHeaderValue ──────────────────────────────────────

func TestSanitizeConfluenceHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "normal value unchanged",
			input: "SEN-12345678",
			want:  "SEN-12345678",
		},
		{
			name:  "control characters stripped",
			input: "value\x00\x01\x1f/suffix",
			want:  "value/suffix",
		},
		{
			name:  "DEL character stripped",
			input: "value\x7fafter",
			want:  "valueafter",
		},
		{
			name:  "value over 256 chars truncated",
			input: string(make([]byte, 300)),
			want:  "",
		},
		{
			name:  "printable ASCII preserved",
			input: "1710000000000",
			want:  "1710000000000",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeConfluenceHeaderValue(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── Integration test ──────────────────────────────────────────────────────────

func TestConfluenceFingerprinter_Integration(t *testing.T) {
	// Save and restore global state to prevent test pollution.
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &ConfluenceFingerprinter{}
	Register(fp)

	resp := makeConfluenceResp(200,
		map[string]string{"Content-Type": "text/html"},
		confluenceLoginBody,
	)

	results := RunFingerprinters(resp, []byte(confluenceLoginBody))

	var found bool
	for _, result := range results {
		if result.Technology == "confluence" {
			found = true
			assert.Equal(t, "8.5.4", result.Version)
			require.NotEmpty(t, result.CPEs)
			assert.Equal(t, "cpe:2.3:a:atlassian:confluence_server:8.5.4:*:*:*:*:*:*:*", result.CPEs[0])
			assert.Equal(t, "Atlassian", result.Metadata["vendor"])
			assert.Equal(t, "Confluence", result.Metadata["product"])
			assert.Equal(t, "server", result.Metadata["deployment_type"])
		}
	}

	assert.True(t, found, "ConfluenceFingerprinter not found in RunFingerprinters results")
}
