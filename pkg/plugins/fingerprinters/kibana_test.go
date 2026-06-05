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
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// ── Name / ProbeEndpoint / ProbeAccept ────────────────────────────────────────

func TestKibanaFingerprinter_Name(t *testing.T) {
	fp := &KibanaFingerprinter{}
	assert.Equal(t, "kibana", fp.Name())
}

func TestKibanaFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &KibanaFingerprinter{}
	assert.Equal(t, "/api/status", fp.ProbeEndpoint())
}

func TestKibanaFingerprinter_ProbeAccept(t *testing.T) {
	fp := &KibanaFingerprinter{}
	assert.Equal(t, "application/json", fp.ProbeAccept())
}

// ── Match ──────────────────────────────────────────────────────────────────────

func TestKibanaFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		headers     map[string]string
		want        bool
	}{
		{
			name:        "200 text/html → true",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 application/json → true",
			statusCode:  200,
			contentType: "application/json",
			want:        true,
		},
		{
			name:       "200 image/png → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "500 server error → false",
			statusCode: 500,
			want:       false,
		},
		{
			name:       "100 informational → false",
			statusCode: 100,
			want:       false,
		},
		{
			name:       "kbn-name header present → true regardless of Content-Type",
			statusCode: 200,
			headers: map[string]string{
				"kbn-name": "kibana",
			},
			want: true,
		},
		{
			name:       "kbn-version header present → true",
			statusCode: 200,
			headers: map[string]string{
				"kbn-version": "8.12.0",
			},
			want: true,
		},
		{
			name:       "kbn-xsrf header present → true",
			statusCode: 200,
			headers: map[string]string{
				"kbn-xsrf": "true",
			},
			want: true,
		},
		{
			name:        "302 redirect with text/html → true",
			statusCode:  302,
			contentType: "text/html",
			want:        true,
		},
		{
			name:       "503 with kbn-name → true (startup grace)",
			statusCode: 503,
			headers: map[string]string{
				"kbn-name": "kibana",
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KibanaFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ── Fingerprint: API status endpoint ─────────────────────────────────────────

func TestKibanaFingerprinter_Fingerprint_APIStatus(t *testing.T) {
	tests := []struct {
		name                string
		body                string
		probePath           string
		wantNil             bool
		wantVersion         string
		wantCPE             string
		wantDetectionMethod string
		wantAnonymousAccess bool
		wantSeverityHigh    bool
		wantBuildHash       bool
		wantInstanceUUID    bool
	}{
		{
			name: "full Kibana 8.12.0 status response → version extracted, anonymous_access, SeverityHigh",
			body: `{
				"name": "kibana-instance",
				"uuid": "5b2de169-2785-441b-ae8c-186a1936b17d",
				"version": {
					"number": "8.12.0",
					"build_hash": "abc123def456",
					"build_number": 12345,
					"build_snapshot": false
				},
				"status": {
					"overall": {
						"state": "green"
					}
				}
			}`,
			wantVersion:         "8.12.0",
			wantCPE:             "cpe:2.3:a:elastic:kibana:8.12.0:*:*:*:*:*:*:*",
			wantDetectionMethod: "api_status",
			wantAnonymousAccess: true,
			wantSeverityHigh:    true,
			wantBuildHash:       true,
			wantInstanceUUID:    true,
		},
		{
			name: "Kibana 7.17.3 status response → version extracted",
			body: `{
				"name": "kibana-old",
				"uuid": "aaaabbbb-cccc-dddd-eeee-ffffffffffff",
				"version": {
					"number": "7.17.3",
					"build_hash": "deadbeef",
					"build_number": 99999,
					"build_snapshot": false
				},
				"status": {
					"overall": {
						"state": "yellow"
					}
				}
			}`,
			wantVersion:         "7.17.3",
			wantCPE:             "cpe:2.3:a:elastic:kibana:7.17.3:*:*:*:*:*:*:*",
			wantDetectionMethod: "api_status",
			wantAnonymousAccess: true,
			wantSeverityHigh:    true,
		},
		{
			name:      "active probe /api/status → detection_method=active_probe",
			probePath: "/api/status",
			body: `{
				"name": "kibana",
				"uuid": "uuid-123",
				"version": {
					"number": "8.10.1",
					"build_hash": "cafebabe",
					"build_number": 1
				},
				"status": {"overall": {"state": "green"}}
			}`,
			wantVersion:         "8.10.1",
			wantDetectionMethod: "active_probe",
			wantSeverityHigh:    true,
			wantAnonymousAccess: true,
		},
		{
			name: "status JSON without version.number → not Kibana",
			body: `{
				"name": "some-service",
				"uuid": "abc",
				"version": {},
				"status": {"overall": {"state": "green"}}
			}`,
			wantNil: true,
		},
		{
			name: "version.number present but no name/uuid/build_hash → not Kibana",
			body: `{
				"version": {
					"number": "8.12.0"
				},
				"status": {"overall": {"state": "green"}}
			}`,
			wantNil: true,
		},
		{
			name:    "plain JSON unrelated to Kibana → not matched",
			body:    `{"status": "ok", "service": "my-api"}`,
			wantNil: true,
		},
		{
			name:    "invalid JSON → not matched",
			body:    `not json at all`,
			wantNil: true,
		},
		{
			name: "Kibana 8.x status with level instead of state",
			body: `{
				"name": "kibana-8x",
				"uuid": "uuid-8x",
				"version": {
					"number": "8.15.0",
					"build_hash": "abc123",
					"build_number": 1
				},
				"status": {"overall": {"level": "available"}}
			}`,
			wantVersion:         "8.15.0",
			wantCPE:             "cpe:2.3:a:elastic:kibana:8.15.0:*:*:*:*:*:*:*",
			wantDetectionMethod: "api_status",
			wantAnonymousAccess: true,
			wantSeverityHigh:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KibanaFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "application/json")

			if tt.probePath != "" {
				resp.Request = &http.Request{
					URL: &url.URL{Path: tt.probePath},
				}
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, "kibana", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)

			if tt.wantCPE != "" {
				assert.Contains(t, result.CPEs, tt.wantCPE)
			}

			assert.Equal(t, tt.wantDetectionMethod, result.Metadata["detection_method"])

			if tt.wantAnonymousAccess {
				assert.Equal(t, true, result.Metadata["anonymous_access"])
			}

			if tt.wantSeverityHigh {
				assert.Equal(t, plugins.SeverityHigh, result.Severity)
			}

			if tt.wantBuildHash {
				_, hasBuildHash := result.Metadata["build_hash"]
				assert.True(t, hasBuildHash, "expected build_hash in metadata")
			}

			if tt.wantInstanceUUID {
				_, hasUUID := result.Metadata["instance_uuid"]
				assert.True(t, hasUUID, "expected instance_uuid in metadata")
			}
		})
	}
}

// ── Fingerprint: web UI HTML ───────────────────────────────────────────────────

func TestKibanaFingerprinter_Fingerprint_WebUI(t *testing.T) {
	tests := []struct {
		name                string
		body                string
		wantNil             bool
		wantDetectionMethod string
		wantAuthEnabled     bool
	}{
		{
			name:                "kbn-injected-metadata tag → web_ui detection",
			body:                `<!DOCTYPE html><html><head><kbn-injected-metadata data="{}"></kbn-injected-metadata></head><body></body></html>`,
			wantDetectionMethod: "web_ui",
			wantAuthEnabled:     true,
		},
		{
			name:                "title contains 'Kibana' → web_ui detection",
			body:                `<html><head><title>Kibana</title></head><body></body></html>`,
			wantDetectionMethod: "web_ui",
			wantAuthEnabled:     true,
		},
		{
			name:    "title contains only 'Elastic' → not matched (too broad)",
			body:    `<html><head><title>Elastic</title></head><body></body></html>`,
			wantNil: true,
		},
		{
			name:                "title 'Kibana - Login' → web_ui detection",
			body:                `<html><head><title>Kibana - Login</title></head><body></body></html>`,
			wantDetectionMethod: "web_ui",
			wantAuthEnabled:     true,
		},
		{
			name:                "title 'Kibana Dashboard' → web_ui detection",
			body:                `<html><head><title>Kibana Dashboard</title></head><body><p>Welcome to Kibana</p></body></html>`,
			wantDetectionMethod: "web_ui",
			wantAuthEnabled:     true,
		},
		{
			name:    "HTML with no Kibana markers → not matched",
			body:    `<html><head><title>My App</title></head><body></body></html>`,
			wantNil: true,
		},
		{
			name:    "HTML mentioning kibana only in prose (not in title) → not matched",
			body:    `<html><head><title>Blog Post</title></head><body><p>We use kibana for monitoring.</p></body></html>`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KibanaFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")

			result, err := fp.Fingerprint(resp, []byte(tt.body))

			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, result)
				return
			}

			require.NotNil(t, result)
			assert.Equal(t, "kibana", result.Technology)
			assert.Equal(t, tt.wantDetectionMethod, result.Metadata["detection_method"])

			if tt.wantAuthEnabled {
				assert.Equal(t, true, result.Metadata["authentication_enabled"])
			}
		})
	}
}

// ── Fingerprint: kbn-* header only ────────────────────────────────────────────

func TestKibanaFingerprinter_Fingerprint_HeaderOnly(t *testing.T) {
	fp := &KibanaFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("kbn-name", "kibana")
	resp.Header.Set("Content-Type", "text/plain") // Not a scan candidate content type, but header fires

	body := []byte(`some other content`)

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "kibana", result.Technology)
	assert.Equal(t, "response_header", result.Metadata["detection_method"])
	assert.Equal(t, "kibana", result.Metadata["kbn_name"])
}

func TestKibanaFingerprinter_Fingerprint_KbnVersionHeader(t *testing.T) {
	fp := &KibanaFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("kbn-version", "8.11.0")
	resp.Header.Set("Content-Type", "text/html")

	// HTML body without any Kibana structural markers → falls back to header detection.
	body := []byte(`<html><head><title>Some App</title></head><body></body></html>`)

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "kibana", result.Technology)
	// Version from header when no API signal.
	assert.Equal(t, "8.11.0", result.Version)
	assert.Equal(t, "response_header", result.Metadata["detection_method"])
}

// ── Fingerprint: security guardrails ──────────────────────────────────────────

func TestKibanaFingerprinter_Fingerprint_StatusCodeFilters(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		wantNil    bool
	}{
		{name: "200 → not nil", statusCode: 200, wantNil: false},
		{name: "401 → not nil", statusCode: 401, wantNil: false},
		{name: "404 → not nil", statusCode: 404, wantNil: false},
		{name: "500 → nil", statusCode: 500, wantNil: true},
		{name: "503 → not nil (startup grace)", statusCode: 503, wantNil: false},
		{name: "199 → nil", statusCode: 199, wantNil: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KibanaFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			resp.Header.Set("kbn-name", "kibana")

			result, err := fp.Fingerprint(resp, []byte(`{}`))
			require.NoError(t, err)

			if tt.wantNil {
				assert.Nil(t, result)
			} else {
				assert.NotNil(t, result)
			}
		})
	}
}

func TestKibanaFingerprinter_Fingerprint_BodyCapGuard(t *testing.T) {
	fp := &KibanaFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	// Body exceeds 2 MiB — guard should return nil, nil.
	bigBody := []byte(strings.Repeat("x", 2*1024*1024+1))

	result, err := fp.Fingerprint(resp, bigBody)
	assert.Nil(t, result)
	assert.Nil(t, err)
}

func TestKibanaFingerprinter_Fingerprint_CPEInjectionGuard(t *testing.T) {
	// Craft a body whose version.number field contains CPE metacharacters.
	// The guard must zero out the version.
	fp := &KibanaFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	body := []byte(`{
		"name": "kibana",
		"uuid": "uuid-abc",
		"version": {
			"number": "8:1*2",
			"build_hash": "",
			"build_number": 0
		},
		"status": {"overall": {"state": "green"}}
	}`)

	result, err := fp.Fingerprint(resp, body)
	// The version.number parses as non-empty but fails validation.
	// With no other version source, version should be empty.
	// The API signal still fires because version.number != "" before validation.
	require.NoError(t, err)
	if result != nil {
		// If a result is returned (API signal triggered), version must be sanitized.
		assert.Equal(t, "", result.Version)
		cpe := buildKibanaCPE(result.Version)
		assert.NotContains(t, cpe, "8:1*2")
	}
}

// ── buildKibanaCPE ─────────────────────────────────────────────────────────────

func TestBuildKibanaCPE(t *testing.T) {
	tests := []struct {
		name     string
		version  string
		expected string
	}{
		{
			name:     "version 8.12.0",
			version:  "8.12.0",
			expected: "cpe:2.3:a:elastic:kibana:8.12.0:*:*:*:*:*:*:*",
		},
		{
			name:     "empty version → wildcard CPE",
			version:  "",
			expected: "cpe:2.3:a:elastic:kibana:*:*:*:*:*:*:*:*",
		},
		{
			name:     "version 7.17.3",
			version:  "7.17.3",
			expected: "cpe:2.3:a:elastic:kibana:7.17.3:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, buildKibanaCPE(tt.version))
		})
	}
}

// ── Integration: Match + Fingerprint ─────────────────────────────────────────

func TestKibanaFingerprinter_Integration_APIStatus(t *testing.T) {
	fp := &KibanaFingerprinter{}

	body := []byte(`{
		"name": "kibana-instance",
		"uuid": "5b2de169-2785-441b-ae8c-186a1936b17d",
		"version": {
			"number": "8.12.0",
			"build_hash": "abc123def456",
			"build_number": 12345,
			"build_snapshot": false
		},
		"status": {
			"overall": {
				"state": "green"
			}
		}
	}`)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "kibana", result.Technology)
	assert.Equal(t, "8.12.0", result.Version)
	assert.Equal(t, plugins.SeverityHigh, result.Severity)
	assert.Equal(t, true, result.Metadata["anonymous_access"])
}

func TestKibanaFingerprinter_Integration_LoginPage(t *testing.T) {
	fp := &KibanaFingerprinter{}

	body := []byte(`<!DOCTYPE html>
<html>
<head>
<kbn-injected-metadata data="{}"></kbn-injected-metadata>
<title>Kibana</title>
</head>
<body>
<div id="root"></div>
</body>
</html>`)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Set("kbn-name", "kibana")
	resp.Header.Set("kbn-version", "8.12.0")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "kibana", result.Technology)
	// Web UI signal takes precedence over header-only for detection method.
	// kbn-version header can still provide the version.
	assert.Equal(t, "web_ui", result.Metadata["detection_method"])
	assert.Equal(t, true, result.Metadata["authentication_enabled"])
}
