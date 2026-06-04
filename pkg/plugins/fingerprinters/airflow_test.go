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
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// ── Name / ProbeEndpoint ───────────────────────────────────────────────────────

func TestAirflowFingerprinter_Name(t *testing.T) {
	fp := &AirflowFingerprinter{}
	assert.Equal(t, "airflow", fp.Name())
}

func TestAirflowFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &AirflowFingerprinter{}
	assert.Equal(t, "/api/v1/health", fp.ProbeEndpoint())
}

// ── Match ──────────────────────────────────────────────────────────────────────

func TestAirflowFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "200 with text/html → true",
			statusCode:  200,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 with application/json → true",
			statusCode:  200,
			contentType: "application/json",
			want:        true,
		},
		{
			name:       "200 with no relevant headers → false",
			statusCode: 200,
			want:       false,
		},
		{
			name:       "500 error → false",
			statusCode: 500,
			want:       false,
		},
		{
			name:        "302 with text/html → true",
			statusCode:  302,
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 with image/png → false",
			statusCode:  200,
			contentType: "image/png",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AirflowFingerprinter{}
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

// ── Fingerprint: positive (valid) ─────────────────────────────────────────────

func TestAirflowFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name                     string
		statusCode               int
		body                     string
		probePath                string
		wantVersion              string
		wantCPE                  string
		wantDetectionMethod      string
		wantAnonymousAPIAccess   bool
		wantSeverityHigh         bool
		wantProbePathKey         bool
	}{
		{
			name:                "Web UI title 'Airflow - Login' → technology=airflow, detection_method=web_ui",
			statusCode:          200,
			body:                `<html><head><title>Airflow - Login</title></head><body></body></html>`,
			wantDetectionMethod: "web_ui",
		},
		{
			name:                "Web UI with asset references → detects via web_ui",
			statusCode:          200,
			body:                `<html><head><link href="/static/airflow/css/main.css"></head><body></body></html>`,
			wantDetectionMethod: "web_ui",
		},
		{
			name:                "Web UI with version in JSON body → extracts version",
			statusCode:          200,
			body:                `<html><head><title>Airflow - DAGs</title></head><body><script>var config={"version":"2.8.1"};</script></body></html>`,
			wantVersion:         "2.8.1",
			wantCPE:             "cpe:2.3:a:apache:airflow:2.8.1:*:*:*:*:*:*:*",
			wantDetectionMethod: "web_ui",
		},
		{
			name:                   "API health endpoint JSON → anonymous_api_access=true, SeverityHigh",
			statusCode:             200,
			body:                   `{"metadatabase":{"status":"healthy"},"scheduler":{"latest_scheduler_heartbeat":"2024-01-01T00:00:00","status":"healthy"},"version":"2.7.0"}`,
			wantVersion:            "2.7.0",
			wantCPE:                "cpe:2.3:a:apache:airflow:2.7.0:*:*:*:*:*:*:*",
			wantDetectionMethod:    "api_health",
			wantAnonymousAPIAccess: true,
			wantSeverityHigh:       true,
		},
		{
			name:                   "Active probe /api/v1/health with health JSON → active_probe detection, probe_path, SeverityHigh",
			statusCode:             200,
			body:                   `{"metadatabase":{"status":"healthy"},"scheduler":{"latest_scheduler_heartbeat":"2024-01-01T00:00:00","status":"healthy"}}`,
			probePath:              "/api/v1/health",
			wantDetectionMethod:    "active_probe",
			wantAnonymousAPIAccess: true,
			wantSeverityHigh:       true,
			wantProbePathKey:       true,
		},
		{
			name:                "Web UI with no version → wildcard CPE",
			statusCode:          200,
			body:                `<html><head><title>Airflow</title></head><body></body></html>`,
			wantCPE:             "cpe:2.3:a:apache:airflow:*:*:*:*:*:*:*:*",
			wantDetectionMethod: "web_ui",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AirflowFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.probePath != "" {
				resp.Request = &http.Request{URL: &url.URL{Path: tt.probePath}}
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			assert.NoError(t, err)
			assert.NotNil(t, result, "expected non-nil result")

			if result == nil {
				return
			}

			assert.Equal(t, "airflow", result.Technology)
			assert.NotEmpty(t, result.CPEs)
			assert.NotNil(t, result.Metadata)

			if tt.wantVersion != "" {
				assert.Equal(t, tt.wantVersion, result.Version)
			}
			if tt.wantCPE != "" {
				assert.Equal(t, tt.wantCPE, result.CPEs[0])
			}
			if tt.wantDetectionMethod != "" {
				assert.Equal(t, tt.wantDetectionMethod, result.Metadata["detection_method"])
			}
			if tt.wantAnonymousAPIAccess {
				access, ok := result.Metadata["anonymous_api_access"].(bool)
				assert.True(t, ok, "anonymous_api_access should be bool")
				assert.True(t, access, "anonymous_api_access should be true")
			}
			if !tt.wantAnonymousAPIAccess {
				_, hasAccess := result.Metadata["anonymous_api_access"]
				assert.False(t, hasAccess, "anonymous_api_access should be absent when not expected")
			}
			if tt.wantSeverityHigh {
				assert.NotEmpty(t, result.Severity, "expected severity to be set")
			}
			if tt.wantProbePathKey {
				assert.Equal(t, "/api/v1/health", result.Metadata["probe_path"])
			} else {
				_, hasProbePath := result.Metadata["probe_path"]
				assert.False(t, hasProbePath, "probe_path should be absent for non-active-probe responses")
			}
		})
	}
}

// ── Fingerprint: negative (invalid — must return nil) ─────────────────────────

func TestAirflowFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "Status 500 → nil",
			statusCode: 500,
			body:       `{"metadatabase":{"status":"unhealthy"},"scheduler":{"status":"unhealthy"}}`,
		},
		{
			name:       "Body > 2 MiB → nil",
			statusCode: 200,
			body:       strings.Repeat("A", 2*1024*1024+1),
		},
		{
			name:       "No airflow markers → nil",
			statusCode: 200,
			body:       `{"status":"ok","version":"1.0.0"}`,
		},
		{
			name:       "Generic HTML page → nil",
			statusCode: 200,
			body:       `<html><head><title>Welcome</title></head><body><h1>Hello World</h1></body></html>`,
		},
		{
			name:       "Prose mention of 'airflow' in paragraph → nil (not in title/asset)",
			statusCode: 200,
			body:       `<html><body><p>We use airflow for our ETL pipelines.</p></body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &AirflowFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			assert.NoError(t, err)
			assert.Nil(t, result, "expected nil result for negative test case")
		})
	}
}

// ── TestExtractAirflowVersion ──────────────────────────────────────────────────

func TestExtractAirflowVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: `JSON "version": "2.8.1"`,
			body: `{"version":"2.8.1","metadatabase":{"status":"healthy"}}`,
			want: "2.8.1",
		},
		{
			name: `JSON "version": "2.7.0.1" (four-component)`,
			body: `{"version":"2.7.0.1"}`,
			want: "2.7.0.1",
		},
		{
			name: "No version in body",
			body: `{"metadatabase":{"status":"healthy"},"scheduler":{"status":"healthy"}}`,
			want: "",
		},
		{
			name: "Version with CPE metacharacters → empty after validation",
			body: `{"version":"2.8.1:*"}`,
			want: "",
		},
		{
			name: "Empty body",
			body: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractAirflowVersion([]byte(tt.body))
			assert.Equal(t, tt.want, got)
		})
	}
}

// ── TestBuildAirflowCPE ────────────────────────────────────────────────────────

func TestBuildAirflowCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "version 2.8.1 → full CPE with version",
			version: "2.8.1",
			want:    "cpe:2.3:a:apache:airflow:2.8.1:*:*:*:*:*:*:*",
		},
		{
			name:    "empty → wildcard CPE",
			version: "",
			want:    "cpe:2.3:a:apache:airflow:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, buildAirflowCPE(tt.version))
		})
	}
}

// ── Integration test ───────────────────────────────────────────────────────────

func TestAirflowFingerprinter_Integration(t *testing.T) {
	// Save and restore global registry state.
	saved := httpFingerprinters
	httpFingerprinters = nil
	defer func() { httpFingerprinters = saved }()

	fp := &AirflowFingerprinter{}

	t.Run("web UI with title triggers detection", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			fmt.Fprintln(w, `<html><head><title>Airflow - Login</title></head><body></body></html>`)
		}))
		defer ts.Close()

		resp, err := http.Get(ts.URL)
		assert.NoError(t, err)
		defer resp.Body.Close()

		body := []byte(`<html><head><title>Airflow - Login</title></head><body></body></html>`)
		assert.True(t, fp.Match(resp))
		result, err := fp.Fingerprint(resp, body)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		if result != nil {
			assert.Equal(t, "airflow", result.Technology)
			assert.Equal(t, "Apache", result.Metadata["vendor"])
			assert.Equal(t, "Airflow", result.Metadata["product"])
			assert.Equal(t, "web_ui", result.Metadata["detection_method"])
		}
	})

	t.Run("health API body triggers high severity", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintln(w, `{"metadatabase":{"status":"healthy"},"scheduler":{"status":"healthy"},"version":"2.8.1"}`)
		}))
		defer ts.Close()

		resp, err := http.Get(ts.URL)
		assert.NoError(t, err)
		defer resp.Body.Close()

		body := []byte(`{"metadatabase":{"status":"healthy"},"scheduler":{"status":"healthy"},"version":"2.8.1"}`)
		assert.True(t, fp.Match(resp))
		result, err := fp.Fingerprint(resp, body)
		assert.NoError(t, err)
		assert.NotNil(t, result)
		if result != nil {
			assert.NotEmpty(t, result.Severity)
			access, ok := result.Metadata["anonymous_api_access"].(bool)
			assert.True(t, ok)
			assert.True(t, access)
			assert.Equal(t, "2.8.1", result.Version)
		}
	})
}
