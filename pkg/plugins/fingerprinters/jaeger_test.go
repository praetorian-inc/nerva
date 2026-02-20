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

func TestJaegerFingerprinter_Name(t *testing.T) {
	fp := &JaegerFingerprinter{}
	assert.Equal(t, "jaeger", fp.Name())
}

func TestJaegerFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &JaegerFingerprinter{}
	assert.Equal(t, "/api/services", fp.ProbeEndpoint())
}

func TestJaegerFingerprinter_Match(t *testing.T) {
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
			name:        "Content-Type: text/html returns true",
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "Content-Type: text/html; charset=utf-8 returns true",
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "No Content-Type header returns false",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &JaegerFingerprinter{}
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

func TestJaegerFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name               string
		body               string
		wantVersion        string
		wantCPE            string
		wantServiceCount   int
		wantTotalPresent   bool
		wantTotal          int
		wantLimitPresent   bool
		wantLimit          int
		wantOffsetPresent  bool
		wantOffset         int
		wantFirstService   string
		wantServicesLength int
		wantGitCommit      string
		wantBuildDate      string
	}{
		{
			name: "Full response with multiple services, total, limit, offset",
			body: `{
				"data": ["service-a", "service-b", "checkout", "frontend"],
				"errors": null,
				"limit": 100,
				"offset": 0,
				"total": 4
			}`,
			wantVersion:        "",
			wantCPE:            "cpe:2.3:a:jaegertracing:jaeger:*:*:*:*:*:*:*:*",
			wantServiceCount:   4,
			wantTotalPresent:   true,
			wantTotal:          4,
			wantLimitPresent:   true,
			wantLimit:          100,
			wantOffsetPresent:  false, // offset is 0, shouldn't be in metadata
			wantOffset:         0,
			wantFirstService:   "service-a",
			wantServicesLength: 4,
		},
		{
			name: "Minimal response with just data and one service",
			body: `{
				"data": ["api-gateway"],
				"errors": null,
				"limit": 0,
				"offset": 0,
				"total": 1
			}`,
			wantVersion:        "",
			wantCPE:            "cpe:2.3:a:jaegertracing:jaeger:*:*:*:*:*:*:*:*",
			wantServiceCount:   1,
			wantTotalPresent:   true,
			wantTotal:          1,
			wantLimitPresent:   false, // limit is 0, shouldn't be in metadata
			wantLimit:          0,
			wantOffsetPresent:  false, // offset is 0, shouldn't be in metadata
			wantOffset:         0,
			wantFirstService:   "api-gateway",
			wantServicesLength: 1,
		},
		{
			name: "Response with many services (10+)",
			body: `{
				"data": [
					"user-service", "auth-service", "payment-service",
					"notification-service", "analytics-service", "logging-service",
					"monitoring-service", "api-gateway", "frontend", "backend",
					"database-service", "cache-service"
				],
				"errors": null,
				"limit": 50,
				"offset": 0,
				"total": 12
			}`,
			wantVersion:        "",
			wantCPE:            "cpe:2.3:a:jaegertracing:jaeger:*:*:*:*:*:*:*:*",
			wantServiceCount:   12,
			wantTotalPresent:   true,
			wantTotal:          12,
			wantLimitPresent:   true,
			wantLimit:          50,
			wantOffsetPresent:  false,
			wantOffset:         0,
			wantFirstService:   "user-service",
			wantServicesLength: 12,
		},
		{
			name: "Response with total > 0 but limit = 0",
			body: `{
				"data": ["service-x", "service-y", "service-z"],
				"errors": null,
				"limit": 0,
				"offset": 0,
				"total": 3
			}`,
			wantVersion:        "",
			wantCPE:            "cpe:2.3:a:jaegertracing:jaeger:*:*:*:*:*:*:*:*",
			wantServiceCount:   3,
			wantTotalPresent:   true,
			wantTotal:          3,
			wantLimitPresent:   false, // limit is 0
			wantLimit:          0,
			wantOffsetPresent:  false, // offset is 0
			wantOffset:         0,
			wantFirstService:   "service-x",
			wantServicesLength: 3,
		},
		{
			name: "Response with pagination (offset > 0)",
			body: `{
				"data": ["service-d", "service-e", "service-f"],
				"errors": null,
				"limit": 3,
				"offset": 3,
				"total": 10
			}`,
			wantVersion:        "",
			wantCPE:            "cpe:2.3:a:jaegertracing:jaeger:*:*:*:*:*:*:*:*",
			wantServiceCount:   3,
			wantTotalPresent:   true,
			wantTotal:          10,
			wantLimitPresent:   true,
			wantLimit:          3,
			wantOffsetPresent:  true,
			wantOffset:         3,
			wantFirstService:   "service-d",
			wantServicesLength: 3,
		},
		{
			name: "Fresh instance with null data (no services traced yet)",
			body: `{
				"data": null,
				"errors": null,
				"limit": 0,
				"offset": 0,
				"total": 0
			}`,
			wantVersion:        "",
			wantCPE:            "cpe:2.3:a:jaegertracing:jaeger:*:*:*:*:*:*:*:*",
			wantServiceCount:   0,
			wantTotalPresent:   false, // total is 0, shouldn't be in metadata
			wantTotal:          0,
			wantLimitPresent:   false,
			wantLimit:          0,
			wantOffsetPresent:  false,
			wantOffset:         0,
			wantFirstService:   "",
			wantServicesLength: 0,
		},
		{
			name: "Fresh instance with empty data array (no services traced yet)",
			body: `{
				"data": [],
				"errors": null,
				"limit": 0,
				"offset": 0,
				"total": 0
			}`,
			wantVersion:        "",
			wantCPE:            "cpe:2.3:a:jaegertracing:jaeger:*:*:*:*:*:*:*:*",
			wantServiceCount:   0,
			wantTotalPresent:   false, // total is 0, shouldn't be in metadata
			wantTotal:          0,
			wantLimitPresent:   false,
			wantLimit:          0,
			wantOffsetPresent:  false,
			wantOffset:         0,
			wantFirstService:   "",
			wantServicesLength: 0,
		},
		{
			name: "Jaeger v2 root HTML with title tag and version",
			body: `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Jaeger UI</title>
  <base href="/">
  <script>
    function getJaegerVersion() {
      const DEFAULT_VERSION = {'gitCommit':'', 'gitVersion':'', 'buildDate':''};
      const JAEGER_VERSION = {"gitCommit":"63b27e1810a710ac54dc4522da0538e540bdc545","gitVersion":"v1.76.0","buildDate":"2025-12-03T16:07:08Z"};
      return JAEGER_VERSION;
    }
  </script>
</head>
<body>
  <div id="jaeger-ui-root"></div>
</body>
</html>`,
			wantVersion:        "1.76.0",
			wantCPE:            "cpe:2.3:a:jaegertracing:jaeger:1.76.0:*:*:*:*:*:*:*",
			wantServiceCount:   0,
			wantTotalPresent:   false,
			wantTotal:          0,
			wantLimitPresent:   false,
			wantLimit:          0,
			wantOffsetPresent:  false,
			wantOffset:         0,
			wantFirstService:   "",
			wantServicesLength: 0,
			wantGitCommit:      "63b27e1810a710ac54dc4522da0538e540bdc545",
			wantBuildDate:      "2025-12-03T16:07:08Z",
		},
		{
			name:               "Jaeger v1 root HTML (minified) with version",
			body:               `<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Jaeger UI</title><base href="/"><script>function getJaegerVersion(){const DEFAULT_VERSION={'gitCommit':'','gitVersion':'','buildDate':''};const JAEGER_VERSION={"gitCommit":"abc123","gitVersion":"v1.35.0","buildDate":"2024-01-15T10:30:00Z"};return JAEGER_VERSION;}</script></head><body><div id="jaeger-ui-root"></div></body></html>`,
			wantVersion:        "1.35.0",
			wantCPE:            "cpe:2.3:a:jaegertracing:jaeger:1.35.0:*:*:*:*:*:*:*",
			wantServiceCount:   0,
			wantTotalPresent:   false,
			wantTotal:          0,
			wantLimitPresent:   false,
			wantLimit:          0,
			wantOffsetPresent:  false,
			wantOffset:         0,
			wantFirstService:   "",
			wantServicesLength: 0,
			wantGitCommit:      "abc123",
			wantBuildDate:      "2024-01-15T10:30:00Z",
		},
		{
			name: "HTML with version but no gitCommit",
			body: `<!doctype html>
<html lang="en">
<head>
  <title>Jaeger UI</title>
  <script>
    function getJaegerVersion() {
      const JAEGER_VERSION = {"gitCommit":"","gitVersion":"v2.0.0","buildDate":"2025-01-10T12:00:00Z"};
      return JAEGER_VERSION;
    }
  </script>
</head>
<body><div id="jaeger-ui-root"></div></body>
</html>`,
			wantVersion:        "2.0.0",
			wantCPE:            "cpe:2.3:a:jaegertracing:jaeger:2.0.0:*:*:*:*:*:*:*",
			wantServiceCount:   0,
			wantTotalPresent:   false,
			wantTotal:          0,
			wantLimitPresent:   false,
			wantLimit:          0,
			wantOffsetPresent:  false,
			wantOffset:         0,
			wantFirstService:   "",
			wantServicesLength: 0,
			wantBuildDate:      "2025-01-10T12:00:00Z",
		},
		{
			name: "HTML without JAEGER_VERSION function",
			body: `<!doctype html>
<html lang="en">
<head>
  <title>Jaeger UI</title>
</head>
<body><div id="jaeger-ui-root"></div></body>
</html>`,
			wantVersion:        "",
			wantCPE:            "cpe:2.3:a:jaegertracing:jaeger:*:*:*:*:*:*:*:*",
			wantServiceCount:   0,
			wantTotalPresent:   false,
			wantTotal:          0,
			wantLimitPresent:   false,
			wantLimit:          0,
			wantOffsetPresent:  false,
			wantOffset:         0,
			wantFirstService:   "",
			wantServicesLength: 0,
		},
		{
			name: "HTML with malicious version (CPE injection attempt)",
			body: `<!doctype html>
<html lang="en">
<head>
  <title>Jaeger UI</title>
  <script>
    function getJaegerVersion() {
      const JAEGER_VERSION = {"gitCommit":"abc","gitVersion":"v1.0.0:*:*:*:*:*:*:*","buildDate":"2025-01-01T00:00:00Z"};
      return JAEGER_VERSION;
    }
  </script>
</head>
<body><div id="jaeger-ui-root"></div></body>
</html>`,
			wantVersion:        "",
			wantCPE:            "cpe:2.3:a:jaegertracing:jaeger:*:*:*:*:*:*:*:*",
			wantServiceCount:   0,
			wantTotalPresent:   false,
			wantTotal:          0,
			wantLimitPresent:   false,
			wantLimit:          0,
			wantOffsetPresent:  false,
			wantOffset:         0,
			wantFirstService:   "",
			wantServicesLength: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &JaegerFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			// Set Content-Type based on body content
			if strings.Contains(tt.body, "<html") {
				resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			} else {
				resp.Header.Set("Content-Type", "application/json")
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result)

			assert.Equal(t, "jaeger", result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)

			// Check metadata - serviceCount (always present)
			serviceCount, exists := result.Metadata["serviceCount"]
			require.True(t, exists, "Expected serviceCount in metadata")
			assert.Equal(t, tt.wantServiceCount, serviceCount)

			// Check metadata - services array (only if services exist)
			if tt.wantServicesLength > 0 {
				services, exists := result.Metadata["services"]
				require.True(t, exists, "Expected services in metadata when services exist")
				serviceSlice, ok := services.([]string)
				require.True(t, ok, "Expected services to be []string")
				assert.Len(t, serviceSlice, tt.wantServicesLength)
				assert.Equal(t, tt.wantFirstService, serviceSlice[0])
			} else {
				// When no services, services key should not be present
				_, exists := result.Metadata["services"]
				assert.False(t, exists, "Did not expect services in metadata when serviceCount is 0")
			}

			// Check metadata - total
			if tt.wantTotalPresent {
				total, exists := result.Metadata["total"]
				assert.True(t, exists, "Expected total in metadata")
				assert.Equal(t, tt.wantTotal, total)
			}

			// Check metadata - limit
			if tt.wantLimitPresent {
				limit, exists := result.Metadata["limit"]
				assert.True(t, exists, "Expected limit in metadata")
				assert.Equal(t, tt.wantLimit, limit)
			} else {
				_, exists := result.Metadata["limit"]
				assert.False(t, exists, "Did not expect limit in metadata when limit=0")
			}

			// Check metadata - offset
			if tt.wantOffsetPresent {
				offset, exists := result.Metadata["offset"]
				assert.True(t, exists, "Expected offset in metadata")
				assert.Equal(t, tt.wantOffset, offset)
			} else {
				_, exists := result.Metadata["offset"]
				assert.False(t, exists, "Did not expect offset in metadata when offset=0")
			}

			// Check metadata - gitCommit
			if tt.wantGitCommit != "" {
				gitCommit, exists := result.Metadata["gitCommit"]
				assert.True(t, exists, "Expected gitCommit in metadata")
				assert.Equal(t, tt.wantGitCommit, gitCommit)
			}

			// Check metadata - buildDate
			if tt.wantBuildDate != "" {
				buildDate, exists := result.Metadata["buildDate"]
				assert.True(t, exists, "Expected buildDate in metadata")
				assert.Equal(t, tt.wantBuildDate, buildDate)
			}

			// Check CPE
			require.NotEmpty(t, result.CPEs)
			assert.Contains(t, result.CPEs, tt.wantCPE)
		})
	}
}

func TestJaegerFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Non-JSON body",
			body: "OK",
		},
		{
			name: "JSON missing total field (structural validation)",
			body: `{"data": [], "errors": null, "limit": 0, "offset": 0}`,
		},
		{
			name: "JSON missing errors field (structural validation)",
			body: `{"data": [], "total": 0, "limit": 0, "offset": 0}`,
		},
		{
			name: "JSON missing limit field (structural validation)",
			body: `{"data": [], "errors": null, "total": 0, "offset": 0}`,
		},
		{
			name: "JSON missing offset field (structural validation)",
			body: `{"data": [], "errors": null, "total": 0, "limit": 0}`,
		},
		{
			name: "JSON missing data field (structural validation)",
			body: `{"errors": null, "total": 0, "limit": 0, "offset": 0}`,
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
			name: "Different JSON structure (e.g., not Jaeger format)",
			body: `{"services": ["a"], "status": "ok"}`,
		},
		{
			name: "Random JSON object (prevent false positives)",
			body: `{"foo": "bar", "baz": 123, "nested": {"key": "value"}}`,
		},
		{
			name: "Malformed JSON",
			body: `{"data": ["service-a", "errors": null}`,
		},
		{
			name: "HTML without Jaeger title",
			body: `<!doctype html><html><head><title>Welcome</title></head><body>Hello</body></html>`,
		},
		{
			name: "HTML with different title",
			body: `<!doctype html><html><head><title>Grafana</title></head><body><div id="root"></div></body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &JaegerFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			// Set appropriate Content-Type
			if strings.Contains(tt.body, "<html") {
				resp.Header.Set("Content-Type", "text/html")
			} else {
				resp.Header.Set("Content-Type", "application/json")
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestBuildJaegerCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "1.76.0",
			want:    "cpe:2.3:a:jaegertracing:jaeger:1.76.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:jaegertracing:jaeger:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildJaegerCPE(tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestJaegerFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter
	fp := &JaegerFingerprinter{}
	Register(fp)

	// Create a valid Jaeger /api/services response
	body := []byte(`{
		"data": ["service-a", "service-b", "checkout", "frontend"],
		"errors": null,
		"limit": 0,
		"offset": 0,
		"total": 4
	}`)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	results := RunFingerprinters(resp, body)

	// Should find at least the Jaeger fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "jaeger" {
			found = true
			assert.Equal(t, "", result.Version) // No version exposed via JSON endpoint
			assert.Contains(t, result.CPEs, buildJaegerCPE(""))
			serviceCount, exists := result.Metadata["serviceCount"]
			assert.True(t, exists)
			assert.Equal(t, 4, serviceCount)
		}
	}

	assert.True(t, found, "JaegerFingerprinter not found in results")
}
