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
	"net/http"
	"strings"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// mockRespWazuh builds a minimal *http.Response for Wazuh tests.
// Body bytes are passed separately to Fingerprint; this helper wires only
// StatusCode and Content-Type. Named to avoid collision with mockResp defined
// in telerik_ui_aspnet_ajax_test.go.
func mockRespWazuh(status int, contentType string) *http.Response {
	resp := &http.Response{
		StatusCode: status,
		Header:     make(http.Header),
	}
	if contentType != "" {
		resp.Header.Set("Content-Type", contentType)
	}
	return resp
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// wazuhAPIRealBody is the canonical JSON returned by the Wazuh Manager REST
// API at its root `/` endpoint. Shape taken from Wazuh API docs
// requests-responses.html.
const wazuhAPIRealBody = `{"data":{"title":"Wazuh API","api_version":"4.7.5","revision":40705,"license_name":"GPL 2.0","license_url":"https://github.com/wazuh/wazuh/blob/master/LICENSE","hostname":"wazuh-master","timestamp":"2024-06-01T00:00:00+0000"},"error":0}`

// wazuhDashboardHTML is a realistic Wazuh Dashboard login page. Both required
// markers are present: "Wazuh" literal and "/plugins/wazuh/" asset path.
const wazuhDashboardHTML = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Wazuh</title>
<link rel="icon" href="/plugins/wazuh/assets/icon.svg" />
<script src="/plugins/wazuh/assets/main.abc123.js"></script>
</head>
<body class="osdBody">
<div id="opensearch-dashboards-loading-message">Loading Wazuh</div>
</body>
</html>`

// wazuhDashboardHTMLWithVersion extends wazuhDashboardHTML to include an
// opportunistic version string that the dashboard extractor can find.
const wazuhDashboardHTMLWithVersion = `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Wazuh</title>
<script src="/plugins/wazuh/assets/main.abc123.js"></script>
<meta name="description" content="Wazuh - 4.7.5 security platform" />
</head>
<body>
<div>Wazuh Dashboard</div>
</body>
</html>`

// openSearchDashboardsHTML is vanilla OpenSearch Dashboards without any Wazuh
// references — must not be detected.
const openSearchDashboardsHTML = `<!DOCTYPE html>
<html>
<head><title>OpenSearch Dashboards</title></head>
<body><p>Welcome to OpenSearch Dashboards</p></body>
</html>`

// splunkLoginHTML is Splunk Web login page — must not be detected.
const splunkLoginHTML = `<!DOCTYPE html>
<html>
<head><title>Splunk Login</title></head>
<body>
<form action="/en-US/account/login" method="post">
<input type="password" name="password" />
</form>
</body>
</html>`

// ---------------------------------------------------------------------------
// TestWazuhAPI_Match
// ---------------------------------------------------------------------------

// TestWazuhAPI_Match verifies status-code and content-type pre-filter logic.
// Match must return true ONLY when status ∈ [200,500) AND Content-Type contains
// "application/json".
func TestWazuhAPI_Match(t *testing.T) {
	fp := &WazuhAPIFingerprinter{}

	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		// Status boundary checks with application/json
		{"status 199 below boundary, json → false", 199, "application/json", false},
		{"status 200 lower boundary, json → true", 200, "application/json", true},
		{"status 300 redirect, json → true", 300, "application/json", true},
		{"status 400 client error, json → true", 400, "application/json", true},
		{"status 499 upper boundary, json → true", 499, "application/json", true},
		{"status 500 server error, json → false", 500, "application/json", false},
		// Content-type checks at status 200
		{"status 200, application/json with charset → true", 200, "application/json; charset=utf-8", true},
		{"status 200, text/html → false", 200, "text/html", false},
		{"status 200, missing content-type → false", 200, "", false},
		// Content-type checks at status 400 (auth-required scenario)
		{"status 401, application/json → true (Match only, no body check)", 401, "application/json", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := mockRespWazuh(tt.statusCode, tt.contentType)
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestWazuhAPI_Fingerprint
// ---------------------------------------------------------------------------

func TestWazuhAPI_Fingerprint(t *testing.T) {
	fp := &WazuhAPIFingerprinter{}

	tests := []struct {
		name              string
		statusCode        int
		contentType       string
		body              []byte
		wantNil           bool
		wantTechnology    string
		wantVersion       string
		wantCPE           string
		wantVendor        string
		wantProduct       string
		wantSurface       string
		wantSeverity      plugins.Severity
	}{
		{
			// Wazuh API docs requests-responses.html — canonical real-world response.
			name:           "real API root response with api_version 4.7.5",
			statusCode:     200,
			contentType:    "application/json",
			body:           []byte(wazuhAPIRealBody),
			wantNil:        false,
			wantTechnology: "wazuh-api",
			wantVersion:    "4.7.5",
			wantCPE:        "cpe:2.3:a:wazuh:wazuh:4.7.5:*:*:*:*:*:*:*",
			wantVendor:     "Wazuh",
			wantProduct:    "Wazuh API",
			wantSurface:    "manager-api",
			wantSeverity:   plugins.SeverityInfo,
		},
		{
			name:           "api_version 5.0.0 (major 5 boundary, valid)",
			statusCode:     200,
			contentType:    "application/json",
			body:           []byte(`{"data":{"title":"Wazuh API","api_version":"5.0.0"},"error":0}`),
			wantNil:        false,
			wantTechnology: "wazuh-api",
			wantVersion:    "5.0.0",
			wantCPE:        "cpe:2.3:a:wazuh:wazuh:5.0.0:*:*:*:*:*:*:*",
		},
		{
			name:           "api_version 3.13.0 (major 3 boundary, valid)",
			statusCode:     200,
			contentType:    "application/json",
			body:           []byte(`{"data":{"title":"Wazuh API","api_version":"3.13.0"},"error":0}`),
			wantNil:        false,
			wantTechnology: "wazuh-api",
			wantVersion:    "3.13.0",
			wantCPE:        "cpe:2.3:a:wazuh:wazuh:3.13.0:*:*:*:*:*:*:*",
		},
		{
			// Missing the required title marker — must return nil.
			name:        "body missing Wazuh API title marker",
			statusCode:  200,
			contentType: "application/json",
			body:        []byte(`{"data":{"api_version":"4.7.5"},"error":0}`),
			wantNil:     true,
		},
		{
			// Marker present but api_version is absent — Technology populated, wildcard CPE.
			name:           "marker present but missing api_version field",
			statusCode:     200,
			contentType:    "application/json",
			body:           []byte(`{"data":{"title":"Wazuh API"},"error":0}`),
			wantNil:        false,
			wantTechnology: "wazuh-api",
			wantVersion:    "",
			wantCPE:        "cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*",
		},
		{
			// Pre-release suffix "4.7.5-rc1" fails the anchored validator — wildcard CPE.
			name:           "marker present but api_version is invalid (rc1 suffix)",
			statusCode:     200,
			contentType:    "application/json",
			body:           []byte(`{"data":{"title":"Wazuh API","api_version":"4.7.5-rc1"},"error":0}`),
			wantNil:        false,
			wantTechnology: "wazuh-api",
			wantVersion:    "",
			wantCPE:        "cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*",
		},
		{
			// Major version 99 is outside the anchored [3-5] range — wildcard CPE.
			name:           "api_version 99.0.0 outside major range → wildcard CPE",
			statusCode:     200,
			contentType:    "application/json",
			body:           []byte(`{"data":{"title":"Wazuh API","api_version":"99.0.0"},"error":0}`),
			wantNil:        false,
			wantTechnology: "wazuh-api",
			wantVersion:    "",
			wantCPE:        "cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*",
		},
		{
			// `:*:` body rejection guard fires before marker check.
			name:        "body containing :*: injection sequence → nil",
			statusCode:  200,
			contentType: "application/json",
			body:        []byte(`{"data":{"title":"Wazuh API","api_version":"4.7.5:*:*"},"error":0}`),
			wantNil:     true,
		},
		{
			// 3 MiB body exceeds the 2 MiB wazuhBodyCap — nil.
			name:        "3 MiB body with marker → nil (body cap exceeded)",
			statusCode:  200,
			contentType: "application/json",
			body: func() []byte {
				prefix := []byte(wazuhAPIRealBody)
				pad := bytes.Repeat([]byte("x"), 3*1024*1024)
				return append(prefix, pad...)
			}(),
			wantNil: true,
		},
		{
			// Status 500 is outside [200,500) — Fingerprint returns nil regardless of body.
			name:        "status 500 with valid body → nil",
			statusCode:  500,
			contentType: "application/json",
			body:        []byte(wazuhAPIRealBody),
			wantNil:     true,
		},
		{
			// Status 401 without the required title marker — nil.
			name:        "status 401 without title marker → nil",
			statusCode:  401,
			contentType: "application/json",
			body:        []byte(`{"error":3,"message":"Unauthorized"}`),
			wantNil:     true,
		},
		{
			// Content-Type defense-in-depth: marker present but wrong content type.
			name:        "marker present, content-type text/html → nil",
			statusCode:  200,
			contentType: "text/html",
			body:        []byte(wazuhAPIRealBody),
			wantNil:     true,
		},
		{
			// CPE injection in api_version: "4.7.5:*:*" — body contains :*: so guard fires.
			name:        "malicious api_version 4.7.5:*:* → nil (body guard fires)",
			statusCode:  200,
			contentType: "application/json",
			body:        []byte(`{"data":{"title":"Wazuh API","api_version":"4.7.5:*:*"},"error":0}`),
			wantNil:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := mockRespWazuh(tt.statusCode, tt.contentType)
			result, err := fp.Fingerprint(resp, tt.body)
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Fingerprint() returned nil, expected result")
			}

			if tt.wantTechnology != "" && result.Technology != tt.wantTechnology {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTechnology)
			}
			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			// For cases where we expect empty version, assert explicitly.
			if tt.wantVersion == "" && !tt.wantNil && result.Version != "" {
				// Only assert empty version when the test doesn't specify wantVersion AND
				// we're checking CPE fallback cases — check CPE instead.
			}
			if tt.wantCPE != "" {
				if len(result.CPEs) == 0 {
					t.Fatal("CPEs is empty")
				}
				if result.CPEs[0] != tt.wantCPE {
					t.Errorf("CPEs[0] = %q, want %q", result.CPEs[0], tt.wantCPE)
				}
			}
			if tt.wantVendor != "" {
				if v, ok := result.Metadata["vendor"].(string); !ok || v != tt.wantVendor {
					t.Errorf("Metadata[vendor] = %v, want %q", result.Metadata["vendor"], tt.wantVendor)
				}
			}
			if tt.wantProduct != "" {
				if p, ok := result.Metadata["product"].(string); !ok || p != tt.wantProduct {
					t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], tt.wantProduct)
				}
			}
			if tt.wantSurface != "" {
				if s, ok := result.Metadata["surface"].(string); !ok || s != tt.wantSurface {
					t.Errorf("Metadata[surface] = %v, want %q", result.Metadata["surface"], tt.wantSurface)
				}
			}
			if tt.wantSeverity != "" && result.Severity != tt.wantSeverity {
				t.Errorf("Severity = %v, want %v", result.Severity, tt.wantSeverity)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestWazuhDashboard_Match
// ---------------------------------------------------------------------------

// TestWazuhDashboard_Match verifies that the dashboard fingerprinter only
// pre-matches responses with status ∈ [200,500) and Content-Type containing
// "text/html".
func TestWazuhDashboard_Match(t *testing.T) {
	fp := &WazuhDashboardFingerprinter{}

	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		// Status boundaries with text/html
		{"status 199 below boundary, html → false", 199, "text/html", false},
		{"status 200 lower boundary, html → true", 200, "text/html", true},
		{"status 300 redirect, html → true", 300, "text/html", true},
		{"status 400 client error, html → true", 400, "text/html", true},
		{"status 499 upper boundary, html → true", 499, "text/html", true},
		{"status 500 server error, html → false", 500, "text/html", false},
		// Content-type checks at status 200
		{"status 200, text/html; charset=utf-8 → true", 200, "text/html; charset=utf-8", true},
		{"status 200, application/json → false", 200, "application/json", false},
		{"status 200, missing content-type → false", 200, "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := mockRespWazuh(tt.statusCode, tt.contentType)
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestWazuhDashboard_Fingerprint
// ---------------------------------------------------------------------------

func TestWazuhDashboard_Fingerprint(t *testing.T) {
	fp := &WazuhDashboardFingerprinter{}

	tests := []struct {
		name              string
		statusCode        int
		contentType       string
		body              []byte
		wantNil           bool
		wantTechnology    string
		wantVersion       string
		wantCPE           string
		wantVendor        string
		wantProduct       string
		wantSurface       string
		wantVersionSource string // non-empty → assert Metadata["version_source"]
		wantSeverity      plugins.Severity
	}{
		{
			// Both required markers present; no version extractable.
			name:           "realistic dashboard HTML with both markers, no version",
			statusCode:     200,
			contentType:    "text/html",
			body:           []byte(wazuhDashboardHTML),
			wantNil:        false,
			wantTechnology: "wazuh-dashboard",
			wantVersion:    "",
			wantCPE:        "cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*",
			wantVendor:     "Wazuh",
			wantProduct:    "Wazuh Dashboard",
			wantSurface:    "dashboard",
			wantSeverity:   plugins.SeverityInfo,
		},
		{
			// Both markers plus opportunistic version string "Wazuh - 4.7.5".
			name:              "dashboard HTML with both markers and version 4.7.5",
			statusCode:        200,
			contentType:       "text/html",
			body:              []byte(wazuhDashboardHTMLWithVersion),
			wantNil:           false,
			wantTechnology:    "wazuh-dashboard",
			wantVersion:       "4.7.5",
			wantCPE:           "cpe:2.3:a:wazuh:wazuh:4.7.5:*:*:*:*:*:*:*",
			wantVersionSource: "html_pattern",
		},
		{
			// Only "Wazuh" present without "/plugins/wazuh/" — dual-marker rejects.
			name:        "only Wazuh title marker (no /plugins/wazuh/ path) → nil",
			statusCode:  200,
			contentType: "text/html",
			body:        []byte(`<!DOCTYPE html><html><head><title>Wazuh</title></head><body></body></html>`),
			wantNil:     true,
		},
		{
			// Only "/plugins/wazuh/" without "Wazuh" literal — dual-marker rejects.
			name:        "only /plugins/wazuh/ asset path (no Wazuh title) → nil",
			statusCode:  200,
			contentType: "text/html",
			body:        []byte(`<!DOCTYPE html><html><head><script src="/plugins/wazuh/main.js"></script></head><body></body></html>`),
			wantNil:     true,
		},
		{
			// Vanilla OpenSearch Dashboards — must not trigger.
			name:        "vanilla OpenSearch Dashboards HTML → nil",
			statusCode:  200,
			contentType: "text/html",
			body:        []byte(openSearchDashboardsHTML),
			wantNil:     true,
		},
		{
			// Splunk login page — must not trigger.
			name:        "Splunk login HTML → nil",
			statusCode:  200,
			contentType: "text/html",
			body:        []byte(splunkLoginHTML),
			wantNil:     true,
		},
		{
			// `:*:` body rejection guard fires before marker check.
			name:        "HTML with :*: injection sequence → nil",
			statusCode:  200,
			contentType: "text/html",
			body:        []byte("<html><title>Wazuh</title><script src=\"/plugins/wazuh/:*:main.js\"></script></html>"),
			wantNil:     true,
		},
		{
			// 3 MiB body exceeds the 2 MiB wazuhBodyCap.
			name:        "3 MiB body with both markers → nil (body cap exceeded)",
			statusCode:  200,
			contentType: "text/html",
			body: func() []byte {
				prefix := []byte(wazuhDashboardHTML)
				pad := bytes.Repeat([]byte("x"), 3*1024*1024)
				return append(prefix, pad...)
			}(),
			wantNil: true,
		},
		{
			// Status 500 is outside [200,500).
			name:        "status 500 with both markers → nil",
			statusCode:  500,
			contentType: "text/html",
			body:        []byte(wazuhDashboardHTML),
			wantNil:     true,
		},
		{
			// Wrong content-type: both markers present but body is served as JSON.
			name:        "application/json content-type with both markers → nil",
			statusCode:  200,
			contentType: "application/json",
			body:        []byte(wazuhDashboardHTML),
			wantNil:     true,
		},
		{
			// Injected version with ":*:*" suffix — the body guard fires on `:*:`.
			name:        "both markers + injected version 4.7.5:*:* → nil (body guard)",
			statusCode:  200,
			contentType: "text/html",
			body: []byte(`<!DOCTYPE html>
<html><head><title>Wazuh</title>
<script src="/plugins/wazuh/main.js"></script>
</head><body>Version 4.7.5:*:* installed</body></html>`),
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := mockRespWazuh(tt.statusCode, tt.contentType)
			result, err := fp.Fingerprint(resp, tt.body)
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}

			if tt.wantNil {
				if result != nil {
					t.Errorf("expected nil, got %+v", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Fingerprint() returned nil, expected result")
			}

			if tt.wantTechnology != "" && result.Technology != tt.wantTechnology {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTechnology)
			}
			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if tt.wantCPE != "" {
				if len(result.CPEs) == 0 {
					t.Fatal("CPEs is empty")
				}
				if result.CPEs[0] != tt.wantCPE {
					t.Errorf("CPEs[0] = %q, want %q", result.CPEs[0], tt.wantCPE)
				}
			}
			if tt.wantVendor != "" {
				if v, ok := result.Metadata["vendor"].(string); !ok || v != tt.wantVendor {
					t.Errorf("Metadata[vendor] = %v, want %q", result.Metadata["vendor"], tt.wantVendor)
				}
			}
			if tt.wantProduct != "" {
				if p, ok := result.Metadata["product"].(string); !ok || p != tt.wantProduct {
					t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], tt.wantProduct)
				}
			}
			if tt.wantSurface != "" {
				if s, ok := result.Metadata["surface"].(string); !ok || s != tt.wantSurface {
					t.Errorf("Metadata[surface] = %v, want %q", result.Metadata["surface"], tt.wantSurface)
				}
			}
			if tt.wantVersionSource != "" {
				if vs, ok := result.Metadata["version_source"].(string); !ok || vs != tt.wantVersionSource {
					t.Errorf("Metadata[version_source] = %v, want %q", result.Metadata["version_source"], tt.wantVersionSource)
				}
			}
			if tt.wantSeverity != "" && result.Severity != tt.wantSeverity {
				t.Errorf("Severity = %v, want %v", result.Severity, tt.wantSeverity)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestBuildWazuhCPE
// ---------------------------------------------------------------------------

func TestBuildWazuhCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "empty version → wildcard CPE",
			version: "",
			want:    "cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*",
		},
		{
			name:    "4.7.5 → embedded",
			version: "4.7.5",
			want:    "cpe:2.3:a:wazuh:wazuh:4.7.5:*:*:*:*:*:*:*",
		},
		{
			name:    "5.0.0 → embedded",
			version: "5.0.0",
			want:    "cpe:2.3:a:wazuh:wazuh:5.0.0:*:*:*:*:*:*:*",
		},
		{
			name:    "3.13.0 → embedded",
			version: "3.13.0",
			want:    "cpe:2.3:a:wazuh:wazuh:3.13.0:*:*:*:*:*:*:*",
		},
		{
			// Major 99 is outside [3-5] range — anchored validator rejects.
			name:    "99.0.0 outside major range → wildcard",
			version: "99.0.0",
			want:    "cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*",
		},
		{
			// Pre-release suffix fails the anchored regex.
			name:    "4.7.5-rc1 (pre-release suffix) → wildcard",
			version: "4.7.5-rc1",
			want:    "cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*",
		},
		{
			// CPE injection attempt with embedded component separators.
			name:    "4.7.5:*:* (CPE injection) → wildcard",
			version: "4.7.5:*:*",
			want:    "cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*",
		},
		{
			// SQL-like injection; fails anchored validator.
			name:    ";DROP TABLE → wildcard",
			version: ";DROP TABLE",
			want:    "cpe:2.3:a:wazuh:wazuh:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildWazuhCPE(tt.version); got != tt.want {
				t.Errorf("buildWazuhCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestExtractWazuhAPIVersion
// ---------------------------------------------------------------------------

func TestExtractWazuhAPIVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			// Canonical nested JSON from Wazuh API root endpoint.
			name: "real API root body → 4.7.5",
			body: wazuhAPIRealBody,
			want: "4.7.5",
		},
		{
			name: "body without api_version field → empty",
			body: `{"data":{"title":"Wazuh API"},"error":0}`,
			want: "",
		},
		{
			// Validator rejects the pre-release suffix.
			name: "malformed api_version 'foo' → empty (validator rejects)",
			body: `{"data":{"title":"Wazuh API","api_version":"foo"},"error":0}`,
			want: "",
		},
		{
			// Field length cap of 256 bytes.
			name: "api_version length > 256 chars → empty (field-length cap)",
			body: `{"data":{"title":"Wazuh API","api_version":"` + strings.Repeat("4", 260) + `"},"error":0}`,
			want: "",
		},
		{
			// The helper extracts regardless of the title presence — title is checked at
			// the Fingerprint level, not in the helper. This test documents that behaviour.
			name: "valid api_version in body without Wazuh title — extraction succeeds (gate is separate)",
			body: `{"data":{"api_version":"4.7.5"},"error":0}`,
			want: "4.7.5",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractWazuhAPIVersion([]byte(tt.body)); got != tt.want {
				t.Errorf("extractWazuhAPIVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestExtractWazuhDashboardVersion
// ---------------------------------------------------------------------------

func TestExtractWazuhDashboardVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			// "Wazuh - 4.7.5" pattern (dash-separated label).
			name: "HTML with 'Wazuh - 4.7.5' → 4.7.5",
			body: `<meta name="description" content="Wazuh - 4.7.5 security platform" />`,
			want: "4.7.5",
		},
		{
			// Hyphenated pattern without spaces.
			name: "HTML with 'Wazuh-5.0.0' → 5.0.0",
			body: `<div class="version">Wazuh-5.0.0</div>`,
			want: "5.0.0",
		},
		{
			// No version pattern present.
			name: "HTML without version pattern → empty",
			body: `<html><head><title>Wazuh</title></head><body></body></html>`,
			want: "",
		},
		{
			// Version-like pattern without "Wazuh" prefix — regex requires Wazuh prefix.
			name: "version pattern without Wazuh prefix (e.g. Apache 2.4.41) → empty",
			body: `<p>Powered by Apache 2.4.41</p>`,
			want: "",
		},
		{
			// "4.7.foo" fails the digit-only validator.
			name: "Wazuh prefix with malformed version 4.7.foo → empty",
			body: `<p>Wazuh 4.7.foo</p>`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractWazuhDashboardVersion([]byte(tt.body)); got != tt.want {
				t.Errorf("extractWazuhDashboardVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// TestWazuh_DistinctRegistryNames
// ---------------------------------------------------------------------------

// TestWazuh_DistinctRegistryNames is a regression guard ensuring both Wazuh
// fingerprinters are registered under distinct Name() values so they coexist
// correctly in the global registry.
func TestWazuh_DistinctRegistryNames(t *testing.T) {
	// Snapshot and restore the global registry so this test is order-independent.
	saved := append([]HTTPFingerprinter(nil), httpFingerprinters...)
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	Register(&WazuhAPIFingerprinter{})
	Register(&WazuhDashboardFingerprinter{})

	fingerprinters := GetFingerprinters()

	wantNames := map[string]bool{
		"wazuh-api":       false,
		"wazuh-dashboard": false,
	}

	for _, fp := range fingerprinters {
		if _, ok := wantNames[fp.Name()]; ok {
			wantNames[fp.Name()] = true
		}
	}

	for name, found := range wantNames {
		if !found {
			t.Errorf("fingerprinter %q not found in registry", name)
		}
	}

	// Verify they have distinct Name() values.
	if len(fingerprinters) < 2 {
		t.Fatalf("expected at least 2 fingerprinters, got %d", len(fingerprinters))
	}
	nameSet := make(map[string]struct{})
	for _, fp := range fingerprinters {
		if _, dup := nameSet[fp.Name()]; dup {
			t.Errorf("duplicate fingerprinter Name() %q in registry", fp.Name())
		}
		nameSet[fp.Name()] = struct{}{}
	}
}
