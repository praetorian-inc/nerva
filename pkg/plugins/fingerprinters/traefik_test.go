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
)

// validOverviewBody is a representative /api/overview response with all three protocols.
const validOverviewBody = `{
	"http": {
		"routers": {"total": 5, "warnings": 0, "errors": 0},
		"services": {"total": 3, "warnings": 0, "errors": 0},
		"middlewares": {"total": 2, "warnings": 0, "errors": 0}
	},
	"tcp": {
		"routers": {"total": 0, "warnings": 0, "errors": 0},
		"services": {"total": 0, "warnings": 0, "errors": 0},
		"middlewares": {"total": 0, "warnings": 0, "errors": 0}
	},
	"udp": {
		"routers": {"total": 0, "warnings": 0, "errors": 0},
		"services": {"total": 0, "warnings": 0, "errors": 0},
		"middlewares": {"total": 0, "warnings": 0, "errors": 0}
	}
}`

// validVersionBody is a representative /api/version response.
const validVersionBody = `{
	"Version": "2.6.0",
	"Codename": "rocamadour",
	"startDate": "2021-08-16T16:44:35.000000000Z",
	"pilotEnabled": true
}`

func makeJSONResponse(statusCode int) *http.Response {
	resp := &http.Response{
		StatusCode: statusCode,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")
	return resp
}

// --- TraefikOverviewFingerprinter tests ---

func TestTraefikOverviewFingerprinter_Name(t *testing.T) {
	fp := &TraefikOverviewFingerprinter{}
	if got := fp.Name(); got != "traefik-dashboard" {
		t.Errorf("Name() = %q, want %q", got, "traefik-dashboard")
	}
}

func TestTraefikOverviewFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &TraefikOverviewFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/api/overview" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/api/overview")
	}
}

func TestTraefikOverviewFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "application/json 200 returns true",
			statusCode:  200,
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "application/json; charset=utf-8 returns true",
			statusCode:  200,
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "+json vendor type returns true",
			statusCode:  200,
			contentType: "application/vnd.api+json",
			want:        true,
		},
		{
			name:        "text/html returns false",
			statusCode:  200,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "empty Content-Type returns false",
			statusCode:  200,
			contentType: "",
			want:        false,
		},
		{
			name:        "500 status returns false",
			statusCode:  500,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "503 status returns false",
			statusCode:  503,
			contentType: "application/json",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TraefikOverviewFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTraefikOverviewFingerprinter_Fingerprint_Valid(t *testing.T) {
	t.Run("valid overview detects traefik-dashboard with wildcard CPE", func(t *testing.T) {
		fp := &TraefikOverviewFingerprinter{}
		resp := makeJSONResponse(200)

		result, err := fp.Fingerprint(resp, []byte(validOverviewBody))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want result")
		}

		if result.Technology != "traefik-dashboard" {
			t.Errorf("Technology = %q, want %q", result.Technology, "traefik-dashboard")
		}
		if result.Version != "" {
			t.Errorf("Version = %q, want empty string", result.Version)
		}
		wantCPE := "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*"
		if len(result.CPEs) != 1 || result.CPEs[0] != wantCPE {
			t.Errorf("CPEs = %v, want [%s]", result.CPEs, wantCPE)
		}
	})

	t.Run("valid overview with non-zero counts reflects counts in metadata", func(t *testing.T) {
		fp := &TraefikOverviewFingerprinter{}
		resp := makeJSONResponse(200)
		body := `{
			"http": {
				"routers": {"total": 10, "warnings": 1, "errors": 0},
				"services": {"total": 7, "warnings": 0, "errors": 0},
				"middlewares": {"total": 3, "warnings": 0, "errors": 0}
			},
			"tcp": {
				"routers": {"total": 2, "warnings": 0, "errors": 0},
				"services": {"total": 2, "warnings": 0, "errors": 0},
				"middlewares": {"total": 0, "warnings": 0, "errors": 0}
			},
			"udp": {
				"routers": {"total": 1, "warnings": 0, "errors": 0},
				"services": {"total": 1, "warnings": 0, "errors": 0},
				"middlewares": {"total": 0, "warnings": 0, "errors": 0}
			}
		}`

		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want result")
		}

		if v, ok := result.Metadata["http_routers"].(int); !ok || v != 10 {
			t.Errorf("http_routers = %v, want 10", result.Metadata["http_routers"])
		}
		if v, ok := result.Metadata["http_services"].(int); !ok || v != 7 {
			t.Errorf("http_services = %v, want 7", result.Metadata["http_services"])
		}
		if v, ok := result.Metadata["tcp_routers"].(int); !ok || v != 2 {
			t.Errorf("tcp_routers = %v, want 2", result.Metadata["tcp_routers"])
		}
		if v, ok := result.Metadata["udp_routers"].(int); !ok || v != 1 {
			t.Errorf("udp_routers = %v, want 1", result.Metadata["udp_routers"])
		}
	})
}

func TestTraefikOverviewFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "missing tcp key",
			statusCode: 200,
			body: `{
				"http": {"routers": {"total": 5, "warnings": 0, "errors": 0}, "services": {"total": 3, "warnings": 0, "errors": 0}, "middlewares": {"total": 2, "warnings": 0, "errors": 0}},
				"udp": {"routers": {"total": 0, "warnings": 0, "errors": 0}, "services": {"total": 0, "warnings": 0, "errors": 0}, "middlewares": {"total": 0, "warnings": 0, "errors": 0}}
			}`,
		},
		{
			name:       "missing routers sub-key in http",
			statusCode: 200,
			body: `{
				"http": {"services": {"total": 3, "warnings": 0, "errors": 0}, "middlewares": {"total": 2, "warnings": 0, "errors": 0}},
				"tcp": {"routers": {"total": 0, "warnings": 0, "errors": 0}, "services": {"total": 0, "warnings": 0, "errors": 0}, "middlewares": {"total": 0, "warnings": 0, "errors": 0}},
				"udp": {"routers": {"total": 0, "warnings": 0, "errors": 0}, "services": {"total": 0, "warnings": 0, "errors": 0}, "middlewares": {"total": 0, "warnings": 0, "errors": 0}}
			}`,
		},
		{
			name:       "empty JSON object",
			statusCode: 200,
			body:       `{}`,
		},
		{
			name:       "empty body",
			statusCode: 200,
			body:       ``,
		},
		{
			name:       "500 status",
			statusCode: 500,
			body:       validOverviewBody,
		},
		{
			name:       "oversized body",
			statusCode: 200,
			body:       strings.Repeat("x", 1*1024*1024+1),
		},
		{
			name:       "generic JSON with http key but wrong structure",
			statusCode: 200,
			body:       `{"http": {"status": "ok"}, "tcp": {"status": "ok"}, "udp": {"status": "ok"}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TraefikOverviewFingerprinter{}
			resp := makeJSONResponse(tt.statusCode)

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v, want nil", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil for case: %s", result, tt.name)
			}
		})
	}
}

func TestTraefikOverviewFingerprinter_NonJSON_Match(t *testing.T) {
	fp := &TraefikOverviewFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html")

	if got := fp.Match(resp); got {
		t.Error("Match() = true for text/html, want false")
	}
}

func TestTraefikOverviewFingerprinter_DetectionOnlyContract(t *testing.T) {
	fp := &TraefikOverviewFingerprinter{}
	resp := makeJSONResponse(200)

	result, err := fp.Fingerprint(resp, []byte(validOverviewBody))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}

	// Fingerprinter-only ticket: Severity must be unset (empty string).
	if result.Severity != "" {
		t.Errorf("Severity = %q, want empty", result.Severity)
	}
	// No SecurityFindings should be emitted.
	if len(result.SecurityFindings) != 0 {
		t.Errorf("SecurityFindings = %v, want empty", result.SecurityFindings)
	}
}

func TestTraefikOverviewFingerprinter_MetadataFields(t *testing.T) {
	fp := &TraefikOverviewFingerprinter{}
	resp := makeJSONResponse(200)

	result, err := fp.Fingerprint(resp, []byte(validOverviewBody))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}

	if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != "api_overview" {
		t.Errorf("detection_method = %v, want api_overview", result.Metadata["detection_method"])
	}
	// All nine protocol count keys must be present.
	countKeys := []string{
		"http_routers", "http_services", "http_middlewares",
		"tcp_routers", "tcp_services", "tcp_middlewares",
		"udp_routers", "udp_services", "udp_middlewares",
	}
	for _, k := range countKeys {
		if _, ok := result.Metadata[k]; !ok {
			t.Errorf("metadata missing key %q", k)
		}
	}
}

// --- TraefikVersionFingerprinter tests ---

func TestTraefikVersionFingerprinter_Name(t *testing.T) {
	fp := &TraefikVersionFingerprinter{}
	if got := fp.Name(); got != "traefik-api" {
		t.Errorf("Name() = %q, want %q", got, "traefik-api")
	}
}

func TestTraefikVersionFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &TraefikVersionFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/api/version" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/api/version")
	}
}

func TestTraefikVersionFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		want        bool
	}{
		{
			name:        "application/json 200 returns true",
			statusCode:  200,
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "+json vendor type returns true",
			statusCode:  200,
			contentType: "application/vnd.api+json",
			want:        true,
		},
		{
			name:        "text/html returns false",
			statusCode:  200,
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "500 status returns false",
			statusCode:  500,
			contentType: "application/json",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TraefikVersionFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTraefikVersionFingerprinter_Fingerprint_Valid(t *testing.T) {
	t.Run("valid version response detects traefik-api with version and CPE", func(t *testing.T) {
		fp := &TraefikVersionFingerprinter{}
		resp := makeJSONResponse(200)

		result, err := fp.Fingerprint(resp, []byte(validVersionBody))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want result")
		}

		if result.Technology != "traefik-api" {
			t.Errorf("Technology = %q, want %q", result.Technology, "traefik-api")
		}
		if result.Version != "2.6.0" {
			t.Errorf("Version = %q, want %q", result.Version, "2.6.0")
		}
		wantCPE := "cpe:2.3:a:traefik:traefik:2.6.0:*:*:*:*:*:*:*"
		if len(result.CPEs) != 1 || result.CPEs[0] != wantCPE {
			t.Errorf("CPEs = %v, want [%s]", result.CPEs, wantCPE)
		}
	})

	t.Run("version 2.x produces correct CPE", func(t *testing.T) {
		fp := &TraefikVersionFingerprinter{}
		resp := makeJSONResponse(200)
		body := `{"Version": "2.10.4", "Codename": "banon"}`

		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil")
		}
		if result.Version != "2.10.4" {
			t.Errorf("Version = %q, want %q", result.Version, "2.10.4")
		}
		wantCPE := "cpe:2.3:a:traefik:traefik:2.10.4:*:*:*:*:*:*:*"
		if len(result.CPEs) != 1 || result.CPEs[0] != wantCPE {
			t.Errorf("CPEs = %v, want [%s]", result.CPEs, wantCPE)
		}
	})

	t.Run("version 3.x produces correct CPE", func(t *testing.T) {
		fp := &TraefikVersionFingerprinter{}
		resp := makeJSONResponse(200)
		body := `{"Version": "3.1.3", "Codename": "perizia"}`

		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil")
		}
		if result.Version != "3.1.3" {
			t.Errorf("Version = %q, want %q", result.Version, "3.1.3")
		}
		wantCPE := "cpe:2.3:a:traefik:traefik:3.1.3:*:*:*:*:*:*:*"
		if len(result.CPEs) != 1 || result.CPEs[0] != wantCPE {
			t.Errorf("CPEs = %v, want [%s]", result.CPEs, wantCPE)
		}
	})

	t.Run("missing Version field detects but uses wildcard CPE", func(t *testing.T) {
		fp := &TraefikVersionFingerprinter{}
		resp := makeJSONResponse(200)
		body := `{"Codename": "rocamadour"}`

		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want result (Codename is sufficient)")
		}
		if result.Version != "" {
			t.Errorf("Version = %q, want empty string", result.Version)
		}
		wantCPE := "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*"
		if len(result.CPEs) != 1 || result.CPEs[0] != wantCPE {
			t.Errorf("CPEs = %v, want [%s]", result.CPEs, wantCPE)
		}
	})

	t.Run("invalid version format uses wildcard CPE but still detects", func(t *testing.T) {
		fp := &TraefikVersionFingerprinter{}
		resp := makeJSONResponse(200)
		body := `{"Version": "2.6.0-beta1", "Codename": "rocamadour"}`

		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want result")
		}
		if result.Version != "" {
			t.Errorf("Version = %q, want empty (invalid format should not be stored)", result.Version)
		}
		wantCPE := "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*"
		if len(result.CPEs) != 1 || result.CPEs[0] != wantCPE {
			t.Errorf("CPEs = %v, want [%s]", result.CPEs, wantCPE)
		}
	})

	t.Run("CPE injection attempt via Version field uses wildcard", func(t *testing.T) {
		fp := &TraefikVersionFingerprinter{}
		resp := makeJSONResponse(200)
		body := `{"Version": "2.6.0:*:*", "Codename": "rocamadour"}`

		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want result")
		}
		wantCPE := "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*"
		if len(result.CPEs) != 1 || result.CPEs[0] != wantCPE {
			t.Errorf("CPEs = %v, want [%s]", result.CPEs, wantCPE)
		}
		if strings.Contains(result.CPEs[0], "2.6.0:*:*") {
			t.Error("CPE contains injected metacharacters")
		}
	})
}

func TestTraefikVersionFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "missing Codename",
			statusCode: 200,
			body:       `{"Version": "2.6.0"}`,
		},
		{
			name:       "empty JSON object",
			statusCode: 200,
			body:       `{}`,
		},
		{
			name:       "non-JSON body",
			statusCode: 200,
			body:       `Not JSON`,
		},
		{
			name:       "500 status",
			statusCode: 500,
			body:       validVersionBody,
		},
		{
			name:       "oversized body",
			statusCode: 200,
			body:       strings.Repeat("x", 1*1024*1024+1),
		},
		{
			name:       "empty body",
			statusCode: 200,
			body:       ``,
		},
		{
			name:       "generic JSON with Version but no Codename",
			statusCode: 200,
			body:       `{"Version": "2.6.0", "status": "ok", "data": {}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TraefikVersionFingerprinter{}
			resp := makeJSONResponse(tt.statusCode)

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v, want nil", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil for case: %s", result, tt.name)
			}
		})
	}
}

func TestTraefikVersionFingerprinter_CodenameMetadata(t *testing.T) {
	fp := &TraefikVersionFingerprinter{}
	resp := makeJSONResponse(200)

	result, err := fp.Fingerprint(resp, []byte(validVersionBody))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}

	codename, ok := result.Metadata["codename"].(string)
	if !ok || codename != "rocamadour" {
		t.Errorf("codename = %v, want rocamadour", result.Metadata["codename"])
	}
	dm, ok := result.Metadata["detection_method"].(string)
	if !ok || dm != "api_version" {
		t.Errorf("detection_method = %v, want api_version", result.Metadata["detection_method"])
	}
	startDate, ok := result.Metadata["startDate"].(string)
	if !ok || startDate == "" {
		t.Errorf("startDate = %v, want non-empty", result.Metadata["startDate"])
	}
}

func TestTraefikVersionFingerprinter_CodenameControlCharsSanitized(t *testing.T) {
	fp := &TraefikVersionFingerprinter{}
	resp := makeJSONResponse(200)
	body := `{"Version": "3.0.0", "Codename": "evil\u001bname"}`

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}

	codename, ok := result.Metadata["codename"].(string)
	if !ok {
		t.Fatalf("codename metadata is not a string: %T", result.Metadata["codename"])
	}
	for _, r := range codename {
		if r < 0x20 && r != '\t' {
			t.Errorf("codename contains unsanitized control character: U+%04X", r)
		}
	}
}

func TestTraefikVersionFingerprinter_DetectionOnlyContract(t *testing.T) {
	fp := &TraefikVersionFingerprinter{}
	resp := makeJSONResponse(200)

	result, err := fp.Fingerprint(resp, []byte(validVersionBody))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}

	// Fingerprinter-only ticket: Severity must be unset (empty string).
	if result.Severity != "" {
		t.Errorf("Severity = %q, want empty", result.Severity)
	}
	// No SecurityFindings should be emitted.
	if len(result.SecurityFindings) != 0 {
		t.Errorf("SecurityFindings = %v, want empty", result.SecurityFindings)
	}
}

// --- Registration tests ---

func TestTraefikFingerprinters_Registration(t *testing.T) {
	t.Run("traefik-dashboard is registered", func(t *testing.T) {
		fp := GetFingerprinterByName("traefik-dashboard")
		if fp == nil {
			t.Fatal("fingerprinter 'traefik-dashboard' not registered")
		}
	})

	t.Run("traefik-api is registered", func(t *testing.T) {
		fp := GetFingerprinterByName("traefik-api")
		if fp == nil {
			t.Fatal("fingerprinter 'traefik-api' not registered")
		}
	})
}

// --- buildTraefikCPE tests ---

func TestBuildTraefikCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "valid semver version",
			version: "2.6.0",
			want:    "cpe:2.3:a:traefik:traefik:2.6.0:*:*:*:*:*:*:*",
		},
		{
			name:    "valid version 3.x",
			version: "3.1.3",
			want:    "cpe:2.3:a:traefik:traefik:3.1.3:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version with qualifier uses wildcard",
			version: "2.6.0-beta1",
			want:    "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version with colon metacharacter uses wildcard",
			version: "2.6.0:*:*",
			want:    "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version with asterisk metacharacter uses wildcard",
			version: "2.6.0*",
			want:    "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*",
		},
		{
			name:    "version with question mark metacharacter uses wildcard",
			version: "2.6.?",
			want:    "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildTraefikCPE(tt.version); got != tt.want {
				t.Errorf("buildTraefikCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}
