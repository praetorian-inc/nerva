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
)

// -- Name / ProbeEndpoint --

func TestQuestKACEFingerprinter_Name(t *testing.T) {
	fp := &QuestKACEFingerprinter{}
	if got := fp.Name(); got != "quest-kace" {
		t.Errorf("Name() = %q, want %q", got, "quest-kace")
	}
}

func TestQuestKACEFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &QuestKACEFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/admin" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/admin")
	}
}

// -- Match --

func TestQuestKACEFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{name: "200 OK passes", statusCode: 200, want: true},
		{name: "302 redirect passes", statusCode: 302, want: true},
		{name: "404 passes", statusCode: 404, want: true},
		{name: "499 passes (upper boundary)", statusCode: 499, want: true},
		{name: "100 rejected", statusCode: 100, want: false},
		{name: "500 rejected", statusCode: 500, want: false},
		{name: "503 rejected", statusCode: 503, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &QuestKACEFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// -- Fingerprint: positive --

func TestQuestKACEFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		headers       map[string]string
		body          string
		probePath     string
		wantVersion   string
		wantCPE       string
		wantDetection string
	}{
		{
			name:          "X-KACE-Version header with version",
			statusCode:    200,
			headers:       map[string]string{"X-KACE-Version": "14.1.101"},
			wantVersion:   "14.1.101",
			wantCPE:       "cpe:2.3:a:quest:kace_systems_management_appliance:14.1.101:*:*:*:*:*:*:*",
			wantDetection: "kace_version_header",
		},
		{
			name:          "X-KACE-Appliance header alone",
			statusCode:    200,
			headers:       map[string]string{"X-KACE-Appliance": "1"},
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:quest:kace_systems_management_appliance:*:*:*:*:*:*:*:*",
			wantDetection: "kace_appliance_header",
		},
		{
			name:          "Title brand in body",
			statusCode:    200,
			body:          "<html><head><title>KACE Systems Management Appliance</title></head></html>",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:quest:kace_systems_management_appliance:*:*:*:*:*:*:*:*",
			wantDetection: "title",
		},
		{
			name:          "Case-insensitive title detection",
			statusCode:    200,
			body:          "<html><head><title>kace systems management appliance</title></head></html>",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:quest:kace_systems_management_appliance:*:*:*:*:*:*:*:*",
			wantDetection: "title",
		},
		{
			name:          "Priority: kace_version_header beats kace_appliance_header",
			statusCode:    200,
			headers:       map[string]string{"X-KACE-Version": "8.0.318", "X-KACE-Appliance": "1"},
			wantVersion:   "8.0.318",
			wantCPE:       "cpe:2.3:a:quest:kace_systems_management_appliance:8.0.318:*:*:*:*:*:*:*",
			wantDetection: "kace_version_header",
		},
		{
			name:          "Priority: kace_appliance_header beats title",
			statusCode:    200,
			headers:       map[string]string{"X-KACE-Appliance": "1"},
			body:          "<html><head><title>KACE Systems Management Appliance</title></head></html>",
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:quest:kace_systems_management_appliance:*:*:*:*:*:*:*:*",
			wantDetection: "kace_appliance_header",
		},
		{
			name:          "Priority: kace_version_header beats title",
			statusCode:    302,
			headers:       map[string]string{"X-KACE-Version": "13.0.385"},
			body:          "<html><head><title>KACE Systems Management Appliance</title></head></html>",
			wantVersion:   "13.0.385",
			wantCPE:       "cpe:2.3:a:quest:kace_systems_management_appliance:13.0.385:*:*:*:*:*:*:*",
			wantDetection: "kace_version_header",
		},
		{
			name:          "Four-segment version accepted",
			statusCode:    200,
			headers:       map[string]string{"X-KACE-Version": "6.4.120822.0"},
			wantVersion:   "6.4.120822.0",
			wantCPE:       "cpe:2.3:a:quest:kace_systems_management_appliance:6.4.120822.0:*:*:*:*:*:*:*",
			wantDetection: "kace_version_header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &QuestKACEFingerprinter{}
			header := make(http.Header)
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{StatusCode: tt.statusCode, Header: header}
			if tt.probePath != "" {
				resp.Request = &http.Request{URL: &url.URL{Path: tt.probePath}}
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want non-nil")
			}
			if result.Technology != "quest-kace-sma" {
				t.Errorf("Technology = %q, want quest-kace-sma", result.Technology)
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			} else if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], tt.wantCPE)
			}
			if result.Metadata == nil {
				t.Fatal("Metadata is nil")
			}
			if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != tt.wantDetection {
				t.Errorf("Metadata[detection_method] = %v, want %q", result.Metadata["detection_method"], tt.wantDetection)
			}
		})
	}
}

// -- Fingerprint: negative --

func TestQuestKACEFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		headers    map[string]string
		body       string
	}{
		{name: "Generic nginx page", statusCode: 200, body: "<html><title>Welcome to nginx</title></html>"},
		{name: "No KACE signals", statusCode: 200, body: "<html><title>Login</title></html>"},
		{name: "CPE-injection attempt", statusCode: 200, headers: map[string]string{"X-KACE-Version": "14.1.101"}, body: "<html>:*:malicious</html>"},
		{name: "Body > 2 MiB rejected", statusCode: 200, body: "<title>KACE Systems Management Appliance</title>" + string(make([]byte, 2*1024*1024+1))},
		{name: "Status 500 rejected", statusCode: 500, headers: map[string]string{"X-KACE-Version": "14.1.101"}},
		{name: "Status 199 rejected", statusCode: 199, headers: map[string]string{"X-KACE-Version": "14.1.101"}},
		{name: "Invalid version format rejected", statusCode: 200, headers: map[string]string{"X-KACE-Version": "abc.def.ghi"}},
		{name: "Empty body no headers", statusCode: 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &QuestKACEFingerprinter{}
			header := make(http.Header)
			for k, v := range tt.headers {
				header.Set(k, v)
			}
			resp := &http.Response{StatusCode: tt.statusCode, Header: header}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

// -- Invalid version still detects but with empty version --

func TestQuestKACEFingerprinter_InvalidVersionHeaderStillDetects(t *testing.T) {
	fp := &QuestKACEFingerprinter{}
	header := make(http.Header)
	header.Set("X-KACE-Version", "abc.def")
	header.Set("X-KACE-Appliance", "1")
	resp := &http.Response{StatusCode: 200, Header: header}

	result, err := fp.Fingerprint(resp, []byte("<html></html>"))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want non-nil (X-KACE-Appliance still present)")
	}
	if result.Version != "" {
		t.Errorf("Version = %q, want empty (invalid format)", result.Version)
	}
	if result.CPEs[0] != "cpe:2.3:a:quest:kace_systems_management_appliance:*:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q, want wildcard", result.CPEs[0])
	}
}

// -- buildQuestKACECPE --

func TestBuildQuestKACECPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{name: "Version 14.1.101", version: "14.1.101", want: "cpe:2.3:a:quest:kace_systems_management_appliance:14.1.101:*:*:*:*:*:*:*"},
		{name: "Version 8.0.318", version: "8.0.318", want: "cpe:2.3:a:quest:kace_systems_management_appliance:8.0.318:*:*:*:*:*:*:*"},
		{name: "Empty version uses wildcard", version: "", want: "cpe:2.3:a:quest:kace_systems_management_appliance:*:*:*:*:*:*:*:*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildQuestKACECPE(tt.version); got != tt.want {
				t.Errorf("buildQuestKACECPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// -- Integration --

func TestQuestKACEFingerprinter_Integration(t *testing.T) {
	fp := &QuestKACEFingerprinter{}

	header := make(http.Header)
	header.Set("X-KACE-Version", "14.1.101")
	header.Set("X-KACE-Appliance", "1")
	resp := &http.Response{StatusCode: 200, Header: header}
	body := []byte(`<html><head><title>KACE Systems Management Appliance</title></head><body></body></html>`)

	if !fp.Match(resp) {
		t.Fatal("Match() returned false, want true")
	}
	result, err := fp.Fingerprint(resp, body)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}
	if result.Technology != "quest-kace-sma" {
		t.Errorf("Technology = %q, want quest-kace-sma", result.Technology)
	}
	if result.Version != "14.1.101" {
		t.Errorf("Version = %q, want 14.1.101", result.Version)
	}
	if len(result.CPEs) == 0 {
		t.Error("Expected at least one CPE")
	} else if result.CPEs[0] != "cpe:2.3:a:quest:kace_systems_management_appliance:14.1.101:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q, want canonical CPE", result.CPEs[0])
	}
	if v, ok := result.Metadata["vendor"].(string); !ok || v != "Quest" {
		t.Errorf("Metadata[vendor] = %v, want Quest", result.Metadata["vendor"])
	}
	if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != "kace_version_header" {
		t.Errorf("Metadata[detection_method] = %v, want kace_version_header", result.Metadata["detection_method"])
	}
}
