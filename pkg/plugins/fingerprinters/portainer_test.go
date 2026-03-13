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
	"testing"
)

func TestPortainerFingerprinter_Name(t *testing.T) {
	fp := &PortainerFingerprinter{}
	if got := fp.Name(); got != "portainer" {
		t.Errorf("Name() = %q, want %q", got, "portainer")
	}
}

func TestPortainerFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &PortainerFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/api/system/status" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/api/system/status")
	}
}

func TestPortainerFingerprinter_Match(t *testing.T) {
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
			name:        "Content-Type: text/html returns false",
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "No Content-Type header returns false",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PortainerFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
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

func TestPortainerFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantVersion    string
		wantRawVersion string
		wantInstanceID string
	}{
		{
			name: "Standard response (2.21.0)",
			body: `{
				"Version": "2.21.0",
				"InstanceID": "299ab403-70a8-4c05-92f7-bf7a994d50df"
			}`,
			wantVersion:    "2.21.0",
			wantRawVersion: "2.21.0",
			wantInstanceID: "299ab403-70a8-4c05-92f7-bf7a994d50df",
		},
		{
			name: "Older version (2.0.0)",
			body: `{
				"Version": "2.0.0",
				"InstanceID": "abc12345-def6-7890-abcd-ef1234567890"
			}`,
			wantVersion:    "2.0.0",
			wantRawVersion: "2.0.0",
			wantInstanceID: "abc12345-def6-7890-abcd-ef1234567890",
		},
		{
			name: "Latest version (2.39.0)",
			body: `{
				"Version": "2.39.0",
				"InstanceID": "f47ac10b-58cc-4372-a567-0e02b2c3d479"
			}`,
			wantVersion:    "2.39.0",
			wantRawVersion: "2.39.0",
			wantInstanceID: "f47ac10b-58cc-4372-a567-0e02b2c3d479",
		},
		{
			name: "Pre-release version strips suffix for CPE",
			body: `{
				"Version": "2.21.0-alpha",
				"InstanceID": "aaa11111-bb22-cc33-dd44-ee5555555555"
			}`,
			wantVersion:    "2.21.0",
			wantRawVersion: "2.21.0-alpha",
			wantInstanceID: "aaa11111-bb22-cc33-dd44-ee5555555555",
		},
		{
			name: "Build metadata version strips suffix for CPE",
			body: `{
				"Version": "2.21.0+build.123",
				"InstanceID": "bbb22222-cc33-dd44-ee55-ff6666666666"
			}`,
			wantVersion:    "2.21.0",
			wantRawVersion: "2.21.0+build.123",
			wantInstanceID: "bbb22222-cc33-dd44-ee55-ff6666666666",
		},
		{
			name: "Pre-release with rc suffix",
			body: `{
				"Version": "2.22.0-rc1",
				"InstanceID": "ccc33333-dd44-ee55-ff66-001111111111"
			}`,
			wantVersion:    "2.22.0",
			wantRawVersion: "2.22.0-rc1",
			wantInstanceID: "ccc33333-dd44-ee55-ff66-001111111111",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PortainerFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "portainer" {
				t.Errorf("Technology = %q, want %q", result.Technology, "portainer")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check metadata
			if instanceID, ok := result.Metadata["instanceId"].(string); !ok || instanceID != tt.wantInstanceID {
				t.Errorf("Metadata[instanceId] = %v, want %v", result.Metadata["instanceId"], tt.wantInstanceID)
			}
			if rawVersion, ok := result.Metadata["raw_version"].(string); !ok || rawVersion != tt.wantRawVersion {
				t.Errorf("Metadata[raw_version] = %v, want %v", result.Metadata["raw_version"], tt.wantRawVersion)
			}

			// Check CPE uses normalized version
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:portainer:portainer:" + tt.wantVersion + ":*:*:*:*:*:*:*"
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestPortainerFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Non-JSON body",
			body: "OK",
		},
		{
			name: "JSON without Version",
			body: `{"InstanceID": "299ab403-70a8-4c05-92f7-bf7a994d50df"}`,
		},
		{
			name: "JSON without InstanceID",
			body: `{"Version": "2.21.0"}`,
		},
		{
			name: "Empty JSON object",
			body: `{}`,
		},
		{
			name: "Empty string",
			body: "",
		},
		{
			name: "Version with CPE injection attempt (colons)",
			body: `{"Version": "2.0.0:*:*:*:*:*:*:*", "InstanceID": "abc123"}`,
		},
		{
			name: "Non-semver version without digits",
			body: `{"Version": "latest", "InstanceID": "abc123"}`,
		},
		{
			name: "Version with spaces",
			body: `{"Version": "2.21.0 beta", "InstanceID": "abc123"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PortainerFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}

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

func TestBuildPortainerCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "2.21.0",
			want:    "cpe:2.3:a:portainer:portainer:2.21.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:portainer:portainer:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildPortainerCPE(tt.version); got != tt.want {
				t.Errorf("buildPortainerCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPortainerFingerprinter_Integration(t *testing.T) {
	// Clear registry and register only this fingerprinter
	httpFingerprinters = nil
	Register(&PortainerFingerprinter{})

	body := []byte(`{
		"Version": "2.21.0",
		"InstanceID": "299ab403-70a8-4c05-92f7-bf7a994d50df"
	}`)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	results := RunFingerprinters(resp, body)

	found := false
	for _, result := range results {
		if result.Technology == "portainer" {
			found = true
			if result.Version != "2.21.0" {
				t.Errorf("Version = %q, want %q", result.Version, "2.21.0")
			}
		}
	}

	if !found {
		t.Error("PortainerFingerprinter not found in results")
	}
}
