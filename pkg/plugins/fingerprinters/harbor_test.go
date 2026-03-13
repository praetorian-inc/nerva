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

func TestHarborFingerprinter_Name(t *testing.T) {
	fp := &HarborFingerprinter{}
	if got := fp.Name(); got != "harbor" {
		t.Errorf("Name() = %q, want %q", got, "harbor")
	}
}

func TestHarborFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &HarborFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/api/v2.0/systeminfo" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/api/v2.0/systeminfo")
	}
}

func TestHarborFingerprinter_Match(t *testing.T) {
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
			fp := &HarborFingerprinter{}
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

func TestHarborFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name                   string
		body                   string
		wantVersion            string
		wantAuthMode           string
		wantSelfRegistration   bool
		wantPrimaryAuthMode    bool
		wantRegistryURLPresent bool
		wantExternalURLPresent bool
	}{
		{
			name: "Unauthenticated response (auth_mode and self_registration only, no version)",
			body: `{
				"auth_mode": "db_auth",
				"primary_auth_mode": false,
				"self_registration": true
			}`,
			wantVersion:          "",
			wantAuthMode:         "db_auth",
			wantSelfRegistration: true,
			wantPrimaryAuthMode:  false,
		},
		{
			name: "Authenticated response with harbor_version 2.10.0",
			body: `{
				"auth_mode": "db_auth",
				"primary_auth_mode": false,
				"self_registration": false,
				"harbor_version": "v2.10.0"
			}`,
			wantVersion:          "2.10.0",
			wantAuthMode:         "db_auth",
			wantSelfRegistration: false,
			wantPrimaryAuthMode:  false,
		},
		{
			name: "LDAP auth mode",
			body: `{
				"auth_mode": "ldap_auth",
				"primary_auth_mode": true,
				"self_registration": false
			}`,
			wantVersion:          "",
			wantAuthMode:         "ldap_auth",
			wantSelfRegistration: false,
			wantPrimaryAuthMode:  true,
		},
		{
			name: "OIDC auth mode",
			body: `{
				"auth_mode": "oidc_auth",
				"primary_auth_mode": false,
				"self_registration": false
			}`,
			wantVersion:          "",
			wantAuthMode:         "oidc_auth",
			wantSelfRegistration: false,
			wantPrimaryAuthMode:  false,
		},
		{
			name: "UAA auth mode",
			body: `{
				"auth_mode": "uaa_auth",
				"primary_auth_mode": false,
				"self_registration": false
			}`,
			wantVersion:          "",
			wantAuthMode:         "uaa_auth",
			wantSelfRegistration: false,
			wantPrimaryAuthMode:  false,
		},
		{
			name: "HTTP auth mode",
			body: `{
				"auth_mode": "http_auth",
				"primary_auth_mode": true,
				"self_registration": false
			}`,
			wantVersion:          "",
			wantAuthMode:         "http_auth",
			wantSelfRegistration: false,
			wantPrimaryAuthMode:  true,
		},
		{
			name: "With registry_url and external_url",
			body: `{
				"auth_mode": "db_auth",
				"primary_auth_mode": false,
				"self_registration": true,
				"harbor_version": "v2.10.0",
				"registry_url": "harbor.example.com",
				"external_url": "https://harbor.example.com"
			}`,
			wantVersion:            "2.10.0",
			wantAuthMode:           "db_auth",
			wantSelfRegistration:   true,
			wantPrimaryAuthMode:    false,
			wantRegistryURLPresent: true,
			wantExternalURLPresent: true,
		},
		{
			name: "Release candidate version 2.11.0-rc1",
			body: `{
				"auth_mode": "db_auth",
				"primary_auth_mode": false,
				"self_registration": false,
				"harbor_version": "v2.11.0-rc1"
			}`,
			wantVersion:          "2.11.0-rc1",
			wantAuthMode:         "db_auth",
			wantSelfRegistration: false,
			wantPrimaryAuthMode:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HarborFingerprinter{}
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

			if result.Technology != "harbor" {
				t.Errorf("Technology = %q, want %q", result.Technology, "harbor")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check required metadata fields
			if authMode, ok := result.Metadata["authMode"].(string); !ok || authMode != tt.wantAuthMode {
				t.Errorf("Metadata[authMode] = %v, want %v", result.Metadata["authMode"], tt.wantAuthMode)
			}
			if selfReg, ok := result.Metadata["selfRegistration"].(bool); !ok || selfReg != tt.wantSelfRegistration {
				t.Errorf("Metadata[selfRegistration] = %v, want %v", result.Metadata["selfRegistration"], tt.wantSelfRegistration)
			}
			if primaryAuth, ok := result.Metadata["primaryAuthMode"].(bool); !ok || primaryAuth != tt.wantPrimaryAuthMode {
				t.Errorf("Metadata[primaryAuthMode] = %v, want %v", result.Metadata["primaryAuthMode"], tt.wantPrimaryAuthMode)
			}

			// Check optional metadata fields
			if tt.wantRegistryURLPresent {
				if _, ok := result.Metadata["registryUrl"]; !ok {
					t.Error("Expected registryUrl in metadata, but it's missing")
				}
			} else {
				if _, ok := result.Metadata["registryUrl"]; ok {
					t.Error("Expected no registryUrl in metadata, but it exists")
				}
			}

			if tt.wantExternalURLPresent {
				if _, ok := result.Metadata["externalUrl"]; !ok {
					t.Error("Expected externalUrl in metadata, but it's missing")
				}
			} else {
				if _, ok := result.Metadata["externalUrl"]; ok {
					t.Error("Expected no externalUrl in metadata, but it exists")
				}
			}

			// Check CPE value
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			wantVersion := tt.wantVersion
			if wantVersion == "" {
				wantVersion = "*"
			}
			expectedCPE := "cpe:2.3:a:goharbor:harbor:" + wantVersion + ":*:*:*:*:*:*:*"
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestHarborFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Non-JSON body",
			body: "OK",
		},
		{
			name: "JSON without auth_mode",
			body: `{"self_registration": true, "primary_auth_mode": false}`,
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
			name: "Unknown auth_mode value (false positive prevention)",
			body: `{"auth_mode": "custom_auth", "self_registration": true, "primary_auth_mode": false}`,
		},
		{
			name: "Version with CPE injection attempt",
			body: `{"auth_mode": "db_auth", "self_registration": false, "primary_auth_mode": false, "harbor_version": "v2.0.0:*:*:*:*:*:*:*"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HarborFingerprinter{}
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

func TestBuildHarborCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "2.10.0",
			want:    "cpe:2.3:a:goharbor:harbor:2.10.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:goharbor:harbor:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildHarborCPE(tt.version); got != tt.want {
				t.Errorf("buildHarborCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestHarborFingerprinter_Integration(t *testing.T) {
	// Clear registry
	httpFingerprinters = nil

	// Register should work via init() but test explicitly
	fp := &HarborFingerprinter{}
	Register(fp)

	// Create a valid Harbor systeminfo response
	body := []byte(`{
		"auth_mode": "db_auth",
		"primary_auth_mode": false,
		"self_registration": true,
		"harbor_version": "v2.10.0"
	}`)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	results := RunFingerprinters(resp, body)

	// Should find at least the Harbor fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "harbor" {
			found = true
			if result.Version != "2.10.0" {
				t.Errorf("Version = %q, want %q", result.Version, "2.10.0")
			}
		}
	}

	if !found {
		t.Error("HarborFingerprinter not found in results")
	}
}
