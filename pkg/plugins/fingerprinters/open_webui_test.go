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
	"sort"
	"testing"
)

func TestOpenWebUIFingerprinter_Name(t *testing.T) {
	fp := &OpenWebUIFingerprinter{}
	if got := fp.Name(); got != "open_webui" {
		t.Errorf("Name() = %q, want %q", got, "open_webui")
	}
}

func TestOpenWebUIFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &OpenWebUIFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/api/config" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/api/config")
	}
}

func TestOpenWebUIFingerprinter_Match(t *testing.T) {
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
			fp := &OpenWebUIFingerprinter{}
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

func TestOpenWebUIFingerprinter_Fingerprint(t *testing.T) {
	// validConfigBody is a representative response from /api/config
	const validConfigBody = `{
		"status": true,
		"name": "Open WebUI",
		"version": "0.5.20",
		"default_locale": "en-US",
		"oauth": {"providers": {}},
		"features": {
			"auth": true,
			"auth_trusted_header": false,
			"enable_signup_password_confirmation": false,
			"enable_ldap": false,
			"enable_api_keys": false,
			"enable_signup": true,
			"enable_login_form": true,
			"enable_websocket": true,
			"enable_version_update_check": true,
			"enable_public_active_users_count": false,
			"enable_easter_eggs": false
		}
	}`

	tests := []struct {
		name          string
		body          string
		wantNil       bool
		wantVersion   string
		wantTech      string
		checkMetadata func(t *testing.T, metadata map[string]any)
	}{
		{
			name:        "Valid config response detects with version and metadata",
			body:        validConfigBody,
			wantNil:     false,
			wantVersion: "0.5.20",
			wantTech:    "open_webui",
			checkMetadata: func(t *testing.T, metadata map[string]any) {
				t.Helper()
				if name, ok := metadata["name"].(string); !ok || name != "Open WebUI" {
					t.Errorf("Metadata[name] = %v, want %q", metadata["name"], "Open WebUI")
				}
				if auth, ok := metadata["auth_enabled"].(bool); !ok || !auth {
					t.Errorf("Metadata[auth_enabled] = %v, want true", metadata["auth_enabled"])
				}
				if signup, ok := metadata["signup_enabled"].(bool); !ok || !signup {
					t.Errorf("Metadata[signup_enabled] = %v, want true", metadata["signup_enabled"])
				}
				if loginForm, ok := metadata["login_form"].(bool); !ok || !loginForm {
					t.Errorf("Metadata[login_form] = %v, want true", metadata["login_form"])
				}
				if apiKeys, ok := metadata["api_keys_enabled"].(bool); ok && apiKeys {
					t.Errorf("Metadata[api_keys_enabled] = %v, want false", metadata["api_keys_enabled"])
				}
				if ldap, ok := metadata["ldap_enabled"].(bool); ok && ldap {
					t.Errorf("Metadata[ldap_enabled] = %v, want false", metadata["ldap_enabled"])
				}
				if locale, ok := metadata["default_locale"].(string); !ok || locale != "en-US" {
					t.Errorf("Metadata[default_locale] = %v, want %q", metadata["default_locale"], "en-US")
				}
				// Onboarding should NOT be present when false
				if _, ok := metadata["onboarding"]; ok {
					t.Errorf("Metadata[onboarding] should not be set when false")
				}
			},
		},
		{
			name: "Valid config with onboarding=true sets onboarding metadata",
			body: `{
				"status": true,
				"name": "Open WebUI",
				"version": "0.5.20",
				"default_locale": "en-US",
				"onboarding": true,
				"oauth": {"providers": {}},
				"features": {
					"auth": true,
					"enable_signup": true,
					"enable_login_form": true,
					"enable_api_keys": false,
					"enable_ldap": false
				}
			}`,
			wantNil:     false,
			wantVersion: "0.5.20",
			wantTech:    "open_webui",
			checkMetadata: func(t *testing.T, metadata map[string]any) {
				t.Helper()
				if onboarding, ok := metadata["onboarding"].(bool); !ok || !onboarding {
					t.Errorf("Metadata[onboarding] = %v, want true", metadata["onboarding"])
				}
			},
		},
		{
			name: "Valid config with OAuth providers extracts provider names",
			body: `{
				"status": true,
				"name": "Open WebUI",
				"version": "0.5.20",
				"default_locale": "en-US",
				"oauth": {
					"providers": {
						"google": {},
						"github": {}
					}
				},
				"features": {
					"auth": true,
					"enable_signup": true,
					"enable_login_form": true,
					"enable_api_keys": false,
					"enable_ldap": false
				}
			}`,
			wantNil:     false,
			wantVersion: "0.5.20",
			wantTech:    "open_webui",
			checkMetadata: func(t *testing.T, metadata map[string]any) {
				t.Helper()
				providers, ok := metadata["oauth_providers"].([]string)
				if !ok {
					t.Fatalf("Metadata[oauth_providers] type = %T, want []string", metadata["oauth_providers"])
				}
				if len(providers) != 2 {
					t.Errorf("len(oauth_providers) = %d, want 2", len(providers))
				}
				sort.Strings(providers)
				if providers[0] != "github" || providers[1] != "google" {
					t.Errorf("oauth_providers = %v, want [github google]", providers)
				}
			},
		},
		{
			name: "Custom name (not 'Open WebUI') still detects",
			body: `{
				"status": true,
				"name": "My Company AI",
				"version": "0.5.20",
				"default_locale": "en-US",
				"oauth": {"providers": {}},
				"features": {
					"auth": true,
					"enable_signup": false,
					"enable_login_form": true,
					"enable_api_keys": false,
					"enable_ldap": false
				}
			}`,
			wantNil:     false,
			wantVersion: "0.5.20",
			wantTech:    "open_webui",
			checkMetadata: func(t *testing.T, metadata map[string]any) {
				t.Helper()
				if name, ok := metadata["name"].(string); !ok || name != "My Company AI" {
					t.Errorf("Metadata[name] = %v, want %q", metadata["name"], "My Company AI")
				}
			},
		},
		{
			name: "Missing version returns nil",
			body: `{
				"status": true,
				"name": "Open WebUI",
				"default_locale": "en-US",
				"oauth": {"providers": {}},
				"features": {
					"auth": true,
					"enable_signup": true,
					"enable_login_form": true,
					"enable_api_keys": false,
					"enable_ldap": false
				}
			}`,
			wantNil: true,
		},
		{
			name: "Missing features returns nil",
			body: `{
				"status": true,
				"name": "Open WebUI",
				"version": "0.5.20",
				"default_locale": "en-US",
				"oauth": {"providers": {}}
			}`,
			wantNil: true,
		},
		{
			name: "status=false returns nil",
			body: `{
				"status": false,
				"name": "Open WebUI",
				"version": "0.5.20",
				"default_locale": "en-US",
				"oauth": {"providers": {}},
				"features": {
					"auth": true,
					"enable_signup": true,
					"enable_login_form": true,
					"enable_api_keys": false,
					"enable_ldap": false
				}
			}`,
			wantNil: true,
		},
		{
			name: "Invalid version format (v-prefixed) returns nil",
			body: `{
				"status": true,
				"name": "Open WebUI",
				"version": "v0.5.20",
				"default_locale": "en-US",
				"oauth": {"providers": {}},
				"features": {
					"auth": true,
					"enable_signup": true,
					"enable_login_form": true,
					"enable_api_keys": false,
					"enable_ldap": false
				}
			}`,
			wantNil: true,
		},
		{
			name: "Invalid version format (non-numeric) returns nil",
			body: `{
				"status": true,
				"name": "Open WebUI",
				"version": "abc",
				"default_locale": "en-US",
				"oauth": {"providers": {}},
				"features": {
					"auth": true,
					"enable_signup": true,
					"enable_login_form": true,
					"enable_api_keys": false,
					"enable_ldap": false
				}
			}`,
			wantNil: true,
		},
		{
			name:    "Invalid JSON returns nil",
			body:    `{not valid json`,
			wantNil: true,
		},
		{
			name:    "Empty body returns nil",
			body:    "",
			wantNil: true,
		},
		{
			name:    "Empty JSON object returns nil",
			body:    `{}`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &OpenWebUIFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}

			if tt.wantNil {
				if result != nil {
					t.Errorf("Fingerprint() = %+v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Fingerprint() returned nil, want non-nil result")
			}

			if result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Verify CPE is present and correctly formatted
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			} else {
				expectedCPE := "cpe:2.3:a:openwebui:open_webui:" + tt.wantVersion + ":*:*:*:*:*:*:*"
				if result.CPEs[0] != expectedCPE {
					t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
				}
			}

			if tt.checkMetadata != nil {
				if result.Metadata == nil {
					t.Fatal("Metadata is nil")
				}
				tt.checkMetadata(t, result.Metadata)
			}
		})
	}
}

func TestBuildOpenWebUICPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version 0.5.20",
			version: "0.5.20",
			want:    "cpe:2.3:a:openwebui:open_webui:0.5.20:*:*:*:*:*:*:*",
		},
		{
			name:    "With version 1.0.0",
			version: "1.0.0",
			want:    "cpe:2.3:a:openwebui:open_webui:1.0.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:openwebui:open_webui:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildOpenWebUICPE(tt.version); got != tt.want {
				t.Errorf("buildOpenWebUICPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOpenWebUIFingerprinter_Integration(t *testing.T) {
	// Save and restore global state to prevent test pollution
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &OpenWebUIFingerprinter{}
	Register(fp)

	body := []byte(`{
		"status": true,
		"name": "Open WebUI",
		"version": "0.5.20",
		"default_locale": "en-US",
		"oauth": {"providers": {}},
		"features": {
			"auth": true,
			"auth_trusted_header": false,
			"enable_signup_password_confirmation": false,
			"enable_ldap": false,
			"enable_api_keys": false,
			"enable_signup": true,
			"enable_login_form": true,
			"enable_websocket": true,
			"enable_version_update_check": true,
			"enable_public_active_users_count": false,
			"enable_easter_eggs": false
		}
	}`)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	results := RunFingerprinters(resp, body)

	found := false
	for _, result := range results {
		if result.Technology == "open_webui" {
			found = true
			if result.Version != "0.5.20" {
				t.Errorf("Version = %q, want %q", result.Version, "0.5.20")
			}
		}
	}

	if !found {
		t.Error("OpenWebUIFingerprinter not found in results")
	}
}
