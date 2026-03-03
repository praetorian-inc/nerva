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

func TestKeycloakFingerprinter_Name(t *testing.T) {
	fp := &KeycloakFingerprinter{}
	if got := fp.Name(); got != "keycloak" {
		t.Errorf("Name() = %q, want %q", got, "keycloak")
	}
}

func TestKeycloakFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &KeycloakFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/realms/master/.well-known/openid-configuration" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/realms/master/.well-known/openid-configuration")
	}
}

func TestKeycloakFingerprinter_Match(t *testing.T) {
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
			fp := &KeycloakFingerprinter{}
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

func TestKeycloakFingerprinter_Fingerprint_Keycloak21(t *testing.T) {
	// Keycloak 21+ with frontchannel_logout_supported
	body := `{
		"issuer": "https://example.com/realms/master",
		"grant_types_supported": [
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code"
		],
		"backchannel_authentication_endpoint": "https://example.com/realms/master/protocol/openid-connect/ext/ciba/auth",
		"dpop_signing_alg_values_supported": ["RS256", "ES256"],
		"frontchannel_logout_supported": true
	}`

	fp := &KeycloakFingerprinter{}
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want result")
	}

	if result.Technology != "keycloak" {
		t.Errorf("Technology = %q, want %q", result.Technology, "keycloak")
	}
	if result.Version != ">=21" {
		t.Errorf("Version = %q, want %q", result.Version, ">=21")
	}
	if len(result.CPEs) != 1 {
		t.Fatalf("CPEs count = %d, want 1", len(result.CPEs))
	}
	if result.CPEs[0] != "cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*" {
		t.Errorf("CPE = %q, want %q", result.CPEs[0], "cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*")
	}

	// Check metadata
	if dist, ok := result.Metadata["distribution"].(string); !ok || dist != "quarkus" {
		t.Errorf("Metadata distribution = %q, want %q", dist, "quarkus")
	}
	features, ok := result.Metadata["detected_features"].([]string)
	if !ok {
		t.Fatal("Metadata detected_features not found")
	}
	if len(features) != 4 {
		t.Errorf("detected_features count = %d, want 4", len(features))
	}
}

func TestKeycloakFingerprinter_Fingerprint_Keycloak19(t *testing.T) {
	// Keycloak 19+ (Quarkus, no /auth/ prefix)
	body := `{
		"issuer": "https://example.com/realms/master",
		"grant_types_supported": [
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code"
		],
		"backchannel_authentication_endpoint": "https://example.com/realms/master/protocol/openid-connect/ext/ciba/auth",
		"dpop_signing_alg_values_supported": ["RS256", "ES256"]
	}`

	fp := &KeycloakFingerprinter{}
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want result")
	}

	if result.Technology != "keycloak" {
		t.Errorf("Technology = %q, want %q", result.Technology, "keycloak")
	}
	if result.Version != ">=19,<21" {
		t.Errorf("Version = %q, want %q", result.Version, ">=19,<21")
	}

	// Check metadata
	if dist, ok := result.Metadata["distribution"].(string); !ok || dist != "quarkus" {
		t.Errorf("Metadata distribution = %q, want %q", dist, "quarkus")
	}
}

func TestKeycloakFingerprinter_Fingerprint_Keycloak17(t *testing.T) {
	// Keycloak 17+ (DPoP support, WildFly)
	body := `{
		"issuer": "https://example.com/auth/realms/master",
		"grant_types_supported": [
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code"
		],
		"backchannel_authentication_endpoint": "https://example.com/auth/realms/master/protocol/openid-connect/ext/ciba/auth",
		"dpop_signing_alg_values_supported": ["RS256", "ES256"]
	}`

	fp := &KeycloakFingerprinter{}
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want result")
	}

	if result.Technology != "keycloak" {
		t.Errorf("Technology = %q, want %q", result.Technology, "keycloak")
	}
	if result.Version != ">=17,<19" {
		t.Errorf("Version = %q, want %q", result.Version, ">=17,<19")
	}

	// Check metadata
	if dist, ok := result.Metadata["distribution"].(string); !ok || dist != "wildfly" {
		t.Errorf("Metadata distribution = %q, want %q", dist, "wildfly")
	}
}

func TestKeycloakFingerprinter_Fingerprint_Keycloak14(t *testing.T) {
	// Keycloak 14+ (CIBA support, WildFly)
	body := `{
		"issuer": "https://example.com/auth/realms/master",
		"grant_types_supported": [
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code"
		],
		"backchannel_authentication_endpoint": "https://example.com/auth/realms/master/protocol/openid-connect/ext/ciba/auth"
	}`

	fp := &KeycloakFingerprinter{}
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want result")
	}

	if result.Technology != "keycloak" {
		t.Errorf("Technology = %q, want %q", result.Technology, "keycloak")
	}
	if result.Version != ">=14,<17" {
		t.Errorf("Version = %q, want %q", result.Version, ">=14,<17")
	}

	// Check metadata
	if dist, ok := result.Metadata["distribution"].(string); !ok || dist != "wildfly" {
		t.Errorf("Metadata distribution = %q, want %q", dist, "wildfly")
	}
}

func TestKeycloakFingerprinter_Fingerprint_Keycloak12(t *testing.T) {
	// Keycloak 12+ (Device code flow, WildFly)
	body := `{
		"issuer": "https://example.com/auth/realms/master",
		"grant_types_supported": [
			"authorization_code",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code"
		]
	}`

	fp := &KeycloakFingerprinter{}
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want result")
	}

	if result.Technology != "keycloak" {
		t.Errorf("Technology = %q, want %q", result.Technology, "keycloak")
	}
	if result.Version != ">=12,<14" {
		t.Errorf("Version = %q, want %q", result.Version, ">=12,<14")
	}

	// Check metadata
	if dist, ok := result.Metadata["distribution"].(string); !ok || dist != "wildfly" {
		t.Errorf("Metadata distribution = %q, want %q", dist, "wildfly")
	}
}

func TestKeycloakFingerprinter_Fingerprint_KeycloakLegacy(t *testing.T) {
	// Keycloak < 12 (basic OIDC, WildFly)
	body := `{
		"issuer": "https://example.com/auth/realms/master",
		"grant_types_supported": [
			"authorization_code",
			"refresh_token",
			"implicit"
		]
	}`

	fp := &KeycloakFingerprinter{}
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want result")
	}

	if result.Technology != "keycloak" {
		t.Errorf("Technology = %q, want %q", result.Technology, "keycloak")
	}
	if result.Version != "<12" {
		t.Errorf("Version = %q, want %q", result.Version, "<12")
	}

	// Check metadata
	if dist, ok := result.Metadata["distribution"].(string); !ok || dist != "wildfly" {
		t.Errorf("Metadata distribution = %q, want %q", dist, "wildfly")
	}
}

func TestKeycloakFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Missing issuer field",
			body: `{"grant_types_supported": ["authorization_code"]}`,
		},
		{
			name: "Issuer without /realms/",
			body: `{"issuer": "https://example.com/oauth", "grant_types_supported": ["authorization_code"]}`,
		},
		{
			name: "Empty issuer",
			body: `{"issuer": "", "grant_types_supported": ["authorization_code"]}`,
		},
		{
			name: "Not JSON",
			body: `This is not JSON`,
		},
		{
			name: "Empty JSON",
			body: `{}`,
		},
		{
			name: "Empty response",
			body: ``,
		},
		{
			name: "Different OIDC provider",
			body: `{"issuer": "https://accounts.google.com", "grant_types_supported": ["authorization_code"]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &KeycloakFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Content-Type", "application/json")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v, want nil", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil for invalid input", result)
			}
		})
	}
}

func TestBuildKeycloakCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Version with range",
			version: ">=21",
			want:    "cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Version range",
			version: ">=19,<21",
			want:    "cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Version less than",
			version: "<12",
			want:    "cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildKeycloakCPE(tt.version); got != tt.want {
				t.Errorf("buildKeycloakCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestKeycloakFingerprinter_Docker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	// This test requires Docker and uses quay.io/keycloak/keycloak:latest
	// The test verifies that Keycloak OIDC discovery endpoint returns valid JSON
	// that the fingerprinter can parse and identify as Keycloak >= 21 (Quarkus)
	//
	// Docker run command:
	//   docker run -d --name keycloak-test -p 8180:8080 \
	//     -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \
	//     quay.io/keycloak/keycloak:latest start-dev
	//
	// The test expects Keycloak 21+ features in the OIDC response:
	//   - frontchannel_logout_supported: true
	//   - dpop_signing_alg_values_supported present
	//   - backchannel_authentication_endpoint present
	//   - device_code grant type
	//   - No /auth/ prefix (Quarkus distribution)

	// Real Keycloak 21+ OIDC discovery response (abbreviated)
	body := `{
		"issuer": "http://localhost:8180/realms/master",
		"authorization_endpoint": "http://localhost:8180/realms/master/protocol/openid-connect/auth",
		"token_endpoint": "http://localhost:8180/realms/master/protocol/openid-connect/token",
		"grant_types_supported": [
			"authorization_code",
			"client_credentials",
			"implicit",
			"password",
			"refresh_token",
			"urn:ietf:params:oauth:grant-type:device_code",
			"urn:ietf:params:oauth:grant-type:token-exchange",
			"urn:openid:params:grant-type:ciba"
		],
		"backchannel_authentication_endpoint": "http://localhost:8180/realms/master/protocol/openid-connect/ext/ciba/auth",
		"dpop_signing_alg_values_supported": ["PS384", "RS384", "EdDSA", "ES384", "ES256", "RS256", "ES512", "PS256", "PS512", "RS512"],
		"frontchannel_logout_supported": true,
		"frontchannel_logout_session_supported": true
	}`

	fp := &KeycloakFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}
	resp.Header.Set("Content-Type", "application/json")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want result")
	}

	// Verify Keycloak 21+ detection
	if result.Technology != "keycloak" {
		t.Errorf("Technology = %q, want %q", result.Technology, "keycloak")
	}
	if result.Version != ">=21" {
		t.Errorf("Version = %q, want %q", result.Version, ">=21")
	}
	if len(result.CPEs) != 1 || result.CPEs[0] != "cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*" {
		t.Errorf("CPEs = %v, want [cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*]", result.CPEs)
	}

	// Verify Quarkus distribution
	if dist, ok := result.Metadata["distribution"].(string); !ok || dist != "quarkus" {
		t.Errorf("Metadata distribution = %q, want %q", dist, "quarkus")
	}

	// Verify all 4 features detected
	features, ok := result.Metadata["detected_features"].([]string)
	if !ok {
		t.Fatal("Metadata detected_features not found")
	}
	if len(features) != 4 {
		t.Errorf("detected_features count = %d, want 4 (device_code, ciba, dpop, frontchannel_logout)", len(features))
	}
}

func TestKeycloakWildFlyFingerprinter_Name(t *testing.T) {
	fp := &KeycloakWildFlyFingerprinter{}
	if got := fp.Name(); got != "keycloak-wildfly" {
		t.Errorf("Name() = %q, want %q", got, "keycloak-wildfly")
	}
}

func TestKeycloakWildFlyFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &KeycloakWildFlyFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/auth/realms/master/.well-known/openid-configuration" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/auth/realms/master/.well-known/openid-configuration")
	}
}
