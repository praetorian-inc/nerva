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

/*
Package fingerprinters provides HTTP fingerprinting for Keycloak.

# Detection Strategy

Keycloak is an open-source identity and access management solution. Detection uses
OIDC (OpenID Connect) discovery endpoints:
  - /realms/master/.well-known/openid-configuration (Quarkus distro, KC >= 19)
  - /auth/realms/master/.well-known/openid-configuration (WildFly distro, KC < 19)

Key indicators:
  - issuer field contains "/realms/"
  - grant_types_supported contains OIDC-specific grants

# Version Detection

Version ranges are determined by OIDC feature presence:
  - KC 12+: urn:ietf:params:oauth:grant-type:device_code in grant_types_supported
  - KC 14+: backchannel_authentication_endpoint present (CIBA)
  - KC 17+: dpop_signing_alg_values_supported present (DPoP)
  - KC 19+: No /auth/ prefix (Quarkus distribution)
  - KC 21+: frontchannel_logout_supported = true

# Distribution Detection

  - Quarkus: No /auth/ prefix in issuer (KC >= 19)
  - WildFly: /auth/ prefix in issuer (KC < 19)

# Example Usage

	fp := &KeycloakFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s\n", result.Technology, result.Version)
		}
	}
*/
package fingerprinters

import (
	"encoding/json"
	"net/http"
	"strings"
)

// KeycloakFingerprinter detects Keycloak via OIDC discovery endpoint (Quarkus distro, KC >= 19)
type KeycloakFingerprinter struct{}

// KeycloakWildFlyFingerprinter detects Keycloak via OIDC discovery endpoint (WildFly distro, KC < 19)
type KeycloakWildFlyFingerprinter struct{}

type keycloakOIDCConfig struct {
	Issuer                         string   `json:"issuer"`
	GrantTypesSupported            []string `json:"grant_types_supported"`
	BackchannelAuthEndpoint        string   `json:"backchannel_authentication_endpoint"`
	DPoPSigningAlgValuesSupported  []string `json:"dpop_signing_alg_values_supported"`
	FrontchannelLogoutSupported    bool     `json:"frontchannel_logout_supported"`
}

func init() {
	Register(&KeycloakFingerprinter{})
	Register(&KeycloakWildFlyFingerprinter{})
}

func (f *KeycloakFingerprinter) Name() string {
	return "keycloak"
}

func (f *KeycloakFingerprinter) ProbeEndpoint() string {
	return "/realms/master/.well-known/openid-configuration"
}

func (f *KeycloakFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *KeycloakFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var config keycloakOIDCConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, nil
	}

	// Key indicator: issuer must contain "/realms/"
	if config.Issuer == "" || !strings.Contains(config.Issuer, "/realms/") {
		return nil, nil
	}

	// Detect distribution based on /auth/ prefix
	distribution := "quarkus"
	if strings.Contains(config.Issuer, "/auth/realms/") {
		distribution = "wildfly"
	}

	// Detect version based on features
	version, features := detectKeycloakVersion(config, distribution)

	metadata := map[string]any{
		"distribution":     distribution,
		"detected_features": features,
	}

	return &FingerprintResult{
		Technology: "keycloak",
		Version:    version,
		CPEs:       []string{buildKeycloakCPE(version)},
		Metadata:   metadata,
	}, nil
}

// detectKeycloakVersion determines version range based on OIDC features
func detectKeycloakVersion(config keycloakOIDCConfig, distribution string) (string, []string) {
	var features []string

	// Check for device code flow (KC 12+)
	hasDeviceCode := false
	for _, grant := range config.GrantTypesSupported {
		if grant == "urn:ietf:params:oauth:grant-type:device_code" {
			hasDeviceCode = true
			features = append(features, "device_code")
			break
		}
	}

	// Check for CIBA (KC 14+)
	hasCIBA := config.BackchannelAuthEndpoint != ""
	if hasCIBA {
		features = append(features, "ciba")
	}

	// Check for DPoP (KC 17+)
	hasDPoP := len(config.DPoPSigningAlgValuesSupported) > 0
	if hasDPoP {
		features = append(features, "dpop")
	}

	// Check for frontchannel logout (KC 21+)
	hasFrontchannelLogout := config.FrontchannelLogoutSupported
	if hasFrontchannelLogout {
		features = append(features, "frontchannel_logout")
	}

	// Determine version range
	if hasFrontchannelLogout {
		return ">=21", features
	}
	if hasDPoP && distribution == "quarkus" {
		return ">=19,<21", features
	}
	if hasDPoP {
		return ">=17,<19", features
	}
	if hasCIBA {
		return ">=14,<17", features
	}
	if hasDeviceCode {
		return ">=12,<14", features
	}
	return "<12", features
}

// buildKeycloakCPE generates a CPE (Common Platform Enumeration) string for Keycloak.
// CPE format: cpe:2.3:a:redhat:keycloak:{version}:*:*:*:*:*:*:*
//
// Since we return version ranges (e.g., ">=19,<21"), we use "*" for the version field
// to enable asset inventory use cases while still providing version information in the
// Version field.
func buildKeycloakCPE(version string) string {
	// Always use "*" since we return version ranges, not exact versions
	return "cpe:2.3:a:redhat:keycloak:*:*:*:*:*:*:*:*"
}

// KeycloakWildFlyFingerprinter methods

func (f *KeycloakWildFlyFingerprinter) Name() string {
	return "keycloak-wildfly"
}

func (f *KeycloakWildFlyFingerprinter) ProbeEndpoint() string {
	return "/auth/realms/master/.well-known/openid-configuration"
}

func (f *KeycloakWildFlyFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *KeycloakWildFlyFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var config keycloakOIDCConfig
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, nil
	}

	// Key indicator: issuer must contain "/realms/"
	if config.Issuer == "" || !strings.Contains(config.Issuer, "/realms/") {
		return nil, nil
	}

	// Detect distribution based on /auth/ prefix
	distribution := "quarkus"
	if strings.Contains(config.Issuer, "/auth/realms/") {
		distribution = "wildfly"
	}

	// Detect version based on features
	version, features := detectKeycloakVersion(config, distribution)

	metadata := map[string]any{
		"distribution":     distribution,
		"detected_features": features,
	}

	return &FingerprintResult{
		Technology: "keycloak",
		Version:    version,
		CPEs:       []string{buildKeycloakCPE(version)},
		Metadata:   metadata,
	}, nil
}
