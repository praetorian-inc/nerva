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
Package fingerprinters provides HTTP fingerprinting for Open WebUI.

# Detection Strategy

Open WebUI is an open-source self-hosted web interface for interacting with LLM
backends (Ollama, OpenAI-compatible APIs). Exposed instances represent security
concerns due to:
  - Unrestricted access to AI model inference capabilities
  - Potential exposure of API keys and backend credentials
  - User data and conversation history exposure
  - Onboarding mode allows unauthenticated first-user account creation
  - Often deployed with default configurations lacking proper access control

Detection uses active probing:
  - Active: Query /api/config endpoint (no authentication required)
  - Response must contain status=true, version, and features fields

# API Response Format

The /api/config endpoint returns JSON without authentication:

	{
	  "status": true,
	  "name": "Open WebUI",
	  "version": "0.5.20",
	  "default_locale": "en-US",
	  "oauth": {"providers": {}},
	  "features": {
	    "auth": true,
	    "auth_trusted_header": false,
	    "enable_signup": true,
	    "enable_login_form": true,
	    "enable_api_keys": false,
	    "enable_ldap": false,
	    "enable_websocket": true
	  }
	}

When no users exist (onboarding mode), an additional field is present:

	"onboarding": true

# Port Configuration

Open WebUI typically runs on:
  - 3000: Default Open WebUI HTTP port
  - 8080: Alternative port
  - 443:  HTTPS in production

# Example Usage

	fp := &OpenWebUIFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s\n", result.Technology, result.Version)
			if onboarding, ok := result.Metadata["onboarding"].(bool); ok && onboarding {
				fmt.Println("WARNING: Instance in onboarding mode - no users configured")
			}
		}
	}
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// OpenWebUIFingerprinter detects Open WebUI instances via /api/config endpoint
type OpenWebUIFingerprinter struct{}

// openWebUIConfigResponse represents the JSON structure from /api/config
type openWebUIConfigResponse struct {
	Status        bool                   `json:"status"`
	Name          string                 `json:"name"`
	Version       string                 `json:"version"`
	DefaultLocale string                 `json:"default_locale"`
	Onboarding    bool                   `json:"onboarding"`
	OAuth         *openWebUIOAuth        `json:"oauth"`
	Features      *openWebUIFeatures     `json:"features"`
}

// openWebUIOAuth represents the OAuth configuration block
type openWebUIOAuth struct {
	Providers map[string]any `json:"providers"`
}

// openWebUIFeatures represents the features block distinctive to Open WebUI
type openWebUIFeatures struct {
	Auth                              bool `json:"auth"`
	AuthTrustedHeader                 bool `json:"auth_trusted_header"`
	EnableSignupPasswordConfirmation  bool `json:"enable_signup_password_confirmation"`
	EnableLDAP                        bool `json:"enable_ldap"`
	EnableAPIKeys                     bool `json:"enable_api_keys"`
	EnableSignup                      bool `json:"enable_signup"`
	EnableLoginForm                   bool `json:"enable_login_form"`
	EnableWebsocket                   bool `json:"enable_websocket"`
	EnableVersionUpdateCheck          bool `json:"enable_version_update_check"`
	EnablePublicActiveUsersCount      bool `json:"enable_public_active_users_count"`
	EnableEasterEggs                  bool `json:"enable_easter_eggs"`
}

// openWebUIVersionRegex validates Open WebUI version format for CPE safety.
// Accepts: 0.5.20, 1.0.0, etc. (strict semantic versioning with exactly 3 components)
// Rejects: v-prefixed versions (v0.5.20), pre-release tags, and any characters
// that could enable CPE injection attacks.
var openWebUIVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&OpenWebUIFingerprinter{})
}

func (f *OpenWebUIFingerprinter) Name() string {
	return "open_webui"
}

func (f *OpenWebUIFingerprinter) ProbeEndpoint() string {
	return "/api/config"
}

func (f *OpenWebUIFingerprinter) Match(resp *http.Response) bool {
	// Check for Content-Type: application/json header as a weak pre-filter.
	// Open WebUI API responses always return JSON; this avoids reading the body
	// for non-JSON responses (HTML login pages, plain-text errors, etc.).
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *OpenWebUIFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var config openWebUIConfigResponse
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, nil // Not valid JSON
	}

	// Validate required fields that uniquely identify Open WebUI:
	//   - status must be true (Open WebUI sets this on healthy responses)
	//   - version must be non-empty (always present in the config endpoint)
	//   - features must be present (this block is distinctive to Open WebUI)
	if !config.Status {
		return nil, nil
	}
	if config.Version == "" {
		return nil, nil
	}
	if config.Features == nil {
		return nil, nil
	}

	// Validate version format to prevent CPE injection
	if !openWebUIVersionRegex.MatchString(config.Version) {
		return nil, nil
	}

	// Build metadata from available fields
	metadata := map[string]any{
		"auth_enabled":   config.Features.Auth,
		"signup_enabled": config.Features.EnableSignup,
		"login_form":     config.Features.EnableLoginForm,
		"api_keys_enabled": config.Features.EnableAPIKeys,
		"ldap_enabled":   config.Features.EnableLDAP,
	}

	if config.Name != "" {
		metadata["name"] = config.Name
	}
	if config.DefaultLocale != "" {
		metadata["default_locale"] = config.DefaultLocale
	}
	if config.Onboarding {
		metadata["onboarding"] = true
	}

	// Extract OAuth provider names if any are configured
	if config.OAuth != nil && len(config.OAuth.Providers) > 0 {
		providers := make([]string, 0, len(config.OAuth.Providers))
		for name := range config.OAuth.Providers {
			providers = append(providers, name)
		}
		metadata["oauth_providers"] = providers
	}

	return &FingerprintResult{
		Technology: "open_webui",
		Version:    config.Version,
		CPEs:       []string{buildOpenWebUICPE(config.Version)},
		Metadata:   metadata,
	}, nil
}

func buildOpenWebUICPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:openwebui:open_webui:%s:*:*:*:*:*:*:*", version)
}
