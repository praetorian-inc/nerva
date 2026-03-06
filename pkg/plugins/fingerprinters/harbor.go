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
Package fingerprinters provides HTTP fingerprinting for Harbor container registry.

# Detection Strategy

Harbor is an open-source container registry. Exposed instances represent a
security concern due to:
  - Container image storage and distribution
  - Potential access to private images and artifacts
  - Built-in vulnerability scanning results
  - Replication policies revealing internal infrastructure

Detection uses active probing:
  - Active: Query /api/v2.0/systeminfo endpoint (no authentication required for basic response)
  - Response must contain auth_mode field matching known Harbor values

# API Response Format

The /api/v2.0/systeminfo endpoint returns JSON without authentication:

	{
	  "auth_mode": "db_auth",
	  "primary_auth_mode": false,
	  "self_registration": true
	}

When authenticated, additional fields are present:

	{
	  "auth_mode": "db_auth",
	  "primary_auth_mode": false,
	  "self_registration": true,
	  "harbor_version": "v2.10.0",
	  "registry_url": "harbor.example.com",
	  "external_url": "https://harbor.example.com"
	}

# Port Configuration

Harbor typically runs on:
  - 80:  Default HTTP port
  - 443: HTTPS in production

# Example Usage

	fp := &HarborFingerprinter{}
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
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// HarborFingerprinter detects Harbor container registry instances via /api/v2.0/systeminfo endpoint
type HarborFingerprinter struct{}

// harborSystemInfoResponse represents the JSON structure from /api/v2.0/systeminfo
type harborSystemInfoResponse struct {
	AuthMode         string  `json:"auth_mode"`
	PrimaryAuthMode  bool    `json:"primary_auth_mode"`
	SelfRegistration bool    `json:"self_registration"`
	HarborVersion    *string `json:"harbor_version"`
	RegistryURL      *string `json:"registry_url"`
	ExternalURL      *string `json:"external_url"`
}

// harborVersionRegex validates Harbor version format
// Accepts: 2.10.0 (standard), 2.11.0-rc1 (release candidate)
var harborVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(-rc\d+)?$`)

// harborKnownAuthModes is the set of valid Harbor authentication modes.
// Restricting to known values prevents false positives from other JSON APIs.
var harborKnownAuthModes = map[string]bool{
	"db_auth":   true,
	"ldap_auth": true,
	"oidc_auth": true,
	"uaa_auth":  true,
	"http_auth": true,
}

func init() {
	Register(&HarborFingerprinter{})
}

func (f *HarborFingerprinter) Name() string {
	return "harbor"
}

func (f *HarborFingerprinter) ProbeEndpoint() string {
	return "/api/v2.0/systeminfo"
}

func (f *HarborFingerprinter) Match(resp *http.Response) bool {
	// Check for application/json Content-Type header
	// This is present on Harbor API responses but not unique to Harbor
	// Use as weak pre-filter before active probe
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *HarborFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Try to parse as Harbor systeminfo response
	var info harborSystemInfoResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, nil // Not Harbor format
	}

	// Validate it's actually Harbor by checking auth_mode against known values.
	// auth_mode is always present in the unauthenticated Harbor response and
	// must be one of the known values to prevent false positives.
	if info.AuthMode == "" || !harborKnownAuthModes[info.AuthMode] {
		return nil, nil
	}

	// Build metadata with fields always present in unauthenticated response
	metadata := map[string]any{
		"authMode":         info.AuthMode,
		"selfRegistration": info.SelfRegistration,
		"primaryAuthMode":  info.PrimaryAuthMode,
	}

	// Add optional fields only present when authenticated
	if info.RegistryURL != nil {
		metadata["registryUrl"] = *info.RegistryURL
	}
	if info.ExternalURL != nil {
		metadata["externalUrl"] = *info.ExternalURL
	}

	// Extract version from harbor_version field (only present when authenticated)
	version := ""
	if info.HarborVersion != nil {
		v := *info.HarborVersion
		// Harbor versions are prefixed with "v" (e.g., "v2.10.0") - strip it
		v = strings.TrimPrefix(v, "v")
		// Validate version format to prevent CPE injection.
		// If harbor_version is present but fails validation, reject the response
		// entirely - a malformed version field indicates a tampered or unexpected
		// response that should not be trusted.
		if !harborVersionRegex.MatchString(v) {
			return nil, nil
		}
		version = v
	}

	return &FingerprintResult{
		Technology: "harbor",
		Version:    version,
		CPEs:       []string{buildHarborCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildHarborCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:goharbor:harbor:%s:*:*:*:*:*:*:*", version)
}
