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
Package fingerprinters provides HTTP fingerprinting for HashiCorp Vault.

# Detection Strategy

HashiCorp Vault is the most widely deployed secrets management solution. Exposed
instances represent a critical security concern due to:
  - Storage of secrets and credentials
  - Potential access to sensitive data if unsealed
  - Cluster configuration information leakage
  - Authentication and authorization bypass vulnerabilities

Detection uses a two-pronged approach:
1. Passive: Check for Cache-Control: no-store header (weak pre-filter)
2. Active: Query /v1/sys/health endpoint (no authentication required)

# API Response Format

The /v1/sys/health endpoint returns JSON without authentication:

	{
	  "initialized": true,
	  "sealed": false,
	  "version": "1.12.3",
	  "cluster_name": "vault-cluster-7089ef9c",
	  "cluster_id": "9c5dcbaa-7361-202d-3dba-b235c6f7f443",
	  "enterprise": false
	}

Format breakdown:
  - version: Vault version string (required for detection)
  - sealed: Whether the Vault is sealed (security critical)
  - initialized: Whether Vault has been initialized
  - cluster_name: Cluster identifier (optional)
  - enterprise: Whether this is Vault Enterprise

# Port Configuration

Vault typically runs on:
  - 8200: Default Vault HTTP API port
  - 443:  HTTPS in production deployments

# Example Usage

	fp := &VaultFingerprinter{}
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

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// VaultFingerprinter detects HashiCorp Vault instances via /v1/sys/health endpoint
type VaultFingerprinter struct{}

// vaultHealthResponse represents the JSON structure from /v1/sys/health
type vaultHealthResponse struct {
	Initialized *bool  `json:"initialized"`
	Sealed      *bool  `json:"sealed"`
	Version     string `json:"version"`
	ClusterName string `json:"cluster_name"`
	Enterprise  bool   `json:"enterprise"`
}

// vaultVersionRegex validates Vault version format
// Accepts: 1.12.3 (OSS), 1.12.3+ent (Enterprise), 1.12.3+ent.hsm (Enterprise HSM)
var vaultVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(\+ent(\.hsm)?)?$`)

func init() {
	Register(&VaultFingerprinter{})
}

func (f *VaultFingerprinter) Name() string {
	return "vault"
}

func (f *VaultFingerprinter) ProbeEndpoint() string {
	return "/v1/sys/health"
}

func (f *VaultFingerprinter) Match(resp *http.Response) bool {
	// Check for Cache-Control: no-store header
	// This is present on all Vault responses but not unique to Vault
	// Use as weak pre-filter before active probe
	return strings.Contains(resp.Header.Get("Cache-Control"), "no-store")
}

func (f *VaultFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Try to parse as Vault health response
	var health vaultHealthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		return nil, nil // Not Vault format
	}

	// Validate it's actually Vault by checking version field and required boolean fields
	// Vault health endpoint always returns version, initialized, and sealed
	if health.Version == "" || health.Initialized == nil || health.Sealed == nil {
		return nil, nil
	}

	// Validate version format to prevent CPE injection
	if !vaultVersionRegex.MatchString(health.Version) {
		return nil, nil
	}

	// Build metadata
	metadata := map[string]any{
		"sealed":      *health.Sealed,
		"initialized": *health.Initialized,
		"enterprise":  health.Enterprise,
	}

	// Add cluster name if present
	if health.ClusterName != "" {
		metadata["cluster_name"] = health.ClusterName
	}

	return &FingerprintResult{
		Technology: "vault",
		Version:    health.Version,
		CPEs:       []string{buildVaultCPE(health.Version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityMedium,
	}, nil
}

func buildVaultCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:hashicorp:vault:%s:*:*:*:*:*:*:*", version)
}
