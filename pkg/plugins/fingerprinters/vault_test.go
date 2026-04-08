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

func TestVaultFingerprinter_Name(t *testing.T) {
	fp := &VaultFingerprinter{}
	if got := fp.Name(); got != "vault" {
		t.Errorf("Name() = %q, want %q", got, "vault")
	}
}

func TestVaultFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &VaultFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/v1/sys/health" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/v1/sys/health")
	}
}

func TestVaultFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name         string
		cacheControl string
		want         bool
	}{
		{
			name:         "Cache-Control: no-store returns true",
			cacheControl: "no-store",
			want:         true,
		},
		{
			name:         "Cache-Control: no-cache, no-store returns true",
			cacheControl: "no-cache, no-store",
			want:         true,
		},
		{
			name:         "Cache-Control: max-age=300 returns false",
			cacheControl: "max-age=300",
			want:         false,
		},
		{
			name:         "No Cache-Control header returns false",
			cacheControl: "",
			want:         false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &VaultFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.cacheControl != "" {
				resp.Header.Set("Cache-Control", tt.cacheControl)
			}

			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVaultFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name                 string
		body                 string
		wantVersion          string
		wantSealed           bool
		wantInitialized      bool
		wantEnterprise       bool
		wantClusterNameExist bool
	}{
		{
			name: "Full health response (unsealed, initialized, not enterprise)",
			body: `{
				"initialized": true,
				"sealed": false,
				"version": "1.12.3",
				"cluster_name": "vault-cluster-7089ef9c",
				"enterprise": false
			}`,
			wantVersion:          "1.12.3",
			wantSealed:           false,
			wantInitialized:      true,
			wantEnterprise:       false,
			wantClusterNameExist: true,
		},
		{
			name: "Sealed vault",
			body: `{
				"initialized": true,
				"sealed": true,
				"version": "1.15.0",
				"cluster_name": "prod-vault",
				"enterprise": false
			}`,
			wantVersion:          "1.15.0",
			wantSealed:           true,
			wantInitialized:      true,
			wantEnterprise:       false,
			wantClusterNameExist: true,
		},
		{
			name: "Enterprise vault",
			body: `{
				"initialized": true,
				"sealed": false,
				"version": "1.16.1+ent",
				"cluster_name": "enterprise-vault",
				"enterprise": true
			}`,
			wantVersion:          "1.16.1+ent",
			wantSealed:           false,
			wantInitialized:      true,
			wantEnterprise:       true,
			wantClusterNameExist: true,
		},
		{
			name: "Minimal response (no cluster_name)",
			body: `{
				"initialized": true,
				"sealed": false,
				"version": "1.10.0"
			}`,
			wantVersion:          "1.10.0",
			wantSealed:           false,
			wantInitialized:      true,
			wantEnterprise:       false,
			wantClusterNameExist: false,
		},
		{
			name: "Enterprise HSM vault",
			body: `{
				"initialized": true,
				"sealed": false,
				"version": "1.16.1+ent.hsm",
				"cluster_name": "enterprise-hsm-vault",
				"enterprise": true
			}`,
			wantVersion:          "1.16.1+ent.hsm",
			wantSealed:           false,
			wantInitialized:      true,
			wantEnterprise:       true,
			wantClusterNameExist: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &VaultFingerprinter{}
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

			if result.Technology != "vault" {
				t.Errorf("Technology = %q, want %q", result.Technology, "vault")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check metadata
			if sealed, ok := result.Metadata["sealed"].(bool); !ok || sealed != tt.wantSealed {
				t.Errorf("Metadata[sealed] = %v, want %v", sealed, tt.wantSealed)
			}
			if initialized, ok := result.Metadata["initialized"].(bool); !ok || initialized != tt.wantInitialized {
				t.Errorf("Metadata[initialized] = %v, want %v", initialized, tt.wantInitialized)
			}
			if enterprise, ok := result.Metadata["enterprise"].(bool); !ok || enterprise != tt.wantEnterprise {
				t.Errorf("Metadata[enterprise] = %v, want %v", enterprise, tt.wantEnterprise)
			}

			if tt.wantClusterNameExist {
				if _, ok := result.Metadata["cluster_name"]; !ok {
					t.Error("Expected clusterName in metadata, but it's missing")
				}
			} else {
				if _, ok := result.Metadata["cluster_name"]; ok {
					t.Error("Expected no clusterName in metadata, but it exists")
				}
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}

		})
	}
}

func TestVaultFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Non-JSON body",
			body: "OK",
		},
		{
			name: "JSON without version",
			body: `{"initialized": true, "sealed": false}`,
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
			name: "Version with CPE injection attempt",
			body: `{"initialized": true, "sealed": false, "version": "1.0.0:*:*:*:*:*:*:*"}`,
		},
		{
			name: "Missing sealed field (false positive risk)",
			body: `{"initialized": true, "version": "1.12.3"}`,
		},
		{
			name: "Missing initialized field (false positive risk)",
			body: `{"sealed": false, "version": "1.12.3"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &VaultFingerprinter{}
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

func TestBuildVaultCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "1.12.3",
			want:    "cpe:2.3:a:hashicorp:vault:1.12.3:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:hashicorp:vault:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildVaultCPE(tt.version); got != tt.want {
				t.Errorf("buildVaultCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVaultFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &VaultFingerprinter{}
	Register(fp)

	// Create a valid Vault health response
	body := []byte(`{
		"initialized": true,
		"sealed": false,
		"version": "1.12.3",
		"cluster_name": "vault-cluster-7089ef9c"
	}`)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Cache-Control", "no-store")

	results := RunFingerprinters(resp, body)

	// Should find at least the Vault fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "vault" {
			found = true
			if result.Version != "1.12.3" {
				t.Errorf("Version = %q, want %q", result.Version, "1.12.3")
			}
		}
	}

	if !found {
		t.Error("VaultFingerprinter not found in results")
	}
}
