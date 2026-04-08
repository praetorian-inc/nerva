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

func TestConsulFingerprinter_Name(t *testing.T) {
	fp := &ConsulFingerprinter{}
	if got := fp.Name(); got != "consul" {
		t.Errorf("Name() = %q, want %q", got, "consul")
	}
}

func TestConsulFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ConsulFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/v1/agent/self" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/v1/agent/self")
	}
}

func TestConsulFingerprinter_Match(t *testing.T) {
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
			fp := &ConsulFingerprinter{}
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

func TestConsulFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name           string
		body           string
		wantVersion    string
		wantDatacenter string
		wantNodeName   string
		wantServer     bool
		wantEnterprise bool
	}{
		{
			name: "Consul 1.22.3 OSS",
			body: `{
				"Config": {
					"Datacenter": "dc1",
					"NodeName": "consul-server-1",
					"Version": "1.22.3",
					"Server": true
				}
			}`,
			wantVersion:    "1.22.3",
			wantDatacenter: "dc1",
			wantNodeName:   "consul-server-1",
			wantServer:     true,
			wantEnterprise: false,
		},
		{
			name: "Consul 1.16.3 Enterprise",
			body: `{
				"Config": {
					"Datacenter": "dc2",
					"NodeName": "ent-server",
					"Version": "1.16.3+ent",
					"Server": true
				}
			}`,
			wantVersion:    "1.16.3",
			wantDatacenter: "dc2",
			wantNodeName:   "ent-server",
			wantServer:     true,
			wantEnterprise: true,
		},
		{
			name: "Consul 1.16.3 Enterprise HSM",
			body: `{
				"Config": {
					"Datacenter": "dc1",
					"NodeName": "hsm-server",
					"Version": "1.16.3+ent.hsm",
					"Server": true
				}
			}`,
			wantVersion:    "1.16.3",
			wantDatacenter: "dc1",
			wantNodeName:   "hsm-server",
			wantServer:     true,
			wantEnterprise: true,
		},
		{
			name: "Consul client node",
			body: `{
				"Config": {
					"Datacenter": "dc1",
					"NodeName": "client-1",
					"Version": "1.15.0",
					"Server": false
				}
			}`,
			wantVersion:    "1.15.0",
			wantDatacenter: "dc1",
			wantNodeName:   "client-1",
			wantServer:     false,
			wantEnterprise: false,
		},
		{
			name: "Consul without version",
			body: `{
				"Config": {
					"Datacenter": "dc1",
					"NodeName": "node-1"
				}
			}`,
			wantVersion:    "*",
			wantDatacenter: "dc1",
			wantNodeName:   "node-1",
			wantServer:     false,
			wantEnterprise: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ConsulFingerprinter{}
			resp := &http.Response{}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want result")
			}

			if result.Technology != "consul" {
				t.Errorf("Technology = %q, want %q", result.Technology, "consul")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) != 1 {
				t.Errorf("CPEs count = %d, want 1", len(result.CPEs))
			}

			// Check metadata
			if datacenter, ok := result.Metadata["datacenter"].(string); !ok || datacenter != tt.wantDatacenter {
				t.Errorf("Metadata datacenter = %q, want %q", datacenter, tt.wantDatacenter)
			}
			if nodeName, ok := result.Metadata["node_name"].(string); !ok || nodeName != tt.wantNodeName {
				t.Errorf("Metadata node_name = %q, want %q", nodeName, tt.wantNodeName)
			}
			if server, ok := result.Metadata["server"].(bool); !ok || server != tt.wantServer {
				t.Errorf("Metadata server = %v, want %v", server, tt.wantServer)
			}
			if enterprise, ok := result.Metadata["enterprise"].(bool); !ok || enterprise != tt.wantEnterprise {
				t.Errorf("Metadata enterprise = %v, want %v", enterprise, tt.wantEnterprise)
			}

		})
	}
}

func TestConsulFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Missing Datacenter field",
			body: `{"Config": {"Version": "1.16.3", "NodeName": "node-1"}}`,
		},
		{
			name: "Empty Datacenter",
			body: `{"Config": {"Datacenter": "", "Version": "1.16.3"}}`,
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
			name: "Different service JSON",
			body: `{"status": "ok", "version": "1.0"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ConsulFingerprinter{}
			resp := &http.Response{}

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

func TestBuildConsulCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Valid version",
			version: "1.16.3",
			want:    "cpe:2.3:a:hashicorp:consul:1.16.3:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Wildcard version",
			version: "*",
			want:    "cpe:2.3:a:hashicorp:consul:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildConsulCPE(tt.version); got != tt.want {
				t.Errorf("buildConsulCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}
