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

func TestRabbitMQManagementFingerprinter_Name(t *testing.T) {
	fp := &RabbitMQManagementFingerprinter{}
	if got := fp.Name(); got != "rabbitmq-management" {
		t.Errorf("Name() = %q, want %q", got, "rabbitmq-management")
	}
}

func TestRabbitMQManagementFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &RabbitMQManagementFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/api/overview" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/api/overview")
	}
}

func TestRabbitMQManagementFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name            string
		statusCode      int
		contentType     string
		wwwAuthenticate string
		want            bool
	}{
		{
			name:        "200 application/json returns true",
			statusCode:  http.StatusOK,
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "200 application/json; charset=utf-8 returns true",
			statusCode:  http.StatusOK,
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "200 text/html returns false",
			statusCode:  http.StatusOK,
			contentType: "text/html",
			want:        false,
		},
		{
			name:            `401 WWW-Authenticate with realm="RabbitMQ Management" returns true`,
			statusCode:      http.StatusUnauthorized,
			wwwAuthenticate: `Basic realm="RabbitMQ Management"`,
			want:            true,
		},
		{
			name:            `401 WWW-Authenticate with realm="Other" returns false`,
			statusCode:      http.StatusUnauthorized,
			wwwAuthenticate: `Basic realm="Other"`,
			want:            false,
		},
		{
			name:       "401 no WWW-Authenticate header returns false",
			statusCode: http.StatusUnauthorized,
			want:       false,
		},
		{
			name:            `401 RABBITMQ MANAGEMENT uppercase returns true (case-insensitive)`,
			statusCode:      http.StatusUnauthorized,
			wwwAuthenticate: `Basic realm="RABBITMQ MANAGEMENT"`,
			want:            true,
		},
		{
			name:        "500 application/json returns false",
			statusCode:  http.StatusInternalServerError,
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "199 application/json returns false",
			statusCode:  199,
			contentType: "application/json",
			want:        false,
		},
		{
			name:       "302 no matching headers returns false",
			statusCode: http.StatusFound,
			want:       false,
		},
		{
			name:       "200 empty Content-Type returns false",
			statusCode: http.StatusOK,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RabbitMQManagementFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if tt.wwwAuthenticate != "" {
				resp.Header.Set("WWW-Authenticate", tt.wwwAuthenticate)
			}

			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestRabbitMQManagementFingerprinter_Fingerprint_ValidJSON(t *testing.T) {
	tests := []struct {
		name                   string
		body                   string
		wantVersion            string
		wantCPE                string
		wantMetadataKeys       []string
		wantAbsentMetadataKeys []string
	}{
		{
			name: "Full response with all fields",
			body: `{
				"rabbitmq_version": "3.12.14",
				"erlang_version": "26.2.5",
				"cluster_name": "rabbit@hostname",
				"management_version": "3.12.14"
			}`,
			wantVersion: "3.12.14",
			wantCPE:     "cpe:2.3:a:vmware:rabbitmq:3.12.14:*:*:*:*:*:*:*",
			wantMetadataKeys: []string{
				"rabbitmq_version",
				"erlang_version",
				"cluster_name",
				"management_version",
			},
		},
		{
			name:        "Minimal response with only rabbitmq_version",
			body:        `{"rabbitmq_version": "3.10.0"}`,
			wantVersion: "3.10.0",
			wantCPE:     "cpe:2.3:a:vmware:rabbitmq:3.10.0:*:*:*:*:*:*:*",
			wantMetadataKeys: []string{
				"rabbitmq_version",
			},
			wantAbsentMetadataKeys: []string{
				"erlang_version",
				"cluster_name",
				"management_version",
			},
		},
		{
			name: "4-segment version 3.12.14.1 should produce wildcard version",
			body: `{"rabbitmq_version": "3.12.14.1"}`,
			wantVersion: "*",
			wantCPE:     "cpe:2.3:a:vmware:rabbitmq:*:*:*:*:*:*:*:*",
			wantMetadataKeys: []string{
				"rabbitmq_version",
			},
		},
		{
			name: "Response without erlang_version should not include erlang_version key",
			body: `{
				"rabbitmq_version": "3.11.5",
				"cluster_name": "rabbit@node1",
				"management_version": "3.11.5"
			}`,
			wantVersion: "3.11.5",
			wantCPE:     "cpe:2.3:a:vmware:rabbitmq:3.11.5:*:*:*:*:*:*:*",
			wantMetadataKeys: []string{
				"rabbitmq_version",
				"cluster_name",
				"management_version",
			},
			wantAbsentMetadataKeys: []string{
				"erlang_version",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RabbitMQManagementFingerprinter{}
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want result")
			}

			if result.Technology != "rabbitmq-management" {
				t.Errorf("Technology = %q, want %q", result.Technology, "rabbitmq-management")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) != 1 {
				t.Fatalf("CPEs count = %d, want 1", len(result.CPEs))
			}
			if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPEs[0] = %q, want %q", result.CPEs[0], tt.wantCPE)
			}

			for _, key := range tt.wantMetadataKeys {
				if _, ok := result.Metadata[key]; !ok {
					t.Errorf("Metadata missing expected key %q", key)
				}
			}
			for _, key := range tt.wantAbsentMetadataKeys {
				if _, ok := result.Metadata[key]; ok {
					t.Errorf("Metadata has unexpected key %q", key)
				}
			}
		})
	}
}

func TestRabbitMQManagementFingerprinter_Fingerprint_InvalidJSON(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Empty rabbitmq_version field",
			body: `{"rabbitmq_version": ""}`,
		},
		{
			name: "Not JSON (HTML content)",
			body: `<html><body>Not JSON</body></html>`,
		},
		{
			name: "Empty body",
			body: ``,
		},
		{
			name: "Empty JSON object",
			body: `{}`,
		},
		{
			name: "Different service JSON",
			body: `{"status": "ok", "version": "1.0"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RabbitMQManagementFingerprinter{}
			resp := &http.Response{
				StatusCode: http.StatusOK,
				Header:     make(http.Header),
			}

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

func TestRabbitMQManagementFingerprinter_Fingerprint_AuthChallenge(t *testing.T) {
	tests := []struct {
		name            string
		wwwAuthenticate string
		wantNil         bool
	}{
		{
			name:            `401 with Basic realm="RabbitMQ Management" returns result`,
			wwwAuthenticate: `Basic realm="RabbitMQ Management"`,
			wantNil:         false,
		},
		{
			name:            `401 with Basic realm="Other Service" returns nil`,
			wwwAuthenticate: `Basic realm="Other Service"`,
			wantNil:         true,
		},
		{
			name:    "401 with no WWW-Authenticate returns nil",
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RabbitMQManagementFingerprinter{}
			resp := &http.Response{
				StatusCode: http.StatusUnauthorized,
				Header:     make(http.Header),
			}
			if tt.wwwAuthenticate != "" {
				resp.Header.Set("WWW-Authenticate", tt.wwwAuthenticate)
			}

			result, err := fp.Fingerprint(resp, nil)
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}

			if tt.wantNil {
				if result != nil {
					t.Errorf("Fingerprint() = %+v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Fingerprint() returned nil, want result")
			}
			if result.Technology != "rabbitmq-management" {
				t.Errorf("Technology = %q, want %q", result.Technology, "rabbitmq-management")
			}
			if result.Version != "*" {
				t.Errorf("Version = %q, want %q", result.Version, "*")
			}
			if len(result.CPEs) != 1 {
				t.Fatalf("CPEs count = %d, want 1", len(result.CPEs))
			}
			if result.CPEs[0] != "cpe:2.3:a:vmware:rabbitmq:*:*:*:*:*:*:*:*" {
				t.Errorf("CPEs[0] = %q, want %q", result.CPEs[0], "cpe:2.3:a:vmware:rabbitmq:*:*:*:*:*:*:*:*")
			}
			if len(result.Metadata) != 0 {
				t.Errorf("Metadata = %v, want empty map", result.Metadata)
			}
		})
	}
}

func TestBuildRabbitMQCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Valid version 3.12.14",
			version: "3.12.14",
			want:    "cpe:2.3:a:vmware:rabbitmq:3.12.14:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:vmware:rabbitmq:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Wildcard version",
			version: "*",
			want:    "cpe:2.3:a:vmware:rabbitmq:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildRabbitMQCPE(tt.version); got != tt.want {
				t.Errorf("buildRabbitMQCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}
