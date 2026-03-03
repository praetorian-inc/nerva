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

func TestTiDBFingerprinter_Name(t *testing.T) {
	fp := &TiDBFingerprinter{}
	if got := fp.Name(); got != "tidb" {
		t.Errorf("Name() = %q, want %q", got, "tidb")
	}
}

func TestTiDBFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &TiDBFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/status" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/status")
	}
}

func TestTiDBFingerprinter_Match(t *testing.T) {
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
			fp := &TiDBFingerprinter{}
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

func TestTiDBFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantVersion     string
		wantConnections int
		wantGitHash     string
	}{
		{
			name: "Full status response (v7.5.1)",
			body: `{
				"connections": 0,
				"version": "8.0.11-TiDB-v7.5.1",
				"git_hash": "7d16cc79e81bbf573124df3fd9351c26963f3e70"
			}`,
			wantVersion:     "v7.5.1",
			wantConnections: 0,
			wantGitHash:     "7d16cc79e81bbf573124df3fd9351c26963f3e70",
		},
		{
			name: "Older version (v7.1.0)",
			body: `{
				"connections": 5,
				"version": "5.7.25-TiDB-v7.1.0",
				"git_hash": "abc123def456"
			}`,
			wantVersion:     "v7.1.0",
			wantConnections: 5,
			wantGitHash:     "abc123def456",
		},
		{
			name: "Newer version (v8.0.0)",
			body: `{
				"connections": 10,
				"version": "8.0.11-TiDB-v8.0.0",
				"git_hash": "xyz789"
			}`,
			wantVersion:     "v8.0.0",
			wantConnections: 10,
			wantGitHash:     "xyz789",
		},
		{
			name: "Version with patch (v7.5.1-alpha)",
			body: `{
				"connections": 2,
				"version": "8.0.11-TiDB-v7.5.1-alpha",
				"git_hash": "1b895f16a067"
			}`,
			wantVersion:     "v7.5.1-alpha",
			wantConnections: 2,
			wantGitHash:     "1b895f16a067",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TiDBFingerprinter{}
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

			if result.Technology != "tidb" {
				t.Errorf("Technology = %q, want %q", result.Technology, "tidb")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check metadata
			if connections, ok := result.Metadata["connections"].(int); !ok || connections != tt.wantConnections {
				t.Errorf("Metadata[connections] = %v, want %v", connections, tt.wantConnections)
			}
			if gitHash, ok := result.Metadata["git_hash"].(string); !ok || gitHash != tt.wantGitHash {
				t.Errorf("Metadata[git_hash] = %v, want %v", gitHash, tt.wantGitHash)
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:pingcap:tidb:" + tt.wantVersion + ":*:*:*:*:*:*:*"
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestTiDBFingerprinter_Fingerprint_Invalid(t *testing.T) {
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
			body: `{"connections": 0, "git_hash": "abc123"}`,
		},
		{
			name: "JSON without git_hash",
			body: `{"connections": 0, "version": "8.0.11-TiDB-v7.5.1"}`,
		},
		{
			name: "Version without TiDB marker",
			body: `{"connections": 0, "version": "8.0.11", "git_hash": "abc123"}`,
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
			body: `{"connections": 0, "version": "8.0.11-TiDB-v7.5.1:*:*:*:*:*:*:*", "git_hash": "abc"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TiDBFingerprinter{}
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

func TestBuildTiDBCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "v7.5.1",
			want:    "cpe:2.3:a:pingcap:tidb:v7.5.1:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:pingcap:tidb:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildTiDBCPE(tt.version); got != tt.want {
				t.Errorf("buildTiDBCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}
