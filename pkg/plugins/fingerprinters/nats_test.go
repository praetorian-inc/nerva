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

func TestNATSFingerprinter_Name(t *testing.T) {
	f := &NATSFingerprinter{}
	if got := f.Name(); got != "nats" {
		t.Errorf("Name() = %q, want %q", got, "nats")
	}
}

func TestNATSFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &NATSFingerprinter{}
	if got := f.ProbeEndpoint(); got != "/varz" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/varz")
	}
}

func TestNATSFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "JSON content type",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "JSON with charset",
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "HTML content type",
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "HTML with charset",
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "plain text",
			contentType: "text/plain",
			want:        false,
		},
		{
			name:        "empty content type",
			contentType: "",
			want:        false,
		},
	}

	f := &NATSFingerprinter{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			if got := f.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNATSFingerprinter_Fingerprint(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        []byte
		want        *FingerprintResult
		wantErr     bool
	}{
		{
			name:        "valid NATS /varz response",
			contentType: "application/json",
			body: []byte(`{
				"server_id": "NDBZMW7MVKOKGQV3XZMQF6YPVF5PDKMW",
				"server_name": "test-nats",
				"version": "2.10.7",
				"go": "go1.21.5",
				"git_commit": "c9d29f6a",
				"jetstream": true
			}`),
			want: &FingerprintResult{
				Technology: "nats",
				Version:    "2.10.7",
				CPEs:       []string{"cpe:2.3:a:nats:nats-server:2.10.7:*:*:*:*:*:*:*"},
			},
			wantErr: false,
		},
		{
			name:        "NATS without version",
			contentType: "application/json",
			body: []byte(`{
				"server_id": "TEST123",
				"server_name": "simple-nats"
			}`),
			want: &FingerprintResult{
				Technology: "nats",
				Version:    "",
				CPEs:       []string{"cpe:2.3:a:nats:nats-server:*:*:*:*:*:*:*:*"},
			},
			wantErr: false,
		},
		{
			name:        "NATS with metadata",
			contentType: "application/json",
			body: []byte(`{
				"server_id": "ABC123",
				"server_name": "prod-nats",
				"version": "2.9.0",
				"go": "go1.20.0",
				"git_commit": "abc123",
				"jetstream": false
			}`),
			want: &FingerprintResult{
				Technology: "nats",
				Version:    "2.9.0",
				CPEs:       []string{"cpe:2.3:a:nats:nats-server:2.9.0:*:*:*:*:*:*:*"},
			},
			wantErr: false,
		},
		{
			name:        "NATS monitoring HTML page with version",
			contentType: "text/html",
			body:        []byte(`<html><head><link rel="shortcut icon" href="https://nats.io/favicon.ico"></head><body><a href=https://github.com/nats-io/nats-server/tree/v2.12.4 class='version'>v2.12.4</a><a href=./varz>General<span class="endpoint"> /varz</span></a><a href=./connz>Connections<span class="endpoint"> /connz</span></a></body></html>`),
			want: &FingerprintResult{
				Technology: "nats",
				Version:    "2.12.4",
				CPEs:       []string{"cpe:2.3:a:nats:nats-server:2.12.4:*:*:*:*:*:*:*"},
			},
			wantErr: false,
		},
		{
			name:        "NATS HTML without version",
			contentType: "text/html",
			body:        []byte(`<html><head><link rel="shortcut icon" href="https://nats.io/favicon.ico"></head><body><a href=./varz>General<span class="endpoint"> /varz</span></a><a href=./connz>Connections</a></body></html>`),
			want: &FingerprintResult{
				Technology: "nats",
				Version:    "",
				CPEs:       []string{"cpe:2.3:a:nats:nats-server:*:*:*:*:*:*:*:*"},
			},
			wantErr: false,
		},
		{
			name:        "non-NATS HTML page",
			contentType: "text/html",
			body:        []byte(`<html><body><h1>Hello World</h1><p>This is a test page</p></body></html>`),
			want:        nil,
			wantErr:     false,
		},
		{
			name:        "HTML with nats-server but no /varz endpoint",
			contentType: "text/html",
			body:        []byte(`<html><body><a href=https://github.com/nats-io/nats-server/tree/v2.10.0>NATS Server</a></body></html>`),
			want:        nil,
			wantErr:     false,
		},
		{
			name:        "missing server_id",
			contentType: "application/json",
			body:        []byte(`{"version": "2.10.7"}`),
			want:        nil,
			wantErr:     false,
		},
		{
			name:        "empty server_id",
			contentType: "application/json",
			body:        []byte(`{"server_id": "", "version": "2.10.7"}`),
			want:        nil,
			wantErr:     false,
		},
		{
			name:        "invalid JSON",
			contentType: "application/json",
			body:        []byte(`{invalid json}`),
			want:        nil,
			wantErr:     false,
		},
		{
			name:        "invalid version format",
			contentType: "application/json",
			body:        []byte(`{"server_id": "TEST", "version": "v2.10"}`),
			want:        nil,
			wantErr:     false,
		},
		{
			name:        "empty body",
			contentType: "application/json",
			body:        []byte{},
			want:        nil,
			wantErr:     false,
		},
	}

	f := &NATSFingerprinter{}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				Header: http.Header{
					"Content-Type": []string{tt.contentType},
				},
			}
			got, err := f.Fingerprint(resp, tt.body)
			if (err != nil) != tt.wantErr {
				t.Errorf("Fingerprint() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.want == nil {
				if got != nil {
					t.Errorf("Fingerprint() = %+v, want nil", got)
				}
				return
			}

			if got == nil {
				t.Fatalf("Fingerprint() = nil, want non-nil")
			}

			if got.Technology != tt.want.Technology {
				t.Errorf("Technology = %q, want %q", got.Technology, tt.want.Technology)
			}
			if got.Version != tt.want.Version {
				t.Errorf("Version = %q, want %q", got.Version, tt.want.Version)
			}
			if len(got.CPEs) != len(tt.want.CPEs) {
				t.Errorf("CPEs length = %d, want %d", len(got.CPEs), len(tt.want.CPEs))
			} else if len(got.CPEs) > 0 && got.CPEs[0] != tt.want.CPEs[0] {
				t.Errorf("CPE = %q, want %q", got.CPEs[0], tt.want.CPEs[0])
			}
		})
	}
}

func TestBuildNATSCPE_Fingerprinter(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "version 2.10.7",
			version: "2.10.7",
			want:    "cpe:2.3:a:nats:nats-server:2.10.7:*:*:*:*:*:*:*",
		},
		{
			name:    "version 2.9.0",
			version: "2.9.0",
			want:    "cpe:2.3:a:nats:nats-server:2.9.0:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version (wildcard)",
			version: "",
			want:    "cpe:2.3:a:nats:nats-server:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildNATSCPE(tt.version)
			if got != tt.want {
				t.Errorf("buildNATSCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}
