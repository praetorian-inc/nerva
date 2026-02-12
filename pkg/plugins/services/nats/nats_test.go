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

package nats

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestNATS(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "nats",
			Port:        4222,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "nats",
				Tag:        "latest",
			},
		},
	}

	p := &NATSPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}

// TestCheckNATSResponse tests NATS INFO message validation and parsing
func TestCheckNATSResponse(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{
			name: "valid NATS INFO message",
			data: []byte(`INFO {"server_id":"NDBZMW7MVKOKGQV3XZMQF6YPVF5PDKMW","server_name":"NDBZMW7MVKOKGQV3XZMQF6YPVF5PDKMW","version":"2.10.7","go":"go1.21.5","host":"0.0.0.0","port":4222,"headers":true,"max_payload":1048576,"proto":1,"jetstream":true}` + "\r\n"),
			wantErr: false,
		},
		{
			name: "NATS INFO with minimal fields",
			data: []byte(`INFO {"server_id":"TEST123","version":"2.9.0"}` + "\r\n"),
			wantErr: false,
		},
		{
			name:    "response too short",
			data:    []byte("INFO"),
			wantErr: true,
		},
		{
			name:    "missing INFO prefix",
			data:    []byte(`{"server_id":"TEST123"}` + "\r\n"),
			wantErr: true,
		},
		{
			name:    "missing CRLF terminator",
			data:    []byte(`INFO {"server_id":"TEST123"}`),
			wantErr: true,
		},
		{
			name:    "invalid JSON",
			data:    []byte(`INFO {invalid json}` + "\r\n"),
			wantErr: true,
		},
		{
			name:    "missing server_id field",
			data:    []byte(`INFO {"version":"2.10.7"}` + "\r\n"),
			wantErr: true,
		},
		{
			name:    "empty server_id",
			data:    []byte(`INFO {"server_id":"","version":"2.10.7"}` + "\r\n"),
			wantErr: true,
		},
		{
			name:    "empty response",
			data:    []byte{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := checkNATSResponse(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkNATSResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && info == nil {
				t.Errorf("checkNATSResponse() returned nil info for valid input")
			}
			if !tt.wantErr && info.ServerID == "" {
				t.Errorf("checkNATSResponse() returned empty server_id for valid input")
			}
		})
	}
}

// TestBuildNATSCPE tests CPE generation for NATS servers
func TestBuildNATSCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "specific version 2.10.7",
			version: "2.10.7",
			want:    "cpe:2.3:a:nats:nats-server:2.10.7:*:*:*:*:*:*:*",
		},
		{
			name:    "version 2.9.0",
			version: "2.9.0",
			want:    "cpe:2.3:a:nats:nats-server:2.9.0:*:*:*:*:*:*:*",
		},
		{
			name:    "version 2.8.4",
			version: "2.8.4",
			want:    "cpe:2.3:a:nats:nats-server:2.8.4:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown version (wildcard)",
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

// TestNATSInfoParsing tests parsing of complete NATS INFO messages
func TestNATSInfoParsing(t *testing.T) {
	tests := []struct {
		name           string
		data           []byte
		wantVersion    string
		wantServerName string
		wantJetStream  bool
	}{
		{
			name: "full NATS INFO with JetStream",
			data: []byte(`INFO {"server_id":"NDBZMW7MVKOKGQV3XZMQF6YPVF5PDKMW","server_name":"test-server","version":"2.10.7","go":"go1.21.5","host":"0.0.0.0","port":4222,"headers":true,"max_payload":1048576,"proto":1,"jetstream":true}` + "\r\n"),
			wantVersion:    "2.10.7",
			wantServerName: "test-server",
			wantJetStream:  true,
		},
		{
			name: "NATS INFO without JetStream",
			data: []byte(`INFO {"server_id":"TEST123","server_name":"simple-nats","version":"2.9.0","port":4222}` + "\r\n"),
			wantVersion:    "2.9.0",
			wantServerName: "simple-nats",
			wantJetStream:  false,
		},
		{
			name: "NATS INFO minimal",
			data: []byte(`INFO {"server_id":"MINIMAL","version":"2.8.0"}` + "\r\n"),
			wantVersion:    "2.8.0",
			wantServerName: "",
			wantJetStream:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := checkNATSResponse(tt.data)
			if err != nil {
				t.Fatalf("checkNATSResponse() error = %v", err)
			}
			if info.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", info.Version, tt.wantVersion)
			}
			if info.ServerName != tt.wantServerName {
				t.Errorf("ServerName = %q, want %q", info.ServerName, tt.wantServerName)
			}
			if info.JetStream != tt.wantJetStream {
				t.Errorf("JetStream = %v, want %v", info.JetStream, tt.wantJetStream)
			}
		})
	}
}

// TestShodanVectors tests realistic NATS INFO banners found on Shodan
// These represent real-world security-relevant configurations
func TestShodanVectors(t *testing.T) {
	tests := []struct {
		name     string
		data     []byte
		validate func(t *testing.T, info *natsInfo)
	}{
		{
			name: "open NATS server - no auth, no TLS (most common Shodan finding)",
			data: []byte(`INFO {"server_id":"NCXQBKO4D4EKZWQVS6KYKQGNAT2OS5CX2R5ICKZ7XMODD4L7SLZYRIH","server_name":"NCXQBKO4D4EKZWQVS6KYKQGNAT2OS5CX2R5ICKZ7XMODD4L7SLZYRIH","version":"2.10.4","proto":1,"go":"go1.21.3","host":"0.0.0.0","port":4222,"headers":true,"max_payload":1048576,"jetstream":true,"auth_required":false,"tls_required":false}` + "\r\n"),
			validate: func(t *testing.T, info *natsInfo) {
				if info.AuthRequired {
					t.Errorf("AuthRequired = true, want false (open server)")
				}
				if info.TLSRequired {
					t.Errorf("TLSRequired = true, want false (unencrypted)")
				}
				if info.Version != "2.10.4" {
					t.Errorf("Version = %q, want %q", info.Version, "2.10.4")
				}
				if !info.JetStream {
					t.Errorf("JetStream = false, want true")
				}
			},
		},
		{
			name: "auth-required NATS with nonce (token-based auth)",
			data: []byte(`INFO {"server_id":"ND2JOB62CCQR6P6ZQDFQIWSSIKPYXHHI","version":"2.9.22","proto":1,"go":"go1.20.10","host":"0.0.0.0","port":4222,"headers":true,"max_payload":1048576,"auth_required":true,"tls_required":false,"nonce":"XYz123AbC"}` + "\r\n"),
			validate: func(t *testing.T, info *natsInfo) {
				if !info.AuthRequired {
					t.Errorf("AuthRequired = false, want true")
				}
				if info.TLSRequired {
					t.Errorf("TLSRequired = true, want false")
				}
				if info.Version != "2.9.22" {
					t.Errorf("Version = %q, want %q", info.Version, "2.9.22")
				}
				if info.Nonce != "XYz123AbC" {
					t.Errorf("Nonce = %q, want %q", info.Nonce, "XYz123AbC")
				}
			},
		},
		{
			name: "TLS-required NATS server with client verification",
			data: []byte(`INFO {"server_id":"NATS_TLS_SERVER_ID_ABC123","server_name":"secure-nats","version":"2.10.7","proto":1,"go":"go1.21.5","host":"0.0.0.0","port":4222,"headers":true,"max_payload":1048576,"auth_required":true,"tls_required":true,"tls_verify":true}` + "\r\n"),
			validate: func(t *testing.T, info *natsInfo) {
				if !info.AuthRequired {
					t.Errorf("AuthRequired = false, want true")
				}
				if !info.TLSRequired {
					t.Errorf("TLSRequired = false, want true")
				}
				if !info.TLSVerify {
					t.Errorf("TLSVerify = false, want true")
				}
				if info.ServerName != "secure-nats" {
					t.Errorf("ServerName = %q, want %q", info.ServerName, "secure-nats")
				}
			},
		},
		{
			name: "cluster node with connect_urls (topology exposure)",
			data: []byte(`INFO {"server_id":"NCLUSTER123","server_name":"nats-cluster-east-1","version":"2.10.4","proto":1,"go":"go1.21.3","host":"0.0.0.0","port":4222,"headers":true,"max_payload":1048576,"auth_required":false,"cluster":"prod-east","connect_urls":["10.0.1.10:4222","10.0.1.11:4222","10.0.1.12:4222"],"jetstream":true}` + "\r\n"),
			validate: func(t *testing.T, info *natsInfo) {
				if info.Cluster != "prod-east" {
					t.Errorf("Cluster = %q, want %q", info.Cluster, "prod-east")
				}
				if len(info.ConnectURLs) != 3 {
					t.Errorf("len(ConnectURLs) = %d, want 3", len(info.ConnectURLs))
				}
				if len(info.ConnectURLs) > 0 && info.ConnectURLs[0] != "10.0.1.10:4222" {
					t.Errorf("ConnectURLs[0] = %q, want %q", info.ConnectURLs[0], "10.0.1.10:4222")
				}
				if info.AuthRequired {
					t.Errorf("AuthRequired = true, want false (exposes internal topology)")
				}
			},
		},
		{
			name: "older NATS v2.2 (minimal INFO, pre-headers)",
			data: []byte(`INFO {"server_id":"OLDNAT2SERVER","version":"2.2.6","go":"go1.16.5","host":"0.0.0.0","port":4222,"max_payload":1048576,"proto":1}` + "\r\n"),
			validate: func(t *testing.T, info *natsInfo) {
				if info.Version != "2.2.6" {
					t.Errorf("Version = %q, want %q", info.Version, "2.2.6")
				}
				if info.Headers {
					t.Errorf("Headers = true, want false (pre-headers version)")
				}
				if info.JetStream {
					t.Errorf("JetStream = true, want false (pre-JetStream version)")
				}
			},
		},
		{
			name: "NATS with JetStream domain (multi-tenant/leaf node)",
			data: []byte(`INFO {"server_id":"NJSDOM123","server_name":"leaf-west","version":"2.10.7","proto":1,"go":"go1.21.5","host":"0.0.0.0","port":4222,"headers":true,"max_payload":1048576,"jetstream":true,"domain":"hub","ldm":false,"auth_required":false,"tls_available":true}` + "\r\n"),
			validate: func(t *testing.T, info *natsInfo) {
				if info.Domain != "hub" {
					t.Errorf("Domain = %q, want %q", info.Domain, "hub")
				}
				if !info.JetStream {
					t.Errorf("JetStream = false, want true")
				}
				if !info.TLSAvailable {
					t.Errorf("TLSAvailable = false, want true")
				}
				if info.LDM {
					t.Errorf("LDM = true, want false")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info, err := checkNATSResponse(tt.data)
			if err != nil {
				t.Fatalf("checkNATSResponse() error = %v", err)
			}
			tt.validate(t, info)
		})
	}
}
