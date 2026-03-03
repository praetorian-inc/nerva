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

package runner

import (
	"net/netip"
	"strings"
	"testing"
)

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantAddr    string // expected IP:port string
		wantHost    string // expected hostname (empty if IP was provided directly)
		wantErr     bool
		errContains string
	}{
		// IPv4 cases
		{
			name:     "IPv4 with port",
			input:    "192.168.1.1:80",
			wantAddr: "192.168.1.1:80",
			wantHost: "",
			wantErr:  false,
		},
		{
			name:     "IPv4 with high port",
			input:    "10.0.0.1:65535",
			wantAddr: "10.0.0.1:65535",
			wantHost: "",
			wantErr:  false,
		},

		// IPv6 cases - these are the bug fix tests
		{
			name:     "IPv6 with brackets and port",
			input:    "[::1]:80",
			wantAddr: "[::1]:80",
			wantHost: "",
			wantErr:  false,
		},
		{
			name:     "IPv6 full address with brackets",
			input:    "[2a01:239:42a:2200::1]:443",
			wantAddr: "[2a01:239:42a:2200::1]:443",
			wantHost: "",
			wantErr:  false,
		},
		{
			name:     "IPv6 localhost with brackets",
			input:    "[::1]:8080",
			wantAddr: "[::1]:8080",
			wantHost: "",
			wantErr:  false,
		},
		{
			name:     "IPv6 all zeros with brackets",
			input:    "[::]:22",
			wantAddr: "[::]:22",
			wantHost: "",
			wantErr:  false,
		},

		// Error cases
		{
			name:        "missing port",
			input:       "192.168.1.1",
			wantErr:     true,
			errContains: "invalid target",
		},
		{
			name:        "empty string",
			input:       "",
			wantErr:     true,
			errContains: "invalid target",
		},
		{
			name:        "invalid port",
			input:       "192.168.1.1:abc",
			wantErr:     true,
			errContains: "invalid port",
		},
		{
			name:        "port out of range",
			input:       "192.168.1.1:70000",
			wantErr:     true,
			errContains: "invalid port",
		},
		{
			name:        "IPv6 without brackets",
			input:       "2a01:239:42a:2200::1:443",
			wantErr:     true,
			errContains: "invalid target",
		},
		{
			name:        "IPv6 missing closing bracket",
			input:       "[2a01:239:42a:2200::1:443",
			wantErr:     true,
			errContains: "invalid target",
		},
		{
			name:     "whitespace around target",
			input:    "  192.168.1.1:80  ",
			wantAddr: "192.168.1.1:80",
			wantHost: "",
			wantErr:  false,
		},
		{
			name:     "port zero",
			input:    "192.168.1.1:0",
			wantAddr: "192.168.1.1:0",
			wantHost: "",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseTarget(tt.input)

			if tt.wantErr {
				if err == nil {
					t.Errorf("parseTarget(%q) expected error containing %q, got nil", tt.input, tt.errContains)
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("parseTarget(%q) error = %q, want error containing %q", tt.input, err.Error(), tt.errContains)
				}
				return
			}

			if err != nil {
				t.Errorf("parseTarget(%q) unexpected error: %v", tt.input, err)
				return
			}

			// Parse expected address for comparison
			wantAddrPort, err := netip.ParseAddrPort(tt.wantAddr)
			if err != nil {
				t.Fatalf("invalid test case: cannot parse wantAddr %q: %v", tt.wantAddr, err)
			}

			if got.Address != wantAddrPort {
				t.Errorf("parseTarget(%q).Address = %v, want %v", tt.input, got.Address, wantAddrPort)
			}

			if got.Host != tt.wantHost {
				t.Errorf("parseTarget(%q).Host = %q, want %q", tt.input, got.Host, tt.wantHost)
			}
		})
	}
}
