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

	"github.com/praetorian-inc/nerva/pkg/plugins"
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

// Test Group 6: Target Serialization

func TestTargetToString_IPOnly(t *testing.T) {
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:80"),
	}

	result := TargetToString(target)

	if result != "192.168.1.1:80" {
		t.Errorf("TargetToString() = %q, want %q", result, "192.168.1.1:80")
	}
}

func TestTargetToString_WithHostname(t *testing.T) {
	target := plugins.Target{
		Address: netip.MustParseAddrPort("93.184.216.34:443"),
		Host:    "example.com",
	}

	result := TargetToString(target)

	if result != "93.184.216.34:443|example.com" {
		t.Errorf("TargetToString() = %q, want %q", result, "93.184.216.34:443|example.com")
	}
}

func TestTargetToString_IPv6(t *testing.T) {
	target := plugins.Target{
		Address: netip.MustParseAddrPort("[::1]:8080"),
	}

	result := TargetToString(target)

	if result != "::1:8080" {
		t.Errorf("TargetToString() = %q, want %q", result, "::1:8080")
	}
}

func TestTargetsToStrings_Batch(t *testing.T) {
	targets := []plugins.Target{
		{Address: netip.MustParseAddrPort("1.1.1.1:80")},
		{Address: netip.MustParseAddrPort("2.2.2.2:443"), Host: "example.com"},
	}

	result := TargetsToStrings(targets)

	expected := []string{"1.1.1.1:80", "2.2.2.2:443|example.com"}
	if len(result) != len(expected) {
		t.Fatalf("TargetsToStrings() length = %d, want %d", len(result), len(expected))
	}
	for i := range expected {
		if result[i] != expected[i] {
			t.Errorf("TargetsToStrings()[%d] = %q, want %q", i, result[i], expected[i])
		}
	}
}

func TestTargetsToStrings_Empty(t *testing.T) {
	result := TargetsToStrings([]plugins.Target{})

	if len(result) != 0 {
		t.Errorf("TargetsToStrings([]) length = %d, want 0", len(result))
	}
	if result == nil {
		t.Error("TargetsToStrings([]) = nil, want empty slice")
	}
}

// Test Group 7: Target Deserialization

func TestStringToTarget_IPOnly(t *testing.T) {
	target, err := StringToTarget("192.168.1.1:80", false)

	if err != nil {
		t.Fatalf("StringToTarget() unexpected error: %v", err)
	}
	if target.Address.Addr().String() != "192.168.1.1" {
		t.Errorf("StringToTarget().Address.Addr() = %q, want %q", target.Address.Addr().String(), "192.168.1.1")
	}
	if target.Address.Port() != 80 {
		t.Errorf("StringToTarget().Address.Port() = %d, want %d", target.Address.Port(), 80)
	}
	if target.Host != "" {
		t.Errorf("StringToTarget().Host = %q, want empty string", target.Host)
	}
}

func TestStringToTarget_WithHostname(t *testing.T) {
	target, err := StringToTarget("93.184.216.34:443|example.com", false)

	if err != nil {
		t.Fatalf("StringToTarget() unexpected error: %v", err)
	}
	if target.Address.Addr().String() != "93.184.216.34" {
		t.Errorf("StringToTarget().Address.Addr() = %q, want %q", target.Address.Addr().String(), "93.184.216.34")
	}
	if target.Address.Port() != 443 {
		t.Errorf("StringToTarget().Address.Port() = %d, want %d", target.Address.Port(), 443)
	}
	if target.Host != "example.com" {
		t.Errorf("StringToTarget().Host = %q, want %q", target.Host, "example.com")
	}
}

func TestStringToTarget_InvalidFormat(t *testing.T) {
	tests := []struct {
		input string
		desc  string
	}{
		{"invalid", "missing port"},
		{"1.1.1.1", "no port separator"},
		{"1.1.1.1:abc", "non-numeric port"},
		{"", "empty string"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			_, err := StringToTarget(tt.input, false)
			if err == nil {
				t.Errorf("StringToTarget(%q) expected error, got nil", tt.input)
			}
		})
	}
}

func TestStringsToTargets_SkipsInvalid(t *testing.T) {
	input := []string{
		"1.1.1.1:80",
		"invalid-entry",
		"2.2.2.2:443|example.com",
	}

	result := StringsToTargets(input, true)

	if len(result) != 2 {
		t.Fatalf("StringsToTargets() length = %d, want 2", len(result))
	}
	if result[0].Address.Addr().String() != "1.1.1.1" {
		t.Errorf("StringsToTargets()[0].Address.Addr() = %q, want %q", result[0].Address.Addr().String(), "1.1.1.1")
	}
	if result[1].Address.Addr().String() != "2.2.2.2" {
		t.Errorf("StringsToTargets()[1].Address.Addr() = %q, want %q", result[1].Address.Addr().String(), "2.2.2.2")
	}
}

func TestTargetSerialization_RoundTrip(t *testing.T) {
	original := plugins.Target{
		Address: netip.MustParseAddrPort("93.184.216.34:443"),
		Host:    "example.com",
	}

	serialized := TargetToString(original)
	restored, err := StringToTarget(serialized, false)

	if err != nil {
		t.Fatalf("StringToTarget() unexpected error: %v", err)
	}
	if original.Address != restored.Address {
		t.Errorf("roundtrip Address = %v, want %v", restored.Address, original.Address)
	}
	if original.Host != restored.Host {
		t.Errorf("roundtrip Host = %q, want %q", restored.Host, original.Host)
	}
}

// Test Group 8: FilterPendingTargets

func TestFilterPendingTargets_RemovesCompleted(t *testing.T) {
	allTargets := []plugins.Target{
		{Address: netip.MustParseAddrPort("1.1.1.1:80")},
		{Address: netip.MustParseAddrPort("2.2.2.2:80")},
		{Address: netip.MustParseAddrPort("3.3.3.3:80")},
	}
	completed := []string{"1.1.1.1:80", "3.3.3.3:80"}

	pending := FilterPendingTargets(allTargets, completed)

	if len(pending) != 1 {
		t.Fatalf("FilterPendingTargets() length = %d, want 1", len(pending))
	}
	if pending[0].Address.Addr().String() != "2.2.2.2" {
		t.Errorf("FilterPendingTargets()[0].Address.Addr() = %q, want %q", pending[0].Address.Addr().String(), "2.2.2.2")
	}
}

func TestFilterPendingTargets_PreservesHostname(t *testing.T) {
	allTargets := []plugins.Target{
		{Address: netip.MustParseAddrPort("1.1.1.1:80"), Host: "one.com"},
		{Address: netip.MustParseAddrPort("2.2.2.2:80"), Host: "two.com"},
	}
	completed := []string{"1.1.1.1:80|one.com"}

	pending := FilterPendingTargets(allTargets, completed)

	if len(pending) != 1 {
		t.Fatalf("FilterPendingTargets() length = %d, want 1", len(pending))
	}
	if pending[0].Host != "two.com" {
		t.Errorf("FilterPendingTargets()[0].Host = %q, want %q", pending[0].Host, "two.com")
	}
}

func TestFilterPendingTargets_EmptyCompleted(t *testing.T) {
	allTargets := []plugins.Target{
		{Address: netip.MustParseAddrPort("1.1.1.1:80")},
		{Address: netip.MustParseAddrPort("2.2.2.2:80")},
	}

	pending := FilterPendingTargets(allTargets, []string{})

	if len(pending) != 2 {
		t.Errorf("FilterPendingTargets() length = %d, want 2", len(pending))
	}
}

func TestFilterPendingTargets_AllCompleted(t *testing.T) {
	allTargets := []plugins.Target{
		{Address: netip.MustParseAddrPort("1.1.1.1:80")},
	}
	completed := []string{"1.1.1.1:80"}

	pending := FilterPendingTargets(allTargets, completed)

	if len(pending) != 0 {
		t.Errorf("FilterPendingTargets() length = %d, want 0", len(pending))
	}
}
