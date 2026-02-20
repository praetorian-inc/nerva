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

package dhcp

import (
	"testing"

	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestDHCP(t *testing.T) {
	// cwd, err := os.Getwd()
	// if err != nil {
	// 	t.Fatalf("failed to get current directory")
	// }
	// TODO more work is required to get this test working locally
	testcases := []test.Testcase{
		// {
		// 	Description: "dhcp",
		// 	Port:        67,
		// 	Protocol:    plugins.UDP,
		// 	Expected: func(res *plugins.PluginResults) bool {
		// 		return res != nil
		// 	},
		// 	RunConfig: dockertest.RunOptions{
		// 		Repository:   "wastrachan/dhcpd",
		// 		Mounts:       []string{fmt.Sprintf("%s/dhcpd.conf:/config/dhcpd.conf", cwd)},
		// 		ExposedPorts: []string{"67/udp"},
		// 	},
		// },
	}

	var p *Plugin

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%s", err.Error())
			}
		})
	}
}

// TestHostnameParseOverflow tests that hostnameParse handles malicious length values
func TestHostnameParseOverflow(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		wantErr bool
	}{
		{
			name:    "length exceeds buffer at line 196",
			input:   []byte{0x00, 0xFF, 0x01, 0x02}, // options[1]=0xFF (255), but only 2 bytes follow
			wantErr: false,                           // should not panic, return empty
		},
		{
			name:    "truncated option",
			input:   []byte{0x00, 0x10}, // claims 16 bytes but none provided
			wantErr: false,               // should not panic
		},
		{
			name:    "length causes integer overflow",
			input:   []byte{0x00, 0x80, 0x01}, // large length with minimal data
			wantErr: false,
		},
		{
			name:    "compression pointer out of bounds at line 217",
			input:   []byte{0x00, 0x05, 0x03, 0x66, 0x6f, 0x6f, 0xc0, 0xFF}, // compression pointer to 0xFF
			wantErr: false,                                                   // should not panic
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("hostnameParse panicked: %v", r)
				}
			}()
			result := hostnameParse(tt.input)
			// Result should be empty or valid, not panic
			_ = result
		})
	}
}

// TestIPParseOverflow tests that ipParse handles malicious length values
func TestIPParseOverflow(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{
			name:  "length exceeds buffer",
			input: []byte{0x00, 0xFF}, // options[1]=0xFF (255 bytes), but no data follows
		},
		{
			name:  "truncated IP data",
			input: []byte{0x00, 0x08, 0x01, 0x02}, // claims 8 bytes (2 IPs) but only 2 bytes
		},
		{
			name:  "length not multiple of 4",
			input: []byte{0x00, 0x05, 0x01}, // 5 bytes is not valid for IPs
		},
		{
			name:  "large length value",
			input: []byte{0x00, 0x80}, // 128 bytes claimed
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("ipParse panicked: %v", r)
				}
			}()
			result := ipParse(tt.input)
			// Result should be empty or valid, not panic
			_ = result
		})
	}
}
