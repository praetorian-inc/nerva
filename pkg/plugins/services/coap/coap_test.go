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

package coap

import (
	"testing"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestCoAP(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "coap",
			Port:        5683,
			Protocol:    plugins.UDP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository:   "opensourcefoundries/californium",
				ExposedPorts: []string{"5683/udp"},
			},
		},
	}

	var p *CoAPPlugin

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

func TestExtractPayload(t *testing.T) {
	tests := []struct {
		name            string
		response        []byte
		wantResources   string
		wantVersion     string
	}{
		{
			name:          "response too short - less than 4 bytes",
			response:      []byte{0x40, 0x01, 0x00},
			wantResources: "",
			wantVersion:   "",
		},
		{
			name:          "empty response",
			response:      []byte{},
			wantResources: "",
			wantVersion:   "",
		},
		{
			// Header only, no options, no payload marker.
			// TKL=0, so idx starts at 4 which equals len(response) — loop
			// never executes and we fall through to the "no payload" check.
			name:          "header only no payload marker",
			response:      []byte{0x40, 0x45, 0x00, 0x01},
			wantResources: "",
			wantVersion:   "",
		},
		{
			// Minimal valid packet: 4-byte header + 0xFF + payload "hello".
			// TKL=0, no options. Payload marker immediately follows header.
			name:          "payload marker with content",
			response:      []byte{0x40, 0x45, 0x00, 0x01, 0xFF, 'h', 'e', 'l', 'l', 'o'},
			wantResources: "hello",
			wantVersion:   "",
		},
		{
			// Payload contains "Cf 3.7.0" — version should be extracted.
			name:          "payload with Californium version string",
			response:      []byte{0x40, 0x45, 0x00, 0x01, 0xFF, 'C', 'f', ' ', '3', '.', '7', '.', '0'},
			wantResources: "Cf 3.7.0",
			wantVersion:   "3.7.0",
		},
		{
			// Version string followed by trailing text after a space.
			// "Cf 3.8.0 eclipse" → version should be "3.8.0", not "3.8.0 eclipse".
			name: "Californium version with trailing text after whitespace",
			response: []byte{
				0x40, 0x45, 0x00, 0x01, 0xFF,
				'C', 'f', ' ', '3', '.', '8', '.', '0', ' ', 'e', 'c', 'l', 'i', 'p', 's', 'e',
			},
			wantResources: "Cf 3.8.0 eclipse",
			wantVersion:   "3.8.0",
		},
		{
			// TKL=2 means 2 token bytes follow the fixed 4-byte header before
			// options begin. The loop should skip the token and then find 0xFF.
			name: "token bytes TKL=2 then payload marker",
			response: []byte{
				0x42,       // Ver=1, Type=CON, TKL=2
				0x45, 0x00, 0x01, // code, msgID
				0xAB, 0xCD, // 2 token bytes
				0xFF,                // payload marker
				'o', 'k',
			},
			wantResources: "ok",
			wantVersion:   "",
		},
		{
			// deltaNibble=13: one extra byte consumed for delta extension.
			// Option byte: 0xD0 (delta=13, length=0). Next byte is the extended
			// delta value (ignored). No option value bytes. Then 0xFF + payload.
			name: "option with extended delta nibble 13",
			response: []byte{
				0x40, 0x45, 0x00, 0x01, // header, TKL=0
				0xD0, // delta nibble=13, length nibble=0
				0x05, // extended delta byte (value+13 = actual delta, but we just skip it)
				// no option value (length=0)
				0xFF,
				'p', 'a', 'y',
			},
			wantResources: "pay",
			wantVersion:   "",
		},
		{
			// deltaNibble=14: two extra bytes consumed for delta extension.
			// Option byte: 0xE0 (delta=14, length=0). Next 2 bytes are the
			// extended delta value. No option value bytes. Then 0xFF + payload.
			name: "option with extended delta nibble 14",
			response: []byte{
				0x40, 0x45, 0x00, 0x01, // header, TKL=0
				0xE0,       // delta nibble=14, length nibble=0
				0x00, 0x01, // 2 extended delta bytes
				// no option value (length=0)
				0xFF,
				'd', 'a', 't', 'a',
			},
			wantResources: "data",
			wantVersion:   "",
		},
		{
			// deltaNibble=15 is reserved and must return ("", "").
			name:          "option with reserved delta nibble 15",
			response:      []byte{0x40, 0x45, 0x00, 0x01, 0xF0},
			wantResources: "",
			wantVersion:   "",
		},
		{
			// lengthNibble=13: optLen = byte value + 13.
			// Option byte: 0x0D (delta nibble=0, length nibble=13).
			// Next byte is 0x00 → optLen = 0 + 13 = 13. Skip 13 option value bytes.
			name: "option with extended length nibble 13",
			response: append(
				[]byte{
					0x40, 0x45, 0x00, 0x01, // header, TKL=0
					0x0D, // delta nibble=0, length nibble=13
					0x00, // extended length byte: optLen = 0+13 = 13
				},
				append(make([]byte, 13), 0xFF, 'L', '1', '3')..., // 13 option bytes + marker + payload
			),
			wantResources: "L13",
			wantVersion:   "",
		},
		{
			// lengthNibble=14: optLen = uint16 big-endian value + 269.
			// Option byte: 0x0E (delta nibble=0, length nibble=14).
			// Next 2 bytes: 0x00,0x00 → optLen = 0+269 = 269. Skip 269 bytes.
			name: "option with extended length nibble 14",
			response: append(
				[]byte{
					0x40, 0x45, 0x00, 0x01, // header, TKL=0
					0x0E,       // delta nibble=0, length nibble=14
					0x00, 0x00, // extended length: uint16=0 → optLen=269
				},
				append(make([]byte, 269), 0xFF, 'L', '1', '4')..., // 269 option bytes + marker + payload
			),
			wantResources: "L14",
			wantVersion:   "",
		},
		{
			// lengthNibble=15 is reserved and must return ("", "").
			name:          "option with reserved length nibble 15",
			response:      []byte{0x40, 0x45, 0x00, 0x01, 0x0F},
			wantResources: "",
			wantVersion:   "",
		},
		{
			// deltaNibble=13 but no extra byte available → truncated, return ("", "").
			name:          "truncated extended delta 13 no extra byte",
			response:      []byte{0x40, 0x45, 0x00, 0x01, 0xD0},
			wantResources: "",
			wantVersion:   "",
		},
		{
			// deltaNibble=14 but only 1 byte remains (need 2) → truncated.
			name:          "truncated extended delta 14 only one byte available",
			response:      []byte{0x40, 0x45, 0x00, 0x01, 0xE0, 0x00},
			wantResources: "",
			wantVersion:   "",
		},
		{
			// lengthNibble=13 but no extra byte available → truncated.
			// delta nibble=0, length nibble=13 → needs 1 more byte for extended length.
			name:          "truncated extended length 13 no extra byte",
			response:      []byte{0x40, 0x45, 0x00, 0x01, 0x0D},
			wantResources: "",
			wantVersion:   "",
		},
		{
			// lengthNibble=14 but only 1 byte remains (need 2) → truncated.
			name:          "truncated extended length 14 only one byte available",
			response:      []byte{0x40, 0x45, 0x00, 0x01, 0x0E, 0x00},
			wantResources: "",
			wantVersion:   "",
		},
		{
			// Option value length extends past end of response → out-of-bounds, return ("", "").
			// Option byte: 0x05 (delta=0, length=5). Only 2 bytes remain after the
			// option header, but we need 5 → idx+optLen > len(response).
			name:          "option value exceeds response length",
			response:      []byte{0x40, 0x45, 0x00, 0x01, 0x05, 0xAA, 0xBB},
			wantResources: "",
			wantVersion:   "",
		},
		{
			// 0xFF is the last byte — payload marker present but nothing after it.
			name:          "payload marker at end with no payload after it",
			response:      []byte{0x40, 0x45, 0x00, 0x01, 0xFF},
			wantResources: "",
			wantVersion:   "",
		},
		{
			// Two options then a payload marker then content.
			// Option 1: byte 0x03 → delta nibble=0, length nibble=3 → skip 3 bytes.
			// Option 2: byte 0x02 → delta nibble=0, length nibble=2 → skip 2 bytes.
			// Then 0xFF + "multi".
			name: "multiple options then payload",
			response: []byte{
				0x40, 0x45, 0x00, 0x01, // header, TKL=0
				0x03, 0xAA, 0xBB, 0xCC, // option 1: length=3, 3 value bytes
				0x02, 0xDD, 0xEE, // option 2: length=2, 2 value bytes
				0xFF,
				'm', 'u', 'l', 't', 'i',
			},
			wantResources: "multi",
			wantVersion:   "",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			gotResources, gotVersion := extractPayload(tt.response)
			if gotResources != tt.wantResources {
				t.Errorf("extractPayload() resources = %q, want %q", gotResources, tt.wantResources)
			}
			if gotVersion != tt.wantVersion {
				t.Errorf("extractPayload() version = %q, want %q", gotVersion, tt.wantVersion)
			}
		})
	}
}
