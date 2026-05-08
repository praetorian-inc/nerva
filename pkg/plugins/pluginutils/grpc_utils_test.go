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

package pluginutils

import (
	"strings"
	"testing"
)

func TestRawBytesCodec_Marshal(t *testing.T) {
	codec := RawBytesCodec{}

	tests := []struct {
		name      string
		input     interface{}
		wantBytes []byte
		wantErr   bool
		errContains string
	}{
		{
			name:      "valid []byte input returns same bytes",
			input:     []byte{0x01, 0x02, 0x03},
			wantBytes: []byte{0x01, 0x02, 0x03},
			wantErr:   false,
		},
		{
			name:      "empty []byte returns empty bytes",
			input:     []byte{},
			wantBytes: []byte{},
			wantErr:   false,
		},
		{
			name:        "non-[]byte input returns error containing expected []byte",
			input:       "hello",
			wantBytes:   nil,
			wantErr:     true,
			errContains: "expected []byte",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := codec.Marshal(tt.input)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Marshal() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Marshal() error = %q, want error containing %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Errorf("Marshal() unexpected error: %v", err)
				return
			}
			if len(got) != len(tt.wantBytes) {
				t.Errorf("Marshal() len = %d, want %d", len(got), len(tt.wantBytes))
				return
			}
			for i := range got {
				if got[i] != tt.wantBytes[i] {
					t.Errorf("Marshal() byte[%d] = %#x, want %#x", i, got[i], tt.wantBytes[i])
				}
			}
		})
	}
}

func TestRawBytesCodec_Unmarshal(t *testing.T) {
	codec := RawBytesCodec{}

	tests := []struct {
		name        string
		data        []byte
		target      interface{}
		wantErr     bool
		errContains string
		wantData    []byte
	}{
		{
			name:     "valid *[]byte target copies data correctly",
			data:     []byte{0x0a, 0x0b, 0x0c},
			target:   func() *[]byte { b := []byte{}; return &b }(),
			wantErr:  false,
			wantData: []byte{0x0a, 0x0b, 0x0c},
		},
		{
			name:        "non-*[]byte target returns error containing expected *[]byte",
			data:        []byte{0x01},
			target:      func() *string { s := ""; return &s }(),
			wantErr:     true,
			errContains: "expected *[]byte",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := codec.Unmarshal(tt.data, tt.target)
			if tt.wantErr {
				if err == nil {
					t.Errorf("Unmarshal() expected error, got nil")
					return
				}
				if tt.errContains != "" && !strings.Contains(err.Error(), tt.errContains) {
					t.Errorf("Unmarshal() error = %q, want error containing %q", err.Error(), tt.errContains)
				}
				return
			}
			if err != nil {
				t.Errorf("Unmarshal() unexpected error: %v", err)
				return
			}
			// Verify the data was copied into the target
			bp, ok := tt.target.(*[]byte)
			if !ok {
				t.Fatalf("test setup error: target is not *[]byte")
			}
			if len(*bp) != len(tt.wantData) {
				t.Errorf("Unmarshal() data len = %d, want %d", len(*bp), len(tt.wantData))
				return
			}
			for i := range *bp {
				if (*bp)[i] != tt.wantData[i] {
					t.Errorf("Unmarshal() byte[%d] = %#x, want %#x", i, (*bp)[i], tt.wantData[i])
				}
			}
		})
	}
}

func TestRawBytesCodec_Name(t *testing.T) {
	codec := RawBytesCodec{}
	if got := codec.Name(); got != "raw-bytes" {
		t.Errorf("RawBytesCodec.Name() = %q, want %q", got, "raw-bytes")
	}
}
