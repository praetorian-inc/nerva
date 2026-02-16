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

package ethercat

import (
	"encoding/binary"
	"testing"
)

func TestBuildBroadcastReadProbe(t *testing.T) {
	probe := buildBroadcastReadProbe()

	// Test 1: Probe should be exactly 14 bytes
	if len(probe) != 14 {
		t.Errorf("Expected probe length 14, got %d", len(probe))
	}

	// Test 2: Frame header (first 2 bytes)
	// Bits 0-10: Length (12 bytes for datagram)
	// Bits 14-15: Type (1 = EtherCAT commands)
	frameHeader := binary.LittleEndian.Uint16(probe[0:2])
	length := frameHeader & 0x7FF // Lower 11 bits
	frameType := (frameHeader >> 14) & 0x03 // Upper 2 bits

	if length != 12 {
		t.Errorf("Expected frame length 12, got %d", length)
	}
	if frameType != 1 {
		t.Errorf("Expected frame type 1 (EtherCAT), got %d", frameType)
	}

	// Test 3: Datagram header
	cmd := probe[2]
	if cmd != 0x07 {
		t.Errorf("Expected command 0x07 (BRD), got 0x%02x", cmd)
	}

	// ADP should be 0x0000
	adp := binary.LittleEndian.Uint16(probe[4:6])
	if adp != 0x0000 {
		t.Errorf("Expected ADP 0x0000, got 0x%04x", adp)
	}

	// ADO should be 0x0000
	ado := binary.LittleEndian.Uint16(probe[6:8])
	if ado != 0x0000 {
		t.Errorf("Expected ADO 0x0000, got 0x%04x", ado)
	}

	// Length field should be 0x0000 (0 data bytes)
	lengthField := binary.LittleEndian.Uint16(probe[8:10])
	dataLen := lengthField & 0x7FF
	if dataLen != 0 {
		t.Errorf("Expected data length 0, got %d", dataLen)
	}

	// IRQ should be 0x0000
	irq := binary.LittleEndian.Uint16(probe[10:12])
	if irq != 0x0000 {
		t.Errorf("Expected IRQ 0x0000, got 0x%04x", irq)
	}

	// Working Counter should be 0x0000
	wc := binary.LittleEndian.Uint16(probe[12:14])
	if wc != 0x0000 {
		t.Errorf("Expected working counter 0x0000, got 0x%04x", wc)
	}
}

func TestIsValidEtherCATResponse(t *testing.T) {
	tests := []struct {
		name     string
		response []byte
		index    byte
		want     bool
	}{
		{
			name:     "empty response",
			response: []byte{},
			index:    0x42,
			want:     false,
		},
		{
			name:     "too short response",
			response: []byte{0x0C, 0x40, 0x07},
			index:    0x42,
			want:     false,
		},
		{
			name: "valid response with working counter > 0",
			response: []byte{
				0x0C, 0x40, // Frame header (length=12, type=1)
				0x07, 0x42, // Cmd=BRD, Index matches
				0x00, 0x00, // ADP
				0x00, 0x00, // ADO
				0x00, 0x00, // Length/Flags
				0x00, 0x00, // IRQ
				0x01, 0x00, // Working counter = 1 (device responded)
			},
			index: 0x42,
			want:  true,
		},
		{
			name: "invalid frame type",
			response: []byte{
				0x0C, 0x00, // Frame header (type=0, not EtherCAT)
				0x07, 0x42,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x01, 0x00,
			},
			index: 0x42,
			want:  false,
		},
		{
			name: "wrong index",
			response: []byte{
				0x0C, 0x40,
				0x07, 0x99, // Index doesn't match
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x01, 0x00,
			},
			index: 0x42,
			want:  false,
		},
		{
			name: "working counter = 0",
			response: []byte{
				0x0C, 0x40,
				0x07, 0x42,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00, // Working counter = 0 (no slaves processed)
			},
			index: 0x42,
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isValidEtherCATResponse(tt.response, tt.index)
			if got != tt.want {
				t.Errorf("isValidEtherCATResponse() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseEtherCATResponse(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantWC  uint16
		wantCnt int
	}{
		{
			name:    "empty response",
			data:    []byte{},
			wantWC:  0,
			wantCnt: 0,
		},
		{
			name: "single datagram with WC=1",
			data: []byte{
				0x0C, 0x40, // Frame header
				0x07, 0x42, // Cmd, Index
				0x00, 0x00, // ADP
				0x00, 0x00, // ADO
				0x00, 0x00, // Length/Flags (M flag = 0, no more datagrams)
				0x00, 0x00, // IRQ
				0x01, 0x00, // Working counter = 1
			},
			wantWC:  1,
			wantCnt: 1,
		},
		{
			name: "single datagram with WC=3",
			data: []byte{
				0x0C, 0x40,
				0x07, 0x42,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00,
				0x03, 0x00, // Working counter = 3
			},
			wantWC:  3,
			wantCnt: 1,
		},
		{
			name: "multiple datagrams (M flag set)",
			data: []byte{
				// First datagram
				0x1C, 0x10, // Frame header (length includes both datagrams)
				0x07, 0x42,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x80, // M flag set (bit 15)
				0x00, 0x00,
				0x02, 0x00, // WC = 2
				// Second datagram
				0x07, 0x43,
				0x00, 0x00,
				0x00, 0x00,
				0x00, 0x00, // M flag not set (last datagram)
				0x00, 0x00,
				0x01, 0x00, // WC = 1
			},
			wantWC:  1, // Should return WC of last datagram
			wantCnt: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wc, cnt := parseEtherCATResponse(tt.data)
			if wc != tt.wantWC {
				t.Errorf("parseEtherCATResponse() working counter = %d, want %d", wc, tt.wantWC)
			}
			if cnt != tt.wantCnt {
				t.Errorf("parseEtherCATResponse() datagram count = %d, want %d", cnt, tt.wantCnt)
			}
		})
	}
}
