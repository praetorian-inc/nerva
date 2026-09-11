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

package dnp3

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TestCRCKnownVectors pins calculateDNP3CRC against headers captured from real
// DNP3 devices. The expected values come from the captures themselves, not from
// calculateDNP3CRC, so this fails if the algorithm or the byte range regresses.
func TestCRCKnownVectors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		header   []byte
		expected uint16
	}{
		{
			// Internet-facing outstation observed via Shodan. The frame carries
			// CRC 0x4c36 in its last two bytes (little-endian 0x36 0x4c).
			name:     "captured outstation frame",
			header:   []byte{0x05, 0x64, 0x05, 0xc9, 0x00, 0x00, 0x00, 0x00},
			expected: 0x4c36,
		},
		{
			// Link Status reply (function 0x0b) from an outstation at address 4.
			name:     "link status reply",
			header:   []byte{0x05, 0x64, 0x05, 0x0b, 0x01, 0x00, 0x00, 0x04},
			expected: 0x4064,
		},
		{
			// Unsolicited response some outstations push on connect.
			name:     "unsolicited response",
			header:   []byte{0x05, 0x64, 0x0a, 0x44, 0x01, 0x00, 0x00, 0x00},
			expected: 0x511f,
		},
		{
			name:     "empty data",
			header:   []byte{},
			expected: 0xFFFF,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, calculateDNP3CRC(tc.header),
				"CRC must be computed over every header byte, including both start bytes")
		})
	}
}

// TestParseCapturedFrame validates structure parsing against a real capture.
func TestParseCapturedFrame(t *testing.T) {
	t.Parallel()

	// 05 64 05 c9 00 00 00 00 36 4c
	//   0x05 0x64 = start bytes
	//   0x05      = length
	//   0xc9      = control: DIR=1, PRM=1, FCB=0, FCV=0, func=0x09
	//   0x00 0x00 = destination address
	//   0x00 0x00 = source address
	//   0x36 0x4c = header CRC (little-endian 0x4c36)
	frame := []byte{0x05, 0x64, 0x05, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x36, 0x4c}

	assert.Equal(t, byte(DNP3StartByte1), frame[0])
	assert.Equal(t, byte(DNP3StartByte2), frame[1])
	assert.GreaterOrEqual(t, len(frame), DNP3MinLength)
	assert.True(t, validHeaderCRC(frame), "captured frame must pass CRC validation")

	assert.Equal(t, "master", parseDeviceRole(frame), "DIR=1 indicates a master")

	controlByte := frame[3]
	assert.True(t, controlByte&CtrlDIR != 0, "DIR bit should be set")
	assert.True(t, controlByte&CtrlPRM != 0, "PRM bit should be set")
	assert.Equal(t, byte(FuncRequestLinkStatus), controlByte&FuncCodeMask)
}

func TestValidHeaderCRC(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		frame []byte
		want  bool
	}{
		{
			name:  "correct CRC",
			frame: []byte{0x05, 0x64, 0x05, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x36, 0x4c},
			want:  true,
		},
		{
			name:  "corrupted CRC",
			frame: []byte{0x05, 0x64, 0x05, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
			want:  false,
		},
		{
			// CRC over frame[1:8] instead of the full header.
			name:  "CRC over the wrong byte range",
			frame: []byte{0x05, 0x64, 0x05, 0xc9, 0x00, 0x00, 0x00, 0x00, 0x6c, 0x02},
			want:  false,
		},
		{
			name:  "too short",
			frame: []byte{0x05, 0x64, 0x05},
			want:  false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, validHeaderCRC(tc.frame))
		})
	}
}

func TestParseDeviceRole(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		response []byte
		expected string
	}{
		{"master (DIR=1)", []byte{0x05, 0x64, 0x05, 0xc9}, "master"},
		{"outstation (DIR=0)", []byte{0x05, 0x64, 0x05, 0x49}, "outstation"},
		{"too short frame", []byte{0x05, 0x64}, "unknown"},
		{"empty frame", []byte{}, "unknown"},
		{"all control bits set", []byte{0x05, 0x64, 0x05, 0xFF}, "master"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.expected, parseDeviceRole(tc.response))
		})
	}
}

// TestBuildRequestLinkStatusProbe verifies the probe is a frame a conforming
// outstation will accept: master direction and a valid full-header CRC.
func TestBuildRequestLinkStatusProbe(t *testing.T) {
	t.Parallel()

	probe, err := buildRequestLinkStatusProbe()
	require.NoError(t, err)
	require.Len(t, probe, DNP3MinLength)

	assert.Equal(t, byte(DNP3StartByte1), probe[0])
	assert.Equal(t, byte(DNP3StartByte2), probe[1])
	assert.Equal(t, byte(0x05), probe[2], "length byte should be 0x05")

	assert.Equal(t, byte(CtrlDIR|CtrlPRM|FuncRequestLinkStatus), probe[3],
		"probe must be a master-direction Request Link Status (0xC9)")
	assert.True(t, probe[3]&CtrlDIR != 0, "DIR must be set or outstations ignore the probe")

	assert.Equal(t, byte(0x00), probe[4])
	assert.Equal(t, byte(0x00), probe[5])

	srcAddr := uint16(probe[6]) | (uint16(probe[7]) << 8)
	assert.NotEqual(t, uint16(0), srcAddr)
	assert.NotEqual(t, uint16(0xFFFF), srcAddr)

	assert.True(t, validHeaderCRC(probe), "probe must carry a valid header CRC")
}

// buildLinkStatusResponse creates a Link Status reply from an outstation.
func buildLinkStatusResponse() []byte {
	frame := []byte{
		0x05, 0x64, // Start bytes
		0x05,       // Length
		0x0b,       // Control: DIR=0, PRM=0, func=0x0b (Link Status)
		0x01, 0x00, // Destination address
		0x00, 0x04, // Source address (outstation)
	}
	crc := calculateDNP3CRC(frame)
	return append(frame, byte(crc&0xFF), byte(crc>>8))
}

// buildMasterDNP3Response creates a valid frame with DIR set (master role).
func buildMasterDNP3Response() []byte {
	frame := []byte{
		0x05, 0x64,
		0x05,
		0x80,       // Control: DIR=1
		0x01, 0x00, // Destination address
		0x00, 0x00, // Source address
	}
	crc := calculateDNP3CRC(frame)
	return append(frame, byte(crc&0xFF), byte(crc>>8))
}

// corruptCRC returns frame with its trailing CRC invalidated.
func corruptCRC(frame []byte) []byte {
	out := append([]byte{}, frame...)
	out[len(out)-1] ^= 0xFF
	return out
}

// runAgainstResponse drives the plugin against a canned server response.
func runAgainstResponse(t *testing.T, response []byte, misconfigs bool) *plugins.Service {
	t.Helper()

	server, client := net.Pipe()
	go func() {
		buf := make([]byte, 256)
		if _, err := server.Read(buf); err != nil {
			return
		}
		if len(response) > 0 {
			_, _ = server.Write(response)
		}
		server.Close()
	}()

	addr := netip.MustParseAddrPort("127.0.0.1:20000")
	target := plugins.Target{Host: "127.0.0.1", Address: addr, Misconfigs: misconfigs}

	service, err := (&DNP3Plugin{}).Run(client, 5*time.Second, target)
	if err != nil {
		return nil
	}
	return service
}

func TestRunDetection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		response      []byte
		expectService bool
		expectRole    string
		expectFunc    uint8
	}{
		{
			name:          "link status reply",
			response:      buildLinkStatusResponse(),
			expectService: true,
			expectRole:    "outstation",
			expectFunc:    0x0b,
		},
		{
			name:          "master direction reply",
			response:      buildMasterDNP3Response(),
			expectService: true,
			expectRole:    "master",
			expectFunc:    0x00,
		},
		{
			name:          "start bytes but corrupted CRC",
			response:      corruptCRC(buildLinkStatusResponse()),
			expectService: false,
		},
		{
			// Unrelated binary service that happens to begin with 0x05 0x64.
			name:          "start bytes with random payload",
			response:      []byte{0x05, 0x64, 0xde, 0xad, 0xbe, 0xef, 0x00, 0x11, 0x22, 0x33},
			expectService: false,
		},
		{
			name:          "invalid start bytes",
			response:      []byte{0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00},
			expectService: false,
		},
		{
			name:          "too short response",
			response:      []byte{0x05, 0x64, 0x05},
			expectService: false,
		},
		{
			name:          "empty response",
			response:      []byte{},
			expectService: false,
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			service := runAgainstResponse(t, tc.response, false)
			if !tc.expectService {
				require.Nil(t, service, "must not report a service")
				return
			}

			require.NotNil(t, service)
			meta, ok := service.Metadata().(plugins.ServiceDNP3)
			require.True(t, ok, "expected ServiceDNP3 metadata, got %T", service.Metadata())
			assert.Equal(t, tc.expectRole, meta.DeviceRole)
			assert.Equal(t, tc.expectFunc, meta.FunctionCode,
				"function code must come from the response, not from the probe")
		})
	}
}

func TestDNP3SecurityFinding(t *testing.T) {
	t.Parallel()

	service := runAgainstResponse(t, buildLinkStatusResponse(), true)
	require.NotNil(t, service)

	assert.True(t, service.AnonymousAccess)
	require.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "dnp3-no-auth", service.SecurityFindings[0].ID)
	assert.Equal(t, plugins.SeverityHigh, service.SecurityFindings[0].Severity)
}

// TestDNP3SecurityFindingMasterResponse verifies findings regardless of role.
func TestDNP3SecurityFindingMasterResponse(t *testing.T) {
	t.Parallel()

	service := runAgainstResponse(t, buildMasterDNP3Response(), true)
	require.NotNil(t, service)

	assert.True(t, service.AnonymousAccess)
	require.Len(t, service.SecurityFindings, 1)
	assert.Equal(t, "dnp3-no-auth", service.SecurityFindings[0].ID)

	meta, ok := service.Metadata().(plugins.ServiceDNP3)
	require.True(t, ok)
	assert.Equal(t, "master", meta.DeviceRole)
}

func TestDNP3NoSecurityFinding(t *testing.T) {
	t.Parallel()

	service := runAgainstResponse(t, buildLinkStatusResponse(), false)
	require.NotNil(t, service)

	assert.False(t, service.AnonymousAccess)
	assert.Empty(t, service.SecurityFindings)
}

func TestPluginMetadata(t *testing.T) {
	t.Parallel()

	p := &DNP3Plugin{}
	assert.Equal(t, DNP3, p.Name())
	assert.Equal(t, plugins.TCP, p.Type())
	assert.Equal(t, 400, p.Priority())
	assert.True(t, p.PortPriority(20000))
	assert.False(t, p.PortPriority(502))
}
