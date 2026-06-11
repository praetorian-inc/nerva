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

package rdpeudp

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestBuildSYNProbe(t *testing.T) {
	probe := buildSYNProbe()

	if len(probe) != 16 {
		t.Fatalf("expected probe length 16, got %d", len(probe))
	}

	// snSourceAck must be 0xFFFFFFFF
	snSourceAck := binary.LittleEndian.Uint32(probe[0:4])
	if snSourceAck != 0xFFFFFFFF {
		t.Errorf("expected snSourceAck 0xFFFFFFFF, got 0x%08X", snSourceAck)
	}

	// uReceiveWindowSize must be 16
	windowSize := binary.LittleEndian.Uint16(probe[4:6])
	if windowSize != 16 {
		t.Errorf("expected uReceiveWindowSize 16, got %d", windowSize)
	}

	// uFlags must be RDPUDP_FLAG_SYN (0x0001)
	flags := binary.LittleEndian.Uint16(probe[6:8])
	if flags != flagSYN {
		t.Errorf("expected uFlags 0x0001, got 0x%04X", flags)
	}

	// uUpStreamMtu must be 1232
	upMtu := binary.LittleEndian.Uint16(probe[12:14])
	if upMtu != 1232 {
		t.Errorf("expected uUpStreamMtu 1232, got %d", upMtu)
	}

	// uDownStreamMtu must be 1232
	downMtu := binary.LittleEndian.Uint16(probe[14:16])
	if downMtu != 1232 {
		t.Errorf("expected uDownStreamMtu 1232, got %d", downMtu)
	}
}

func TestParseSYNACK_Valid(t *testing.T) {
	// Construct a valid SYN+ACK response (16 bytes minimum)
	resp := make([]byte, 16)
	binary.LittleEndian.PutUint32(resp[0:4], 0x00000001)      // snSourceAck
	binary.LittleEndian.PutUint16(resp[4:6], 32)               // uReceiveWindowSize
	binary.LittleEndian.PutUint16(resp[6:8], flagSYN|flagACK)  // uFlags = SYN+ACK
	binary.LittleEndian.PutUint32(resp[8:12], 0x12345678)      // snInitialSequenceNumber
	binary.LittleEndian.PutUint16(resp[12:14], 1232)           // uUpStreamMtu
	binary.LittleEndian.PutUint16(resp[14:16], 1132)           // uDownStreamMtu

	metadata, ok := parseSYNACK(resp)
	if !ok {
		t.Fatal("expected parseSYNACK to return true for valid SYN+ACK")
	}
	if metadata.UpStreamMtu != 1232 {
		t.Errorf("expected UpStreamMtu 1232, got %d", metadata.UpStreamMtu)
	}
	if metadata.DownStreamMtu != 1132 {
		t.Errorf("expected DownStreamMtu 1132, got %d", metadata.DownStreamMtu)
	}
	if metadata.ProtocolVersion != 0 {
		t.Errorf("expected ProtocolVersion 0 (no SYNEX), got %d", metadata.ProtocolVersion)
	}
}

func TestParseSYNACK_WithSYNEX(t *testing.T) {
	// Construct SYN+ACK with SYNEX payload (20 bytes)
	resp := make([]byte, 20)
	binary.LittleEndian.PutUint32(resp[0:4], 0x00000001)
	binary.LittleEndian.PutUint16(resp[4:6], 32)
	binary.LittleEndian.PutUint16(resp[6:8], flagSYN|flagACK|flagSYNEX) // SYN+ACK+SYNEX
	binary.LittleEndian.PutUint32(resp[8:12], 0x12345678)
	binary.LittleEndian.PutUint16(resp[12:14], 1232)
	binary.LittleEndian.PutUint16(resp[14:16], 1232)
	// SYNDATAEX_PAYLOAD
	binary.LittleEndian.PutUint16(resp[16:18], 0x0001) // uSynExFlags
	binary.LittleEndian.PutUint16(resp[18:20], 0x0002) // uUdpVer = RDPUDP_PROTOCOL_VERSION_2

	metadata, ok := parseSYNACK(resp)
	if !ok {
		t.Fatal("expected parseSYNACK to return true for valid SYN+ACK+SYNEX")
	}
	if metadata.ProtocolVersion != 0x0002 {
		t.Errorf("expected ProtocolVersion 0x0002, got 0x%04X", metadata.ProtocolVersion)
	}
}

func TestParseSYNACK_TooShort(t *testing.T) {
	resp := make([]byte, 10) // too short
	_, ok := parseSYNACK(resp)
	if ok {
		t.Error("expected parseSYNACK to return false for short response")
	}
}

func TestParseSYNACK_NoSYNFlag(t *testing.T) {
	resp := make([]byte, 16)
	binary.LittleEndian.PutUint16(resp[6:8], flagACK) // ACK only, no SYN
	_, ok := parseSYNACK(resp)
	if ok {
		t.Error("expected parseSYNACK to return false when SYN flag missing")
	}
}

func TestParseSYNACK_NoACKFlag(t *testing.T) {
	resp := make([]byte, 16)
	binary.LittleEndian.PutUint16(resp[6:8], flagSYN) // SYN only, no ACK
	_, ok := parseSYNACK(resp)
	if ok {
		t.Error("expected parseSYNACK to return false when ACK flag missing")
	}
}

// TestPlugin_RunWithMockServer tests the full plugin Run method using a mock UDP server.
func TestPlugin_RunWithMockServer(t *testing.T) {
	// Start a mock RDPEUDP server on a random port
	serverAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	serverConn, err := net.ListenUDP("udp", serverAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer serverConn.Close()

	actualAddr := serverConn.LocalAddr().(*net.UDPAddr)

	// Mock server: read probe, respond with SYN+ACK
	go func() {
		buf := make([]byte, 1024)
		n, addr, err := serverConn.ReadFromUDP(buf)
		if err != nil || n == 0 {
			return
		}

		resp := make([]byte, 1232) // Pad to typical RDPEUDP MTU size
		binary.LittleEndian.PutUint32(resp[0:4], 0x00000001)
		binary.LittleEndian.PutUint16(resp[4:6], 32)
		binary.LittleEndian.PutUint16(resp[6:8], flagSYN|flagACK|flagSYNEX)
		binary.LittleEndian.PutUint32(resp[8:12], 0xDEADBEEF)
		binary.LittleEndian.PutUint16(resp[12:14], 1232)
		binary.LittleEndian.PutUint16(resp[14:16], 1232)
		binary.LittleEndian.PutUint16(resp[16:18], 0x0001)
		binary.LittleEndian.PutUint16(resp[18:20], 0x0101) // Version 3

		serverConn.WriteToUDP(resp, addr)
	}()

	// Connect to mock server
	conn, err := net.Dial("udp", actualAddr.String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	p := &Plugin{}
	target := plugins.Target{}
	service, err := p.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if service == nil {
		t.Fatal("Run returned nil service")
	}
	if service.Protocol != "rdpeudp" {
		t.Errorf("expected protocol rdpeudp, got %s", service.Protocol)
	}
}
