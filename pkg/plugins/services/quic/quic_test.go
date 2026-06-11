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

package quic

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestBuildVersionNegotiationProbe(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	probe := buildVersionNegotiationProbe(dcid)

	if len(probe) != minDatagram {
		t.Fatalf("expected probe length %d, got %d", minDatagram, len(probe))
	}

	// Long header form
	if probe[0]&0x80 == 0 {
		t.Error("expected high bit set (long header form)")
	}

	// Invalid version 0xBABABABA
	if probe[1] != 0xBA || probe[2] != 0xBA || probe[3] != 0xBA || probe[4] != 0xBA {
		t.Errorf("expected version 0xBABABABA, got 0x%02X%02X%02X%02X",
			probe[1], probe[2], probe[3], probe[4])
	}

	// DCID length
	if probe[5] != 8 {
		t.Errorf("expected DCID length 8, got %d", probe[5])
	}

	// DCID matches
	for i := 0; i < 8; i++ {
		if probe[6+i] != dcid[i] {
			t.Errorf("DCID byte %d: expected 0x%02X, got 0x%02X", i, dcid[i], probe[6+i])
		}
	}

	// SCID length = 0
	if probe[14] != 0 {
		t.Errorf("expected SCID length 0, got %d", probe[14])
	}
}

func TestParseVersionNegotiation_Valid(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Construct a valid Version Negotiation response
	resp := []byte{
		0x80,                   // Long header form
		0x00, 0x00, 0x00, 0x00, // Version = 0 (Version Negotiation)
		0x00,                   // DCID Length = 0 (echoed SCID from probe = empty)
		0x08,                   // SCID Length = 8 (echoed DCID from probe)
	}
	resp = append(resp, dcid...) // Echoed DCID

	// Supported versions
	v1 := make([]byte, 4)
	binary.BigEndian.PutUint32(v1, 0x00000001) // QUIC v1
	resp = append(resp, v1...)

	v2 := make([]byte, 4)
	binary.BigEndian.PutUint32(v2, 0x6B3343CF) // QUIC v2
	resp = append(resp, v2...)

	metadata, ok := parseVersionNegotiation(resp, dcid)
	if !ok {
		t.Fatal("expected parseVersionNegotiation to return true for valid VN response")
	}
	if len(metadata.SupportedVersions) != 2 {
		t.Fatalf("expected 2 supported versions, got %d", len(metadata.SupportedVersions))
	}
	if metadata.SupportedVersions[0] != "QUICv1" {
		t.Errorf("expected QUICv1, got %s", metadata.SupportedVersions[0])
	}
	if metadata.SupportedVersions[1] != "QUICv2" {
		t.Errorf("expected QUICv2, got %s", metadata.SupportedVersions[1])
	}
}

func TestParseVersionNegotiation_UnknownVersion(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	resp := []byte{
		0x80,
		0x00, 0x00, 0x00, 0x00,
		0x00,
		0x08,
	}
	resp = append(resp, dcid...)

	v := make([]byte, 4)
	binary.BigEndian.PutUint32(v, 0xDEADBEEF) // Unknown version
	resp = append(resp, v...)

	metadata, ok := parseVersionNegotiation(resp, dcid)
	if !ok {
		t.Fatal("expected parseVersionNegotiation to return true")
	}
	if len(metadata.SupportedVersions) != 1 {
		t.Fatalf("expected 1 version, got %d", len(metadata.SupportedVersions))
	}
	if metadata.SupportedVersions[0] != "0xDEADBEEF" {
		t.Errorf("expected 0xDEADBEEF, got %s", metadata.SupportedVersions[0])
	}
}

func TestParseVersionNegotiation_TooShort(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	resp := []byte{0x80, 0x00, 0x00, 0x00, 0x00} // Too short
	_, ok := parseVersionNegotiation(resp, dcid)
	if ok {
		t.Error("expected parseVersionNegotiation to return false for short response")
	}
}

func TestParseVersionNegotiation_NonZeroVersion(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	resp := []byte{
		0x80,
		0x00, 0x00, 0x00, 0x01, // Version = 1 (not a VN packet)
		0x00,
		0x08,
	}
	resp = append(resp, dcid...)
	resp = append(resp, 0x00, 0x00, 0x00, 0x01)
	_, ok := parseVersionNegotiation(resp, dcid)
	if ok {
		t.Error("expected parseVersionNegotiation to return false for non-VN packet")
	}
}

func TestParseVersionNegotiation_ShortHeader(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	resp := []byte{
		0x40,                   // Short header (high bit NOT set)
		0x00, 0x00, 0x00, 0x00,
		0x00,
		0x08,
	}
	resp = append(resp, dcid...)
	resp = append(resp, 0x00, 0x00, 0x00, 0x01)
	_, ok := parseVersionNegotiation(resp, dcid)
	if ok {
		t.Error("expected parseVersionNegotiation to return false for short header form")
	}
}

func TestParseVersionNegotiation_WrongDCID(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}
	wrongDCID := []byte{0xFF, 0xFE, 0xFD, 0xFC, 0xFB, 0xFA, 0xF9, 0xF8}

	resp := []byte{
		0x80,
		0x00, 0x00, 0x00, 0x00,
		0x00,
		0x08,
	}
	resp = append(resp, wrongDCID...) // Different DCID than what we sent
	resp = append(resp, 0x00, 0x00, 0x00, 0x01)
	_, ok := parseVersionNegotiation(resp, dcid)
	if ok {
		t.Error("expected parseVersionNegotiation to return false for mismatched DCID")
	}
}

func TestParseVersionNegotiation_SCIDLengthMismatch(t *testing.T) {
	dcid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

	// Response echoes only 4 bytes of SCID when we sent 8-byte DCID
	resp := []byte{
		0x80,
		0x00, 0x00, 0x00, 0x00,
		0x00,       // DCID Length
		0x04,       // SCID Length = 4 (does not match our DCID length of 8)
		0x01, 0x02, 0x03, 0x04, // Partial echo
	}
	resp = append(resp, 0x00, 0x00, 0x00, 0x01) // version
	_, ok := parseVersionNegotiation(resp, dcid)
	if ok {
		t.Error("expected parseVersionNegotiation to return false for SCID length mismatch")
	}
}

// TestPlugin_RunWithMockServer tests the full Run method using a mock QUIC VN server.
func TestPlugin_RunWithMockServer(t *testing.T) {
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

	// Mock server: read probe, respond with Version Negotiation
	go func() {
		buf := make([]byte, 2048)
		n, addr, err := serverConn.ReadFromUDP(buf)
		if err != nil || n < 15 {
			return
		}

		probe := buf[:n]
		// Extract DCID from probe
		dcidLen := int(probe[5])
		if 6+dcidLen > n {
			return
		}
		probeDCID := probe[6 : 6+dcidLen]

		// Build Version Negotiation response
		resp := []byte{
			0x80,
			0x00, 0x00, 0x00, 0x00, // Version = 0
			0x00, // DCID Length (echo SCID = 0)
		}
		resp = append(resp, byte(dcidLen)) // SCID Length (echo DCID length)
		resp = append(resp, probeDCID...)  // SCID (echo DCID)
		// Supported versions
		v := make([]byte, 4)
		binary.BigEndian.PutUint32(v, 0x00000001)
		resp = append(resp, v...)

		serverConn.WriteToUDP(resp, addr)
	}()

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
	if service.Protocol != "quic" {
		t.Errorf("expected protocol quic, got %s", service.Protocol)
	}
}
