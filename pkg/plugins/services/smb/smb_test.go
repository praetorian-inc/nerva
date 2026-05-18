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

package smb

import (
	"encoding/binary"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestSMB(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "smb",
			Port:        445,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "dperson/samba",
				Cmd:        []string{"-S"},
			},
		},
	}

	p := &SMBPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

// buildSMBv2SessionSetupResponse builds a minimal SMBv2 SESSION_SETUP response
// with the given NTSTATUS and SessionID for use in mock tests.
func buildSMBv2SessionSetupResponse(status uint32, sessionID uint64) []byte {
	// 4 NetBIOS + 64 SMB2 header + 9 (Session Setup Response body)
	const smb2Len = 64 + 9
	pkt := make([]byte, 4+smb2Len)
	pkt[0] = 0x00
	pkt[1] = 0x00
	pkt[2] = byte(smb2Len >> 8)
	pkt[3] = byte(smb2Len)

	off := 4
	copy(pkt[off:], []byte{0xFE, 'S', 'M', 'B'}) // ProtocolId
	off += 4
	binary.LittleEndian.PutUint16(pkt[off:], 0x40) // StructureSize
	off += 2
	binary.LittleEndian.PutUint16(pkt[off:], 0) // CreditCharge
	off += 2
	binary.LittleEndian.PutUint32(pkt[off:], status) // Status
	off += 4
	binary.LittleEndian.PutUint16(pkt[off:], 0x0001) // Command: SESSION_SETUP
	off += 2
	binary.LittleEndian.PutUint16(pkt[off:], 1) // CreditResponse
	off += 2
	binary.LittleEndian.PutUint32(pkt[off:], 0) // Flags
	off += 4
	binary.LittleEndian.PutUint32(pkt[off:], 0) // NextCommand
	off += 4
	binary.LittleEndian.PutUint64(pkt[off:], 2) // MessageID
	off += 8
	binary.LittleEndian.PutUint32(pkt[off:], 0) // Reserved
	off += 4
	binary.LittleEndian.PutUint32(pkt[off:], 0) // TreeID
	off += 4
	binary.LittleEndian.PutUint64(pkt[off:], sessionID) // SessionID
	off += 8
	off += 16 // Signature

	// Session Setup Response body (9 bytes minimum)
	binary.LittleEndian.PutUint16(pkt[off:], 9) // StructureSize
	off += 2
	binary.LittleEndian.PutUint16(pkt[off:], 0) // SessionFlags
	off += 2
	binary.LittleEndian.PutUint16(pkt[off:], 0) // SecurityBufferOffset
	off += 2
	binary.LittleEndian.PutUint16(pkt[off:], 0) // SecurityBufferLength
	off += 2
	_ = off
	return pkt
}

// buildSMBv2TreeConnectResponse builds a minimal SMBv2 TREE_CONNECT response
// with the given NTSTATUS.
func buildSMBv2TreeConnectResponse(status uint32) []byte {
	const smb2Len = 64 + 16
	pkt := make([]byte, 4+smb2Len)
	pkt[0] = 0x00
	pkt[1] = 0x00
	pkt[2] = byte(smb2Len >> 8)
	pkt[3] = byte(smb2Len)

	off := 4
	copy(pkt[off:], []byte{0xFE, 'S', 'M', 'B'})
	off += 4
	binary.LittleEndian.PutUint16(pkt[off:], 0x40)
	off += 2
	off += 2 // CreditCharge
	binary.LittleEndian.PutUint32(pkt[off:], status) // Status
	off += 4
	binary.LittleEndian.PutUint16(pkt[off:], 0x0003) // Command: TREE_CONNECT
	off += 2
	off += 2  // CreditResponse
	off += 4  // Flags
	off += 4  // NextCommand
	off += 8  // MessageID
	off += 4  // Reserved
	off += 4  // TreeID
	off += 8  // SessionID
	off += 16 // Signature
	// Tree Connect Response body (16 bytes)
	binary.LittleEndian.PutUint16(pkt[off:], 16) // StructureSize
	off += 2
	off += 2 // ShareType + Reserved
	off += 4 // ShareFlags
	off += 4 // Capabilities
	off += 4 // MaximalAccess
	_ = off
	return pkt
}

// multiReadConn returns successive byte slices from a slice of response payloads,
// one per Read call.
type multiReadConn struct {
	responses [][]byte
	idx       int
}

func (m *multiReadConn) Read(b []byte) (int, error) {
	if m.idx >= len(m.responses) {
		return 0, nil
	}
	n := copy(b, m.responses[m.idx])
	m.idx++
	return n, nil
}

func (m *multiReadConn) Write(b []byte) (int, error)         { return len(b), nil }
func (m *multiReadConn) Close() error                        { return nil }
func (m *multiReadConn) LocalAddr() net.Addr                 { return nil }
func (m *multiReadConn) RemoteAddr() net.Addr                { return nil }
func (m *multiReadConn) SetDeadline(t time.Time) error       { return nil }
func (m *multiReadConn) SetReadDeadline(t time.Time) error   { return nil }
func (m *multiReadConn) SetWriteDeadline(t time.Time) error  { return nil }

func TestCheckNullSession_Accepted(t *testing.T) {
	sessionID := uint64(0xABCD1234)
	authResp := buildSMBv2SessionSetupResponse(0x00000000, sessionID)
	treeResp := buildSMBv2TreeConnectResponse(0x00000000)

	conn := &multiReadConn{responses: [][]byte{authResp, treeResp}}
	result := checkNullSession(conn, sessionID, time.Second, "192.0.2.1")
	if !result {
		t.Error("checkNullSession() = false, want true when server accepts anonymous auth and IPC$ connect")
	}
}

func TestCheckNullSession_AuthRejected(t *testing.T) {
	sessionID := uint64(0xABCD1234)
	// STATUS_LOGON_FAILURE
	authResp := buildSMBv2SessionSetupResponse(0xC000006D, sessionID)

	conn := &multiReadConn{responses: [][]byte{authResp}}
	result := checkNullSession(conn, sessionID, time.Second, "192.0.2.1")
	if result {
		t.Error("checkNullSession() = true, want false when auth is rejected")
	}
}

func TestCheckNullSession_TreeConnectRejected(t *testing.T) {
	sessionID := uint64(0xABCD1234)
	authResp := buildSMBv2SessionSetupResponse(0x00000000, sessionID)
	// STATUS_ACCESS_DENIED
	treeResp := buildSMBv2TreeConnectResponse(0xC0000022)

	conn := &multiReadConn{responses: [][]byte{authResp, treeResp}}
	result := checkNullSession(conn, sessionID, time.Second, "192.0.2.1")
	if result {
		t.Error("checkNullSession() = true, want false when tree connect is rejected")
	}
}

func TestCheckNullSession_TruncatedResponse(t *testing.T) {
	sessionID := uint64(0xABCD1234)
	// Response shorter than 16 bytes — should fail bounds check
	shortResp := make([]byte, 10)

	conn := &multiReadConn{responses: [][]byte{shortResp}}
	result := checkNullSession(conn, sessionID, time.Second, "192.0.2.1")
	if result {
		t.Error("checkNullSession() = true, want false for truncated response")
	}
}

func TestDetectSMBv2_AVPairOverflow(t *testing.T) {
	// Build negotiate response (same pattern as TestSMBPlugin_Findings)
	negoResp := make([]byte, 4+64+64)
	negoResp[0] = 0x00
	negoResp[2] = byte((64 + 64) >> 8)
	negoResp[3] = byte(64 + 64)
	copy(negoResp[4:], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(negoResp[8:], 0x40)  // StructureSize
	binary.LittleEndian.PutUint16(negoResp[16:], 0x00) // Command: NEGOTIATE
	binary.LittleEndian.PutUint16(negoResp[68:], 0x41) // Negotiate StructureSize
	binary.LittleEndian.PutUint16(negoResp[70:], 0x01) // SecurityMode

	// Build session setup response with crafted NTLM challenge.
	//
	// After bytes.Index finds "NTLMSSP\x00", the code re-slices response to
	// start at that offset. TargetInfoBufferOffset is relative to that new
	// slice start. We place the NTLM struct right at the start of the payload
	// (offset 68 in the full packet, which becomes offset 0 in the re-sliced
	// view), so TargetInfoBufferOffset=56 (immediately after the 56-byte
	// NTLMChallenge struct).
	//
	// We append 4 bytes of AVPair data (AvID=1, AvLen=1000). The outer bounds
	// check requires startIdx+targetInfoLen <= len(response); we set
	// targetInfoLen=4 so 56+4=60 == len(response) after slicing. Inside the
	// loop, valueEnd = 56 + 4 + 1000 = 1060 > 60, triggering the inner bounds
	// guard, which returns gracefully without panicking.

	var sessionResp []byte

	// 4-byte NetBIOS header + 64-byte SMBv2 header (placeholder; length fixed later)
	header := make([]byte, 4+64)
	copy(header[4:], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(header[8:], 0x40)   // StructureSize
	binary.LittleEndian.PutUint16(header[16:], 0x0001) // Command: SESSION_SETUP
	sessionResp = append(sessionResp, header...)

	// NTLMChallenge struct: 56 bytes total
	// Offsets within struct:
	//   [0:8]   Signature
	//   [8:12]  MessageType
	//   [12:16] TargetNameLen/MaxLen
	//   [16:20] TargetNameBufferOffset
	//   [20:24] NegotiateFlags
	//   [24:32] ServerChallenge
	//   [32:40] Reserved (must be 0)
	//   [40:42] TargetInfoLen
	//   [42:44] TargetInfoMaxLen
	//   [44:48] TargetInfoBufferOffset
	//   [48:56] Version ([4:] must be [0,0,0,0x0F])
	ntlm := make([]byte, 56)
	copy(ntlm[0:8], []byte("NTLMSSP\x00"))               // Signature
	binary.LittleEndian.PutUint32(ntlm[8:], 0x00000002)  // MessageType = 2
	// TargetNameLen/MaxLen/Offset: 0 (no target name)
	// NegotiateFlags: 0 (don't care)
	// ServerChallenge: 0 (don't care)
	// Reserved: 0 (already zero)
	avPairData := make([]byte, 4)
	binary.LittleEndian.PutUint16(avPairData[0:], 1)    // AvID = NetBIOSComputerName
	binary.LittleEndian.PutUint16(avPairData[2:], 1000) // AvLen = far beyond buffer

	// targetInfoLen=4 (just the 4-byte AVPair header), offset=56 (right after struct)
	binary.LittleEndian.PutUint16(ntlm[40:], 4)  // TargetInfoLen
	binary.LittleEndian.PutUint16(ntlm[42:], 4)  // TargetInfoMaxLen
	binary.LittleEndian.PutUint32(ntlm[44:], 56) // TargetInfoBufferOffset
	// Version[4:8] must equal [0, 0, 0, 0x0F]
	ntlm[52] = 0x00
	ntlm[53] = 0x00
	ntlm[54] = 0x00
	ntlm[55] = 0x0F

	sessionResp = append(sessionResp, ntlm...)
	sessionResp = append(sessionResp, avPairData...)

	// Fix NetBIOS length field
	smbLen := len(sessionResp) - 4
	sessionResp[1] = byte(smbLen >> 16)
	sessionResp[2] = byte(smbLen >> 8)
	sessionResp[3] = byte(smbLen)

	conn := &multiReadConn{responses: [][]byte{negoResp, sessionResp}}
	// Must not panic
	info, _, err := DetectSMBv2(conn, time.Second)
	if err != nil {
		t.Fatalf("DetectSMBv2() unexpected error: %v", err)
	}
	if info == nil {
		t.Fatal("DetectSMBv2() returned nil info")
	}
	// The bounds check fires before the value is read, so NetBIOSComputerName must be empty
	if info.NetBIOSComputerName != "" {
		t.Errorf("NetBIOSComputerName = %q, want empty (overflow blocked by bounds check)", info.NetBIOSComputerName)
	}
}

func TestCheckSMBv1_Valid(t *testing.T) {
	// Build a valid SMBv1 negotiate response
	resp := make([]byte, 40)
	resp[0] = 0x00              // NetBIOS type
	resp[1] = 0x00
	resp[2] = 0x00
	resp[3] = byte(len(resp) - 4)
	copy(resp[4:8], smbv1ProtocolID) // \xFFSMB
	resp[8] = 0x72                   // SMB_COM_NEGOTIATE
	// Status bytes 9-12: 0x00000000
	binary.LittleEndian.PutUint32(resp[9:13], 0x00000000)

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(resp)
	}()

	addr := netip.MustParseAddrPort(listener.Addr().String())
	target := plugins.Target{Address: addr}
	if !checkSMBv1(target, time.Second) {
		t.Error("checkSMBv1() = false, want true for valid SMBv1 response")
	}
}

func TestCheckSMBv1_InvalidProtocol(t *testing.T) {
	// Respond with SMBv2 protocol ID instead of SMBv1
	resp := make([]byte, 20)
	resp[0] = 0x00
	copy(resp[4:8], []byte{0xFE, 'S', 'M', 'B'}) // SMBv2

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer listener.Close()

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 256)
		_, _ = conn.Read(buf)
		_, _ = conn.Write(resp)
	}()

	addr := netip.MustParseAddrPort(listener.Addr().String())
	target := plugins.Target{Address: addr}
	if checkSMBv1(target, time.Second) {
		t.Error("checkSMBv1() = true, want false for SMBv2 response")
	}
}

func TestSMBPlugin_Findings(t *testing.T) {
	// Build a minimal SMBv2 negotiate response with signing NOT required,
	// followed by a session setup NTLM challenge response.
	// This tests that SecurityFindings are populated when Misconfigs=true.
	//
	// We can't easily test null-session or smbv1 findings here (they require
	// real network connections), but we can verify the signing finding path.

	// Minimal valid NegotiateResponse: all zero with correct magic/command
	negoResp := make([]byte, 4+64+64)
	// NetBIOS
	negoResp[0] = 0x00
	negoResp[1] = 0x00
	negoResp[2] = byte((64 + 64) >> 8)
	negoResp[3] = byte(64 + 64)
	// SMBv2 Header
	copy(negoResp[4:], []byte{0xFE, 'S', 'M', 'B'})
	binary.LittleEndian.PutUint16(negoResp[8:], 0x40)  // StructureSize
	binary.LittleEndian.PutUint16(negoResp[16:], 0x00) // Command: NEGOTIATE
	// Negotiate Response
	binary.LittleEndian.PutUint16(negoResp[68:], 0x41) // StructureSize
	// SecurityMode byte 70-71: 0x01 (signing enabled, NOT required)
	binary.LittleEndian.PutUint16(negoResp[70:], 0x01)

	// Session setup response: just timeout (empty) to short-circuit NTLM metadata
	conn := &multiReadConn{responses: [][]byte{negoResp, {}}}

	target := plugins.Target{
		Address:    netip.MustParseAddrPort("127.0.0.1:445"),
		Misconfigs: true,
	}
	p := &SMBPlugin{}
	service, err := p.Run(conn, time.Second, target)
	if err != nil {
		t.Fatalf("SMBPlugin.Run() unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("SMBPlugin.Run() returned nil service")
	}

	var signingFinding *plugins.SecurityFinding
	for i := range service.SecurityFindings {
		if service.SecurityFindings[i].ID == "smb-signing-not-required" {
			signingFinding = &service.SecurityFindings[i]
			break
		}
	}
	if signingFinding == nil {
		t.Fatal("expected smb-signing-not-required finding, got none")
	}
	if signingFinding.Severity != plugins.SeverityMedium {
		t.Errorf("Severity = %q, want medium", signingFinding.Severity)
	}
}
