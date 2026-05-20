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
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"reflect"
	"strings"
	"time"
	"unicode/utf16"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type SMBPlugin struct{}

const SMB = "smb"

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5cd64522-60b3-4f3e-a157-fe66f1228052
type SMB2PacketHeader struct {
	ProtocolID    [4]byte
	StructureSize uint16
	CreditCharge  uint16
	Status        uint32 // In SMB 3.x dialect, used as ChannelSequence & Reserved fields
	Command       uint16
	CreditRequest uint16
	Flags         uint32
	NextCommand   uint32
	MessageID     uint64
	Reserved      uint32
	TreeID        uint32
	SessionID     uint64
	Signature     [16]byte
}

// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/63abf97c-0d09-47e2-88d6-6bfa552949a5
type NegotiateResponse struct {
	SessionMsgPrefix [4]byte
	PacketHeader     SMB2PacketHeader
	// Negotiate Response
	StructureSize        uint16
	SecurityMode         uint16
	DialectRevision      uint16
	Reserved             uint16 // if DialectRevision is 0x0311, used as NegotiateContextCount field
	ServerGUID           [16]byte
	Capabilities         uint32
	MaxTransactSize      uint32
	MaxReadSize          uint32
	MaxWriteSize         uint32
	SystemTime           uint64
	ServerStartTime      uint64
	SecurityBufferOffset uint16
	SecurityBufferLength uint16
	Reserved2            uint32 // if DialectRevision is 0x0311, used as NegotiateContextOffset field
	// Variable (Buffer, Padding, NegotiateContextList, etc.)
}

type NTLMChallenge struct {
	Signature              [8]byte
	MessageType            uint32
	TargetNameLen          uint16
	TargetNameMaxLen       uint16
	TargetNameBufferOffset uint32
	NegotiateFlags         uint32
	ServerChallenge        uint64
	Reserved               uint64
	TargetInfoLen          uint16
	TargetInfoMaxLen       uint16
	TargetInfoBufferOffset uint32
	Version                [8]byte
	// Payload (variable)
}

// sessionIDOffset is the byte offset of the SessionID field in an SMBv2 response.
// Layout: 4 (NetBIOS) + 40 (SMB2 header bytes before SessionID) = 44.
const sessionIDOffset = 44

var smbv1ProtocolID = []byte{0xFF, 0x53, 0x4D, 0x42}

var smbv1NegotiatePacket = []byte{
	// NetBIOS Session Service
	0x00, 0x00, 0x00, 0x2F, // Length (47)
	// SMBv1 Header (32 bytes)
	0xFF, 0x53, 0x4D, 0x42, // Protocol: \xFFSMB
	0x72,                   // Command: SMB_COM_NEGOTIATE
	0x00, 0x00, 0x00, 0x00, // Status
	0x18,       // Flags
	0x53, 0xC8, // Flags2 (UNICODE | NT_STATUS | EXTENDED_SECURITY)
	0x00, 0x00, // PIDHigh
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
	0x00, 0x00, // Reserved
	0x00, 0x00, // TID
	0x00, 0x00, // PID
	0x00, 0x00, // UID
	0x00, 0x00, // MID
	// Negotiate Request
	0x00,       // WordCount
	0x0C, 0x00, // ByteCount (12)
	0x02,                                                       // Dialect buffer format
	'N', 'T', ' ', 'L', 'M', ' ', '0', '.', '1', '2', 0x00,
}

func init() {
	plugins.RegisterPlugin(&SMBPlugin{})
}

func (p *SMBPlugin) PortPriority(port uint16) bool {
	return port == 445
}

func DetectSMBv2(conn net.Conn, timeout time.Duration) (*plugins.ServiceSMB, uint64, error) {
	info := plugins.ServiceSMB{}

	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/e14db7ff-763a-4263-8b10-0c3944f52fc5
	negotiateReqPacket := []byte{
		// NetBios Session Service
		0x00,             // Message Type
		0x00, 0x00, 0x66, // Length

		// SMBv2 Packet Header
		0xFE, 0x53, 0x4D, 0x42, // ProtocolId
		0x40, 0x00, // StructureSize
		0x00, 0x00, // CreditCharge
		0x00, 0x00, 0x00, 0x00, // ChannelSequence/Reserved/Status
		0x00, 0x00, // Command (Negotiate)
		0x00, 0x1F, // CreditRequest
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // NextCommand
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageID
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // TreeID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (continued)

		// SMBv2 Negotiate Request
		0x24, 0x00, // StructureSize
		0x01, 0x00, // DialectCount
		0x01, 0x00, // SecurityMode (Signing Enabled)
		0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // Capabilities
		0x13, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, // ClientGuid
		0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x37, // ClientGuid (continued)
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ClientStartTime
		0x02, 0x02, // Dialects (SMB 2.0.2)
	}
	sessionPrefixLen := 4
	packetHeaderLen := 64
	minNegoResponseLen := 64

	response, err := utils.SendRecv(conn, negotiateReqPacket, timeout)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil, 0, nil
		}
		return nil, 0, err
	}

	// Check the length of the response to see if it is lower than the minimum
	// packet size for SMB2 NEGOTIATE Response Packet
	if len(response) < sessionPrefixLen+packetHeaderLen+minNegoResponseLen {
		return nil, 0, nil
	}

	var negotiateResponseData NegotiateResponse
	responseBuf := bytes.NewBuffer(response)
	err = binary.Read(responseBuf, binary.LittleEndian, &negotiateResponseData)
	if err != nil {
		return nil, 0, err
	}

	if !reflect.DeepEqual(negotiateResponseData.PacketHeader.ProtocolID[:], []byte{0xFE, 'S', 'M', 'B'}) {
		return nil, 0, nil
	}

	if negotiateResponseData.PacketHeader.StructureSize != 0x40 {
		return nil, 0, nil
	}

	if negotiateResponseData.PacketHeader.Command != 0x0000 { // SMB2 NEGOTIATE (0x0000)
		return nil, 0, nil
	}

	if negotiateResponseData.StructureSize != 0x41 {
		return nil, 0, nil
	}

	signingEnabled := false
	signingRequired := false
	if negotiateResponseData.SecurityMode&1 == 1 {
		signingEnabled = true
	}
	if negotiateResponseData.SecurityMode&2 == 2 {
		signingRequired = true
	}
	info.SigningEnabled = signingEnabled
	info.SigningRequired = signingRequired

	/**
	 * At this point, we know SMBv2 is detected.
	 * Below, we try to obtain more metadata via session setup request w/ NTLM auth
	 */

	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-authsod/9a20f8ac-612a-4e0a-baab-30e922e7e1f5
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/5a3c2c28-d6b0-48ed-b917-a86b2ca4575f
	sessionSetupReqPacket := []byte{
		// NetBios Session Service
		0x00,             // Message Type
		0x00, 0x00, 0xA2, // Length

		// SMBv2 Packet Header
		0xFE, 0x53, 0x4D, 0x42, // ProtocolId
		0x40, 0x00, // StructureSize
		0x00, 0x00, // CreditCharge
		0x00, 0x00, 0x00, 0x00, // ChannelSequence/Reserved/Status
		0x01, 0x00, // Command (SESSION_SETUP)
		0x00, 0x20, // CreditRequest
		0x00, 0x00, 0x00, 0x00, // Flags
		0x00, 0x00, 0x00, 0x00, // NextCommand
		0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MessageID
		0x00, 0x00, 0x00, 0x00, // Reserved
		0x00, 0x00, 0x00, 0x00, // TreeID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // SessionID
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Signature (continued)

		// SMBv2 Session Setup Request
		0x19, 0x00, // Structure Size
		0x00,                   // Flags
		0x01,                   // SecurityMode
		0x01, 0x00, 0x00, 0x00, // Capabilities
		0x00, 0x00, 0x00, 0x00, // Channel
		0x58, 0x00, // SecurityBufferOffset
		0x4A, 0x00, // SecurityBufferLength
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // PreviousSessionId
		// Security Buffer
		0x60, 0x48, 0x06, 0x06, 0x2B, 0x06, 0x01, 0x05,
		0x05, 0x02, 0xA0, 0x3E, 0x30, 0x3C, 0xA0, 0x0E,
		0x30, 0x0C, 0x06, 0x0A, 0x2B, 0x06, 0x01, 0x04,
		0x01, 0x82, 0x37, 0x02, 0x02, 0x0A, 0xA2, 0x2A, 0x04, 0x28,
		// Signature
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
		// Message Type
		0x01, 0x00, 0x00, 0x00,
		// Negotiate Flags
		0xF7, 0xBA, 0xDB, 0xE2,
		// Domain Name Fields
		0x00, 0x00, // DomainNameLen
		0x00, 0x00, // DomainNameMaxLen
		0x00, 0x00, 0x00, 0x00, // DomainNameBufferOffset
		// Workstation Fields
		0x00, 0x00, // WorkstationLen
		0x00, 0x00, // WorkstationMaxLen
		0x00, 0x00, 0x00, 0x00, // WorkstationBufferOffset
		// Version
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	response, err = utils.SendRecv(conn, sessionSetupReqPacket, timeout)
	if err != nil {
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return &info, 0, nil
		}
		return &info, 0, err
	}

	// Extract SessionID from the SMB2 header of the session setup response.
	// Layout: 4 NetBIOS + 64 SMB2 header; SessionID is at bytes 44:52 within the response.
	var sessionID uint64
	if len(response) >= sessionIDOffset+8 {
		sessionID = binary.LittleEndian.Uint64(response[sessionIDOffset : sessionIDOffset+8])
	}

	challengeLen := 56
	challengeStartOffset := bytes.Index(response, []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0})
	if challengeStartOffset == -1 {
		return &info, sessionID, nil
	}
	if len(response) < challengeStartOffset+challengeLen {
		return &info, sessionID, nil
	}
	var sessionResponseData NTLMChallenge
	response = response[challengeStartOffset:]
	responseBuf = bytes.NewBuffer(response)
	err = binary.Read(responseBuf, binary.LittleEndian, &sessionResponseData)
	if err != nil {
		return &info, sessionID, err
	}

	// Check if valid NTLM challenge response message structure
	if sessionResponseData.MessageType != 0x00000002 ||
		sessionResponseData.Reserved != 0 ||
		!reflect.DeepEqual(sessionResponseData.Version[4:], []byte{0, 0, 0, 0xF}) {
		return &info, sessionID, nil
	}

	// Parse: Version
	type version struct {
		MajorVersion byte
		MinorVersion byte
		BuildNumber  uint16
	}
	var versionData version
	versionBuf := bytes.NewBuffer(sessionResponseData.Version[:4])
	err = binary.Read(versionBuf, binary.LittleEndian, &versionData)
	if err != nil {
		return &info, sessionID, err
	}
	info.OSVersion = fmt.Sprintf("%d.%d.%d", versionData.MajorVersion,
		versionData.MinorVersion,
		versionData.BuildNumber)

	// Parse: TargetInfo
	AvIDMap := map[uint16]string{
		1: "netbiosComputerName",
		2: "netbiosDomainName",
		3: "dnsComputerName",
		4: "dnsDomainName",
		5: "forestName", // MsvAvDnsTreeName
	}
	type AVPair struct {
		AvID  uint16
		AvLen uint16
		// Value (variable)
	}
	var avPairLen = 4
	targetInfoLen := int(sessionResponseData.TargetInfoLen)
	if targetInfoLen > 0 {
		startIdx := int(sessionResponseData.TargetInfoBufferOffset)
		if startIdx < 0 || startIdx+targetInfoLen > len(response) || len(response)-startIdx < avPairLen {
			return &info, sessionID, nil
		}
		var avPair AVPair
		avPairBuf := bytes.NewBuffer(response[startIdx : startIdx+avPairLen])
		err = binary.Read(avPairBuf, binary.LittleEndian, &avPair)
		if err != nil {
			return &info, sessionID, err
		}
		currIdx := startIdx
		for avPair.AvID != 0 {
			// Validate bounds before slice access
			valueEnd := currIdx + avPairLen + int(avPair.AvLen)
			if currIdx < 0 || currIdx+avPairLen > len(response) || valueEnd > len(response) || valueEnd < currIdx {
				return &info, sessionID, nil
			}
			if field, exists := AvIDMap[avPair.AvID]; exists {
				value := strings.ReplaceAll(string(response[currIdx+avPairLen:valueEnd]), "\x00", "")
				switch field {
				case "netbiosComputerName":
					info.NetBIOSComputerName = value
				case "netbiosDomainName":
					info.NetBIOSDomainName = value
				case "dnsComputerName":
					info.DNSComputerName = value
				case "dnsDomainName":
					info.DNSDomainName = value
				case "forestName": // MsvAvDnsTreeName
					info.ForestName = value
				}
			}
			currIdx += avPairLen + int(avPair.AvLen)
			if currIdx+avPairLen > startIdx+targetInfoLen {
				return &info, sessionID, nil
			}
			avPairBuf = bytes.NewBuffer(response[currIdx : currIdx+avPairLen])
			err = binary.Read(avPairBuf, binary.LittleEndian, &avPair)
			if err != nil {
				return &info, sessionID, nil
			}
		}
	}

	return &info, sessionID, nil
}

// toUTF16LE encodes a string as a UTF-16LE byte slice.
func toUTF16LE(s string) []byte {
	runes := []rune(s)
	u16 := utf16.Encode(runes)
	buf := make([]byte, len(u16)*2)
	for i, r := range u16 {
		binary.LittleEndian.PutUint16(buf[i*2:], r)
	}
	return buf
}

// wrapSPNEGOAuth wraps an NTLM token in a SPNEGO NegTokenResp ASN.1 structure.
func wrapSPNEGOAuth(ntlmAuth []byte) []byte {
	ntlmLen := len(ntlmAuth)

	// Build inner: 04 [ntlm_len] [ntlm_data]
	innerPayload := make([]byte, 0, 2+ntlmLen)
	innerPayload = append(innerPayload, 0x04)
	innerPayload = append(innerPayload, byte(ntlmLen)) // #nosec G115 -- safe: ntlmAuth is the 65-byte null auth blob
	innerPayload = append(innerPayload, ntlmAuth...)

	// A2 [len] [innerPayload]
	a2Block := make([]byte, 0, 2+len(innerPayload))
	a2Block = append(a2Block, 0xA2)
	a2Block = append(a2Block, byte(len(innerPayload))) // #nosec G115 -- safe: innerPayload ≤ 67 bytes
	a2Block = append(a2Block, innerPayload...)

	// 30 [len] [a2Block]
	seqBlock := make([]byte, 0, 2+len(a2Block))
	seqBlock = append(seqBlock, 0x30)
	seqBlock = append(seqBlock, byte(len(a2Block))) // #nosec G115 -- safe: a2Block ≤ 69 bytes
	seqBlock = append(seqBlock, a2Block...)

	// A1 [len] [seqBlock]
	result := make([]byte, 0, 2+len(seqBlock))
	result = append(result, 0xA1)
	result = append(result, byte(len(seqBlock))) // #nosec G115 -- safe: seqBlock ≤ 71 bytes
	result = append(result, seqBlock...)
	return result
}

// buildNullAuthPacket builds an SMBv2 SESSION_SETUP request with anonymous
// NTLM Authenticate credentials.
func buildNullAuthPacket(sessionID uint64) []byte {
	// Anonymous NTLM Authenticate message (Type 3, empty credentials)
	ntlmAuth := []byte{
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00, // Signature
		0x03, 0x00, 0x00, 0x00, // MessageType: Authenticate
		// LmChallengeResponse: Len=1, Max=1, Offset=64
		0x01, 0x00, 0x01, 0x00, 0x40, 0x00, 0x00, 0x00,
		// NtChallengeResponse: empty (Len=0, Max=0, Offset=65)
		0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00,
		// DomainName: empty
		0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00,
		// UserName: empty
		0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00,
		// Workstation: empty
		0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00,
		// EncryptedRandomSessionKey: empty
		0x00, 0x00, 0x00, 0x00, 0x41, 0x00, 0x00, 0x00,
		// NegotiateFlags
		0x00, 0x00, 0x00, 0x00,
		// LmChallengeResponse data (1 byte null)
		0x00,
	}

	spnego := wrapSPNEGOAuth(ntlmAuth)
	spnegoLen := len(spnego)

	// SMBv2 header (64 bytes) + Session Setup body (24 bytes) + spnego
	totalSMBLen := 64 + 24 + spnegoLen
	pkt := make([]byte, 4+totalSMBLen)

	// NetBIOS prefix
	pkt[0] = 0x00
	pkt[1] = byte(totalSMBLen >> 16) // #nosec G115 -- safe: bit-shift isolates 8 bits
	pkt[2] = byte(totalSMBLen >> 8)  // #nosec G115 -- safe: bit-shift isolates 8 bits
	pkt[3] = byte(totalSMBLen)       // #nosec G115 -- safe: totalSMBLen < 256 for null auth packet

	off := 4
	// SMBv2 Header
	copy(pkt[off:], []byte{0xFE, 0x53, 0x4D, 0x42}) // ProtocolId
	off += 4
	binary.LittleEndian.PutUint16(pkt[off:], 0x40) // StructureSize
	off += 2
	binary.LittleEndian.PutUint16(pkt[off:], 0x00) // CreditCharge
	off += 2
	binary.LittleEndian.PutUint32(pkt[off:], 0x00) // Status
	off += 4
	binary.LittleEndian.PutUint16(pkt[off:], 0x0001) // Command: SESSION_SETUP
	off += 2
	binary.LittleEndian.PutUint16(pkt[off:], 0x0020) // CreditRequest
	off += 2
	binary.LittleEndian.PutUint32(pkt[off:], 0x00) // Flags
	off += 4
	binary.LittleEndian.PutUint32(pkt[off:], 0x00) // NextCommand
	off += 4
	binary.LittleEndian.PutUint64(pkt[off:], 0x02) // MessageID
	off += 8
	binary.LittleEndian.PutUint32(pkt[off:], 0x00) // Reserved
	off += 4
	binary.LittleEndian.PutUint32(pkt[off:], 0x00) // TreeID
	off += 4
	binary.LittleEndian.PutUint64(pkt[off:], sessionID) // SessionID
	off += 8
	off += 16 // Signature (zeros)

	// Session Setup Request body
	binary.LittleEndian.PutUint16(pkt[off:], 0x19) // StructureSize
	off += 2
	pkt[off] = 0x00 // Flags
	off++
	pkt[off] = 0x01 // SecurityMode
	off++
	binary.LittleEndian.PutUint32(pkt[off:], 0x00) // Capabilities
	off += 4
	binary.LittleEndian.PutUint32(pkt[off:], 0x00) // Channel
	off += 4
	// SecurityBufferOffset from SMB2 header start: 64 (header) + 24 (body) = 88 = 0x58
	binary.LittleEndian.PutUint16(pkt[off:], 0x58) // SecurityBufferOffset
	off += 2
	binary.LittleEndian.PutUint16(pkt[off:], uint16(spnegoLen)) // #nosec G115 -- safe: spnego ≤ 128 bytes (SecurityBufferLength)
	off += 2
	binary.LittleEndian.PutUint64(pkt[off:], 0x00) // PreviousSessionId
	off += 8

	// Security Buffer
	copy(pkt[off:], spnego)
	return pkt
}

// buildTreeConnectPacket builds an SMBv2 TREE_CONNECT request to \\host\IPC$.
func buildTreeConnectPacket(sessionID uint64, host string) []byte {
	// Bracket IPv6 addresses — colons are invalid in UNC paths
	if strings.ContainsRune(host, ':') {
		host = "[" + host + "]"
	}
	path := "\\\\" + host + "\\IPC$"
	pathUTF16 := toUTF16LE(path)
	pathLen := len(pathUTF16)

	// SMBv2 header (64 bytes) + Tree Connect body (8 bytes) + path
	totalSMBLen := 64 + 8 + pathLen
	pkt := make([]byte, 4+totalSMBLen)

	// NetBIOS prefix
	pkt[0] = 0x00
	pkt[1] = byte(totalSMBLen >> 16) // #nosec G115 -- safe: bit-shift isolates 8 bits
	pkt[2] = byte(totalSMBLen >> 8)  // #nosec G115 -- safe: bit-shift isolates 8 bits
	pkt[3] = byte(totalSMBLen)       // #nosec G115 -- safe: totalSMBLen bounded by max hostname length

	off := 4
	// SMBv2 Header
	copy(pkt[off:], []byte{0xFE, 0x53, 0x4D, 0x42}) // ProtocolId
	off += 4
	binary.LittleEndian.PutUint16(pkt[off:], 0x40) // StructureSize
	off += 2
	binary.LittleEndian.PutUint16(pkt[off:], 0x00) // CreditCharge
	off += 2
	binary.LittleEndian.PutUint32(pkt[off:], 0x00) // Status
	off += 4
	binary.LittleEndian.PutUint16(pkt[off:], 0x0003) // Command: TREE_CONNECT
	off += 2
	binary.LittleEndian.PutUint16(pkt[off:], 0x0020) // CreditRequest
	off += 2
	binary.LittleEndian.PutUint32(pkt[off:], 0x00) // Flags
	off += 4
	binary.LittleEndian.PutUint32(pkt[off:], 0x00) // NextCommand
	off += 4
	binary.LittleEndian.PutUint64(pkt[off:], 0x03) // MessageID
	off += 8
	binary.LittleEndian.PutUint32(pkt[off:], 0x00) // Reserved
	off += 4
	binary.LittleEndian.PutUint32(pkt[off:], 0x00) // TreeID
	off += 4
	binary.LittleEndian.PutUint64(pkt[off:], sessionID) // SessionID
	off += 8
	off += 16 // Signature (zeros)

	// Tree Connect Request body (StructureSize=9, Flags=0, PathOffset, PathLength)
	binary.LittleEndian.PutUint16(pkt[off:], 9)         // StructureSize
	off += 2
	binary.LittleEndian.PutUint16(pkt[off:], 0)         // Flags
	off += 2
	// PathOffset from start of SMB2 header per MS-SMB2 spec: 64 (header) + 8 (body) = 72 = 0x48
	binary.LittleEndian.PutUint16(pkt[off:], 0x48)      // PathOffset
	off += 2
	binary.LittleEndian.PutUint16(pkt[off:], uint16(pathLen)) // #nosec G115 -- safe: path bounded by max hostname length (PathLength)
	off += 2

	// Path
	copy(pkt[off:], pathUTF16)
	return pkt
}

// checkNullSession tests whether the server allows anonymous (null) SMB session
// access to the IPC$ share. It sends an anonymous NTLM Authenticate on the
// existing connection (using the sessionID from the NTLM challenge exchange) and
// then attempts a Tree Connect to \\host\IPC$. Returns true only if both succeed
// with STATUS_SUCCESS.
func checkNullSession(conn net.Conn, sessionID uint64, timeout time.Duration, host string) bool {
	authPkt := buildNullAuthPacket(sessionID)
	authResp, err := utils.SendRecv(conn, authPkt, timeout)
	if err != nil {
		return false
	}
	// STATUS_SUCCESS is 0x00000000 at bytes 12:16 of the SMB2 header (offset 4+8=12 from start)
	if len(authResp) < 16 {
		return false
	}
	if binary.LittleEndian.Uint32(authResp[12:16]) != 0x00000000 {
		return false
	}

	// Extract the SessionID from the auth response for the tree connect
	var authSessionID uint64
	if len(authResp) >= sessionIDOffset+8 {
		authSessionID = binary.LittleEndian.Uint64(authResp[sessionIDOffset : sessionIDOffset+8])
	} else {
		authSessionID = sessionID
	}

	treePkt := buildTreeConnectPacket(authSessionID, host)
	treeResp, err := utils.SendRecv(conn, treePkt, timeout)
	if err != nil {
		return false
	}
	if len(treeResp) < 16 {
		return false
	}
	return binary.LittleEndian.Uint32(treeResp[12:16]) == 0x00000000
}

// checkSMBv1 opens a fresh TCP connection to the target and tests whether SMBv1
// is enabled by sending an SMBv1 Negotiate request and checking the response for
// a valid SMBv1 protocol signature with STATUS_SUCCESS.
func checkSMBv1(target plugins.Target, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", target.Address.String(), timeout)
	if err != nil {
		return false
	}
	defer conn.Close()

	response, err := utils.SendRecv(conn, smbv1NegotiatePacket, timeout)
	if err != nil {
		return false
	}
	if len(response) < 13 {
		return false
	}
	if !bytes.Equal(response[4:8], smbv1ProtocolID) {
		return false
	}
	if response[8] != 0x72 { // SMB_COM_NEGOTIATE
		return false
	}
	return binary.LittleEndian.Uint32(response[9:13]) == 0x00000000
}

func (p *SMBPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	info, sessionID, err := DetectSMBv2(conn, timeout)
	if err != nil {
		return nil, err
	}
	if info == nil {
		// SMBv2 not detected; check for SMBv1-only hosts when misconfig scanning is enabled
		if target.Misconfigs && checkSMBv1(target, timeout) {
			smbInfo := &plugins.ServiceSMB{}
			service := plugins.CreateServiceFrom(target, smbInfo, false, "", plugins.TCP)
			service.SecurityFindings = append(service.SecurityFindings, plugins.SecurityFinding{
				ID:          "smb-v1-enabled",
				Severity:    plugins.SeverityMedium,
				Description: "SMBv1 is enabled, exposing the system to EternalBlue and other vulnerabilities",
				Evidence:    "SMBv1 negotiate response received",
			})
			return service, nil
		}
		return nil, nil
	}

	service := plugins.CreateServiceFrom(target, info, false, info.OSVersion, plugins.TCP)
	if target.Misconfigs {
		if !info.SigningRequired {
			service.SecurityFindings = append(service.SecurityFindings, plugins.SecurityFinding{
				ID:          "smb-signing-not-required",
				Severity:    plugins.SeverityMedium,
				Description: "SMB signing is not required, enabling relay attacks",
				Evidence:    fmt.Sprintf("SigningEnabled=%t, SigningRequired=%t", info.SigningEnabled, info.SigningRequired),
			})
		}
		if sessionID != 0 {
			host := target.Address.Addr().String()
			if checkNullSession(conn, sessionID, timeout, host) {
				service.SecurityFindings = append(service.SecurityFindings, plugins.SecurityFinding{
					ID:          "smb-null-session",
					Severity:    plugins.SeverityHigh,
					Description: "SMB allows null session access to IPC$, enabling user, share, and group enumeration",
					Evidence:    "anonymous session setup and IPC$ tree connect succeeded",
				})
			}
		}
		if checkSMBv1(target, timeout) {
			service.SecurityFindings = append(service.SecurityFindings, plugins.SecurityFinding{
				ID:          "smb-v1-enabled",
				Severity:    plugins.SeverityMedium,
				Description: "SMBv1 is enabled, exposing the system to EternalBlue and other vulnerabilities",
				Evidence:    "SMBv1 negotiate response received",
			})
		}
	}
	return service, nil
}

func (p *SMBPlugin) Name() string {
	return SMB
}
func (p *SMBPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *SMBPlugin) Priority() int {
	return 320
}
