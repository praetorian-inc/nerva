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

package opcua

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type OPCUAPlugin struct{}

func init() {
	plugins.RegisterPlugin(&OPCUAPlugin{})
}

const OPCUA = "opcua"

const maxArrayElements = 1000

// MessageSecurityMode string values returned to callers and used in findings.
const (
	modeNone           = "None"
	modeSign           = "Sign"
	modeSignAndEncrypt = "SignAndEncrypt"
)

func (p *OPCUAPlugin) PortPriority(port uint16) bool {
	return port == 4840
}

// Run implements OPC UA (Unified Architecture) protocol detection.
//
// OPC UA is an industrial communication standard for machine-to-machine communication.
// This implementation sends a Hello message and validates the server's ACK response.
// When target.Misconfigs is true, it additionally performs an OpenSecureChannel +
// GetEndpoints exchange to extract supported security modes.
//
// Protocol Structure:
//   - Hello message contains: MessageType="HEL", ProtocolVersion, buffer sizes, endpoint URL
//   - Valid OPC UA server responds with: MessageType="ACK"
//   - Both messages have 8-byte header: MessageType (3 bytes) + 'F' + MessageSize (4 bytes)
//
// The default TCP port is 4840 (official IANA assignment for OPC UA).
func (p *OPCUAPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	endpointURL := fmt.Sprintf("opc.tcp://%s:%d", target.Address.Addr().String(), target.Address.Port())

	hello := buildOPCUAHello(endpointURL)

	response, err := utils.SendRecv(conn, hello, timeout)
	if err != nil {
		return nil, err
	}

	// Empty response means no OPC UA server
	if len(response) == 0 {
		return nil, nil
	}

	// Valid ACK response must be at least 8 bytes (header size)
	// and start with "ACK" message type
	if len(response) < 8 || string(response[0:3]) != "ACK" {
		return nil, nil
	}

	serviceData := plugins.ServiceOPCUA{
		CPEs: []string{"cpe:2.3:a:opcfoundation:opcua_server:*:*:*:*:*:*:*:*"},
	}

	if target.Misconfigs {
		modes, err := getEndpointSecurityModes(conn, timeout, endpointURL)
		if err == nil && len(modes) > 0 {
			serviceData.SecurityModes = modes
		}
	}

	service := plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP)
	if target.Misconfigs && len(serviceData.SecurityModes) > 0 {
		service.SecurityFindings = checkSecurityModes(serviceData.SecurityModes)
	}
	return service, nil
}

// checkSecurityModes returns security findings based on the advertised security modes.
// If only "None" is present, that is a high-severity finding (no security at all).
// If "None" is present alongside secure modes, that is a medium-severity finding
// (insecure mode available even though the server supports better options).
func checkSecurityModes(modes []string) []plugins.SecurityFinding {
	hasNone := false
	for _, m := range modes {
		if m == modeNone {
			hasNone = true
			break
		}
	}
	if !hasNone {
		return nil
	}

	evidence := "security_modes=" + strings.Join(modes, ",")

	if len(modes) == 1 {
		return []plugins.SecurityFinding{{
			ID:          "opcua-no-security",
			Severity:    plugins.SeverityHigh,
			Description: "OPC UA server only advertises SecurityMode None, providing no message security",
			Evidence:    evidence,
		}}
	}

	return []plugins.SecurityFinding{{
		ID:          "opcua-weak-security",
		Severity:    plugins.SeverityMedium,
		Description: "OPC UA server advertises SecurityMode None alongside secure modes, allowing unauthenticated connections",
		Evidence:    evidence,
	}}
}

// getEndpointSecurityModes performs an OpenSecureChannel + GetEndpoints exchange and
// returns the deduplicated, stably-ordered security modes found in the endpoint list.
// Stable order: None, Sign, SignAndEncrypt.
func getEndpointSecurityModes(conn net.Conn, timeout time.Duration, endpointURL string) ([]string, error) {
	// Step 1: Send OpenSecureChannel (OPN) request.
	opnReq := buildOpenSecureChannel()
	if err := utils.Send(conn, opnReq, timeout); err != nil {
		return nil, err
	}

	// Step 2: Read OPN response.
	opnResp, err := readOPCUAMessage(conn, timeout)
	if err != nil {
		return nil, err
	}

	channelID, tokenID, err := parseOpenSecureChannelResponse(opnResp)
	if err != nil {
		return nil, err
	}

	// Step 3: Send GetEndpoints (MSG) request.
	msgReq := buildGetEndpoints(channelID, tokenID, endpointURL)
	if err := utils.Send(conn, msgReq, timeout); err != nil {
		return nil, err
	}

	// Step 4: Read MSG response.
	msgResp, err := readOPCUAMessage(conn, timeout)
	if err != nil {
		return nil, err
	}

	rawModes, err := parseGetEndpointsResponse(msgResp)
	if err != nil {
		return nil, err
	}

	return deduplicateModes(rawModes), nil
}

// deduplicateModes returns the unique modes from rawModes in stable order:
// None, Sign, SignAndEncrypt.
func deduplicateModes(rawModes []string) []string {
	seen := make(map[string]bool)
	for _, m := range rawModes {
		seen[m] = true
	}

	order := []string{modeNone, modeSign, modeSignAndEncrypt}
	result := make([]string, 0, len(seen))
	for _, m := range order {
		if seen[m] {
			result = append(result, m)
		}
	}
	return result
}

// readOPCUAMessage reads a complete OPC UA binary message from conn.
// It first reads the 8-byte fixed header to determine the total message size,
// then reads the remaining bytes. Returns an error if the declared size is
// larger than 1 MiB or if an I/O error occurs.
func readOPCUAMessage(conn net.Conn, timeout time.Duration) ([]byte, error) {
	const headerSize = 8
	const maxMessageSize = 1 << 20 // 1 MiB

	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}

	header := make([]byte, headerSize)
	if _, err := io.ReadFull(conn, header); err != nil {
		return nil, err
	}

	totalSize := binary.LittleEndian.Uint32(header[4:8])
	if totalSize > maxMessageSize {
		return nil, errors.New("opcua: message size exceeds 1 MiB limit")
	}
	if totalSize < headerSize {
		return nil, errors.New("opcua: message size smaller than header")
	}

	msg := make([]byte, totalSize)
	copy(msg, header)

	remaining := msg[headerSize:]
	if len(remaining) > 0 {
		if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
			return nil, err
		}
		if _, err := io.ReadFull(conn, remaining); err != nil {
			return nil, err
		}
	}

	return msg, nil
}

// buildOpenSecureChannel constructs an OPN message requesting a secure channel
// with SecurityPolicy#None (unencrypted, unauthenticated).
//
// Message layout:
//
//	Header (12 bytes): "OPN" + 'F' + msgSize(4) + secureChannelId=0(4)
//	Asymmetric security header:
//	  PolicyURI string: "http://opcfoundation.org/UA/SecurityPolicy#None"
//	  SenderCertificate: null (int32 = -1)
//	  ReceiverCertificateThumbprint: null (int32 = -1)
//	Sequence header: seqNum=1(4) + requestId=1(4)
//	Body:
//	  TypeId: FourByte NodeId (encoding=1, ns=0, id=446)
//	  RequestHeader: minimal (null nodeId + timestamp + handle + diagnosticsMask)
//	  ClientProtocolVersion: 0
//	  RequestType: 0 (Issue)
//	  SecurityMode: 1 (None)
//	  ClientNonce: null (int32 = -1)
//	  RequestedLifetime: 3600000
func buildOpenSecureChannel() []byte {
	policyURI := "http://opcfoundation.org/UA/SecurityPolicy#None"

	body := make([]byte, 0, 128)

	// TypeId: FourByte NodeId (encoding byte=1, namespace=0, identifier=446)
	body = append(body, 0x01)       // encoding: FourByte
	body = append(body, 0x00)       // namespace index = 0
	body = appendUint16(body, 446)  // node id = 446 (OpenSecureChannelRequest)

	// RequestHeader:
	//   AuthenticationToken: null NodeId (TwoByte encoding=0, id=0)
	body = append(body, 0x00, 0x00)
	//   Timestamp: int64 (0)
	body = appendInt64(body, 0)
	//   RequestHandle: uint32 (0)
	body = appendUint32(body, 0)
	//   ReturnDiagnostics: uint32 (0)
	body = appendUint32(body, 0)
	//   AuditEntryId: null string (int32 = -1)
	body = appendInt32(body, -1)
	//   TimeoutHint: uint32 (0)
	body = appendUint32(body, 0)
	//   AdditionalHeader: ExtensionObject (null NodeId + no body)
	body = append(body, 0x00, 0x00) // null NodeId (TwoByte encoding=0, id=0)
	body = append(body, 0x00)       // encoding = no body

	// ClientProtocolVersion: uint32 = 0
	body = appendUint32(body, 0)
	// RequestType: uint32 = 0 (Issue)
	body = appendUint32(body, 0)
	// SecurityMode: uint32 = 1 (None)
	body = appendUint32(body, 1)
	// ClientNonce: null ByteString (int32 = -1)
	body = appendInt32(body, -1)
	// RequestedLifetime: uint32 = 3600000
	body = appendUint32(body, 3600000)

	// Asymmetric security header
	secHdr := make([]byte, 0, 64)
	secHdr = appendOPCString(secHdr, policyURI)
	secHdr = appendInt32(secHdr, -1) // SenderCertificate: null
	secHdr = appendInt32(secHdr, -1) // ReceiverCertificateThumbprint: null

	// Sequence header: seqNum=1, requestId=1
	seqHdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(seqHdr[0:4], 1)
	binary.LittleEndian.PutUint32(seqHdr[4:8], 1)

	// OPN transport header: "OPN" + 'F' + totalSize(4) + secureChannelId=0(4)
	// total = 4 (msgType+chunkType) + 4 (size field) + 4 (channelId) + len(secHdr) + len(seqHdr) + len(body)
	totalSize := 4 + 4 + 4 + len(secHdr) + len(seqHdr) + len(body)

	msg := make([]byte, 0, totalSize)
	msg = append(msg, []byte("OPN")...)
	msg = append(msg, 'F')
	msg = appendUint32(msg, uint32(totalSize)) // #nosec G115
	msg = appendUint32(msg, 0) // secureChannelId = 0
	msg = append(msg, secHdr...)
	msg = append(msg, seqHdr...)
	msg = append(msg, body...)

	return msg
}

// buildGetEndpoints constructs a MSG message for the GetEndpoints service.
//
// Message layout:
//
//	Header (12 bytes): "MSG" + 'F' + msgSize(4) + channelID(4)
//	Symmetric security header: tokenID(4)
//	Sequence header: seqNum=2(4) + requestId=2(4)
//	Body:
//	  TypeId: FourByte NodeId (encoding=1, ns=0, id=428)
//	  RequestHeader: minimal
//	  EndpointUrl: OPC UA string
//	  LocaleIds: null array (int32 = -1)
//	  ProfileUris: null array (int32 = -1)
func buildGetEndpoints(channelID, tokenID uint32, endpointURL string) []byte {
	body := make([]byte, 0, 128)

	// TypeId: FourByte NodeId (encoding=1, ns=0, id=428 = GetEndpointsRequest)
	body = append(body, 0x01)      // encoding: FourByte
	body = append(body, 0x00)      // namespace index = 0
	body = appendUint16(body, 428) // node id = 428

	// RequestHeader (minimal)
	body = append(body, 0x00, 0x00) // AuthenticationToken: null NodeId (TwoByte)
	body = appendInt64(body, 0)
	body = appendUint32(body, 1) // RequestHandle = 1
	body = appendUint32(body, 0) // ReturnDiagnostics = 0
	body = appendInt32(body, -1) // AuditEntryId: null
	body = appendUint32(body, 0) // TimeoutHint = 0
	body = append(body, 0x00, 0x00) // AdditionalHeader: null NodeId (TwoByte)
	body = append(body, 0x00)       // AdditionalHeader: encoding = no body

	// EndpointUrl
	body = appendOPCString(body, endpointURL)
	// LocaleIds: null array
	body = appendInt32(body, -1)
	// ProfileUris: null array
	body = appendInt32(body, -1)

	// Symmetric security header: tokenID(4)
	symHdr := make([]byte, 4)
	binary.LittleEndian.PutUint32(symHdr, tokenID)

	// Sequence header: seqNum=2, requestId=2
	seqHdr := make([]byte, 8)
	binary.LittleEndian.PutUint32(seqHdr[0:4], 2)
	binary.LittleEndian.PutUint32(seqHdr[4:8], 2)

	// MSG transport header: "MSG" + 'F' + totalSize(4) + channelID(4)
	totalSize := 4 + 4 + 4 + len(symHdr) + len(seqHdr) + len(body)

	msg := make([]byte, 0, totalSize)
	msg = append(msg, []byte("MSG")...)
	msg = append(msg, 'F')
	msg = appendUint32(msg, uint32(totalSize)) // #nosec G115
	msg = appendUint32(msg, channelID)
	msg = append(msg, symHdr...)
	msg = append(msg, seqHdr...)
	msg = append(msg, body...)

	return msg
}

// parseOpenSecureChannelResponse extracts the channelID and tokenID from an OPN response.
// channelID is at bytes 8-11 of the message header.
// tokenID is extracted by parsing through the asymmetric security header, sequence header,
// and response body to the SecurityToken field of OpenSecureChannelResponse.
func parseOpenSecureChannelResponse(data []byte) (channelID, tokenID uint32, err error) {
	if len(data) < 12 {
		return 0, 0, errors.New("opcua: OPN response too short")
	}
	if string(data[0:3]) != "OPN" {
		return 0, 0, errors.New("opcua: expected OPN message type")
	}

	// channelID is at bytes 8-11 (after "OPN" + 'F' + size(4))
	channelID = binary.LittleEndian.Uint32(data[8:12])

	r := &opcuaReader{data: data, pos: 12}

	// Skip asymmetric security header: PolicyURI + SenderCert + ReceiverThumb
	if err = r.skipByteString(); err != nil {
		return 0, 0, fmt.Errorf("opcua: OPN skip PolicyURI: %w", err)
	}
	if err = r.skipByteString(); err != nil {
		return 0, 0, fmt.Errorf("opcua: OPN skip SenderCert: %w", err)
	}
	if err = r.skipByteString(); err != nil {
		return 0, 0, fmt.Errorf("opcua: OPN skip ReceiverThumb: %w", err)
	}

	// Skip sequence header: seqNum(4) + requestId(4)
	if err = r.skip(8); err != nil {
		return 0, 0, fmt.Errorf("opcua: OPN skip sequence header: %w", err)
	}

	// Skip TypeId NodeId
	if err = r.skipNodeId(); err != nil {
		return 0, 0, fmt.Errorf("opcua: OPN skip TypeId: %w", err)
	}

	// Skip ResponseHeader
	if err = r.skipResponseHeader(); err != nil {
		return 0, 0, fmt.Errorf("opcua: OPN skip ResponseHeader: %w", err)
	}

	// ServerProtocolVersion: uint32
	if err = r.skip(4); err != nil {
		return 0, 0, fmt.Errorf("opcua: OPN skip ServerProtocolVersion: %w", err)
	}

	// SecurityToken structure:
	//   ChannelId: uint32
	//   TokenId:   uint32
	//   CreatedAt: int64
	//   RevisedLifetime: uint32
	if err = r.skip(4); err != nil { // ChannelId (we already have it from header)
		return 0, 0, fmt.Errorf("opcua: OPN skip SecurityToken.ChannelId: %w", err)
	}
	if r.pos+4 > len(r.data) {
		return 0, 0, errors.New("opcua: OPN response truncated before TokenId")
	}
	tokenID = binary.LittleEndian.Uint32(r.data[r.pos : r.pos+4])

	return channelID, tokenID, nil
}

// parseGetEndpointsResponse parses a GetEndpoints MSG response and returns
// the security mode string for each endpoint.
// MessageSecurityMode values: 1=None, 2=Sign, 3=SignAndEncrypt.
func parseGetEndpointsResponse(data []byte) ([]string, error) {
	if len(data) < 12 {
		return nil, errors.New("opcua: MSG response too short")
	}
	if string(data[0:3]) != "MSG" {
		return nil, errors.New("opcua: expected MSG message type")
	}

	r := &opcuaReader{data: data, pos: 12}

	// Skip symmetric security header: tokenID(4)
	if err := r.skip(4); err != nil {
		return nil, fmt.Errorf("opcua: MSG skip symHdr: %w", err)
	}

	// Skip sequence header: seqNum(4) + requestId(4)
	if err := r.skip(8); err != nil {
		return nil, fmt.Errorf("opcua: MSG skip seqHdr: %w", err)
	}

	// Skip TypeId NodeId
	if err := r.skipNodeId(); err != nil {
		return nil, fmt.Errorf("opcua: MSG skip TypeId: %w", err)
	}

	// Skip ResponseHeader
	if err := r.skipResponseHeader(); err != nil {
		return nil, fmt.Errorf("opcua: MSG skip ResponseHeader: %w", err)
	}

	// Endpoints array: int32 count
	if r.pos+4 > len(r.data) {
		return nil, errors.New("opcua: MSG truncated before endpoints count")
	}
	count := int32(binary.LittleEndian.Uint32(r.data[r.pos : r.pos+4])) // #nosec G115
	r.pos += 4

	if count < 0 {
		// null array
		return nil, nil
	}
	if count > maxArrayElements {
		return nil, fmt.Errorf("opcua: array count %d exceeds limit", count)
	}

	var modes []string
	for i := int32(0); i < count; i++ {
		mode, err := r.readEndpointSecurityMode()
		if err != nil {
			return modes, err
		}
		modes = append(modes, mode)
	}

	return modes, nil
}

// opcuaReader is a stateful cursor over a byte slice for parsing OPC UA binary-encoded structures.
type opcuaReader struct {
	data []byte
	pos  int
}

func (r *opcuaReader) skip(n int) error {
	if r.pos+n > len(r.data) {
		return fmt.Errorf("opcua: need %d bytes at pos %d, have %d", n, r.pos, len(r.data))
	}
	r.pos += n
	return nil
}

// skipByteString skips an OPC UA ByteString: int32 length (-1=null) + bytes.
func (r *opcuaReader) skipByteString() error {
	if r.pos+4 > len(r.data) {
		return fmt.Errorf("opcua: need 4 bytes for string length at pos %d", r.pos)
	}
	length := int32(binary.LittleEndian.Uint32(r.data[r.pos : r.pos+4])) // #nosec G115
	r.pos += 4
	if length > 0 {
		if err := r.skip(int(length)); err != nil {
			return err
		}
	}
	return nil
}

// skipNodeId skips a NodeId. The encoding byte determines the layout:
//   - 0x00: TwoByte (1 extra byte)
//   - 0x01: FourByte (3 extra bytes)
//   - 0x02: Numeric (4+4 bytes: namespace + uint32)
//   - 0x03: String NodeId (4+string)
//   - 0x04: GUID (4+16 bytes)
//   - 0x05: ByteString (4+bytestring)
func (r *opcuaReader) skipNodeId() error {
	if r.pos >= len(r.data) {
		return fmt.Errorf("opcua: need 1 byte for NodeId encoding at pos %d", r.pos)
	}
	encoding := r.data[r.pos]
	r.pos++
	// Strip flags (bits 6 and 7 are NamespaceURI and ServerIndex flags)
	baseEncoding := encoding & 0x3F
	switch baseEncoding {
	case 0x00: // TwoByte: 1 byte identifier
		return r.skip(1)
	case 0x01: // FourByte: 1 byte namespace + 2 byte identifier
		return r.skip(3)
	case 0x02: // Numeric: 2 byte namespace + 4 byte identifier
		return r.skip(6)
	case 0x03: // String: 2 byte namespace + OPC String
		if err := r.skip(2); err != nil {
			return err
		}
		return r.skipByteString()
	case 0x04: // GUID: 2 byte namespace + 16 bytes
		return r.skip(18)
	case 0x05: // ByteString: 2 byte namespace + ByteString
		if err := r.skip(2); err != nil {
			return err
		}
		return r.skipByteString()
	default:
		return fmt.Errorf("opcua: unknown NodeId encoding 0x%02x at pos %d", encoding, r.pos-1)
	}
}

// skipLocalizedText skips an OPC UA LocalizedText: mask byte, optional locale string, optional text string.
func (r *opcuaReader) skipLocalizedText() error {
	if r.pos >= len(r.data) {
		return fmt.Errorf("opcua: need 1 byte for LocalizedText mask at pos %d", r.pos)
	}
	mask := r.data[r.pos]
	r.pos++
	if mask&0x01 != 0 { // locale present
		if err := r.skipByteString(); err != nil {
			return err
		}
	}
	if mask&0x02 != 0 { // text present
		if err := r.skipByteString(); err != nil {
			return err
		}
	}
	return nil
}

const maxDiagnosticDepth = 32

// skipDiagnosticInfo skips an OPC UA DiagnosticInfo structure (may be recursive).
func (r *opcuaReader) skipDiagnosticInfo() error {
	return r.skipDiagnosticInfoDepth(0)
}

func (r *opcuaReader) skipDiagnosticInfoDepth(depth int) error {
	if depth > maxDiagnosticDepth {
		return errors.New("opcua: DiagnosticInfo nesting exceeds limit")
	}
	if r.pos >= len(r.data) {
		return fmt.Errorf("opcua: need 1 byte for DiagnosticInfo mask at pos %d", r.pos)
	}
	mask := r.data[r.pos]
	r.pos++
	if mask&0x01 != 0 { // symbolic id
		if err := r.skip(4); err != nil {
			return err
		}
	}
	if mask&0x02 != 0 { // namespace uri
		if err := r.skip(4); err != nil {
			return err
		}
	}
	if mask&0x04 != 0 { // locale
		if err := r.skip(4); err != nil {
			return err
		}
	}
	if mask&0x08 != 0 { // localized text
		if err := r.skip(4); err != nil {
			return err
		}
	}
	if mask&0x10 != 0 { // additional info string
		if err := r.skipByteString(); err != nil {
			return err
		}
	}
	if mask&0x20 != 0 { // inner status code
		if err := r.skip(4); err != nil {
			return err
		}
	}
	if mask&0x40 != 0 { // inner diagnostic info (recursive)
		if err := r.skipDiagnosticInfoDepth(depth + 1); err != nil {
			return err
		}
	}
	return nil
}

// skipExtensionObject skips an OPC UA ExtensionObject: NodeId + encoding byte + optional body.
func (r *opcuaReader) skipExtensionObject() error {
	if err := r.skipNodeId(); err != nil {
		return err
	}
	if r.pos >= len(r.data) {
		return fmt.Errorf("opcua: need 1 byte for ExtensionObject encoding at pos %d", r.pos)
	}
	encoding := r.data[r.pos]
	r.pos++
	if encoding == 0x00 {
		return nil // no body
	}
	// encoding 1 = ByteString body, encoding 2 = XML body — both prefixed with int32 length
	return r.skipByteString()
}

// skipResponseHeader skips the standard OPC UA ResponseHeader:
//
//	Timestamp(8) + RequestHandle(4) + ServiceResult(4) + DiagnosticInfo + StringTable array + ExtensionObject
func (r *opcuaReader) skipResponseHeader() error {
	// Timestamp: int64 (8 bytes)
	if err := r.skip(8); err != nil {
		return err
	}
	// RequestHandle: uint32 (4 bytes)
	if err := r.skip(4); err != nil {
		return err
	}
	// ServiceResult: uint32 (4 bytes)
	if err := r.skip(4); err != nil {
		return err
	}
	// ServiceDiagnostics: DiagnosticInfo
	if err := r.skipDiagnosticInfo(); err != nil {
		return err
	}
	// StringTable: array of strings (int32 count + strings)
	if r.pos+4 > len(r.data) {
		return errors.New("opcua: truncated before StringTable count")
	}
	count := int32(binary.LittleEndian.Uint32(r.data[r.pos : r.pos+4])) // #nosec G115
	r.pos += 4
	if count > maxArrayElements {
		return fmt.Errorf("opcua: array count %d exceeds limit", count)
	}
	if count > 0 {
		for i := int32(0); i < count; i++ {
			if err := r.skipByteString(); err != nil {
				return err
			}
		}
	}
	// AdditionalHeader: ExtensionObject
	return r.skipExtensionObject()
}

// skipApplicationDescription skips an OPC UA ApplicationDescription:
//
//	ApplicationUri(string) + ProductUri(string) + ApplicationName(LocalizedText) +
//	ApplicationType(uint32) + GatewayServerUri(string) + DiscoveryProfileUri(string) +
//	DiscoveryUrls(string array)
func (r *opcuaReader) skipApplicationDescription() error {
	if err := r.skipByteString(); err != nil { // ApplicationUri
		return err
	}
	if err := r.skipByteString(); err != nil { // ProductUri
		return err
	}
	if err := r.skipLocalizedText(); err != nil { // ApplicationName
		return err
	}
	if err := r.skip(4); err != nil { // ApplicationType: uint32
		return err
	}
	if err := r.skipByteString(); err != nil { // GatewayServerUri
		return err
	}
	if err := r.skipByteString(); err != nil { // DiscoveryProfileUri
		return err
	}
	// DiscoveryUrls: string array
	if r.pos+4 > len(r.data) {
		return errors.New("opcua: truncated before DiscoveryUrls count")
	}
	urlCount := int32(binary.LittleEndian.Uint32(r.data[r.pos : r.pos+4])) // #nosec G115
	r.pos += 4
	if urlCount > maxArrayElements {
		return fmt.Errorf("opcua: array count %d exceeds limit", urlCount)
	}
	if urlCount > 0 {
		for i := int32(0); i < urlCount; i++ {
			if err := r.skipByteString(); err != nil {
				return err
			}
		}
	}
	return nil
}

// skipUserTokenPolicy skips an OPC UA UserTokenPolicy:
//
//	PolicyId(string) + TokenType(uint32) + IssuedTokenType(string) +
//	IssuerEndpointUrl(string) + SecurityPolicyUri(string)
func (r *opcuaReader) skipUserTokenPolicy() error {
	if err := r.skipByteString(); err != nil { // PolicyId
		return err
	}
	if err := r.skip(4); err != nil { // TokenType: uint32
		return err
	}
	if err := r.skipByteString(); err != nil { // IssuedTokenType
		return err
	}
	if err := r.skipByteString(); err != nil { // IssuerEndpointUrl
		return err
	}
	return r.skipByteString() // SecurityPolicyUri
}

// readEndpointSecurityMode reads a single EndpointDescription from r and returns
// its MessageSecurityMode as a string ("None", "Sign", or "SignAndEncrypt").
//
// EndpointDescription layout:
//
//	EndpointUrl(string) + Server(ApplicationDescription) + ServerCertificate(ByteString) +
//	MessageSecurityMode(uint32) + SecurityPolicyUri(string) +
//	UserIdentityTokens(array of UserTokenPolicy) + TransportProfileUri(string) +
//	SecurityLevel(byte)
func (r *opcuaReader) readEndpointSecurityMode() (string, error) {
	if err := r.skipByteString(); err != nil { // EndpointUrl
		return "", fmt.Errorf("opcua: endpoint skip EndpointUrl: %w", err)
	}
	if err := r.skipApplicationDescription(); err != nil { // Server
		return "", fmt.Errorf("opcua: endpoint skip Server: %w", err)
	}
	if err := r.skipByteString(); err != nil { // ServerCertificate
		return "", fmt.Errorf("opcua: endpoint skip ServerCertificate: %w", err)
	}

	// MessageSecurityMode: uint32
	if r.pos+4 > len(r.data) {
		return "", errors.New("opcua: truncated before MessageSecurityMode")
	}
	modeVal := binary.LittleEndian.Uint32(r.data[r.pos : r.pos+4])
	r.pos += 4

	var modeName string
	switch modeVal {
	case 1:
		modeName = modeNone
	case 2:
		modeName = modeSign
	case 3:
		modeName = modeSignAndEncrypt
	default:
		modeName = "" // unknown/invalid mode, excluded from analysis
	}

	// Skip remaining fields: SecurityPolicyUri + UserIdentityTokens array + TransportProfileUri + SecurityLevel
	if err := r.skipByteString(); err != nil { // SecurityPolicyUri
		return modeName, nil // best-effort: return mode even if rest fails
	}

	// UserIdentityTokens: array
	if r.pos+4 > len(r.data) {
		return modeName, nil
	}
	tokenCount := int32(binary.LittleEndian.Uint32(r.data[r.pos : r.pos+4])) // #nosec G115
	r.pos += 4
	if tokenCount > maxArrayElements {
		return modeName, fmt.Errorf("opcua: array count %d exceeds limit", tokenCount)
	}
	if tokenCount > 0 {
		for i := int32(0); i < tokenCount; i++ {
			if err := r.skipUserTokenPolicy(); err != nil {
				return modeName, nil // best-effort
			}
		}
	}

	if err := r.skipByteString(); err != nil { // TransportProfileUri
		return modeName, nil
	}
	_ = r.skip(1) // SecurityLevel: byte (best-effort)

	return modeName, nil
}

// buildOPCUAHello constructs an OPC UA Hello message.
//
// Message structure:
//
//	Header (8 bytes):
//	  - Bytes 0-2: "HEL" (MessageType)
//	  - Byte 3: 'F' (final chunk indicator)
//	  - Bytes 4-7: MessageSize as UInt32 little-endian (includes header)
//	Body:
//	  - ProtocolVersion: UInt32 (0 for OPC UA 1.0)
//	  - ReceiveBufferSize: UInt32 (65536 bytes)
//	  - SendBufferSize: UInt32 (65536 bytes)
//	  - MaxMessageSize: UInt32 (0 = no limit)
//	  - MaxChunkCount: UInt32 (0 = no limit)
//	  - EndpointUrl: String (4-byte length prefix + UTF-8 bytes)
func buildOPCUAHello(endpointURL string) []byte {
	// Header
	messageType := []byte("HEL")
	chunkType := byte('F') // Final chunk

	// Body parameters
	protocolVersion := uint32(0)       // OPC UA 1.0
	receiveBufferSize := uint32(65536) // 64 KB
	sendBufferSize := uint32(65536)    // 64 KB
	maxMessageSize := uint32(0)        // No limit
	maxChunkCount := uint32(0)         // No limit

	// Endpoint URL with length prefix
	endpointBytes := []byte(endpointURL)
	endpointLength := uint32(len(endpointBytes)) // #nosec G115

	// Calculate total message size
	messageSize := uint32(8 + // #nosec G115
		4 + // ProtocolVersion
		4 + // ReceiveBufferSize
		4 + // SendBufferSize
		4 + // MaxMessageSize
		4 + // MaxChunkCount
		4 + // EndpointUrl length
		len(endpointBytes)) // EndpointUrl bytes

	// Build message
	message := make([]byte, 0, messageSize)

	// Header
	message = append(message, messageType...)
	message = append(message, chunkType)
	messageSizeBytes := make([]byte, 4)
	binary.LittleEndian.PutUint32(messageSizeBytes, messageSize)
	message = append(message, messageSizeBytes...)

	// Body
	buf := make([]byte, 4)

	binary.LittleEndian.PutUint32(buf, protocolVersion)
	message = append(message, buf...)

	binary.LittleEndian.PutUint32(buf, receiveBufferSize)
	message = append(message, buf...)

	binary.LittleEndian.PutUint32(buf, sendBufferSize)
	message = append(message, buf...)

	binary.LittleEndian.PutUint32(buf, maxMessageSize)
	message = append(message, buf...)

	binary.LittleEndian.PutUint32(buf, maxChunkCount)
	message = append(message, buf...)

	binary.LittleEndian.PutUint32(buf, endpointLength)
	message = append(message, buf...)

	message = append(message, endpointBytes...)

	return message
}

func (p *OPCUAPlugin) Name() string {
	return OPCUA
}

func (p *OPCUAPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *OPCUAPlugin) Priority() int {
	return 400
}

// Binary encoding helpers

func appendUint16(b []byte, v uint16) []byte {
	var buf [2]byte
	binary.LittleEndian.PutUint16(buf[:], v)
	return append(b, buf[:]...)
}

func appendUint32(b []byte, v uint32) []byte {
	var buf [4]byte
	binary.LittleEndian.PutUint32(buf[:], v)
	return append(b, buf[:]...)
}

func appendInt32(b []byte, v int32) []byte {
	return appendUint32(b, uint32(v)) // #nosec G115
}

func appendInt64(b []byte, v int64) []byte {
	var buf [8]byte
	binary.LittleEndian.PutUint64(buf[:], uint64(v)) // #nosec G115
	return append(b, buf[:]...)
}

// appendOPCString appends an OPC UA string: int32 byte-length prefix + UTF-8 bytes.
// An empty string is encoded as length=0 (not null).
func appendOPCString(b []byte, s string) []byte {
	b = appendInt32(b, int32(len(s))) // #nosec G115
	return append(b, []byte(s)...)
}
