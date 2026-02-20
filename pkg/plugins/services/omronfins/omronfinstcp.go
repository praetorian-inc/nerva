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

// Package omronfins implements OMRON FINS service fingerprinting for both UDP and TCP.
//
// FINS/TCP wraps the standard FINS command protocol in a TCP-specific framing layer.
// The protocol requires a node address handshake before commands can be exchanged:
//
//	Phase 1 – Node Address Exchange: the client sends a 20-byte request with the
//	          "FINS" magic marker and command code 0 (Node Address Send). The server
//	          responds with a 24-byte frame containing the assigned client and server
//	          node addresses that must be used in subsequent commands.
//
//	Phase 2 – FINS Command: the Read Controller Data command (MRC=0x05, SRC=0x01)
//	          is wrapped in a FINS/TCP frame (magic + length + command code 2 +
//	          error code) and sent. The server responds with the same framing around
//	          the standard FINS response payload.
package omronfins

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

// finsMagic is the 4-byte magic header present in every FINS/TCP frame.
var finsMagic = []byte{0x46, 0x49, 0x4E, 0x53} // "FINS"

const (
	finsTCPCmdNodeAddrReq  = uint32(0x00000000) // Client Node Address Data Send (request)
	finsTCPCmdNodeAddrResp = uint32(0x00000001) // Node Address Data Send Response
	finsTCPCmdFrameSend    = uint32(0x00000002) // FINS Frame Send (command/response)

	// finsTCPHeaderSize is the byte length of a FINS/TCP wrapper header:
	// magic(4) + length-field(4) + command(4) + error-code(4) = 16 bytes.
	finsTCPHeaderSize = 16

	// nodeAddrRespSize is the total byte length of the Phase 1 response:
	// header(16) + client-node(4) + server-node(4) = 24 bytes.
	nodeAddrRespSize = 24
)

// TCPPlugin implements OMRON FINS over TCP fingerprinting.
type TCPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&TCPPlugin{})
}

// Type returns the protocol transport type.
func (p *TCPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the scan priority.
func (p *TCPPlugin) Priority() int {
	return finsPriority
}

// Name returns the plugin display name.
func (p *TCPPlugin) Name() string {
	return "omron-fins"
}

// PortPriority returns true if the port matches OMRON FINS (9600).
func (p *TCPPlugin) PortPriority(port uint16) bool {
	return port == finsPort
}

// Run performs OMRON FINS/TCP device fingerprinting.
//
// The method executes the two-phase FINS/TCP handshake:
//  1. Node Address Exchange – sends a 20-byte node address request and reads
//     the server's 24-byte response to obtain the assigned client and server
//     node identifiers.
//  2. FINS Command – builds a Read Controller Data request using the assigned
//     node addresses, wraps it in the FINS/TCP frame format, and parses the
//     response with the shared parseControllerData helper.
func (p *TCPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// --- Phase 1: Node Address Exchange ---
	//
	// Request layout (20 bytes):
	//   [0:4]  "FINS" magic
	//   [4:8]  length  = 0x0000000C (12 – counts bytes after this field)
	//   [8:12] command = 0x00000000 (Client Node Address Data Send)
	//  [12:16] error   = 0x00000000
	//  [16:20] client node address = 0x00000000 (request auto-assign)
	nodeAddrReq := buildFinsTCPFrame(finsTCPCmdNodeAddrReq, []byte{0x00, 0x00, 0x00, 0x00})

	nodeAddrResp, err := utils.SendRecv(conn, nodeAddrReq, timeout)
	if err != nil {
		return nil, err
	}
	if len(nodeAddrResp) == 0 {
		return nil, nil
	}

	clientNode, serverNode, err := parseNodeAddrResponse(nodeAddrResp)
	if err != nil {
		return nil, err
	}

	// --- Phase 2: FINS Command (Read Controller Data) ---
	//
	// FINS header bytes (13 bytes):
	//   ICF=0x80, RSV=0x00, GCT=0x02
	//   DNA=0x00, DA1=serverNode, DA2=0x00
	//   SNA=0x00, SA1=clientNode, SA2=0x00
	//   SID=0xEF
	//   MRC=0x05 (Controller Data), SRC=0x01 (Read), Param=0x00
	finsCmd := []byte{
		0x80, 0x00, 0x02,
		0x00, serverNode, 0x00,
		0x00, clientNode, 0x00,
		0xEF,
		0x05, 0x01, 0x00,
	}

	cmdFrame := buildFinsTCPFrame(finsTCPCmdFrameSend, finsCmd)

	cmdResp, err := utils.SendRecv(conn, cmdFrame, timeout)
	if err != nil {
		return nil, err
	}
	if len(cmdResp) == 0 {
		return nil, nil
	}

	finsPayload, err := extractFinsTCPPayload(cmdResp)
	if err != nil {
		return nil, err
	}

	model, version, err := parseControllerData(finsPayload)
	if err != nil {
		return nil, err
	}

	cpes := generateCPE(model, version)

	metadata := plugins.ServiceOMRONFINS{
		ControllerModel:   model,
		ControllerVersion: version,
		CPEs:              cpes,
	}

	versionStr := version
	if versionStr == "" {
		versionStr = model
	}

	return plugins.CreateServiceFrom(target, metadata, false, versionStr, plugins.TCP), nil
}

// buildFinsTCPFrame constructs a FINS/TCP frame by prepending the 16-byte header
// to payload.  The "length" field in the header equals len(payload) + 8 (the
// number of bytes that follow the length field itself: command(4) + error(4) +
// payload).
func buildFinsTCPFrame(cmd uint32, payload []byte) []byte {
	// length = command(4) + error-code(4) + len(payload)
	length := uint32(8 + len(payload))

	frame := make([]byte, finsTCPHeaderSize+len(payload))
	copy(frame[0:4], finsMagic)
	binary.BigEndian.PutUint32(frame[4:8], length)
	binary.BigEndian.PutUint32(frame[8:12], cmd)
	binary.BigEndian.PutUint32(frame[12:16], 0x00000000) // error code
	copy(frame[16:], payload)
	return frame
}

// parseNodeAddrResponse validates the Phase 1 server response and returns the
// assigned client and server node addresses (last byte of each 4-byte field).
//
// Response layout (24 bytes):
//
//	[0:4]   "FINS" magic
//	[4:8]   length  = 0x00000010 (16)
//	[8:12]  command = 0x00000001
//
// [12:16] error code (must be 0)
// [16:20] client node address (assigned by server)
// [20:24] server node address
func parseNodeAddrResponse(data []byte) (clientNode, serverNode byte, err error) {
	if len(data) < nodeAddrRespSize {
		return 0, 0, fmt.Errorf("FINS/TCP node address response too short: %d bytes (expected %d)", len(data), nodeAddrRespSize)
	}

	if data[0] != finsMagic[0] || data[1] != finsMagic[1] || data[2] != finsMagic[2] || data[3] != finsMagic[3] {
		return 0, 0, fmt.Errorf("FINS/TCP node address response: invalid magic bytes")
	}

	cmd := binary.BigEndian.Uint32(data[8:12])
	if cmd != finsTCPCmdNodeAddrResp {
		return 0, 0, fmt.Errorf("FINS/TCP node address response: unexpected command 0x%08x (expected 0x%08x)", cmd, finsTCPCmdNodeAddrResp)
	}

	errorCode := binary.BigEndian.Uint32(data[12:16])
	if errorCode != 0 {
		return 0, 0, fmt.Errorf("FINS/TCP node address response: error code 0x%08x", errorCode)
	}

	// Node addresses are 4-byte big-endian fields; the relevant node number is
	// the last (least-significant) byte used in the FINS header SA1/DA1 fields.
	clientNode = data[19] // last byte of client node field [16:20]
	serverNode = data[23] // last byte of server node field [20:24]
	return clientNode, serverNode, nil
}

// extractFinsTCPPayload validates the FINS/TCP wrapper on a Phase 2 response and
// returns the inner FINS payload (bytes after the 16-byte header).
func extractFinsTCPPayload(data []byte) ([]byte, error) {
	if len(data) < finsTCPHeaderSize {
		return nil, fmt.Errorf("FINS/TCP response too short: %d bytes (expected at least %d)", len(data), finsTCPHeaderSize)
	}

	if data[0] != finsMagic[0] || data[1] != finsMagic[1] || data[2] != finsMagic[2] || data[3] != finsMagic[3] {
		return nil, fmt.Errorf("FINS/TCP response: invalid magic bytes")
	}

	cmd := binary.BigEndian.Uint32(data[8:12])
	if cmd != finsTCPCmdFrameSend {
		return nil, fmt.Errorf("FINS/TCP response: unexpected command 0x%08x (expected 0x%08x)", cmd, finsTCPCmdFrameSend)
	}

	errorCode := binary.BigEndian.Uint32(data[12:16])
	if errorCode != 0 {
		return nil, fmt.Errorf("FINS/TCP response: error code 0x%08x", errorCode)
	}

	return data[finsTCPHeaderSize:], nil
}

