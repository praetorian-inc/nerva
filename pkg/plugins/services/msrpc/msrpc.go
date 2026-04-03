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

// Package msrpc detects Microsoft DCE/RPC services (port 135 endpoint mapper
// and dynamic RPC ports).
//
// DCE/RPC is the primary IPC mechanism in Windows environments, used by Active
// Directory, Exchange, DCOM, WMI, Print Spooler, and many other services.
// Detection sends a DCE/RPC bind request for the endpoint mapper (EPM) interface
// and validates the bind_ack response.
//
// Security relevance: exposed RPC enables PrintNightmare (CVE-2021-34527),
// PetitPotam (NTLM relay), and lateral movement via WMI/DCOM/scheduled tasks.
package msrpc

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	MSRPC       = "msrpc"
	DefaultPort = 135

	// DCE/RPC PDU types
	pduTypeBind    = 0x0b
	pduTypeBindAck = 0x0c

	// DCE/RPC version
	rpcVersionMajor = 5
	rpcVersionMinor = 0

	// Minimum bind_ack response size (header only)
	minBindAckSize = 24
)

// DCE/RPC bind request for the Endpoint Mapper (EPM) interface.
// UUID: e1af8308-5d1f-11c9-91a4-08002b14a0fa, version 3.0
// Transfer syntax: NDR 8a885d04-1ceb-11c9-9fe8-08002b104860, version 2.0
var rpcBindRequest = []byte{
	// Header (16 bytes)
	0x05,       // rpc_vers: 5
	0x00,       // rpc_vers_minor: 0
	pduTypeBind, // PTYPE: bind (11)
	0x03,       // pfc_flags: first_frag | last_frag
	0x10, 0x00, 0x00, 0x00, // packed_drep: little-endian, ASCII, IEEE
	0x48, 0x00, // frag_length: 72
	0x00, 0x00, // auth_length: 0
	0x01, 0x00, 0x00, 0x00, // call_id: 1

	// Bind body
	0xd0, 0x16, // max_xmit_frag: 5840
	0xd0, 0x16, // max_recv_frag: 5840
	0x00, 0x00, 0x00, 0x00, // assoc_group_id: 0
	0x01,                   // p_context_elem.n_context_elem: 1
	0x00, 0x00, 0x00,       // reserved

	// Context item 0
	0x00, 0x00, // p_cont_id: 0
	0x01,       // n_transfer_syn: 1
	0x00,       // reserved

	// Abstract syntax: EPM UUID e1af8308-5d1f-11c9-91a4-08002b14a0fa v3.0
	0x08, 0x83, 0xaf, 0xe1,
	0x1f, 0x5d,
	0xc9, 0x11,
	0x91, 0xa4,
	0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
	0x03, 0x00, 0x00, 0x00, // interface version: 3.0

	// Transfer syntax: NDR 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
	0x04, 0x5d, 0x88, 0x8a,
	0xeb, 0x1c,
	0xc9, 0x11,
	0x9f, 0xe8,
	0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
	0x02, 0x00, 0x00, 0x00, // transfer syntax version: 2.0
}

type MSRPCPlugin struct{}

func init() {
	plugins.RegisterPlugin(&MSRPCPlugin{})
}

func (p *MSRPCPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.SendRecv(conn, rpcBindRequest, timeout)
	if err != nil {
		return nil, nil
	}

	if !isValidBindAck(response) {
		return nil, nil
	}

	payload := plugins.ServiceMSRPC{}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

// isValidBindAck validates a DCE/RPC bind_ack response.
// Checks: version 5.0, PDU type 0x0c (bind_ack), and fragment length consistency.
func isValidBindAck(response []byte) bool {
	if len(response) < minBindAckSize {
		return false
	}

	// Check RPC version 5.0
	if response[0] != rpcVersionMajor || response[1] != rpcVersionMinor {
		return false
	}

	// Check PDU type is bind_ack (0x0c)
	if response[2] != pduTypeBindAck {
		return false
	}

	// Validate fragment length matches response
	fragLen := binary.LittleEndian.Uint16(response[8:10])
	if int(fragLen) != len(response) {
		return false
	}

	return true
}

func (p *MSRPCPlugin) PortPriority(port uint16) bool {
	return port == DefaultPort
}

func (p *MSRPCPlugin) Name() string {
	return MSRPC
}

func (p *MSRPCPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MSRPCPlugin) Priority() int {
	return 200
}
