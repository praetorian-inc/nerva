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

// Package mysqlx detects MySQL X Protocol (port 33060) services.
//
// MySQL X Protocol is enabled by default on MySQL 8.0+ and uses a binary
// framing format: 4-byte little-endian message length + 1-byte message type +
// protobuf payload. On connection, the server immediately sends a
// SESS_AUTHENTICATE_NOTICE (type 11) frame.
package mysqlx

import (
	"encoding/binary"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	MYSQLX     = "mysqlx"
	DefaultPort = 33060

	// MySQL X Protocol server message types
	msgTypeOK              = 0
	msgTypeError           = 1
	msgTypeNotice          = 11
	msgTypeCapabilities    = 2

	// Minimum valid frame: 4-byte length + 1-byte type
	minFrameSize = 5
)

type MySQLXPlugin struct{}

func init() {
	plugins.RegisterPlugin(&MySQLXPlugin{})
}

func (p *MySQLXPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// MySQL X server sends a notice frame immediately on connection
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, nil
	}

	if !isValidMySQLXFrame(response) {
		return nil, nil
	}

	payload := plugins.ServiceMySQLX{
		CPEs: []string{"cpe:2.3:a:oracle:mysql:*:*:*:*:*:*:*:*"},
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

// isValidMySQLXFrame validates a MySQL X Protocol server frame.
// The frame format is: 4-byte LE length + 1-byte message type + payload.
// The length field encodes the size of (type byte + payload), not including
// the 4-byte length prefix itself.
func isValidMySQLXFrame(response []byte) bool {
	if len(response) < minFrameSize {
		return false
	}

	// Parse 4-byte little-endian message length
	msgLen := binary.LittleEndian.Uint32(response[:4])

	// Length must be consistent with response size: msgLen + 4 == total
	if int(msgLen)+4 != len(response) {
		return false
	}

	// Message type must be a known server message type
	msgType := response[4]
	switch msgType {
	case msgTypeOK, msgTypeError, msgTypeNotice, msgTypeCapabilities:
		return true
	default:
		return false
	}
}

func (p *MySQLXPlugin) PortPriority(port uint16) bool {
	return port == DefaultPort
}

func (p *MySQLXPlugin) Name() string {
	return MYSQLX
}

func (p *MySQLXPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MySQLXPlugin) Priority() int {
	return 300
}
