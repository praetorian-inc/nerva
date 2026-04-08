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

// Package x11 implements detection of X11 (X Window System) servers.
//
// X11 servers listen on ports 6000-6063, one port per display number.
// Port 6000 = display :0, port 6001 = display :1, etc.
//
// Detection uses the X11 connection setup protocol (little-endian):
//   - Client sends a 12-byte connection setup request
//   - Server responds with an 8-byte header indicating status:
//     0 = Failed, 1 = Success, 2 = Authenticate (requires auth)
//
// Any valid response with a reasonable protocol version (11.x) confirms X11.
//
// Reference: https://www.x.org/releases/X11R7.7/doc/xproto/x11protocol.html
package x11

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

// X11 is the protocol name constant.
const X11 = "x11"

// x11BasePort is the base port for X11 displays (display :0 = port 6000).
const x11BasePort = 6000

// x11MinResponseLen is the minimum valid response length (8-byte header).
const x11MinResponseLen = 8

// x11SuccessDataLen is the minimum data length for a success response to include vendor info.
// Offset 40 is where the vendor string starts.
const x11SuccessDataLen = 40

// Status codes in the X11 connection setup response.
const (
	x11StatusFailed       = 0
	x11StatusSuccess      = 1
	x11StatusAuthenticate = 2
)

// x11SetupRequest is the 12-byte little-endian X11 connection setup request.
//
// Layout:
//
//	Byte 0:    0x6c (byte order mark = little-endian)
//	Byte 1:    0x00 (unused)
//	Bytes 2-3: 0x0b, 0x00 (protocol major version 11, little-endian)
//	Bytes 4-5: 0x00, 0x00 (protocol minor version 0)
//	Bytes 6-7: 0x00, 0x00 (auth protocol name length = 0)
//	Bytes 8-9: 0x00, 0x00 (auth protocol data length = 0)
//	Bytes 10-11: 0x00, 0x00 (unused padding)
var x11SetupRequest = []byte{
	0x6c, 0x00, // byte order (little-endian), unused
	0x0b, 0x00, // major version 11
	0x00, 0x00, // minor version 0
	0x00, 0x00, // auth name length 0
	0x00, 0x00, // auth data length 0
	0x00, 0x00, // unused padding
}

// Plugin implements the X11 service detection plugin.
type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// PortPriority returns true for ports in the X11 display range (6000-6063).
func (p *Plugin) PortPriority(port uint16) bool {
	return port >= 6000 && port <= 6063
}

// Name returns the protocol name.
func (p *Plugin) Name() string {
	return X11
}

// Type returns TCP as the transport protocol.
func (p *Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

// Priority returns the plugin execution priority.
func (p *Plugin) Priority() int {
	return 10
}

// Run attempts to detect an X11 server on the given connection.
//
// It sends the X11 connection setup request and validates the response.
// Any valid response (status 0, 1, or 2) with a reasonable version (11.x)
// confirms an X11 server is present.
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, err := utils.SendRecv(conn, x11SetupRequest, timeout)
	if err != nil {
		return nil, err
	}

	info, detected := parseX11Response(response)
	if !detected {
		return nil, nil
	}

	// Derive display number from port
	info.DisplayNumber = int(target.Address.Port()) - x11BasePort

	version := fmt.Sprintf("%d.%d", info.MajorVersion, info.MinorVersion)
	service := plugins.CreateServiceFrom(target, info, false, version, plugins.TCP)
	if target.Misconfigs && info.AccessGranted {
		service.AnonymousAccess = true
		service.SecurityFindings = []plugins.SecurityFinding{{
			ID:          "x11-unauth-access",
			Severity:    plugins.SeverityCritical,
			Description: "X11 server grants access without authentication",
			Evidence:    fmt.Sprintf("X11 connection accepted with status=Success (display :%d)", info.DisplayNumber),
		}}
	}
	return service, nil
}

// parseX11Response parses the X11 connection setup response header.
//
// The response header is 8 bytes:
//
//	Byte 0:    status (0=Failed, 1=Success, 2=Authenticate)
//	Byte 1:    unused (success) or reason length (failed)
//	Bytes 2-3: protocol major version (little-endian uint16)
//	Bytes 4-5: protocol minor version (little-endian uint16)
//	Bytes 6-7: length of additional data in 4-byte units (little-endian uint16)
//
// For Success (status=1), additional data follows with vendor info at offset 40.
func parseX11Response(response []byte) (plugins.ServiceX11, bool) {
	if len(response) < x11MinResponseLen {
		return plugins.ServiceX11{}, false
	}

	status := response[0]

	// Only accept valid X11 status codes
	if status != x11StatusFailed && status != x11StatusSuccess && status != x11StatusAuthenticate {
		return plugins.ServiceX11{}, false
	}

	majorVersion := binary.LittleEndian.Uint16(response[2:4])
	minorVersion := binary.LittleEndian.Uint16(response[4:6])

	// Validate version: X11 major version must be 11, minor version reasonable (0-99)
	if majorVersion != 11 || minorVersion > 99 {
		return plugins.ServiceX11{}, false
	}

	info := plugins.ServiceX11{
		MajorVersion:  majorVersion,
		MinorVersion:  minorVersion,
		AccessGranted: status == x11StatusSuccess,
	}

	// For successful connections, try to extract vendor string
	if status == x11StatusSuccess && len(response) >= x11SuccessDataLen {
		vendorLength := binary.LittleEndian.Uint16(response[24:26])
		vendorEnd := x11SuccessDataLen + int(vendorLength)
		if vendorLength > 0 && len(response) >= vendorEnd {
			info.Vendor = string(response[x11SuccessDataLen:vendorEnd])
		}
	}

	return info, true
}
