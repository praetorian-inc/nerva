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

package knxip

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	knxPort     = 3671
	knxPriority = 400 // ICS protocol tier

	// KNXnet/IP header constants
	headerLength   = 0x06
	protocolVer    = 0x10
	searchRequest  uint16 = 0x0201
	searchResponse uint16 = 0x0202

	// DIB type codes
	dibDevInfo = 0x01
	dibSuppSvc = 0x02
)

// Plugin implements KNX/IP service fingerprinting.
type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

func (p *Plugin) Type() plugins.Protocol     { return plugins.UDP }
func (p *Plugin) Priority() int              { return knxPriority }
func (p *Plugin) Name() string               { return "knxip" }
func (p *Plugin) PortPriority(port uint16) bool { return port == knxPort }

// Run performs KNX/IP device fingerprinting via Search Request.
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Build Search Request
	// Discovery endpoint: 0.0.0.0:0 (let device respond to sender)
	request := []byte{
		headerLength, protocolVer, // Header length, protocol version
		0x02, 0x01,                // Service type: Search Request (0x0201)
		0x00, 0x0E,                                    // Total length (14 bytes)
		0x08, 0x01,                                    // HPAI structure length, protocol code (UDP)
		0x00, 0x00, 0x00, 0x00,                        // IP address (0.0.0.0)
		0x00, 0x00,                                    // Port (0)
	}

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) < 8 {
		return nil, nil
	}

	// Validate KNXnet/IP header
	if response[0] != headerLength || response[1] != protocolVer {
		return nil, nil
	}
	serviceType := binary.BigEndian.Uint16(response[2:4])
	if serviceType != searchResponse {
		return nil, nil
	}

	// Validate total length field against actual response length
	totalLength := int(binary.BigEndian.Uint16(response[4:6]))
	if totalLength < headerLength || totalLength > len(response) {
		return nil, nil
	}

	// Parse Search Response, bounded to declared total length
	metadata, err := parseSearchResponse(response[:totalLength])
	if err != nil {
		return nil, err
	}

	return plugins.CreateServiceFrom(target, metadata, false, "", plugins.UDP), nil
}

// parseSearchResponse extracts device info from Search Response.
func parseSearchResponse(data []byte) (plugins.ServiceKNXIP, error) {
	var result plugins.ServiceKNXIP

	// Skip header (6 bytes) + control endpoint HPAI (8 bytes)
	offset := 14
	if len(data) < offset {
		return result, fmt.Errorf("response too short")
	}

	// Parse DIB structures
	for offset < len(data) {
		if offset+2 > len(data) {
			break
		}
		dibLen := int(data[offset])
		dibType := data[offset+1]

		if dibLen == 0 || offset+dibLen > len(data) {
			break
		}

		switch dibType {
		case dibDevInfo:
			parseDeviceInfo(data[offset:offset+dibLen], &result)
		case dibSuppSvc:
			parseServiceFamilies(data[offset:offset+dibLen], &result)
		}

		offset += dibLen
	}

	return result, nil
}

// parseDeviceInfo extracts device metadata from DIB_DEV_INFO.
func parseDeviceInfo(dib []byte, result *plugins.ServiceKNXIP) {
	if len(dib) < 54 {
		return
	}
	// DIB structure: len(1) + type(1) + medium(1) + status(1) + knx_addr(2) +
	//                project_id(2) + serial(6) + multicast(4) + mac(6) + name(30)

	// KNX Medium (offset 2)
	result.KNXMedium = knxMediumString(dib[2])

	// KNX Individual Address (offset 4-5)
	addr := binary.BigEndian.Uint16(dib[4:6])
	result.KNXAddress = fmt.Sprintf("%d.%d.%d", (addr>>12)&0xF, (addr>>8)&0xF, addr&0xFF)

	// Serial Number (offset 8-13)
	result.SerialNumber = hex.EncodeToString(dib[8:14])

	// MAC Address (offset 18-23)
	result.MACAddress = fmt.Sprintf("%02X:%02X:%02X:%02X:%02X:%02X",
		dib[18], dib[19], dib[20], dib[21], dib[22], dib[23])

	// Device Name (offset 24-53, 30 bytes, null-terminated)
	name := strings.TrimRight(string(dib[24:54]), "\x00 ")
	result.DeviceName = name
}

// parseServiceFamilies extracts supported services from DIB_SUPP_SVC_FAMILIES.
func parseServiceFamilies(dib []byte, result *plugins.ServiceKNXIP) {
	if len(dib) < 4 {
		return
	}
	// DIB structure: len(1) + type(1) + (family_id(1) + version(1))...

	var families []string
	for i := 2; i+1 < len(dib); i += 2 {
		familyID := dib[i]
		if name := serviceFamilyName(familyID); name != "" {
			families = append(families, name)
		}
	}
	result.ServiceFamilies = families
}

// knxMediumString converts medium code to string.
func knxMediumString(code byte) string {
	switch code {
	case 0x01:
		return "TP1"
	case 0x02:
		return "PL110"
	case 0x04:
		return "RF"
	case 0x20:
		return "IP"
	default:
		return fmt.Sprintf("0x%02X", code)
	}
}

// serviceFamilyName converts service family ID to name.
func serviceFamilyName(id byte) string {
	switch id {
	case 0x02:
		return "Core"
	case 0x03:
		return "DeviceManagement"
	case 0x04:
		return "Tunnelling"
	case 0x05:
		return "Routing"
	case 0x06:
		return "RemoteLogging"
	case 0x08:
		return "ObjectServer"
	default:
		return ""
	}
}
