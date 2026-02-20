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

/*
Package pcworx provides TCP fingerprinting for Phoenix Contact PLCs via the
PC Worx protocol on port 1962.

# Detection Strategy

Phoenix Contact ILC and AXC controllers expose a binary TCP protocol on port
1962 that requires no authentication (CVE-2019-9201, CVSS 9.8). Detection uses
a read-only 3-packet handshake:

 1. Init: Send 26-byte client identification ("IBETH01N0_M")
 2. Session: Register session using ID extracted from init response
 3. Info: Request device information (PLC type, firmware, model)

# Response Format

The info response contains null-terminated strings at fixed offsets:

	Offset 30:  PLC Type         (e.g., "ILC 151 ETH")
	Offset 66:  Firmware Version (e.g., "4.60")
	Offset 79:  Firmware Date    (e.g., "11/15/17" or "Nov  5 2018")
	Offset 91:  Firmware Time    (e.g., "14:05:00")
	Offset 152: Model Number     (e.g., "2700974")

# Port Configuration

PC Worx runs on TCP port 1962.

# ICS/SCADA Safety

This plugin performs read-only identification only. No CPU start/stop,
configuration changes, or firmware operations are performed.

# Example Usage

	p := &PCWorxPlugin{}
	service, err := p.Run(conn, timeout, target)
	if service != nil {
	    fmt.Printf("Detected: %s\n", service.Protocol)
	}
*/
package pcworx

import (
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	// initResponseSuccess is the first byte of a successful PC Worx response
	initResponseSuccess = 0x81

	// minInitResponseLen is the minimum response length to extract session ID
	minInitResponseLen = 18

	// sessionIDOffset is the 0-indexed byte position of the session ID
	sessionIDOffset = 17

	// initResponseLen is the typical length of the init response
	initResponseLen = 20

	// sessionResponseMinLen is the minimum session response length
	sessionResponseMinLen = 4

	// Info response field offsets (0-indexed)
	plcTypeOffset         = 30
	firmwareVersionOffset = 66
	firmwareDateOffset    = 79
	firmwareTimeOffset    = 91
	modelNumberOffset     = 152
)

// PCWorxPlugin detects Phoenix Contact PLCs via PC Worx protocol on port 1962
type PCWorxPlugin struct{}

func init() {
	plugins.RegisterPlugin(&PCWorxPlugin{})
}

func (p *PCWorxPlugin) PortPriority(port uint16) bool {
	return port == 1962
}

func (p *PCWorxPlugin) Name() string {
	return plugins.ProtoPCWorx
}

func (p *PCWorxPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *PCWorxPlugin) Priority() int {
	return 400 // ICS protocol priority
}

// Run performs the 3-packet PC Worx identification handshake.
// This is a read-only operation that extracts PLC type, firmware, and model info.
// Handles both separate responses (normal network) and coalesced responses (fast servers/testing).
func (p *PCWorxPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Step 1: Send init packet
	initPacket := []byte{
		0x01, 0x01, 0x00, 0x1a, 0x00, 0x00, 0x00, 0x00,
		0x78, 0x80, 0x00, 0x03, 0x00, 0x0c,
		0x49, 0x42, 0x45, 0x54, 0x48, 0x30, 0x31, 0x4e,
		0x30, 0x5f, 0x4d, 0x00, // "IBETH01N0_M\0"
	}

	initResp, err := utils.SendRecv(conn, initPacket, timeout)
	if err != nil {
		// EOF means connection closed, treat as no service detected
		if errors.Is(err, io.EOF) {
			return nil, nil
		}
		return nil, err
	}

	// Validate init response
	if len(initResp) < minInitResponseLen {
		return nil, nil
	}
	if initResp[0] != initResponseSuccess {
		return nil, nil
	}

	// Extract session ID
	sid := initResp[sessionIDOffset]

	// Check if responses are coalesced (all arrived in one buffer)
	// This can happen with fast servers or in testing scenarios
	var sessionResp []byte
	var infoResp []byte

	if len(initResp) > initResponseLen {
		// Coalesced responses detected - parse from single buffer
		remaining := initResp[initResponseLen:]
		if len(remaining) >= sessionResponseMinLen {
			sessionResp = remaining[:sessionResponseMinLen]
			if len(remaining) > sessionResponseMinLen {
				infoResp = remaining[sessionResponseMinLen:]
			}
		}
	}

	// If we don't have session response from coalesced data, send session packet
	if len(sessionResp) == 0 {
		sessionPacket := []byte{
			0x01, 0x05, 0x00, 0x16, 0x00, 0x01, 0x00, 0x00,
			0x78, 0x80, 0x00, sid,
			0x00, 0x00, 0x00, 0x06, 0x00, 0x04, 0x02, 0x95,
			0x00, 0x00,
		}

		sessionResp, err = utils.SendRecv(conn, sessionPacket, timeout)
		if err != nil {
			// EOF means connection closed, treat as no service detected
			if errors.Is(err, io.EOF) {
				return nil, nil
			}
			return nil, err
		}
		if len(sessionResp) == 0 {
			return nil, nil
		}
	}

	// If we don't have info response from coalesced data, send info packet
	if len(infoResp) == 0 {
		infoPacket := []byte{
			0x01, 0x06, 0x00, 0x0e, 0x00, 0x02, 0x00, 0x00,
			0x00, 0x00, 0x00, sid, 0x04, 0x00,
		}

		infoResp, err = utils.SendRecv(conn, infoPacket, timeout)
		if err != nil {
			// EOF means connection closed, treat as no service detected
			if errors.Is(err, io.EOF) {
				return nil, nil
			}
			return nil, err
		}
	}

	// Validate info response
	if len(infoResp) == 0 || infoResp[0] != initResponseSuccess {
		return nil, nil
	}

	// Parse device information from null-terminated strings
	serviceData := plugins.ServicePCWorx{
		PLCType:         extractNullTerminatedString(infoResp, plcTypeOffset),
		FirmwareVersion: extractNullTerminatedString(infoResp, firmwareVersionOffset),
		FirmwareDate:    extractNullTerminatedString(infoResp, firmwareDateOffset),
		FirmwareTime:    extractNullTerminatedString(infoResp, firmwareTimeOffset),
		ModelNumber:     extractNullTerminatedString(infoResp, modelNumberOffset),
	}

	// Generate CPE if PLC type is available
	if serviceData.PLCType != "" {
		serviceData.CPEs = []string{generateCPE(serviceData.PLCType, serviceData.FirmwareVersion)}
	}

	return plugins.CreateServiceFrom(target, serviceData, false, serviceData.FirmwareVersion, plugins.TCP), nil
}

// extractNullTerminatedString extracts a null-terminated string from data at the given offset
func extractNullTerminatedString(data []byte, offset int) string {
	if offset >= len(data) {
		return ""
	}
	end := offset
	for end < len(data) && data[end] != 0 {
		end++
	}
	return string(data[offset:end])
}

// cpeComponentRegex strips characters that are not safe for CPE 2.3 fields
var cpeComponentRegex = regexp.MustCompile(`[^a-z0-9_.-]`)

// normalizePLCType converts PLC type to CPE-safe format
func normalizePLCType(plcType string) string {
	s := strings.ToLower(strings.ReplaceAll(plcType, " ", "_"))
	return cpeComponentRegex.ReplaceAllString(s, "")
}

// generateCPE builds a CPE 2.3 identifier for the detected Phoenix Contact PLC
func generateCPE(plcType, fwVersion string) string {
	product := normalizePLCType(plcType)
	version := "*"
	if fwVersion != "" {
		version = cpeComponentRegex.ReplaceAllString(strings.ToLower(fwVersion), "")
	}
	if product == "" {
		return ""
	}
	return fmt.Sprintf("cpe:2.3:h:phoenixcontact:%s:%s:*:*:*:*:*:*:*", product, version)
}
