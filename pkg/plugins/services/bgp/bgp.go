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

package bgp

import (
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type BGPPlugin struct{}

const (
	BGP            = "bgp"
	BGPPort        = 179
	BGPMarkerByte  = 0xFF
	BGPMarkerSize  = 16
	BGPHeaderSize  = 19
	BGPMinOpenSize = 29
	BGPTypeOpen    = 0x01
	BGPVersion4    = 0x04
	BGPMaxMsgSize  = 4096
)

func init() {
	plugins.RegisterPlugin(&BGPPlugin{})
}

func (p *BGPPlugin) PortPriority(port uint16) bool {
	return port == BGPPort
}

func (p *BGPPlugin) Name() string {
	return BGP
}

func (p *BGPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *BGPPlugin) Priority() int {
	return 1000
}

// validateMarker checks if the first 16 bytes are all 0xFF
func validateMarker(data []byte) bool {
	if len(data) < BGPMarkerSize {
		return false
	}
	for i := 0; i < BGPMarkerSize; i++ {
		if data[i] != BGPMarkerByte {
			return false
		}
	}
	return true
}

// validateHeader validates the BGP header and returns length, type, and validity
func validateHeader(data []byte) (uint16, byte, bool) {
	if len(data) < BGPHeaderSize {
		return 0, 0, false
	}

	// Parse length (bytes 16-17, big-endian)
	length := binary.BigEndian.Uint16(data[16:18])
	if length < BGPHeaderSize || length > BGPMaxMsgSize {
		return 0, 0, false
	}

	// Parse type (byte 18)
	msgType := data[18]
	if msgType != BGPTypeOpen {
		return length, msgType, false
	}

	return length, msgType, true
}

// parseBGPOpen extracts BGP version from OPEN message
func parseBGPOpen(data []byte) (*plugins.ServiceBGP, error) {
	if len(data) < BGPMinOpenSize {
		return nil, fmt.Errorf("message too short for OPEN")
	}

	version := data[19]
	if version != BGPVersion4 {
		return nil, fmt.Errorf("unsupported BGP version: %d", version)
	}

	return &plugins.ServiceBGP{
		Version:  version,
		Detected: true,
	}, nil
}

func (p *BGPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Step 1: Receive OPEN message
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil // Timeout, not an error
	}

	// Step 2: Validate marker
	if !validateMarker(response) {
		return nil, nil // Not BGP
	}

	// Step 3: Validate header
	_, _, valid := validateHeader(response)
	if !valid {
		return nil, nil // Invalid BGP message
	}

	// Step 4: Parse OPEN message
	bgpData, err := parseBGPOpen(response)
	if err != nil {
		return nil, nil // Invalid version or malformed
	}

	// Step 5: Create Service
	return plugins.CreateServiceFrom(
		target,
		bgpData,
		false,      // TLS = false
		"",         // Version string (unused)
		plugins.TCP,
	), nil
}
