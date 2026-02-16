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

package ethercat

import (
	"crypto/rand"
	"encoding/binary"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	ethercatPort     = 34980
	ethercatPriority = 400 // ICS protocol tier (same as BACnet, DNP3, Modbus)
)

// Plugin implements EtherCAT-over-UDP service fingerprinting.
type Plugin struct{}

func init() {
	plugins.RegisterPlugin(&Plugin{})
}

// Type returns the protocol transport type.
func (p *Plugin) Type() plugins.Protocol {
	return plugins.UDP
}

// Priority returns the scan priority (400 = ICS protocol tier).
func (p *Plugin) Priority() int {
	return ethercatPriority
}

// PortPriority returns true if the port matches EtherCAT/UDP (34980).
func (p *Plugin) PortPriority(port uint16) bool {
	return port == ethercatPort
}

// Name returns the plugin display name.
func (p *Plugin) Name() string {
	return "ethercat"
}

// Run performs EtherCAT device fingerprinting via Broadcast Read (BRD) command.
func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Build BRD probe
	probe := buildBroadcastReadProbe()

	// Send and receive using utility function
	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Extract index from probe for validation
	probeIndex := probe[3]

	// Validate response
	if !isValidEtherCATResponse(response, probeIndex) {
		return nil, nil
	}

	// Parse response to extract metadata
	workingCounter, datagramCount := parseEtherCATResponse(response)

	// Create service metadata
	metadata := plugins.ServiceEtherCAT{
		WorkingCounter: workingCounter,
		DatagramCount:  datagramCount,
	}

	return plugins.CreateServiceFrom(target, metadata, false, "", plugins.UDP), nil
}

// buildBroadcastReadProbe creates an EtherCAT Broadcast Read (BRD) probe.
// This is a safe, read-only probe that reads from address 0x0000 with 0 data length.
func buildBroadcastReadProbe() []byte {
	// Generate random index byte for Tx/Rx matching
	indexByte := make([]byte, 1)
	rand.Read(indexByte)

	probe := make([]byte, 14)

	// Frame Header (2 bytes, little-endian)
	// Length: 12 bytes (datagram size)
	// Type: 1 (EtherCAT commands)
	frameHeader := uint16(12) | (uint16(1) << 14)
	binary.LittleEndian.PutUint16(probe[0:2], frameHeader)

	// Datagram Header (10 bytes)
	probe[2] = 0x07                                     // Cmd: BRD (Broadcast Read)
	probe[3] = indexByte[0]                             // Index: random byte
	binary.LittleEndian.PutUint16(probe[4:6], 0x0000)   // ADP: 0x0000
	binary.LittleEndian.PutUint16(probe[6:8], 0x0000)   // ADO: 0x0000
	binary.LittleEndian.PutUint16(probe[8:10], 0x0000)  // Length: 0 bytes
	binary.LittleEndian.PutUint16(probe[10:12], 0x0000) // IRQ: 0x0000

	// Working Counter (2 bytes)
	binary.LittleEndian.PutUint16(probe[12:14], 0x0000)

	return probe
}

// isValidEtherCATResponse validates an EtherCAT response.
// A valid response has:
// 1. Sufficient length (at least 14 bytes)
// 2. Frame type = 1 (EtherCAT)
// 3. Index matches the probe index
// 4. Working Counter > 0 (slaves processed the request)
func isValidEtherCATResponse(data []byte, probeIndex byte) bool {
	// Minimum valid response: frame header (2) + datagram (12) = 14 bytes
	if len(data) < 14 {
		return false
	}

	// Validate frame header
	frameHeader := binary.LittleEndian.Uint16(data[0:2])
	frameType := (frameHeader >> 14) & 0x03

	if frameType != 1 {
		return false
	}

	// Validate index matches
	if data[3] != probeIndex {
		return false
	}

	// Validate working counter > 0
	workingCounter := binary.LittleEndian.Uint16(data[12:14])
	if workingCounter == 0 {
		return false
	}

	return true
}

// parseEtherCATResponse extracts metadata from an EtherCAT response.
// Returns working counter and datagram count.
func parseEtherCATResponse(data []byte) (workingCounter uint16, datagramCount int) {
	if len(data) < 14 {
		return 0, 0
	}

	datagramCount = 0
	offset := 2 // Start after frame header

	// Parse datagrams until no more datagrams (M flag not set)
	for offset+12 <= len(data) {
		datagramCount++

		// Get length/flags field to check M flag (bit 15)
		lengthFlags := binary.LittleEndian.Uint16(data[offset+6 : offset+8])
		mFlag := (lengthFlags >> 15) & 0x01

		// Get working counter for this datagram
		workingCounter = binary.LittleEndian.Uint16(data[offset+10 : offset+12])

		// Get data length from length/flags field (lower 11 bits)
		dataLen := lengthFlags & 0x7FF

		// Move to next datagram: header (10 bytes) + data length + WC (2 bytes)
		offset += 12 + int(dataLen)

		// If M flag is not set, this is the last datagram
		if mFlag == 0 {
			break
		}
	}

	return workingCounter, datagramCount
}
