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

package modbus

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	ModbusHeaderLength           = 7
	ModbusDiscreteInputCode      = 0x2
	ModbusErrorAddend            = 0x80
	ModbusReadDeviceIDCode       = 0x2B
	ModbusEncapsulatedInterface  = 0x0E
	ModbusBasicDeviceID          = 0x01
	ModbusStartObjectID          = 0x00
)

type MODBUSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&MODBUSPlugin{})
}

const MODBUS = "modbus"

func (p *MODBUSPlugin) PortPriority(port uint16) bool {
	return port == 502
}

// Run
/*
   modbus is a communications standard for connecting industrial devices.
   modbus can be carried over a number of frame formats; this program identifies
   modbus over TCP.

   modbus supports diagnostic functions that could be used for fingerprinting,
   however, not all implementations will support the use of these functions.
   Therefore, this program utilizes a read primitive and validates both the success
   response and the error response conditions.

   modbus supports reading and writing to specified memory addresses using a number
   of different primitives. This program utilizes the "Read Discrete Input" primitive,
   which requests the value of a read-only boolean. This is the least likely primitive to
   be disruptive.

   Additionally, all modbus messages begin with a 7-byte header. The first two bytes are a
   client-controlled transaction ID. This program generates a random transaction ID and validates
   that the server echos the correct response.

   Initial testing done with `docker run -it -p 502:5020 oitc/modbus-server:latest`
   The default TCP port is 502, but this is unofficial.
*/
func (p *MODBUSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	transactionID := make([]byte, 2)
	_, err := rand.Read(transactionID)
	if err != nil {
		return nil, &utils.RandomizeError{Message: "Transaction ID"}
	}

	// Read Discrete Input request
	requestBytes := []byte{
		// transaction ID bytes were generated above
		// protocol ID (0)
		0x00, 0x00,
		// following byte length
		0x00, 0x06,
		// remote slave (variable, but fixed to 1 here)
		0x01,
		// function code
		0x02,
		// starting address of 0x0000
		0x00, 0x00,
		// read one bit. this will cause a successful request to return 1 byte, with the
		// 7 high bits set to zero and the low bit set to the response value
		0x00, 0x01,
	}

	requestBytes = append(transactionID, requestBytes...)

	response, err := utils.SendRecv(conn, requestBytes, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// transaction ID was echoed correctly
	if bytes.Equal(response[:2], transactionID) {
		// successful request, validate contents
		if response[ModbusHeaderLength] == ModbusDiscreteInputCode {
			if response[ModbusHeaderLength+1] == 1 && (response[ModbusHeaderLength+2]>>1) == 0x00 {
				// Detection succeeded - attempt enrichment with device identification
				serviceData := p.enrichDeviceIdentification(conn, timeout)
				return plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP), nil
			}
		} else if response[ModbusHeaderLength] == ModbusDiscreteInputCode+ModbusErrorAddend {
			// Detection succeeded (error response is valid) - attempt enrichment
			serviceData := p.enrichDeviceIdentification(conn, timeout)
			return plugins.CreateServiceFrom(target, serviceData, false, "", plugins.TCP), nil
		}
	}
	return nil, nil
}

func (p *MODBUSPlugin) Name() string {
	return MODBUS
}
func (p *MODBUSPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *MODBUSPlugin) Priority() int {
	return 400
}

// buildReadDeviceIDRequest builds a Modbus Read Device Identification request (0x2B/0x0E)
func buildReadDeviceIDRequest(transactionID []byte) []byte {
	return append(transactionID, []byte{
		// protocol ID (0)
		0x00, 0x00,
		// following byte length (5 bytes)
		0x00, 0x05,
		// unit ID
		0x01,
		// function code 0x2B (43)
		ModbusReadDeviceIDCode,
		// MEI type 0x0E (14) - Read Device Identification
		ModbusEncapsulatedInterface,
		// Device ID code 0x01 (Basic identification)
		ModbusBasicDeviceID,
		// Object ID 0x00 (start from VendorName)
		ModbusStartObjectID,
	}...)
}

// parseDeviceIDResponse parses Modbus Read Device Identification response
// Returns map of object ID to value string
func parseDeviceIDResponse(response []byte, transactionID []byte) map[byte]string {
	objects := make(map[byte]string)

	// Verify response length and transaction ID
	if len(response) < ModbusHeaderLength+6 {
		return objects
	}

	// Verify transaction ID match
	if !bytes.Equal(response[:2], transactionID) {
		return objects
	}

	// Verify function code (0x2B)
	if response[ModbusHeaderLength] != ModbusReadDeviceIDCode {
		return objects
	}

	// Verify MEI type (0x0E)
	if response[ModbusHeaderLength+1] != ModbusEncapsulatedInterface {
		return objects
	}

	// Parse response header
	// [7] = function code 0x2B
	// [8] = MEI type 0x0E
	// [9] = Device ID code
	// [10] = Conformity level
	// [11] = More follows
	// [12] = Next object ID
	// [13] = Number of objects
	numObjects := int(response[ModbusHeaderLength+6])

	// Parse objects starting at byte 14
	idx := ModbusHeaderLength + 7
	for i := 0; i < numObjects && idx+2 < len(response); i++ {
		objectID := response[idx]
		objectLen := int(response[idx+1])

		// Bounds check
		if idx+2+objectLen > len(response) {
			break
		}

		// Extract object value as string
		objectValue := string(response[idx+2 : idx+2+objectLen])
		objects[objectID] = objectValue

		// Move to next object
		idx += 2 + objectLen
	}

	return objects
}

// generateCPE generates CPE string from vendor, product, and version
// Format: cpe:2.3:h:{vendor}:{product}:{version}:*:*:*:*:*:*:*
func generateCPE(vendor, product, version string) string {
	// Normalize vendor and product names (lowercase, replace spaces with underscores)
	vendorNorm := normalizeCPEComponent(vendor)
	productNorm := normalizeCPEComponent(product)

	// Use wildcard if version is empty
	versionNorm := version
	if versionNorm == "" {
		versionNorm = "*"
	}

	// Handle missing vendor or product
	if vendorNorm == "" || productNorm == "" {
		return ""
	}

	return fmt.Sprintf("cpe:2.3:h:%s:%s:%s:*:*:*:*:*:*:*", vendorNorm, productNorm, versionNorm)
}

// normalizeCPEComponent normalizes a string for use in CPE (lowercase, replace spaces with underscores)
func normalizeCPEComponent(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "_")
	// Remove non-alphanumeric characters except underscores and hyphens
	reg := regexp.MustCompile(`[^a-z0-9_-]`)
	return reg.ReplaceAllString(s, "")
}

// enrichDeviceIdentification attempts to get device identification metadata
// This is called after successful detection and is non-critical (failures are silent)
func (p *MODBUSPlugin) enrichDeviceIdentification(conn net.Conn, timeout time.Duration) plugins.ServiceModbus {
	serviceData := plugins.ServiceModbus{}

	// Generate transaction ID for device identification request
	transactionID := make([]byte, 2)
	_, err := rand.Read(transactionID)
	if err != nil {
		return serviceData // Return empty struct on error
	}

	// Build and send Read Device Identification request
	request := buildReadDeviceIDRequest(transactionID)
	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil || len(response) == 0 {
		return serviceData // Return empty struct on error
	}

	// Parse device identification response
	objects := parseDeviceIDResponse(response, transactionID)

	// Map object IDs to struct fields
	if val, ok := objects[0x00]; ok {
		serviceData.VendorName = val
	}
	if val, ok := objects[0x01]; ok {
		serviceData.ProductCode = val
	}
	if val, ok := objects[0x02]; ok {
		serviceData.Revision = val
	}
	if val, ok := objects[0x03]; ok {
		serviceData.VendorURL = val
	}
	if val, ok := objects[0x04]; ok {
		serviceData.ProductName = val
	}
	if val, ok := objects[0x05]; ok {
		serviceData.ModelName = val
	}

	// Generate CPE from vendor, product, and version
	// Prefer ProductName over ProductCode, and use Revision as version
	product := serviceData.ProductName
	if product == "" {
		product = serviceData.ProductCode
	}

	if cpe := generateCPE(serviceData.VendorName, product, serviceData.Revision); cpe != "" {
		serviceData.CPEs = []string{cpe}
	}

	return serviceData
}
