// PCOM Mock Server for Integration Testing
//
// Simulates a Unitronics V130-33-T38 PLC responding to PCOM/TCP ASCII ID commands.
// Listens on port 20256 and responds with valid PCOM protocol responses.
package main

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
)

const (
	LISTEN_PORT = "20256"
	ASCII_MODE  = 0x65
	STX_ASCII   = 0x2F // '/'
	ETX_ASCII   = 0x0D // '\r'
)

// mockPLCConfig holds the simulated PLC configuration
type mockPLCConfig struct {
	modelCode string // 6 hex chars
	hwVersion string // 1 hex char
	osMajor   string // 3 chars
	osMinor   string // 3 chars
	osBuild   string // 2 chars
}

var plcConfig = mockPLCConfig{
	modelCode: "180701", // Maps to V130-33-T38
	hwVersion: "2",
	osMajor:   "003",
	osMinor:   "028",
	osBuild:   "00",
}

func main() {
	listener, err := net.Listen("tcp", ":"+LISTEN_PORT)
	if err != nil {
		log.Fatalf("Failed to listen on port %s: %v", LISTEN_PORT, err)
	}
	defer listener.Close()

	log.Printf("PCOM mock server listening on port %s", LISTEN_PORT)
	log.Printf("Simulating PLC: Model=%s HW=%s OS=%s.%s.%s",
		plcConfig.modelCode, plcConfig.hwVersion,
		plcConfig.osMajor, plcConfig.osMinor, plcConfig.osBuild)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	remoteAddr := conn.RemoteAddr().String()
	log.Printf("New connection from %s", remoteAddr)

	// Read request
	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("Read error from %s: %v", remoteAddr, err)
		return
	}

	request := buf[:n]
	log.Printf("Received %d bytes from %s: %X", n, remoteAddr, request)

	// Validate request structure
	if !isValidPCOMRequest(request) {
		log.Printf("Invalid PCOM request from %s", remoteAddr)
		return
	}

	// Extract transaction ID from request (bytes 0-1)
	transactionID := request[0:2]

	// Build response
	response := buildPCOMIDResponse(transactionID)
	log.Printf("Sending response: %X", response)

	// Send response
	_, err = conn.Write(response)
	if err != nil {
		log.Printf("Write error to %s: %v", remoteAddr, err)
		return
	}

	log.Printf("Sent %d byte response to %s", len(response), remoteAddr)
}

// isValidPCOMRequest validates basic PCOM request structure
func isValidPCOMRequest(request []byte) bool {
	// Minimum: 6-byte header + 8-byte ASCII payload
	if len(request) < 14 {
		log.Printf("Request too short: %d bytes", len(request))
		return false
	}

	// Check mode byte (position 2) - should be ASCII mode (0x65)
	if request[2] != ASCII_MODE {
		log.Printf("Invalid mode byte: 0x%02X (expected 0x%02X)", request[2], ASCII_MODE)
		return false
	}

	// Check ASCII payload starts with STX '/' (position 6)
	if request[6] != STX_ASCII {
		log.Printf("Missing STX at position 6: 0x%02X (expected 0x%02X)", request[6], STX_ASCII)
		return false
	}

	// Check for "ID" command (positions 9-10 in full packet)
	if request[9] != 'I' || request[10] != 'D' {
		log.Printf("Missing ID command at positions 9-10: got '%c%c'", request[9], request[10])
		return false
	}

	return true
}

// buildPCOMIDResponse constructs a PCOM/TCP ASCII ID response
//
// Response format:
// - 6-byte TCP header (transaction ID, mode, reserved, length)
// - ASCII payload:
//   /A00ID + modelCode(6) + hwVersion(1) + osMajor(3) + osMinor(3) + osBuild(2) + checksum(2) + \r
func buildPCOMIDResponse(transactionID []byte) []byte {
	// Build ASCII payload
	// Format: /A00ID{model}{hw}{major}{minor}{build}{checksum}\r
	payload := fmt.Sprintf("/A00ID%s%s%s%s%s",
		plcConfig.modelCode, // 6 chars
		plcConfig.hwVersion, // 1 char
		plcConfig.osMajor,   // 3 chars
		plcConfig.osMinor,   // 3 chars
		plcConfig.osBuild,   // 2 chars
	)

	// Calculate checksum: sum of all bytes from position 1 to end (before checksum and ETX)
	checksum := calculateChecksum([]byte(payload))

	// Append checksum (2 hex chars) and ETX
	payload = fmt.Sprintf("%s%02X\r", payload, checksum)

	// Build 6-byte TCP header
	header := make([]byte, 6)
	copy(header[0:2], transactionID)         // Echo transaction ID from request
	header[2] = ASCII_MODE                   // Protocol mode (0x65 = ASCII)
	header[3] = 0x00                         // Reserved
	binary.LittleEndian.PutUint16(header[4:6], uint16(len(payload))) // Data length

	// Concatenate header + payload
	return append(header, []byte(payload)...)
}

// calculateChecksum calculates PCOM checksum
// Sum all bytes from position 1 (skip STX) to end, mod 256
func calculateChecksum(data []byte) byte {
	if len(data) < 2 {
		return 0
	}

	sum := 0
	// Start from position 1 (skip STX '/')
	for i := 1; i < len(data); i++ {
		sum += int(data[i])
	}

	return byte(sum % 256)
}
