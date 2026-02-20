package main

import (
	"fmt"
	"net"
	"os"
)

const (
	cr3HeaderSize = 6
	regManufacturer = 0x012b
	regModel        = 0x012a
)

func main() {
	listener, err := net.Listen("tcp", ":789")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen: %v\n", err)
		os.Exit(1)
	}
	defer listener.Close()

	fmt.Println("Mock Crimson V3 server listening on :789")

	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	for {
		buf := make([]byte, 256)
		n, err := conn.Read(buf)
		if err != nil || n < 6 {
			return
		}

		// Extract register number from bytes 2-3 (big-endian)
		register := uint16(buf[2])<<8 | uint16(buf[3])

		var response []byte
		switch register {
		case regManufacturer:
			response = buildStringResponse(regManufacturer, "Red Lion Controls")
		case regModel:
			response = buildStringResponse(regModel, "G310C2")
		default:
			continue
		}

		_, err = conn.Write(response)
		if err != nil {
			return
		}
	}
}

func buildStringResponse(register uint16, data string) []byte {
	dataBytes := append([]byte(data), 0x00) // null terminate
	payloadLen := 2 + 2 + len(dataBytes)    // register(2) + type(2) + data

	resp := make([]byte, 0, 2+payloadLen)
	resp = append(resp, byte(payloadLen>>8), byte(payloadLen&0xFF)) // length (big-endian)
	resp = append(resp, byte(register>>8), byte(register&0xFF))     // register (big-endian)
	resp = append(resp, 0x03, 0x00)                                  // type 0x0300
	resp = append(resp, dataBytes...)                                // data

	return resp
}
