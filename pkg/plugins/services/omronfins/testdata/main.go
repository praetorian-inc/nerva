// Mock OMRON FINS Server for Integration Testing
//
// Simulates an Omron PLC responding to FINS Read Controller Data (0x0501) commands.
// Listens on both UDP and TCP port 9600 and responds with valid FINS protocol responses.
package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"net"
)

// finsMagic is the 4-byte magic header present in every FINS/TCP frame.
var finsMagic = []byte{0x46, 0x49, 0x4E, 0x53} // "FINS"

func main() {
	model := flag.String("model", "CJ2M-CPU31", "Controller model name")
	version := flag.String("version", "V2.1", "Controller version")
	udpPort := flag.Int("udp-port", 9600, "UDP listen port")
	tcpPort := flag.Int("tcp-port", 9600, "TCP listen port")
	flag.Parse()

	fmt.Printf("Mock OMRON FINS server: model=%s version=%s\n", *model, *version)

	go startUDP(*udpPort, *model, *version)
	startTCP(*tcpPort, *model, *version) // blocks
}

// startUDP listens for FINS Read Controller Data commands on UDP and responds.
func startUDP(port int, model, version string) {
	addr := fmt.Sprintf(":%d", port)
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		fmt.Printf("UDP: failed to listen on %s: %v\n", addr, err)
		return
	}
	defer conn.Close()
	fmt.Printf("UDP: listening on %s\n", addr)

	buf := make([]byte, 1024)
	for {
		n, remote, err := conn.ReadFrom(buf)
		if err != nil {
			fmt.Printf("UDP: read error: %v\n", err)
			continue
		}

		request := make([]byte, n)
		copy(request, buf[:n])
		fmt.Printf("UDP: received %d bytes from %s: %X\n", n, remote, request)

		// Check if this looks like a FINS Read Controller Data command.
		// bytes 10-12 (MRC=0x05, SRC=0x01, Param=0x00)
		if !isFINSReadControllerDataCmd(request) {
			fmt.Printf("UDP: ignoring non-FINS-Read-Controller-Data packet from %s\n", remote)
			continue
		}

		resp := buildFINSResponse(model, version, request)
		fmt.Printf("UDP: sending %d byte response to %s: %X\n", len(resp), remote, resp)

		_, err = conn.WriteTo(resp, remote)
		if err != nil {
			fmt.Printf("UDP: write error to %s: %v\n", remote, err)
		}
	}
}

// isFINSReadControllerDataCmd checks if the packet contains MRC=0x05, SRC=0x01.
// In the FINS UDP frame the command bytes are at offsets 10 and 11.
func isFINSReadControllerDataCmd(data []byte) bool {
	if len(data) < 12 {
		return false
	}
	return data[10] == 0x05 && data[11] == 0x01
}

// buildFINSResponse constructs a FINS Read Controller Data response frame.
// The header swaps source and destination addresses from the request.
func buildFINSResponse(model, version string, request []byte) []byte {
	// 14-byte FINS response header
	resp := []byte{
		0xC0, 0x00, 0x02, // ICF (response), RSV, GCT
		0x00, 0x00, 0x00, // DNA, DA1, DA2 (filled from request below)
		0x00, 0x00, 0x00, // SNA, SA1, SA2 (filled from request below)
		0xEF,             // SID (echo from request)
		0x05, 0x01,       // MRC, SRC (Read Controller Data response)
		0x00, 0x00,       // Response code: 0x0000 = Normal completion
	}

	// Swap source/dest addresses from the request if long enough.
	// FINS header layout: ICF(0) RSV(1) GCT(2) DNA(3) DA1(4) DA2(5) SNA(6) SA1(7) SA2(8) SID(9)
	if len(request) >= 10 {
		resp[3] = request[6] // DNA = request SNA
		resp[4] = request[7] // DA1 = request SA1
		resp[5] = request[8] // DA2 = request SA2
		resp[6] = request[3] // SNA = request DNA
		resp[7] = request[4] // SA1 = request DA1
		resp[8] = request[5] // SA2 = request DA2
		resp[9] = request[9] // SID echo
	}

	// Controller Model: 20 bytes, null-padded
	modelBytes := make([]byte, 20)
	copy(modelBytes, model)

	// Controller Version: 20 bytes, null-padded
	versionBytes := make([]byte, 20)
	copy(versionBytes, version)

	// System info area: 40 bytes (zeros for simulation)
	systemBytes := make([]byte, 40)

	// Additional controller data fields (simplified)
	// Program area size (2 bytes), IOM size (1 byte), DM words (2 bytes), etc.
	extraBytes := make([]byte, 20)

	resp = append(resp, modelBytes...)
	resp = append(resp, versionBytes...)
	resp = append(resp, systemBytes...)
	resp = append(resp, extraBytes...)

	return resp
}

// startTCP listens for FINS/TCP connections on the given port.
func startTCP(port int, model, version string) {
	addr := fmt.Sprintf(":%d", port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Printf("TCP: failed to listen on %s: %v\n", addr, err)
		return
	}
	defer listener.Close()
	fmt.Printf("TCP: listening on %s\n", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			fmt.Printf("TCP: accept error: %v\n", err)
			continue
		}
		go handleTCPConn(conn, model, version)
	}
}

// handleTCPConn handles a single FINS/TCP connection.
// Phase 1: node address handshake.
// Phase 2: FINS command frames.
func handleTCPConn(conn net.Conn, model, version string) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	fmt.Printf("TCP: new connection from %s\n", remote)

	// --- Phase 1: Node Address Handshake ---
	// Expect a 20-byte request: "FINS" + length(4) + command(4)=0 + error(4) + clientNode(4)
	handshakeBuf := make([]byte, 20)
	n, err := readFull(conn, handshakeBuf)
	if err != nil || n < 20 {
		fmt.Printf("TCP: handshake read error from %s: %v\n", remote, err)
		return
	}
	fmt.Printf("TCP: handshake %d bytes from %s: %X\n", n, remote, handshakeBuf[:n])

	// Validate "FINS" magic
	if handshakeBuf[0] != finsMagic[0] || handshakeBuf[1] != finsMagic[1] ||
		handshakeBuf[2] != finsMagic[2] || handshakeBuf[3] != finsMagic[3] {
		fmt.Printf("TCP: invalid magic in handshake from %s\n", remote)
		return
	}

	// Build node address response (24 bytes):
	//   "FINS" + length=16 + command=1 + error=0 + clientNode=1 + serverNode=2
	nodeResp := make([]byte, 24)
	copy(nodeResp[0:4], finsMagic)
	binary.BigEndian.PutUint32(nodeResp[4:8], 16)          // length = 16 (bytes after length field)
	binary.BigEndian.PutUint32(nodeResp[8:12], 0x00000001) // command = 1 (Node Address Response)
	binary.BigEndian.PutUint32(nodeResp[12:16], 0)         // error = 0
	binary.BigEndian.PutUint32(nodeResp[16:20], 1)         // client node = 1
	binary.BigEndian.PutUint32(nodeResp[20:24], 2)         // server node = 2

	fmt.Printf("TCP: sending handshake response to %s: %X\n", remote, nodeResp)
	_, err = conn.Write(nodeResp)
	if err != nil {
		fmt.Printf("TCP: handshake write error to %s: %v\n", remote, err)
		return
	}

	// --- Phase 2: FINS Command Frames ---
	for {
		// Read the 16-byte FINS/TCP header first
		hdrBuf := make([]byte, 16)
		n, err = readFull(conn, hdrBuf)
		if err != nil || n < 16 {
			if err != nil {
				fmt.Printf("TCP: command header read error from %s: %v\n", remote, err)
			}
			return
		}

		// Validate "FINS" magic
		if hdrBuf[0] != finsMagic[0] || hdrBuf[1] != finsMagic[1] ||
			hdrBuf[2] != finsMagic[2] || hdrBuf[3] != finsMagic[3] {
			fmt.Printf("TCP: invalid magic in command frame from %s\n", remote)
			return
		}

		// Extract length field: bytes after the length field itself
		// length = command(4) + error(4) + payload
		frameLen := binary.BigEndian.Uint32(hdrBuf[4:8])
		if frameLen < 8 {
			fmt.Printf("TCP: command frame length too short (%d) from %s\n", frameLen, remote)
			return
		}
		payloadLen := int(frameLen) - 8 // subtract command(4) + error(4)

		// command must be 2 (FINS Frame Send)
		cmd := binary.BigEndian.Uint32(hdrBuf[8:12])
		if cmd != 0x00000002 {
			fmt.Printf("TCP: unexpected command 0x%08x from %s\n", cmd, remote)
			return
		}

		// Read the FINS payload
		finsBuf := make([]byte, payloadLen)
		n, err = readFull(conn, finsBuf)
		if err != nil || n < payloadLen {
			fmt.Printf("TCP: payload read error from %s: %v\n", remote, err)
			return
		}
		fmt.Printf("TCP: received command from %s payload %d bytes: %X\n", remote, n, finsBuf[:n])

		// Check for 0x0501 in the FINS payload (MRC=0x05, SRC=0x01 at offsets 10-11)
		if !isFINSReadControllerDataCmd(finsBuf) {
			fmt.Printf("TCP: ignoring non-Read-Controller-Data FINS command from %s\n", remote)
			continue
		}

		// Build FINS response payload
		finsResp := buildFINSResponse(model, version, finsBuf)

		// Wrap in FINS/TCP frame: "FINS" + length + command=2 + error=0 + finsResp
		totalPayloadLen := uint32(8 + len(finsResp)) // command(4) + error(4) + finsResp
		tcpResp := make([]byte, 16+len(finsResp))
		copy(tcpResp[0:4], finsMagic)
		binary.BigEndian.PutUint32(tcpResp[4:8], totalPayloadLen)
		binary.BigEndian.PutUint32(tcpResp[8:12], 0x00000002) // command = 2 (FINS Frame Send)
		binary.BigEndian.PutUint32(tcpResp[12:16], 0)         // error = 0
		copy(tcpResp[16:], finsResp)

		fmt.Printf("TCP: sending response to %s: %d bytes: %X\n", remote, len(tcpResp), tcpResp)
		_, err = conn.Write(tcpResp)
		if err != nil {
			fmt.Printf("TCP: write error to %s: %v\n", remote, err)
			return
		}
	}
}

// readFull reads exactly len(buf) bytes from conn into buf, returning n bytes read and any error.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}
