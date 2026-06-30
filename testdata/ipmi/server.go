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

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
)

const (
	// portVulnerable is a mock BMC that advertises anonymous login and accepts cipher zero.
	portVulnerable = 10623
	// portSecure is a mock BMC that requires authentication and rejects cipher zero.
	portSecure = 10624
	// portNonIPMI echoes back whatever it receives; the IPMI scanner must not match it.
	portNonIPMI = 10625
)

// buildAuthCapabilitiesResponse constructs the 25-byte Get Channel Authentication
// Capabilities response. The first 13 bytes match ipmiExpectedResponse exactly so
// that the nerva IPMI fingerprinter will accept the packet.
//
//   - authTypeSupport: byte 22 — bitmap of supported authentication types
//   - authStatus:      byte 23 — bit 0 = anonymous login enabled
//   - extCap:          byte 24 — bit 1 = IPMIv2 supported
func buildAuthCapabilitiesResponse(authTypeSupport, authStatus, extCap byte) []byte {
	return []byte{
		// Bytes 0–3: RMCP header
		0x06, 0x00, 0xFF, 0x07,
		// Byte 4: Auth type NONE
		0x00,
		// Bytes 5–8: Session ID (zero)
		0x00, 0x00, 0x00, 0x00,
		// Bytes 9–12: Session sequence (zero)
		0x00, 0x00, 0x00, 0x00,
		// Byte 13: IPMB message length (11 bytes follow)
		0x0B,
		// Bytes 14–19: IPMB header / routing
		0x20, 0x01, 0x00, 0x38, 0x01, 0x97,
		// Byte 20: Completion code (0x00 = success)
		0x00,
		// Byte 21: Channel number
		0x01,
		// Byte 22: Auth type support bitmap
		authTypeSupport,
		// Byte 23: Auth status byte (bit 0 = anonymous login)
		authStatus,
		// Byte 24: Extended capabilities (bit 1 = IPMIv2)
		extCap,
	}
}

// buildCipherZeroResponse constructs the 20-byte RMCP+ Open Session Response.
//
//   - statusCode: byte 17 — 0x00 = accepted, non-zero = rejected
func buildCipherZeroResponse(statusCode byte) []byte {
	resp := make([]byte, 20)
	// RMCP header
	resp[0] = 0x06
	resp[1] = 0x00
	resp[2] = 0xFF
	resp[3] = 0x07
	// Byte 4: Auth type RMCP+
	resp[4] = 0x06
	// Byte 5: Payload type — Open Session Response
	resp[5] = 0x11
	// Bytes 6–16: zero (padding)
	// Byte 17: status code
	resp[17] = statusCode
	return resp
}

// isCipherZeroProbe returns true when the packet is an RMCP+ Open Session
// Request (bytes 4–5 == 0x06, 0x10).
func isCipherZeroProbe(pkt []byte) bool {
	return len(pkt) >= 6 && pkt[4] == 0x06 && pkt[5] == 0x10
}

// vulnerableHandler simulates a BMC that:
//   - advertises auth types: none + MD2 + MD5 + straight key (0x17)
//   - advertises anonymous login enabled (auth status 0x03)
//   - supports IPMIv2 (ext cap 0x02)
//   - accepts RMCP+ cipher suite 0 (status 0x00)
//
// Expected findings: ipmi-exposed, ipmi-anonymous-login, ipmi-cipher-zero
func vulnerableHandler(pkt []byte) []byte {
	if isCipherZeroProbe(pkt) {
		return buildCipherZeroResponse(0x00) // accepted
	}
	return buildAuthCapabilitiesResponse(0x17, 0x03, 0x02)
}

// secureHandler simulates a BMC that:
//   - advertises auth type: MD5 only (0x04)
//   - no anonymous login (auth status 0x00)
//   - supports IPMIv2 (ext cap 0x02)
//   - rejects RMCP+ cipher suite 0 (status 0x01)
//
// Expected findings: ipmi-exposed only
func secureHandler(pkt []byte) []byte {
	if isCipherZeroProbe(pkt) {
		return buildCipherZeroResponse(0x01) // rejected: not permitted
	}
	return buildAuthCapabilitiesResponse(0x04, 0x00, 0x02)
}

// nonIPMIHandler returns a fixed non-RMCP response. An echo would match because
// the IPMI request shares its RMCP header with the expected response prefix.
func nonIPMIHandler(pkt []byte) []byte {
	return []byte("NOT-IPMI")
}

func main() {
	var wg sync.WaitGroup

	listeners := []struct {
		port    int
		handler func([]byte) []byte
	}{
		{portVulnerable, vulnerableHandler},
		{portSecure, secureHandler},
		{portNonIPMI, nonIPMIHandler},
	}

	conns := make([]net.PacketConn, 0, len(listeners))

	for _, l := range listeners {
		addr := fmt.Sprintf("0.0.0.0:%d", l.port)
		conn, err := net.ListenPacket("udp", addr)
		if err != nil {
			log.Fatalf("listen %s: %v", addr, err)
		}
		conns = append(conns, conn)

		log.Printf("listening on %s", addr)

		wg.Add(1)
		go func(c net.PacketConn, h func([]byte) []byte, a string) {
			defer wg.Done()
			buf := make([]byte, 4096)
			for {
				n, remote, err := c.ReadFrom(buf)
				if err != nil {
					return
				}
				pkt := make([]byte, n)
				copy(pkt, buf[:n])
				log.Printf("[%s] received %d bytes from %s", a, n, remote)
				resp := h(pkt)
				if resp != nil {
					if _, werr := c.WriteTo(resp, remote); werr != nil {
						log.Printf("[%s] write to %s: %v", a, remote, werr)
					}
				}
			}
		}(conn, l.handler, addr)
	}

	// Block until SIGINT or SIGTERM.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	log.Println("shutting down")

	// Close all listeners so the goroutines unblock and exit.
	for _, c := range conns {
		if err := c.Close(); err != nil {
			log.Printf("close %s: %v", c.LocalAddr(), err)
		}
	}

	wg.Wait()
	log.Println("done")
}
