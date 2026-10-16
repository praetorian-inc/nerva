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

// Mock Oracle TNS listener / database postures for integration testing.
//
// This fixture implements the published TNS packet layout (Wireshark
// packet-tns, SQL*Net) so a detector can be pointed at three independent
// postures. It is not derived from any Nerva plugin implementation.
//
// MODE env var:
//
//	tns-only       — listener with no registered services. Every TNS Connect
//	                 is refused with ORA-12514. No database session is possible.
//	auth-required  — listener with common SIDs/service names. TNS Accept for
//	                 a known service, then every logon is rejected with
//	                 ORA-01017 (empty/absent credentials included).
//	no-auth        — same listener/services as auth-required, but a completed
//	                 logon establishes a session without verifying credentials
//	                 (PostgreSQL trust / MySQL empty-password analog).
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const (
	tnsHeaderLen = 8

	tnsTypeConnect = 1
	tnsTypeAccept  = 2
	tnsTypeRefuse  = 4
	tnsTypeData    = 6
	tnsTypeResend  = 11

	// TTC / SQL*Net function ids (Wireshark packet-tns).
	sqlnetSetProtocol  = 1
	sqlnetSetDatatypes = 2
	sqlnetUserOCIFunc  = 3

	// OCI function ids that start or finish a logon.
	ociLogon       = 1
	ociLogonV6     = 58
	ociLogon2nd    = 81
	ociLogon1st    = 82
	ociGenericAuth = 115
	ociGetSessKey  = 118

	// VSNNUM for 21.0.0.0.0: major<<24. Matches a typical 21c refuse packet.
	vsnnum21c uint32 = 352321536

	defaultPort    = "1521"
	maxPacketBytes = 65535
	connTimeout    = 15 * time.Second
)

// knownServices are SIDs / SERVICE_NAMEs a real Express/Free/EE listener
// commonly advertises. Unknown names get ORA-12514, same as a stock listener.
var knownServices = map[string]struct{}{
	"XE":       {},
	"XEPDB1":   {},
	"ORCL":     {},
	"ORCLPDB1": {},
	"FREE":     {},
	"FREEPDB1": {},
}

type mode int

const (
	modeTNSOnly mode = iota
	modeAuthRequired
	modeNoAuth
)

func parseMode(s string) (mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "tns-only", "tnsonly":
		return modeTNSOnly, nil
	case "auth-required", "authrequired", "auth":
		return modeAuthRequired, nil
	case "no-auth", "noauth", "unauth":
		return modeNoAuth, nil
	default:
		return 0, fmt.Errorf("unknown MODE %q (want tns-only, auth-required, no-auth)", s)
	}
}

func (m mode) String() string {
	switch m {
	case modeTNSOnly:
		return "tns-only"
	case modeAuthRequired:
		return "auth-required"
	case modeNoAuth:
		return "no-auth"
	default:
		return "unknown"
	}
}

type tnsPacket struct {
	typ     byte
	payload []byte
}

func main() {
	m, err := parseMode(os.Getenv("MODE"))
	if err != nil {
		log.Fatal(err)
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = defaultPort
	}

	ln, err := net.Listen("tcp", ":"+port)
	if err != nil {
		log.Fatalf("listen :%s: %v", port, err)
	}

	log.Printf("oracledb mock starting (mode=%s) on :%s", m, port)

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Printf("shutting down")
		_ = ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn, m)
	}
}

func handleConn(conn net.Conn, m mode) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(connTimeout))

	var lastResponse []byte
	accepted := false

	for {
		pkt, err := readTNS(conn)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				log.Printf("%s: read: %v", conn.RemoteAddr(), err)
			}
			return
		}

		var resp []byte
		switch pkt.typ {
		case tnsTypeResend:
			resp = lastResponse
		case tnsTypeConnect:
			resp, accepted = handleConnect(pkt.payload, m)
		case tnsTypeData:
			if !accepted {
				// Data before Accept is not a database session.
				resp = buildRefuse(12514)
				accepted = false
			} else {
				resp = handleData(pkt.payload, m)
			}
		default:
			log.Printf("%s: ignoring TNS type %d", conn.RemoteAddr(), pkt.typ)
			continue
		}

		if len(resp) == 0 {
			continue
		}
		lastResponse = resp
		if _, err := conn.Write(resp); err != nil {
			log.Printf("%s: write: %v", conn.RemoteAddr(), err)
			return
		}

		// A Refuse ends the TNS conversation the way a real listener does.
		if len(resp) >= 5 && resp[4] == tnsTypeRefuse {
			return
		}
	}
}

func handleConnect(payload []byte, m mode) ([]byte, bool) {
	desc := extractConnectData(payload)
	command := strings.ToUpper(connectField(desc, "COMMAND"))
	if command == "VERSION" {
		return buildVersionRefuse(), false
	}
	if command == "STATUS" {
		return buildStatusRefuse(m), false
	}

	service := connectField(desc, "SERVICE_NAME")
	if service == "" {
		service = connectField(desc, "SID")
	}

	if m == modeTNSOnly || !isKnownService(service) {
		log.Printf("refuse service=%q mode=%s", service, m)
		return buildRefuse(12514), false
	}

	log.Printf("accept service=%q mode=%s", service, m)
	return buildAccept(), true
}

func handleData(payload []byte, m mode) []byte {
	body := tnsDataBody(payload)
	if looksLikeLogon(body) {
		if m == modeNoAuth {
			log.Printf("logon accepted (no-auth)")
			return buildLogonSuccess()
		}
		log.Printf("logon denied (auth-required)")
		return buildLogonDenied()
	}
	// Protocol negotiation (Set Protocol / Set Datatypes / anything else
	// that is not a logon). Keep the session open so the client can proceed
	// to authenticate.
	return buildSetProtocolReply()
}

func tnsDataBody(payload []byte) []byte {
	if len(payload) <= 2 {
		return payload
	}
	// DATA packets carry a 2-byte flags word, then TTC payload.
	return payload[2:]
}

func looksLikeLogon(body []byte) bool {
	if containsASCIIOrUTF16(body, "AUTH_") {
		return true
	}
	if len(body) >= 2 && body[0] == sqlnetUserOCIFunc {
		switch body[1] {
		case ociLogon, ociLogonV6, ociLogon2nd, ociLogon1st, ociGenericAuth, ociGetSessKey:
			return true
		}
	}
	return false
}

func containsASCIIOrUTF16(b []byte, s string) bool {
	if bytesContainsFold(b, []byte(s)) {
		return true
	}
	return bytesContainsFold(b, utf16LE(s))
}

func bytesContainsFold(haystack, needle []byte) bool {
	if len(needle) == 0 || len(haystack) < len(needle) {
		return false
	}
	return strings.Contains(strings.ToUpper(string(haystack)), strings.ToUpper(string(needle)))
}

func utf16LE(s string) []byte {
	out := make([]byte, 0, len(s)*2)
	for i := 0; i < len(s); i++ {
		out = append(out, s[i], 0x00)
	}
	return out
}

func isKnownService(name string) bool {
	_, ok := knownServices[strings.ToUpper(strings.TrimSpace(name))]
	return ok
}

func connectField(desc, key string) string {
	upper := strings.ToUpper(desc)
	token := strings.ToUpper(key) + "="
	i := strings.Index(upper, token)
	if i < 0 {
		return ""
	}
	rest := desc[i+len(token):]
	if j := strings.IndexAny(rest, ")"); j >= 0 {
		rest = rest[:j]
	}
	return strings.TrimSpace(rest)
}

// extractConnectData pulls the connect descriptor out of a TNS Connect body.
// Offset is a 16-bit field at body[18:20] measured from the start of the
// TNS packet (header + body). Fall back to scanning for "(DESCRIPTION=".
func extractConnectData(body []byte) string {
	if len(body) >= 20 {
		dataLen := int(binary.BigEndian.Uint16(body[16:18]))
		dataOff := int(binary.BigEndian.Uint16(body[18:20]))
		start := dataOff - tnsHeaderLen
		if start >= 0 && dataLen >= 0 && start+dataLen <= len(body) {
			return string(body[start : start+dataLen])
		}
	}
	if i := strings.Index(strings.ToUpper(string(body)), "(DESCRIPTION="); i >= 0 {
		return string(body[i:])
	}
	return string(body)
}

func readTNS(r io.Reader) (tnsPacket, error) {
	var hdr [tnsHeaderLen]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return tnsPacket{}, err
	}
	n := int(binary.BigEndian.Uint16(hdr[0:2]))
	if n < tnsHeaderLen || n > maxPacketBytes {
		return tnsPacket{}, fmt.Errorf("invalid TNS length %d", n)
	}
	rest := make([]byte, n-tnsHeaderLen)
	if len(rest) > 0 {
		if _, err := io.ReadFull(r, rest); err != nil {
			return tnsPacket{}, err
		}
	}
	return tnsPacket{typ: hdr[4], payload: rest}, nil
}

func writeTNS(typ byte, payload []byte) []byte {
	n := tnsHeaderLen + len(payload)
	out := make([]byte, n)
	binary.BigEndian.PutUint16(out[0:2], uint16(n))
	out[4] = typ
	copy(out[tnsHeaderLen:], payload)
	return out
}

func buildRefuse(errCode int) []byte {
	data := fmt.Sprintf(
		"(DESCRIPTION=(TMP=)(VSNNUM=%d)(ERR=%d)(ERROR_STACK=(ERROR=(CODE=%d)(EMFI=4))))",
		vsnnum21c, errCode, errCode,
	)
	payload := make([]byte, 4+len(data))
	payload[0] = 0x22 // user refuse reason (captured 21c listener)
	payload[1] = 0x00
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(data)))
	copy(payload[4:], data)
	return writeTNS(tnsTypeRefuse, payload)
}

func buildVersionRefuse() []byte {
	data := fmt.Sprintf(
		"TNSLSNR for Linux: Version 21.0.0.0.0 - Production\n(DESCRIPTION=(TMP=)(VSNNUM=%d)(ERR=0))",
		vsnnum21c,
	)
	payload := make([]byte, 4+len(data))
	payload[0] = 0x22
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(data)))
	copy(payload[4:], data)
	return writeTNS(tnsTypeRefuse, payload)
}

func buildStatusRefuse(m mode) []byte {
	var services string
	if m == modeTNSOnly {
		services = "The listener supports no services"
	} else {
		services = "Services Summary...\nService \"XE\" has 1 instance(s).\nService \"ORCL\" has 1 instance(s).\nService \"FREEPDB1\" has 1 instance(s)."
	}
	data := fmt.Sprintf(
		"TNSLSNR for Linux: Version 21.0.0.0.0 - Production\n%s\n(DESCRIPTION=(TMP=)(VSNNUM=%d)(ERR=0))",
		services, vsnnum21c,
	)
	payload := make([]byte, 4+len(data))
	payload[0] = 0x22
	binary.BigEndian.PutUint16(payload[2:4], uint16(len(data)))
	copy(payload[4:], data)
	return writeTNS(tnsTypeRefuse, payload)
}

// buildAccept returns a TNS Accept for protocol version 316 (0x013c).
// Layout follows go-ora / Wireshark: 16-bit SDU/TDU at 12/14, 32-bit
// SDU/TDU at 32/36 when version >= 315, data offset 40.
func buildAccept() []byte {
	const dataOffset = 40
	payload := make([]byte, dataOffset-tnsHeaderLen)
	binary.BigEndian.PutUint16(payload[0:2], 0x013c) // version 316
	binary.BigEndian.PutUint16(payload[4:6], 0x8000) // SDU
	binary.BigEndian.PutUint16(payload[6:8], 0x7fff) // TDU
	binary.BigEndian.PutUint16(payload[8:10], 1)     // histone
	binary.BigEndian.PutUint16(payload[12:14], dataOffset)
	binary.BigEndian.PutUint32(payload[24:28], 0x8000)
	binary.BigEndian.PutUint32(payload[28:32], 0x7fff)
	return writeTNS(tnsTypeAccept, payload)
}

func buildData(ttc []byte) []byte {
	payload := make([]byte, 2+len(ttc))
	copy(payload[2:], ttc)
	return writeTNS(tnsTypeData, payload)
}

func buildSetProtocolReply() []byte {
	banner := []byte("Oracle Database 21c Express Edition Release 21.0.0.0.0 - Production")
	body := []byte{sqlnetSetProtocol, 6, 0, 0, 0, 0, 0, 0}
	body = append(body, banner...)
	body = append(body, 0x00)
	return buildData(body)
}

func buildLogonDenied() []byte {
	msg := []byte("ORA-01017: invalid username/password; logon denied\n(ERR=1017)")
	body := []byte{sqlnetUserOCIFunc, ociLogon}
	body = append(body, msg...)
	return buildData(body)
}

func buildLogonSuccess() []byte {
	// Session established. AUTH_* keys are what a thin client looks for on
	// a successful OAUTH; there is no ORA-01017.
	msg := []byte("AUTH_SESSKEY\x00AUTH_VFR_DATA\x00AUTH_VERSION\x00")
	body := []byte{sqlnetUserOCIFunc, ociLogon}
	body = append(body, msg...)
	return buildData(body)
}
