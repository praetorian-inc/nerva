// Copyright 2026 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0.
// See LICENSE for license information.

package rat

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"regexp"
	"slices"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

type fingerprint struct {
	product string
	ports   []uint16
	probe   string
	match   func([]byte) (string, bool) // protocol evidence, matched
}

// Ports prioritize probes only. Every probe can identify a remapped service;
// client-first probes run on separate connections managed by Nerva.
var fingerprints = []fingerprint{
	{plugins.ProtoSplashtop, []uint16{6783, 6784, 6785}, "", matchSplashtop},
	{plugins.ProtoDameware, []uint16{6129}, "", matchDameware},
	{plugins.ProtoNetSupport, []uint16{5405}, "", matchNetSupport},
	{plugins.ProtoRealVNC, []uint16{5900}, "", matchRealVNC},
	{plugins.ProtoNoMachine, []uint16{4000}, "NXSH-5.6.7\n", matchNoMachine},
	{plugins.ProtoRadmin, []uint16{4899}, "\x01\x00\x00\x00\x01\x00\x00\x00\x08\x08", matchRadmin},
}

func fingerprintForPort(port uint16) *fingerprint {
	for i := range fingerprints {
		if slices.Contains(fingerprints[i].ports, port) {
			return &fingerprints[i]
		}
	}
	return nil
}

func identifyResponse(data []byte) (product, evidence string) {
	for _, signature := range fingerprints {
		if evidence, matched := signature.match(data); matched {
			return signature.product, evidence
		}
	}
	return "", ""
}

func matchSplashtop(data []byte) (string, bool) {
	return "SRS:Ready\\0", bytes.HasPrefix(data, []byte("SRS:Ready\x00"))
}

func matchDameware(data []byte) (string, bool) {
	// Historical 40-byte server greeting: type 0x1130, marker at byte 15,
	// capability at bytes 28..31, and reserved zero fields. Do not accept
	// just the short 0x30 0x11 prefix (or infer a version from variable bytes).
	if len(data) < 40 || binary.LittleEndian.Uint32(data[:4]) != 0x1130 || data[15] != 0x40 {
		return "", false
	}
	if !bytes.Equal(data[25:28], []byte{0, 0, 0}) || binary.LittleEndian.Uint32(data[28:32]) != 1 ||
		binary.LittleEndian.Uint32(data[32:36]) != 0 || !bytes.Equal(data[37:40], []byte{0, 0, 0}) {
		return "", false
	}
	return "Dameware 40-byte greeting: type=0x1130 marker=0x40 capability=1", true
}

func matchNetSupport(data []byte) (string, bool) {
	// Published Nmap NULL-response structure: variable byte + 00 02 00,
	// a NUL-terminated peer name, NUL padding, then variable byte + 00 01 00.
	// Do not confuse this remote-control greeting with DNA or HTTP Gateway.
	if len(data) < 10 || data[1] != 0 || data[2] != 2 || data[3] != 0 {
		return "", false
	}
	end := bytes.IndexByte(data[4:], 0)
	if end < 1 || end > 255 {
		return "", false
	}
	for _, character := range data[4 : 4+end] {
		if character < 0x20 || character == 0x7f {
			return "", false
		}
	}
	// The variable trailer byte may itself be zero. Check each boundary in
	// the padding run rather than consuming it greedily and losing that byte.
	for offset := 4 + end + 1; offset+4 <= len(data) && offset < maxResponseBytes; offset++ {
		if data[offset+1] == 0 && data[offset+2] == 1 && data[offset+3] == 0 {
			return "NetSupport remote-control greeting: type=0x0002; NUL-terminated peer name; trailer=xx000100 (peer name omitted)", true
		}
		if data[offset] != 0 {
			break
		}
	}
	return "", false
}

func matchRealVNC(data []byte) (string, bool) {
	// These proprietary RFB versions identify the RealVNC family. Standard
	// RFB 003.003/007/008 is vendor-neutral and must remain generic VNC.
	for _, greeting := range []string{"RFB 004.000\n", "RFB 004.001\n", "RFB 005.000\n"} {
		if bytes.HasPrefix(data, []byte(greeting)) {
			return greeting[:len(greeting)-1], true
		}
	}
	return matchRealVNCLicenseFailure(data)
}

func matchRealVNCLicenseFailure(data []byte) (string, bool) {
	// Historical server-first failures carry an RFB 3.x greeting, zero
	// security type, a big-endian reason length, and a branded license reason.
	// Neither ordinary RFB 3.x nor arbitrary text containing RealVNC suffices.
	if len(data) < 20 || !bytes.HasPrefix(data, []byte("RFB 003.00")) || data[10] < '0' || data[10] > '9' || data[11] != '\n' || binary.BigEndian.Uint32(data[12:16]) != 0 {
		return "", false
	}
	length := binary.BigEndian.Uint32(data[16:20])
	if length > maxResponseBytes-20 || int(length) > len(data)-20 {
		return "", false
	}
	switch string(data[20 : 20+int(length)]) {
	case "Server license key is missing, invalid or has expired.\nVisit http://www.realvnc.com to purchase a licence.",
		"Server license key is missing, invalid or has expired.\nVisit http://www.realvnc.com to purchase a license.",
		"VNC Server license key is missing, invalid or has expired.\nVisit http://www.realvnc.com to purchase a license.",
		"Trial period has expired.\nVisit http://www.realvnc.com to purchase a license.":
		return "RealVNC branded RFB license/trial failure; remote-control availability not established", true
	default:
		return "", false
	}
}

var nxGreeting = regexp.MustCompile(`^NXD-[0-9]{1,5}(?:\.[0-9]{1,5}){1,3}\n`)

func matchNoMachine(data []byte) (string, bool) {
	greeting := nxGreeting.Find(data)
	if greeting == nil {
		return "", false
	}
	// This is a protocol greeting version, not necessarily the installed
	// application version; keep Service.Version unset.
	return string(bytes.TrimSuffix(greeting, []byte{'\n'})), true
}

// The complete published rejection header identifies Radmin even when the
// source IP is blocked. Nuclei's five-byte 0100000009 matcher alone is not enough.
const radminSourceBlocked = "\x01\x00\x00\x00\x09\x00\x00\x10\x4f\x2f\x10\x00\x00\x04\x00\x00\x00\x1c"

func matchRadmin(data []byte) (string, bool) {
	if bytes.HasPrefix(data, []byte(radminSourceBlocked)) {
		return "Radmin source-IP-blocked reply=" + hex.EncodeToString(data[:len(radminSourceBlocked)]), true
	}
	if len(data) < 14 || binary.LittleEndian.Uint32(data[:4]) != 1 || data[4] != 0x25 || data[6] != 0 || data[11] != 0 || data[5] != data[12] {
		return "", false
	}
	// Check the complete known negotiation header, not the permissive
	// softmatch. The same status byte occurs twice in the header.
	version := data[7]
	status := data[5]
	switch version {
	case 1:
		if (status != 0x09 && status != 0x0a) || !bytes.Equal(data[8:11], []byte{0x10, 0x08, 0x01}) || data[13] != 0x08 {
			return "", false
		}
	case 2:
		if !knownRadminStatus(status) || !bytes.Equal(data[8:11], []byte{0x12, 0x08, 0x02}) || data[13] != 0x0a {
			return "", false
		}
	default:
		return "", false
	}
	return "Radmin negotiation header=" + hex.EncodeToString(data[:14]), true
}

func knownRadminStatus(status byte) bool {
	switch status {
	case 0x00, 0x71, 0x08, 0x79, 0x59, 0x04:
		return true
	default:
		return false
	}
}
