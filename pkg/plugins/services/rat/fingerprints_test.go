// Copyright 2026 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0.
// See LICENSE for license information.

package rat

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/require"
)

func TestIdentifyResponseFixtures(t *testing.T) {
	for _, fixture := range loadFixtures(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			response := decodeHex(t, fixture.ResponseHex)
			product, evidence := identifyResponse(response)
			require.Equal(t, fixture.Product, product)
			require.NotEmpty(t, evidence)
			for length := 0; length < len(response); length++ {
				product, _ := identifyResponse(response[:length])
				require.Empty(t, product, "truncation at %d", length)
			}
		})
	}
}

func TestIdentifyResponseRejectsUnrelatedData(t *testing.T) {
	for _, response := range [][]byte{
		nil,
		[]byte("HTTP/1.1 200 OK\r\nServer: Splashtop\r\n\r\n"),
		[]byte("SSH-2.0-NoMachine\r\n"),
		[]byte("RFB 003.008\n"),
		[]byte("NXSH-5.6.7\n"),
		[]byte("SRS:Ready!"),
		[]byte("NXD-5..6\n"),
		decodeHex(t, "01000000010000000808"),
	} {
		product, _ := identifyResponse(response)
		require.Empty(t, product, "%x", response)
	}
}

func TestBinarySignaturesRejectCorruption(t *testing.T) {
	for _, fixture := range loadFixtures(t) {
		if fixture.Name == "radmin-source-blocked" || (fixture.Product != plugins.ProtoRadmin && fixture.Product != plugins.ProtoDameware) {
			continue
		}
		response := decodeHex(t, fixture.ResponseHex)
		positions := []int{0, 1, 2, 3, 4, 6, 7, 8, 9, 10, 11, 12, 13}
		match := matchRadmin
		if fixture.Product == plugins.ProtoDameware {
			positions = []int{0, 1, 2, 3, 15, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 37, 38, 39}
			match = matchDameware
		}
		for _, position := range positions {
			corrupted := bytes.Clone(response)
			corrupted[position] ^= 0xff
			_, matched := match(corrupted)
			require.False(t, matched, "%s corruption at %d", fixture.Name, position)
		}
	}
}

func TestRadminKnownStatuses(t *testing.T) {
	for _, status := range []byte{0x00, 0x71, 0x08, 0x79, 0x59, 0x04} {
		response := decodeHex(t, "010000002500000212080200000a")
		response[5], response[12] = status, status
		_, matched := matchRadmin(response)
		require.True(t, matched)
	}
	response := decodeHex(t, "0100000025ff000212080200ff0a")
	_, matched := matchRadmin(response)
	require.False(t, matched, "unknown status must not softmatch")
}

func TestDamewareVariableFields(t *testing.T) {
	for _, fixture := range loadFixtures(t) {
		if fixture.Product != plugins.ProtoDameware {
			continue
		}
		response := decodeHex(t, fixture.ResponseHex)
		for _, position := range []int{4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17, 18, 19, 20, 21, 22, 23, 24, 36} {
			response[position] = byte(position + 1)
		}
		_, matched := matchDameware(response)
		require.True(t, matched)
	}
}

func TestRadminBlockedResponseRequiresCompleteSignature(t *testing.T) {
	// Fixed independent fixture from the published Nmap source-IP-blocked match,
	// not the production constant or Nuclei's much shorter five-byte matcher.
	response := decodeHex(t, "01000000090000104f2f100000040000001c")
	for position := range response {
		corrupted := bytes.Clone(response)
		corrupted[position] ^= 0xff
		_, matched := matchRadmin(corrupted)
		require.False(t, matched, "corruption at %d", position)
	}
	for _, invalid := range [][]byte{
		append([]byte("HTTP/1.1 200 OK\r\n\r\n"), response...),
		append(decodeHex(t, "0100000009"), bytes.Repeat([]byte{0}, 100)...),
		append([]byte{0}, response...),
		decodeHex(t, "010b0000000800000000000000000000"), // fcgiwrap lookalike
	} {
		_, matched := matchRadmin(invalid)
		require.False(t, matched)
	}
	evidence, matched := matchRadmin(response)
	require.True(t, matched)
	require.Contains(t, evidence, "source-IP-blocked")
}

func TestRealVNCLicenseFailureValidation(t *testing.T) {
	reason := "Server license key is missing, invalid or has expired.\nVisit http://www.realvnc.com to purchase a licence."
	response := append([]byte("RFB 003.008\n"), make([]byte, 8)...)
	binary.BigEndian.PutUint32(response[16:20], uint32(len(reason)))
	response = append(response, []byte(reason)...)
	for _, position := range []int{0, 4, 10, 11, 12, 15, 16, 19, 25, len(response) - 1} {
		corrupted := bytes.Clone(response)
		corrupted[position] ^= 0xff
		_, matched := matchRealVNC(corrupted)
		require.False(t, matched, "corruption at %d", position)
	}
	_, matched := matchRealVNC(append([]byte("HTTP/1.1 200 OK\r\n\r\n"), response...))
	require.False(t, matched)
	for _, text := range []string{"RealVNC", "A server mentioning http://www.realvnc.com", "Authentication failed"} {
		unbranded := append([]byte("RFB 003.008\n"), make([]byte, 8)...)
		binary.BigEndian.PutUint32(unbranded[16:20], uint32(len(text)))
		unbranded = append(unbranded, []byte(text)...)
		_, matched := matchRealVNC(unbranded)
		require.False(t, matched)
	}
}

func TestNetSupportGreetingVariants(t *testing.T) {
	for _, tc := range []struct {
		padding int
		trailer byte
	}{
		{1, 0},   // The variable trailer byte may be NUL.
		{8, 4},   // Padding must be skipped.
		{2, 1},   // Trailer can overlap a possible padding boundary.
		{1, 255}, // Variable bytes need not be printable.
	} {
		padding, trailer := tc.padding, tc.trailer
		response := []byte{0x20, 0, 2, 0}
		response = append(response, []byte("private-workstation")...)
		response = append(response, make([]byte, padding)...)
		response = append(response, trailer, 0, 1, 0)
		evidence, matched := matchNetSupport(response)
		require.True(t, matched, "padding %d trailer %d", padding, trailer)
		require.NotContains(t, evidence, "private-workstation")
	}
}

func TestNetSupportNonASCIIPeerNames(t *testing.T) {
	for _, name := range [][]byte{[]byte("équipe"), []byte("设备"), {'p', 'c', '-', 0xe9}} {
		response := append([]byte{0x20, 0, 2, 0}, name...)
		response = append(response, 0, 4, 0, 1, 0)
		evidence, matched := matchNetSupport(response)
		require.True(t, matched, "%x", name)
		require.NotContains(t, evidence, string(name))
	}
}

func TestNetSupportRejectsOtherComponentsAndMalformedGreetings(t *testing.T) {
	valid := decodeHex(t, "0d0002006c61620004000100")
	for _, position := range []int{1, 2, 3, 7, 9, 10, 11} {
		corrupted := bytes.Clone(valid)
		corrupted[position] ^= 0xff
		_, matched := matchNetSupport(corrupted)
		require.False(t, matched, "corruption at %d", position)
	}
	for _, invalid := range [][]byte{
		[]byte("HTTP/1.1 200 OK\r\nServer: NetSupport Gateway/1.0\r\n\r\nCMD=HEARTBEAT\n"),
		decodeHex(t, "0100000001000000000000000a0c303031323334353637383930"), // NetSupport DNA
		decodeHex(t, "0d0002000004000100"),                                   // empty peer name
		decodeHex(t, "0d0002006c01620004000100"),                             // control character
		decodeHex(t, "0d0002006c61620004000200"),                             // wrong trailer
		append(append([]byte{1, 0, 2, 0}, bytes.Repeat([]byte{'x'}, 256)...), 0, 4, 0, 1, 0),
		append([]byte("prefix"), valid...),
	} {
		_, matched := matchNetSupport(invalid)
		require.False(t, matched, "%x", invalid)
	}
}
func FuzzMatchers(f *testing.F) {
	f.Add([]byte("SRS:Ready\x00"))
	f.Add([]byte("NXD-5.6.7\n"))
	f.Add([]byte{1, 0, 0, 0})
	f.Add([]byte(radminSourceBlocked))
	f.Add([]byte("RFB 003.008\n\x00\x00\x00\x00\x00\x00\x00\x4dTrial period has expired.\nVisit http://www.realvnc.com to purchase a license."))
	f.Add([]byte{0x0d, 0, 2, 0, 'l', 'a', 'b', 0, 4, 0, 1, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, signature := range fingerprints {
			evidence, matched := signature.match(data)
			if matched {
				require.NotEmpty(t, evidence)
				require.Less(t, len(evidence), maxResponseBytes)
			}
		}
	})
}

type handshakeFixture struct {
	Name        string `json:"name"`
	Product     string `json:"product"`
	ResponseHex string `json:"responseHex"`
}

func loadFixtures(t *testing.T) []handshakeFixture {
	t.Helper()
	content, err := os.ReadFile("testdata/handshakes.json")
	require.NoError(t, err)
	var fixtures []handshakeFixture
	require.NoError(t, json.Unmarshal(content, &fixtures))
	return fixtures
}

func decodeHex(t *testing.T, value string) []byte {
	t.Helper()
	data, err := hex.DecodeString(value)
	require.NoError(t, err)
	return data
}
