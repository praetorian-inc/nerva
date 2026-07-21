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

package oracledb

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type ORACLEPlugin struct{}

const ORACLE = "oracle"

func init() {
	plugins.RegisterPlugin(&ORACLEPlugin{})
}

/*
Transparent Network Substrate Protocol

	Packet Length: 270
	Packet Checksum: 0x0000
	Packet Type: Connect (1)
	Reserved Byte: 00
	Header Checksum: 0x0000
	Connect
	    Version: 318
	    Version (Compatible): 300
	    Service Options: 0x0c41, Header Checksum, Full Duplex
	    Session Data Unit Size: 8192
	    Maximum Transmission Data Unit Size: 65535
	    NT Protocol Characteristics: 0x7f08, Confirmed release, TDU based IO, Spawner running, Data test,
	    							 Callback IO supported, ASync IO Supported, Packet oriented IO,
	    							 Generate SIGURG signal
	    Line Turnaround Value: 0
	    Value of 1 in Hardware: 0100
	    Length of Connect Data: 196
	    Offset to Connect Data: 74
	    Maximum Receivable Connect Data: 5120
	    Connect Flags 0: 0x41, NA services wanted
	        ...0 .... = NA services required: False
	        .... 0... = NA services linked in: False
	        .... .0.. = NA services enabled: False
	        .... ..0. = Interchange is involved: False
	        .... ...1 = NA services wanted: True
	    Connect Flags 1: 0x41, NA services wanted
	        ...0 .... = NA services required: False
	        .... 0... = NA services linked in: False
	        .... .0.. = NA services enabled: False
	        .... ..0. = Interchange is involved: False
	        .... ...1 = NA services wanted: True
	    Trace Cross Facility Item 1: 0xd8870000
	    Trace Cross Facility Item 2: 0x00000000
	    Trace Unique Connection ID: 0x0000000000000000
	    Connect Data: (DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=XE)(CID=(PROGRAM=sqlplus)
	    			  (HOST=a68e91558f29)(USER=oracle))(CONNECTION_ID=3krKWwBDEZ/gUwQAEaydrQ==))
	    			  (ADDRESS=(PROTOCOL=tcp)(HOST=192.168.1.116)(PORT=1521)))


	    Expected Rejection Response:
	    Transparent Network Substrate Protocol
	    Packet Length: 103
	    Packet Checksum: 0x0000
	    Packet Type: Refuse (4)
	    Reserved Byte: 00
	    Header Checksum: 0x0000
	    Refuse
	    Refuse Reason (User): 0x22
	    Refuse Reason (System): 0x00
	    Refuse Data Length: 91
	    Refuse Data: (DESCRIPTION=(TMP=)(VSNNUM=352321536)(ERR=12514)(ERROR_STACK=(ERROR=(CODE=12514)(EMFI=4))))


	    Transparent Network Substrate Protocol
	Packet Length: 8
	Packet Checksum: 0x0000
	Packet Type: Resend (11)
	Reserved Byte: 00
	Header Checksum: 0x0000


	TESTED AGAINST: Oracle DB XE 21c; however, I could not find an 11g download link which is required
	to build the container for testing. Also please note the heuristic-ness of the response verifications.
	The request settings may need to be tinkered with (areas of tinkering have been noted with comments)

	Oracle Database 10.2, 11.x, 12.x, and 18c are available as a media or FTP request
	 for those customers who own a valid Oracle Database product license for any edition.
	 To request access to these releases, follow the instructions in Oracle Support Document
	  1071023.1 (Requesting Physical Shipment or Download URL for Software Media) from My Oracle Support.
	   NOTE: for Oracle Database 10.2, you should request 10.2.0.1 even if you want to install a later
	   patch set. Once you install 10.2.0.1 you can then apply any 10.2 patch set. Similarly, for
	    11.1 request 11.1.0.6 which must be applied before installing 11.1.0.7. Patch sets can be
	    downloaded from the Patches and Updates tab on My Oracle Support.
*/
func checkForOracle(host string, port string) []byte {
	// This string varies widely for several scripts from metasploit and nmap,
	// probably needs to be adapted over time as we get feedback on how effective it is
	connectData := []byte(
		"(DESCRIPTION=(CONNECT_DATA=(SERVICE_NAME=non-abc-existent-ser-vice-123-a-a-bc-asdf)(CID=(PROGRAM=sqlplus)" +
			"(HOST=__jdbc__)(USER=)))(ADDRESS=(PROTOCOL=tcp)(HOST=" + host + ")(PORT=" + port + ")))",
	)
	return buildTNSConnect(connectData)
}

// buildTNSConnect wraps the given CONNECT_DATA payload in the fixed TNS
// Connect-packet header/body shared by every probe in this plugin.
func buildTNSConnect(connectData []byte) []byte {
	tnsHeaderPktLen := [2]byte{}
	binary.BigEndian.PutUint16(tnsHeaderPktLen[:], uint16(len(connectData)+58))
	tnsHeaderPktCkSm := [2]byte{0x00, 0x00} // This is left empty
	tnsHeaderPktType := [1]byte{0x01}       // Connect type
	tnsHeaderReservedByte := [1]byte{0x00}
	tnsHeaderChecksum := [2]byte{0x00, 0x00}

	connectVersion := [2]byte{0x01, 0x3c}
	connectVersionCompat := [2]byte{0x01, 0x2c}
	connectServiceOpts := [2]byte{0x00, 0x00}
	sessionDUS := [2]byte{0x80, 0x00} // Data Unit Size
	maxSessionDUS := [2]byte{0x7F, 0xFF}
	ntPrtoChar := [2]byte{0x7F, 0x08}
	lineTurnaroundVal := [2]byte{0x00, 0x00}
	valOneInHardware := [2]byte{0x00, 0x01}
	lenConnectData := [2]byte{}
	binary.BigEndian.PutUint16(lenConnectData[:], uint16(len(connectData)))
	offsetConnectData := [2]byte{0x00, 0x3a}
	MaxDataRecv := [4]byte{0x00, 0x00, 0x04, 0x00}
	connectFlags := [2]byte{0x00, 0x00}
	traceCrossFacilityItems := [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	traceUnqConnID := [8]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0}
	magicBytes := [8]byte{
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
		0x00,
	} // These bytes are undocumented, and I believe
	// Are dependent on the version of TNS used and some connect and NT flags.
	// This may be a focus for reliability and accuracy
	combine := [][]byte{
		tnsHeaderPktLen[:],
		tnsHeaderPktCkSm[:],
		tnsHeaderPktType[:],
		tnsHeaderReservedByte[:],
		tnsHeaderChecksum[:],
		connectVersion[:],
		connectVersionCompat[:],
		connectServiceOpts[:],
		sessionDUS[:],
		maxSessionDUS[:],
		ntPrtoChar[:],
		lineTurnaroundVal[:],
		valOneInHardware[:],
		lenConnectData[:],
		offsetConnectData[:],
		MaxDataRecv[:],
		connectFlags[:],
		traceCrossFacilityItems[:],
		traceUnqConnID[:],
		magicBytes[:],
		connectData,
	}

	fullRequest := make([]byte, len(connectData)+58)
	index := 0
	for _, s := range combine {
		index += copy(fullRequest[index:], s)
	}

	return fullRequest
}

func isOracleDBRunning(response []byte) bool {
	beginPattern := []byte{
		0x28, 0x44, 0x45, 0x53, 0x43, 0x52, 0x49, 0x50,
		0x54, 0x49, 0x4f, 0x4e, 0x3d, 0x28, 0x54, 0x4d,
		0x50, 0x3d, 0x29, 0x28, 0x56, 0x53, 0x4e, 0x4e,
		0x55, 0x4d, 0x3d,
	}

	if len(response) < 27 {
		return false
	}

	responseCode := int(response[4])

	// This should always be a response code of 4 (rejection),
	// however I have included resend and accept response codes as well
	if responseCode != 4 && responseCode != 2 && responseCode != 11 {
		return false
	}

	// When making a request with the function above, every oracle version should return a variation of:
	// (DESCRIPTION=(TMP=)(VSNNUM=318767104)(ERR=1189)(ERROR_STACK=(ERROR=(CODE=1189)(EMFI=4))))
	// VSNUM and ERR will change based on the version of oracle used
	// Instead, key off (DESCRIPTION=(TMP=)(VSNNUM= to determine if the server is running oracle
	return bytes.Index(response, beginPattern) > 0
}

// looksLikeOracleTNS is an additive detection heuristic for hardened 18c/19c+
// listeners that suppress VSNNUM and reply with an error stack (or a version
// banner) instead of the classic (DESCRIPTION=(TMP=)(VSNNUM= refuse packet that
// isOracleDBRunning keys off of. It only ever broadens detection, so it cannot
// regress the existing behavior.
//
// It requires an Oracle-specific RESPONSE marker that is NOT present in the
// probe this plugin sends. In particular the bare "(DESCRIPTION=" token is
// deliberately NOT a marker: it is exactly what checkForOracle transmits, so an
// echo/reflecting service would otherwise be misidentified as Oracle. A bare
// "VSNNUM=" is likewise insufficient; only a VSNNUM with a non-zero value counts.
func looksLikeOracleTNS(response []byte) bool {
	markers := [][]byte{
		[]byte("ERROR_STACK="),
		[]byte("(ERR="),
		[]byte("TNSLSNR"),
		[]byte("ORA-"),
	}
	for _, m := range markers {
		if bytes.Contains(response, m) {
			return true
		}
	}
	// A VSNNUM with a non-zero value is Oracle-specific; extractVSNNUM returns
	// ok=false for a missing field or a zero value.
	if _, ok := extractVSNNUM(response); ok {
		return true
	}
	return false
}

var (
	vsnnumRe  = regexp.MustCompile(`VSNNUM=(\d+)`)
	errCodeRe = regexp.MustCompile(`ERR=(\d+)`)
	// bannerVersionRe only matches a dotted version anchored to a "Version" or
	// "Release" context token. A bare dotted-number fallback is intentionally
	// NOT used: it matched IP addresses echoed in HOST= (e.g. 192.168.1.1),
	// whose major component (192) is >= 23 and falsely flipped AICapable on.
	bannerVersionRe = regexp.MustCompile(`(?:Version|Release)\s+(\d+(?:\.\d+)+)`)
)

// extractVSNNUM pulls the decimal VSNNUM field out of a TNS response, if present.
func extractVSNNUM(response []byte) (uint32, bool) {
	m := vsnnumRe.FindSubmatch(response)
	if m == nil {
		return 0, false
	}
	v, err := strconv.ParseUint(string(m[1]), 10, 32)
	if err != nil || v == 0 {
		return 0, false
	}
	return uint32(v), true
}

// decodeVSNNUM decodes the Oracle VSNNUM bitfield into dotted version form.
// e.g. 318767104 -> "19.0.0.0.0", 202375680 -> "12.1.0.2.0". Returns "" for 0.
func decodeVSNNUM(n uint32) string {
	if n == 0 {
		return ""
	}
	major := n >> 24
	minor := (n >> 20) & 0x0F
	patch := (n >> 12) & 0xFF
	interim := (n >> 8) & 0x0F
	release := n & 0xFF
	return fmt.Sprintf("%d.%d.%d.%d.%d", major, minor, patch, interim, release)
}

// extractBannerVersion regexes a dotted version out of a listener banner such as
// "TNSLSNR for Linux: Version 19.0.0.0.0" or "... Release 11.2.0.4". The version
// must be anchored to a "Version"/"Release" token so that unrelated dotted
// numbers (e.g. an IP address echoed in HOST=) are never mistaken for a version.
func extractBannerVersion(response []byte) string {
	if m := bannerVersionRe.FindSubmatch(response); m != nil {
		return string(m[1])
	}
	return ""
}

// majorVersion returns the leading integer component of a dotted version string.
func majorVersion(dotted string) int {
	if dotted == "" {
		return 0
	}
	n, _ := strconv.Atoi(strings.SplitN(dotted, ".", 2)[0])
	return n
}

// oracleCPEs builds the CPE 2.3 strings for an Oracle Database instance. Real
// Oracle DB CVEs key predominantly to the "database_server" product (521 CVEs on
// NVD vs 66 on "database"), so CPEs are emitted on BOTH products to maximize CVE
// matching.
//
// The CPE version is ALWAYS wildcard "*". VSNNUM (the only version source in
// practice) exposes just the RU-less *family* version (e.g. 318767104 ->
// 19.0.0.0.0), but NVD's Oracle DB CVE ranges are keyed to RU-level versions
// (e.g. 19.3-19.23 for CVE-2024-21123). Emitting a fake-precise family version
// such as 19.0.0.0 sorts BELOW those ranges and MISSES the CVEs, so a wildcard
// is used to keep the CPE matchable against every RU range. The full decoded
// family version is preserved separately in the service Version/metadata field
// for human reporting.
func oracleCPEs(version string) []string {
	return []string{
		"cpe:2.3:a:oracle:database_server:*:*:*:*:*:*:*:*",
		"cpe:2.3:a:oracle:database:*:*:*:*:*:*:*:*",
	}
}

// parseInfo builds the human-readable Info map from a TNS response. It is
// panic-safe: fields that are absent (e.g. on hardened listeners that suppress
// VSNNUM) are simply omitted.
func parseInfo(response []byte) map[string]any {
	info := map[string]any{}
	if n, ok := extractVSNNUM(response); ok {
		info["VSNNUM"] = strconv.FormatUint(uint64(n), 10)
		if dotted := decodeVSNNUM(n); dotted != "" {
			info["Oracle TNS Listener Version"] = dotted
		}
	}
	if m := errCodeRe.FindSubmatch(response); m != nil {
		info["ERROR_CODE"] = string(m[1])
	}
	return info
}

func (p *ORACLEPlugin) PortPriority(port uint16) bool {
	return port == 1521
}

func (p *ORACLEPlugin) Name() string {
	return ORACLE
}
func (p *ORACLEPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *ORACLEPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	addr := strings.Split(conn.RemoteAddr().String(), ":")
	ip, port := addr[0], addr[1]
	request := checkForOracle(ip, port)

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Confirm it is an Oracle TNS listener. isOracleDBRunning is the original
	// (unchanged) VSNNUM refuse-packet check; looksLikeOracleTNS additionally
	// recognizes hardened 18c/19c+ listeners that reply with an error stack.
	if !isOracleDBRunning(response) && !looksLikeOracleTNS(response) {
		return nil, nil
	}

	// Decode the version: prefer the VSNNUM bitfield (works on legacy
	// listeners), then a version banner anchored to a Version/Release token.
	// Note: modern (18c/19c+) listeners typically suppress VSNNUM and do not
	// return a banner here, so version is often "" on those.
	version := ""
	if n, ok := extractVSNNUM(response); ok {
		version = decodeVSNNUM(n)
	}
	if version == "" {
		version = extractBannerVersion(response)
	}

	payload := plugins.ServiceOracle{
		Info:    fmt.Sprintf("%s", parseInfo(response)),
		Version: version,
		CPEs:    oracleCPEs(version),
	}
	// Best-effort AI-capability inference. Modern listeners suppress VSNNUM so a
	// version is usually unavailable; in practice this mainly fires on legacy
	// listeners that still return a decodable VSNNUM (or a version banner).
	if majorVersion(version) >= 23 {
		payload.AICapable = true
		payload.Note = "Oracle AI Database (23ai/26ai) - AI Vector Search / Select AI capable (inferred from version, not confirmed)"
	}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *ORACLEPlugin) Priority() int {
	return 900
}
