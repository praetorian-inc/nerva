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

package rdp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"reflect"
	"strconv"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type RDPPlugin struct{}
type TLSPlugin struct{}

type eolEntry struct {
	name     string
	severity plugins.Severity
}

var eolOSSeverity = map[string]plugins.Severity{
	"Windows 2000":                plugins.SeverityCritical,
	"Windows Server 2003":         plugins.SeverityCritical,
	"Windows Server 2008":         plugins.SeverityHigh,
	"Windows 7 or Server 2008 R2": plugins.SeverityHigh,
	"Windows Server 2008 R2 DC":   plugins.SeverityHigh,
	"Windows 8 or Server 2012":    plugins.SeverityMedium,
}

var eolVersionMap = map[string]eolEntry{
	"5.0": {"Windows 2000", plugins.SeverityCritical},
	"5.2": {"Windows Server 2003", plugins.SeverityCritical},
	"6.0": {"Windows Server 2008 or Vista", plugins.SeverityHigh},
	"6.1": {"Windows 7 or Server 2008 R2", plugins.SeverityHigh},
	"6.2": {"Windows 8 or Server 2012", plugins.SeverityMedium},
	"6.3": {"Windows 8.1 or Server 2012 R2", plugins.SeverityMedium},
}

const RDP = "rdp"

const (
	protocolHybrid   = 0x02
	protocolHybridEx = 0x08
	typeNegRSP       = 0x02
)

func init() {
	plugins.RegisterPlugin(&RDPPlugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

// checkSignature checks if a given response matches the expected signature for
// the response
func checkSignature(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i, v := range a {
		if v != b[i] {
			return false
		}
	}
	return true
}

func (p *RDPPlugin) PortPriority(port uint16) bool {
	return port == 3389
}

func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == 3389
}

// getOperatingSystemSignatures returns operating system specific signatures
// for the RDP service.
func getOperatingSystemSignatures() map[string][]byte {
	Windows2000 := []byte{
		0x03, 0x00, 0x00, 0x0b, 0x06, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
	}

	WindowsServer2003 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
		0x03, 0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2008 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x00, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	Windows7OrServer2008R2 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x09, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2008R2DC := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x01, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	Windows10 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x1f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2012Or8 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x0f, 0x08, 0x00, 0x02, 0x00, 0x00, 0x00,
	}

	WindowsServer2016or2019 := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00, 0x02,
		0x1f, 0x08, 0x00, 0x08, 0x00, 0x00, 0x00,
	}

	signatures := map[string][]byte{
		"Windows 2000":                Windows2000,
		"Windows Server 2003":         WindowsServer2003,
		"Windows Server 2008":         WindowsServer2008,
		"Windows 7 or Server 2008 R2": Windows7OrServer2008R2,
		"Windows Server 2008 R2 DC":   WindowsServer2008R2DC,
		"Windows 10":                  Windows10,
		"Windows 8 or Server 2012":    WindowsServer2012Or8,
		"Windows Server 2016 or 2019": WindowsServer2016or2019,
	}

	return signatures
}

// checkIsRDPGeneric leverages a generic RDP signature to identify if the
// target port is running the RDP service.
func checkRDP(response []byte) bool {
	GenericRDPSignature := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xd0, 0x00, 0x00, 0x12, 0x34, 0x00,
	}

	signature := GenericRDPSignature
	signatureLength := len(GenericRDPSignature)

	if len(response) < signatureLength {
		return false
	}

	responseSlice := response[:signatureLength]
	tof := checkSignature(responseSlice, signature)
	return tof
}

// guessOS tries to leverage operating system specific signatures to identify
// if the target port is running a specific operating system.
func guessOS(response []byte) (bool, string) {
	signatures := getOperatingSystemSignatures()
	for fingerprint, signature := range signatures {
		signatureLength := len(signature)

		if len(response) < signatureLength {
			continue
		}

		responseSlice := response[:signatureLength]
		tof := checkSignature(responseSlice, signature)
		if tof {
			return true, fingerprint
		}
	}

	return false, ""
}

// parseSelectedProtocol parses the selectedProtocol field from an RDP
// Negotiation Response. Returns the selectedProtocol value or -1 if the
// response is too short or does not contain a TYPE_RDP_NEG_RSP.
func parseSelectedProtocol(response []byte) int {
	if len(response) < 19 {
		return -1
	}
	negType := response[11]
	if negType != typeNegRSP {
		return -1
	}
	// Validate NEG_RSP length field (must be 8 per MS-RDPBCGR 2.2.1.2.1)
	if binary.LittleEndian.Uint16(response[13:15]) != 0x0008 {
		return -1
	}
	return int(binary.LittleEndian.Uint32(response[15:19]))
}

// checkNLADisabled returns a SecurityFinding when RDP Network Level
// Authentication (NLA) is not required. NLA is considered enabled when
// selectedProtocol has the PROTOCOL_HYBRID (0x02) or PROTOCOL_HYBRID_EX (0x08)
// bit set. A negative selectedProtocol value indicates no negotiation response
// was received.
func checkNLADisabled(selectedProtocol int) *plugins.SecurityFinding {
	// Only evaluate NLA when a NEG_RSP was present (selectedProtocol >= 0).
	// A value of -1 means no negotiation response, which occurs on hosts that
	// predate NLA (Windows 2000, Server 2003). Those are handled by EOL findings.
	if selectedProtocol < 0 {
		return nil
	}
	if selectedProtocol&protocolHybrid != 0 || selectedProtocol&protocolHybridEx != 0 {
		return nil
	}
	return &plugins.SecurityFinding{
		ID:          "rdp-nla-disabled",
		Severity:    plugins.SeverityMedium,
		Description: "RDP Network Level Authentication (NLA) is not required",
		Evidence:    fmt.Sprintf("selectedProtocol=0x%02x", selectedProtocol),
	}
}

func DetectRDP(conn net.Conn, timeout time.Duration) (string, int, bool, error) {
	InitialConnectionPacket := []byte{
		0x03, 0x00, 0x00, 0x13, 0x0e, 0xe0, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x0b,
		0x00, 0x00, 0x00,
	}

	response, err := utils.SendRecv(conn, InitialConnectionPacket, timeout)
	if err != nil {
		return "", -1, false, err
	}
	if len(response) == 0 {
		return "", -1, true, &utils.ServerNotEnable{}
	}

	isRDP := checkRDP(response)
	fingerprint := ""
	if isRDP {
		success, osFingerprint := guessOS(response)
		if success {
			fingerprint = osFingerprint
		}

		return fingerprint, parseSelectedProtocol(response), true, nil
	}
	return "", -1, true, &utils.InvalidResponseError{Service: RDP}
}

func DetectRDPAuth(conn net.Conn, timeout time.Duration) (*plugins.ServiceRDP, bool, error) {
	info := plugins.ServiceRDP{}

	// CredSSP protocol - NTLM authentication
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-cssp
	// https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp
	// http://davenport.sourceforge.net/ntlm.html

	NegotiatePacket := []byte{
		0x30, 0x37, 0xA0, 0x03, 0x02, 0x01, 0x60, 0xA1, 0x30, 0x30, 0x2E, 0x30, 0x2C, 0xA0, 0x2A, 0x04, 0x28,
		// Signature
		'N', 'T', 'L', 'M', 'S', 'S', 'P', 0x00,
		// Message Type
		0x01, 0x00, 0x00, 0x00,
		// Negotiate Flags
		0xF7, 0xBA, 0xDB, 0xE2,
		// Domain Name Fields
		0x00, 0x00, // DomainNameLen
		0x00, 0x00, // DomainNameMaxLen
		0x00, 0x00, 0x00, 0x00, // DomainNameBufferOffset
		// Workstation Fields
		0x00, 0x00, // WorkstationLen
		0x00, 0x00, // WorkstationMaxLen
		0x00, 0x00, 0x00, 0x00, // WorkstationBufferOffset
		// Version
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	}

	response, err := utils.SendRecv(conn, NegotiatePacket, timeout)
	if err != nil {
		return nil, false, err
	}

	type NTLMChallenge struct {
		Signature              [8]byte
		MessageType            uint32
		TargetNameLen          uint16
		TargetNameMaxLen       uint16
		TargetNameBufferOffset uint32
		NegotiateFlags         uint32
		ServerChallenge        uint64
		Reserved               uint64
		TargetInfoLen          uint16
		TargetInfoMaxLen       uint16
		TargetInfoBufferOffset uint32
		Version                [8]byte
		// Payload (variable)
	}
	var challengeLen = 56

	challengeStartOffset := bytes.Index(response, []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0})
	if challengeStartOffset == -1 {
		return nil, false, nil
	}
	if len(response) < challengeStartOffset+challengeLen {
		return nil, false, nil
	}
	var responseData NTLMChallenge
	response = response[challengeStartOffset:]
	responseBuf := bytes.NewBuffer(response)
	err = binary.Read(responseBuf, binary.LittleEndian, &responseData)
	if err != nil {
		return nil, false, err
	}

	// Check if valid NTLM challenge response message structure
	if responseData.MessageType != 0x00000002 ||
		responseData.Reserved != 0 ||
		!reflect.DeepEqual(responseData.Version[4:], []byte{0, 0, 0, 0xF}) {
		return nil, false, nil
	}

	// Parse: Version
	type version struct {
		MajorVersion byte
		MinorVersion byte
		BuildNumber  uint16
	}
	var versionData version
	versionBuf := bytes.NewBuffer(responseData.Version[:4])
	err = binary.Read(versionBuf, binary.LittleEndian, &versionData)
	if err != nil {
		return nil, true, err
	}
	info.OSVersion = fmt.Sprintf("%d.%d.%d", versionData.MajorVersion,
		versionData.MinorVersion,
		versionData.BuildNumber)

	// Parse: TargetName
	targetNameLen := int(responseData.TargetNameLen)
	if targetNameLen > 0 {
		startIdx := int(responseData.TargetNameBufferOffset)
		endIdx := startIdx + targetNameLen
		// Validate bounds before slice access
		if startIdx > len(response) || endIdx > len(response) || endIdx < startIdx {
			return &info, true, &utils.InvalidResponseErrorInfo{Service: RDP, Info: "invalid target name bounds"}
		}
		targetName := strings.ReplaceAll(string(response[startIdx:endIdx]), "\x00", "")
		info.TargetName = targetName
	}

	// Parse: TargetInfo
	AvIDMap := map[uint16]string{
		1: "NetBIOSComputerName",
		2: "NetBIOSDomainName",
		3: "FQDN", // DNS Computer Name
		4: "DNSDomainName",
		5: "DNSTreeName",
	}

	type AVPair struct {
		AvID  uint16
		AvLen uint16
	}
	var avPairLen = 4
	targetInfoLen := int(responseData.TargetInfoLen)
	if targetInfoLen > 0 {
		startIdx := int(responseData.TargetInfoBufferOffset)
		if startIdx+targetInfoLen > len(response) {
			return &info, true, fmt.Errorf("Invalid TargetInfoLen value")
		}
		var avPair AVPair
		avPairBuf := bytes.NewBuffer(response[startIdx : startIdx+avPairLen])
		err = binary.Read(avPairBuf, binary.LittleEndian, &avPair)
		if err != nil {
			return &info, true, err
		}
		currIdx := startIdx
		for avPair.AvID != 0 {
			// Validate bounds before slice access
			valueEnd := currIdx + avPairLen + int(avPair.AvLen)
			if currIdx < 0 || currIdx+avPairLen > len(response) || valueEnd > len(response) || valueEnd < currIdx {
				return &info, true, &utils.InvalidResponseErrorInfo{Service: RDP, Info: "invalid AV_PAIR bounds"}
			}
			if field, exists := AvIDMap[avPair.AvID]; exists {
				value := strings.ReplaceAll(string(response[currIdx+avPairLen:valueEnd]), "\x00", "")
				switch field {
				case "netbiosComputerName":
					info.NetBIOSComputerName = value
				case "netbiosDomainName":
					info.NetBIOSDomainName = value
				case "dnsComputerName":
					info.DNSComputerName = value
				case "dnsDomainName":
					info.DNSDomainName = value
				case "forestName": // MsvAvDnsTreeName
					info.ForestName = value
				}
			}
			currIdx += avPairLen + int(avPair.AvLen)
			if currIdx+avPairLen > startIdx+targetInfoLen {
				return &info, true, fmt.Errorf("Invalid AV_PAIR list")
			}
			avPairBuf = bytes.NewBuffer(response[currIdx : currIdx+avPairLen])
			err = binary.Read(avPairBuf, binary.LittleEndian, &avPair)
			if err != nil {
				return &info, true, err
			}
		}
	}

	return &info, true, nil
}

// checkEOLOS maps an OS fingerprint string (from guessOS) to a SecurityFinding
// if the OS is end-of-life. Returns nil if the OS is not EOL or fingerprint is empty.
func checkEOLOS(fingerprint string) *plugins.SecurityFinding {
	severity, ok := eolOSSeverity[fingerprint]
	if !ok {
		return nil
	}
	return &plugins.SecurityFinding{
		ID:          "rdp-eol-os",
		Severity:    severity,
		Description: fmt.Sprintf("RDP service running end-of-life OS: %s", fingerprint),
		Evidence:    fingerprint,
	}
}

// checkEOLOSVersion maps a "Major.Minor.Build" version string (from NTLM OSVersion)
// to a SecurityFinding if the OS is end-of-life. Returns nil if not EOL or parse error.
func checkEOLOSVersion(osVersion string) *plugins.SecurityFinding {
	parts := strings.SplitN(osVersion, ".", 3)
	if len(parts) < 2 {
		return nil
	}
	major, err := strconv.Atoi(parts[0])
	if err != nil {
		return nil
	}
	minor, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil
	}
	key := fmt.Sprintf("%d.%d", major, minor)
	entry, ok := eolVersionMap[key]
	if !ok {
		return nil
	}
	return &plugins.SecurityFinding{
		ID:          "rdp-eol-os",
		Severity:    entry.severity,
		Description: fmt.Sprintf("RDP service running end-of-life OS: %s", entry.name),
		Evidence:    osVersion,
	}
}

func (p *RDPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	fingerprint, selectedProtocol, check, err := DetectRDP(conn, timeout)
	if check && err != nil {
		return nil, nil
	} else if check && err == nil {
		payload := plugins.ServiceRDP{
			OSFingerprint: fingerprint,
		}
		service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
		if target.Misconfigs {
			if fingerprint != "" {
				if finding := checkEOLOS(fingerprint); finding != nil {
					service.SecurityFindings = append(service.SecurityFindings, *finding)
				}
			}
			if finding := checkNLADisabled(selectedProtocol); finding != nil {
				service.SecurityFindings = append(service.SecurityFindings, *finding)
			}
		}
		return service, nil
	}
	return nil, err
}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	info, check, err := DetectRDPAuth(conn, timeout)
	if check && err != nil {
		return nil, nil
	} else if check && info != nil && err == nil {
		service := plugins.CreateServiceFrom(target, *info, true, "", plugins.TCP)
		if target.Misconfigs {
			if info.OSVersion != "" {
				if finding := checkEOLOSVersion(info.OSVersion); finding != nil {
					service.SecurityFindings = append(service.SecurityFindings, *finding)
				}
			}
			service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
		}
		return service, nil
	}
	return nil, err
}

func (p *RDPPlugin) Name() string {
	return RDP
}
func (p *RDPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TLSPlugin) Name() string {
	return RDP
}
func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *RDPPlugin) Priority() int {
	return 89
}

func (p *TLSPlugin) Priority() int {
	return 89
}
