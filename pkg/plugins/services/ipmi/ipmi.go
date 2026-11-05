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

package ipmi

import (
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// http://72.47.221.139/sites/default/files/standards/documents/DSP0114.pdf

var ipmiInitialPacket = [23]byte{

	//
	// Remote Management Control Protocol, Class: IPMI
	// Version:  0x06
	// Reserved: 0x00
	// Sequence: 0xFF
	// Type:     0x07
	//

	0x06, 0x00, 0xFF, 0x07,

	//
	// IPMI v1.5 Session Wrapper, Session ID 0x00
	// Authentication Type:     NONE (0x00)
	// Session ID: 0x00 0x00 0x00 0x00
	// Session Sequence number: 0x00 0x00 0x00 0x00
	// Message Length:          9
	//

	0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
	0x09,

	//
	// Intelligent Platform Management Bus
	// Bus Command Data: 20 18 C8 81 00 38 8E 04 B5
	//

	0x20, 0x18, 0xC8, 0x81, 0x00, 0x38, 0x8E, 0x04, 0xB5,
}

var ipmiExpectedResponse = [13]byte{

	/*
	 * Remote Management Control Protocol, Class: IPMI
	 * Version:  0x06
	 * Reserved: 0x00
	 * Sequence: 0xFF
	 * Type:     0x07
	 */

	0x06, 0x00, 0xFF, 0x07,

	//
	// IPMI v1.5 Session Wrapper, Session ID 0x00
	// Authentication Type:     NONE (0x00)
	// Session ID: 0x00 0x00 0x00 0x00
	// Session Sequence number: 0x00 0x00 0x00 0x00
	//

	0x00,
	0x00, 0x00, 0x00, 0x00,
	0x00, 0x00, 0x00, 0x00,
}

// cipherZeroPacket is an RMCP+ Open Session Request with cipher suite 0
// (auth=RAKP-None, integrity=None, confidentiality=None).
var cipherZeroPacket = []byte{
	// RMCP header
	0x06, 0x00, 0xFF, 0x07,
	// Session: auth type 0x06 (RMCP+), payload type 0x10 (Open Session Request)
	0x06, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00,
	// Payload: message tag, reserved, requested max privilege level, reserved
	0x00, 0x04, 0x00, 0x00,
	// Remote console session ID
	0xA0, 0xA1, 0xA2, 0xA3,
	// Auth algorithm payload: RAKP-None (0x00)
	0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	// Integrity algorithm payload: None (0x00)
	0x01, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
	// Confidentiality algorithm payload: None (0x00)
	0x02, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00,
}

// Response byte offsets for Get Channel Auth Capabilities response.
const (
	authCapabilitiesMinLen   = 25
	offsetCompletionCode     = 20
	offsetAuthTypeSupport    = 22
	offsetAuthStatus         = 23
	authStatusAnonymousLogin = 0x01
	offsetExtCapabilities    = 24
	extCapIPMIv2             = 0x02
)

// Response byte offsets for RMCP+ Open Session Response.
const (
	cipherZeroRespMinLen = 18
	offsetStatusCode     = 17
)

// authCapabilities holds parsed fields from a Get Channel Auth Capabilities response.
type authCapabilities struct {
	AuthTypeSupport byte
	AuthStatus      byte
	ExtCapabilities byte
}

// IPMIPlugin detects IPMI BMC interfaces.
type IPMIPlugin struct{}

const IPMI = "ipmi"

// detectIPMI sends the Get Channel Authentication Capabilities request and reads
// up to 128 bytes of the response. Returns the response bytes, whether the first
// 13 bytes match ipmiExpectedResponse, and any error.
func detectIPMI(conn net.Conn, timeout time.Duration) ([]byte, bool, error) {
	_, err := conn.Write(ipmiInitialPacket[:])
	if err != nil {
		return nil, false, err
	}

	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return nil, false, err
	}

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, false, err
	}
	response := buf[:n]

	if len(response) < len(ipmiExpectedResponse) {
		return response, false, nil
	}
	for i, b := range ipmiExpectedResponse {
		if response[i] != b {
			return response, false, nil
		}
	}

	return response, true, nil
}

// parseAuthCapabilities parses the auth type support bitmap and auth status byte
// from a Get Channel Authentication Capabilities response. Returns nil when the
// response is too short or indicates a non-zero completion code.
func parseAuthCapabilities(response []byte) *authCapabilities {
	if len(response) < authCapabilitiesMinLen {
		return nil
	}
	if response[offsetCompletionCode] != 0x00 {
		return nil
	}
	return &authCapabilities{
		AuthTypeSupport: response[offsetAuthTypeSupport],
		AuthStatus:      response[offsetAuthStatus],
		ExtCapabilities: response[offsetExtCapabilities],
	}
}

// buildAuthTypeList converts the auth type support bitmap into a slice of
// human-readable strings. Bit positions follow the IPMI 2.0 spec (Table 22-15).
func buildAuthTypeList(caps *authCapabilities) []string {
	if caps == nil {
		return nil
	}
	var types []string
	if caps.AuthTypeSupport&0x01 != 0 {
		types = append(types, "none")
	}
	if caps.AuthTypeSupport&0x02 != 0 {
		types = append(types, "md2")
	}
	if caps.AuthTypeSupport&0x04 != 0 {
		types = append(types, "md5")
	}
	if caps.AuthTypeSupport&0x10 != 0 {
		types = append(types, "straight_key")
	}
	if caps.AuthTypeSupport&0x20 != 0 {
		types = append(types, "oem")
	}
	return types
}

// probeCipherZero sends an RMCP+ Open Session Request with cipher suite 0 and
// returns true if the BMC responds with a status code of 0x00 (accepted).
// The accepted session is left in pending state (RAKP handshake never completes);
// BMCs time out pending sessions in 10-30s per IPMI spec.
func probeCipherZero(conn net.Conn, timeout time.Duration) bool {
	_, err := conn.Write(cipherZeroPacket)
	if err != nil {
		return false
	}

	err = conn.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return false
	}

	buf := make([]byte, 128)
	n, err := conn.Read(buf)
	if err != nil {
		return false
	}
	resp := buf[:n]

	if len(resp) < cipherZeroRespMinLen {
		return false
	}
	// Verify auth type 0x06 (RMCP+) and payload type 0x11 (Open Session Response).
	if resp[4] != 0x06 || resp[5] != 0x11 {
		return false
	}
	return resp[offsetStatusCode] == 0x00
}

func init() {
	plugins.RegisterPlugin(&IPMIPlugin{})
}

func (p *IPMIPlugin) PortPriority(port uint16) bool {
	return port == 623
}

func (p *IPMIPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	response, ok, err := detectIPMI(conn, timeout)
	if !ok || err != nil {
		return nil, nil
	}

	caps := parseAuthCapabilities(response)

	payload := plugins.ServiceIPMI{}

	if caps != nil {
		payload.AuthTypes = buildAuthTypeList(caps)
		payload.IPMIv2 = caps.ExtCapabilities&extCapIPMIv2 != 0
		payload.AnonymousLogin = caps.AuthStatus&authStatusAnonymousLogin != 0
	}

	if target.Misconfigs {
		payload.CipherZero = probeCipherZero(conn, timeout)
	}

	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.UDP)

	if payload.AnonymousLogin {
		service.AnonymousAccess = true
	}

	if target.Misconfigs {
		service.SecurityFindings = []plugins.SecurityFinding{ipmiExposedFinding()}

		if payload.AnonymousLogin {
			service.SecurityFindings = append(service.SecurityFindings, ipmiAnonymousLoginFinding())
		}
		if payload.CipherZero {
			service.SecurityFindings = append(service.SecurityFindings, ipmiCipherZeroFinding())
		}
	}

	return service, nil
}

// ipmiExposedFinding returns a SecurityFinding for an exposed IPMI service.
func ipmiExposedFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "ipmi-exposed",
		Severity:    plugins.SeverityHigh,
		Description: "IPMI BMC interface exposed to network — evaluate authentication configuration and cipher suite restrictions",
		Evidence:    "IPMI Get Channel Authentication Capabilities response received",
	}
}

// ipmiAnonymousLoginFinding returns a SecurityFinding for an IPMI service that
// allows anonymous login (auth status bit 0 set).
func ipmiAnonymousLoginFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "ipmi-anonymous-login",
		Severity:    plugins.SeverityHigh,
		Description: "IPMI BMC permits anonymous login — no credentials required for management access",
		Evidence:    "Auth status byte indicates anonymous login enabled (bit 0 set)",
	}
}

// ipmiCipherZeroFinding returns a SecurityFinding for an IPMI service that
// accepts cipher suite 0 (CVE-2013-4786).
func ipmiCipherZeroFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "ipmi-cipher-zero",
		Severity:    plugins.SeverityHigh,
		Description: "IPMI BMC accepts cipher suite 0 (CVE-2013-4786) — authentication can be bypassed entirely",
		Evidence:    "RMCP+ Open Session Response with status 0x00 received for cipher suite 0 request",
	}
}

func (p *IPMIPlugin) Name() string {
	return IPMI
}
func (p *IPMIPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *IPMIPlugin) Priority() int {
	return 80
}
