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

// Package socks5 implements a SOCKS5 proxy detection plugin.
//
// Detection Strategy:
// Phase 1: Send a SOCKS5 greeting with three offered authentication methods
// (no-auth, GSSAPI, username/password) and validate the server's 2-byte response.
// The server selects one method or indicates no acceptable methods (0xFF).
//
// Wire Protocol (RFC 1928):
//
//	Client greeting:
//	+----+----------+----------+
//	|VER | NMETHODS | METHODS  |
//	+----+----------+----------+
//	| 1  |    1     | 1-255    |
//	+----+----------+----------+
//
//	Server response:
//	+----+--------+
//	|VER | METHOD |
//	+----+--------+
//	| 1  |   1    |
//	+----+--------+
//
// Method codes:
//
//	0x00 = NO AUTHENTICATION REQUIRED (open proxy - CRITICAL security finding)
//	0x01 = GSSAPI
//	0x02 = USERNAME/PASSWORD
//	0xFF = NO ACCEPTABLE METHODS
package socks5

import (
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const SOCKS5 = "socks5"

const (
	methodNoAuth   byte = 0x00
	methodGSSAPI   byte = 0x01
	methodUserPass byte = 0x02
	methodNoAccept byte = 0xFF
)

// socks5Data holds the result of the SOCKS5 greeting handshake.
type socks5Data struct {
	selectedMethod  byte
	offeredMethods  []string
	anonymousAccess bool
}

// SOCKS5Plugin implements the plugins.Plugin interface for SOCKS5 proxy detection.
type SOCKS5Plugin struct{}

func init() {
	plugins.RegisterPlugin(&SOCKS5Plugin{})
}

func (p *SOCKS5Plugin) Name() string {
	return SOCKS5
}

func (p *SOCKS5Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *SOCKS5Plugin) Priority() int {
	return 400
}

func (p *SOCKS5Plugin) PortPriority(port uint16) bool {
	switch port {
	case 1080, 9050, 9150, 1081:
		return true
	}
	return false
}

func (p *SOCKS5Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	data, detected, err := detectSOCKS5(conn, timeout)
	if err != nil {
		return nil, err
	}
	if !detected {
		return nil, nil
	}

	metadata := plugins.ServiceSOCKS5{
		SelectedMethod:  methodName(data.selectedMethod),
		OfferedMethods:  data.offeredMethods,
		AnonymousAccess: data.anonymousAccess,
		CPEs:            []string{buildSOCKS5CPE()},
	}

	return plugins.CreateServiceFrom(target, metadata, false, "", plugins.TCP), nil
}

// detectSOCKS5 sends the SOCKS5 greeting and validates the response.
// Returns (data, true, nil) on successful SOCKS5 detection,
// (data, false, nil) if the response is not SOCKS5,
// (data, false, err) on network errors.
func detectSOCKS5(conn net.Conn, timeout time.Duration) (socks5Data, bool, error) {
	// Greeting: VER=5, NMETHODS=3, METHODS=[0x00, 0x01, 0x02]
	greeting := []byte{0x05, 0x03, 0x00, 0x01, 0x02}

	response, err := utils.SendRecv(conn, greeting, timeout)
	if err != nil {
		return socks5Data{}, false, err
	}
	if len(response) == 0 {
		return socks5Data{}, false, nil
	}

	selectedMethod, err := validateSOCKS5Response(response)
	if err != nil {
		return socks5Data{}, false, nil
	}

	offeredMethods := []string{
		methodName(methodNoAuth),
		methodName(methodGSSAPI),
		methodName(methodUserPass),
	}

	data := socks5Data{
		selectedMethod:  selectedMethod,
		offeredMethods:  offeredMethods,
		anonymousAccess: selectedMethod == methodNoAuth,
	}

	return data, true, nil
}

// validateSOCKS5Response validates the 2-byte SOCKS5 server response.
// Returns the selected method byte on success, or an error if the response
// is not a valid SOCKS5 server selection message.
func validateSOCKS5Response(response []byte) (byte, error) {
	if len(response) < 2 {
		return 0, &utils.InvalidResponseErrorInfo{
			Service: SOCKS5,
			Info:    "response too short",
		}
	}

	if response[0] != 0x05 {
		return 0, &utils.InvalidResponseErrorInfo{
			Service: SOCKS5,
			Info:    fmt.Sprintf("invalid version byte: 0x%02x", response[0]),
		}
	}

	method := response[1]
	switch method {
	case methodNoAuth, methodGSSAPI, methodUserPass, methodNoAccept:
		return method, nil
	default:
		return 0, &utils.InvalidResponseErrorInfo{
			Service: SOCKS5,
			Info:    fmt.Sprintf("unknown method byte: 0x%02x", method),
		}
	}
}

// methodName returns the human-readable name for a SOCKS5 authentication method.
func methodName(method byte) string {
	switch method {
	case methodNoAuth:
		return "no-auth"
	case methodGSSAPI:
		return "gssapi"
	case methodUserPass:
		return "username-password"
	case methodNoAccept:
		return "no-acceptable"
	default:
		return fmt.Sprintf("unknown(0x%02x)", method)
	}
}

// buildSOCKS5CPE returns the CPE identifier for a generic SOCKS5 proxy.
func buildSOCKS5CPE() string {
	return "cpe:2.3:a:*:socks5_proxy:*:*:*:*:*:*:*:*"
}
