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

// Package socks4 implements a SOCKS4 proxy detection plugin.
//
// Detection strategy: Send a SOCKS4 CONNECT request to 127.0.0.1:80, then
// validate the 8-byte response. The reply version byte must be 0x00 and the
// status byte must be one of the four defined SOCKS4 status codes.
//
// SOCKS4 has no authentication mechanism by design (RFC-equivalent), so any
// successful detection implies anonymous access.
//
// SOCKS4 CONNECT request format:
//
//	+----+----+----+----+----+----+----+----+----+----+....+----+
//	| VN | CD | DSTPORT |      DSTIP        | USERID       |NULL|
//	+----+----+----+----+----+----+----+----+----+----+....+----+
//	  1    1      2              4           variable       1
//
// SOCKS4 response format:
//
//	+----+----+----+----+----+----+----+----+
//	| VN | CD | DSTPORT |      DSTIP        |
//	+----+----+----+----+----+----+----+----+
//	  1    1      2              4
package socks4

import (
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const SOCKS4 = "socks4"

// SOCKS4 status codes (response byte index 1).
const (
	statusGranted        byte = 0x5A // Request granted
	statusRejected       byte = 0x5B // Request rejected or failed
	statusIdentdRequired byte = 0x5C // Cannot reach identd
	statusIdentdMismatch byte = 0x5D // Identd mismatch
)

// SOCKS4Plugin detects SOCKS4 proxy services.
type SOCKS4Plugin struct{}

func init() {
	plugins.RegisterPlugin(&SOCKS4Plugin{})
}

// socks4Data holds extracted data from a successful SOCKS4 response.
type socks4Data struct {
	status byte
}

// detectSOCKS4 sends a SOCKS4 CONNECT request to 127.0.0.1:80 and validates
// the response. Returns the parsed data, true on a valid SOCKS4 response, or
// false if the response does not match the SOCKS4 protocol.
func detectSOCKS4(conn net.Conn, timeout time.Duration) (socks4Data, bool, error) {
	// SOCKS4 CONNECT request: VER=0x04, CMD=CONNECT(0x01), DSTPORT=80(0x0050),
	// DSTIP=127.0.0.1, USERID=empty (null-terminated).
	request := []byte{0x04, 0x01, 0x00, 0x50, 0x7f, 0x00, 0x00, 0x01, 0x00}

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return socks4Data{}, false, err
	}
	if len(response) == 0 {
		return socks4Data{}, false, nil
	}

	status, err := validateSOCKS4Response(response)
	if err != nil {
		return socks4Data{}, false, nil
	}

	return socks4Data{status: status}, true, nil
}

// validateSOCKS4Response checks that the response conforms to the SOCKS4
// protocol. Returns the status byte on success, or an error if the response is
// too short, has an invalid reply version byte, or contains an unknown status.
func validateSOCKS4Response(response []byte) (byte, error) {
	if len(response) < 2 {
		return 0, &utils.InvalidResponseErrorInfo{
			Service: SOCKS4,
			Info:    "response too short",
		}
	}

	// Byte 0 is the reply version; SOCKS4 servers always return 0x00.
	if response[0] != 0x00 {
		return 0, &utils.InvalidResponseErrorInfo{
			Service: SOCKS4,
			Info:    "invalid reply version byte",
		}
	}

	status := response[1]
	switch status {
	case statusGranted, statusRejected, statusIdentdRequired, statusIdentdMismatch:
		return status, nil
	default:
		return 0, &utils.InvalidResponseErrorInfo{
			Service: SOCKS4,
			Info:    "unknown status code",
		}
	}
}

// statusName maps a SOCKS4 status byte to a human-readable string.
func statusName(status byte) string {
	switch status {
	case statusGranted:
		return "granted"
	case statusRejected:
		return "rejected"
	case statusIdentdRequired:
		return "identd-required"
	case statusIdentdMismatch:
		return "identd-mismatch"
	default:
		return "unknown"
	}
}

// buildSOCKS4CPE returns a CPE string for a generic SOCKS4 proxy service.
func buildSOCKS4CPE() string {
	return "cpe:2.3:a:*:socks4_proxy:*:*:*:*:*:*:*:*"
}

func (p *SOCKS4Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	data, detected, err := detectSOCKS4(conn, timeout)
	if err != nil {
		return nil, err
	}
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceSOCKS4{
		Status:          statusName(data.status),
		SOCKS4a:         false,
		AnonymousAccess: data.status == statusGranted,
		CPEs:            []string{buildSOCKS4CPE()},
	}

	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

func (p *SOCKS4Plugin) PortPriority(port uint16) bool {
	return port == 1080 || port == 1081
}

func (p *SOCKS4Plugin) Name() string {
	return SOCKS4
}

func (p *SOCKS4Plugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *SOCKS4Plugin) Priority() int {
	return 410
}
