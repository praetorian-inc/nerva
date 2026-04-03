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

// Package rtmp detects RTMP (Real-Time Messaging Protocol) streaming servers.
//
// RTMP is used for live video streaming by media servers including Nginx-RTMP,
// Adobe Flash Media Server, Wowza, and OBS. Exposed RTMP servers may allow
// unauthorized stream access or hijacking.
//
// Detection uses the RTMP handshake: client sends C0 (version byte 0x03) +
// C1 (1536 bytes), server responds with S0 (0x03) + S1 (1536 bytes) + S2.
// We only need the S0 byte to confirm RTMP.
package rtmp

import (
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	RTMP        = "rtmp"
	DefaultPort = 1935

	// RTMP version 3 (the only widely deployed version)
	rtmpVersion = 0x03

	// C1 is 1536 bytes of handshake data (content doesn't matter for detection)
	c1Size = 1536
)

type RTMPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&RTMPPlugin{})
}

func (p *RTMPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Build C0+C1: version byte + 1536 bytes of zeros
	probe := make([]byte, 1+c1Size)
	probe[0] = rtmpVersion

	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, nil
	}

	if !isValidRTMPResponse(response) {
		return nil, nil
	}

	payload := plugins.ServiceRTMP{}
	return plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP), nil
}

// isValidRTMPResponse validates an RTMP S0+S1 response.
// S0 is a single byte containing the RTMP version (must be 0x03).
// S1 follows with 1536 bytes (we only check S0 + minimum length).
func isValidRTMPResponse(response []byte) bool {
	// Need at least S0 (1 byte) + some S1 data
	if len(response) < 1+4 {
		return false
	}

	// S0 must be RTMP version 3
	if response[0] != rtmpVersion {
		return false
	}

	// S1 should be at least partially present (1536 bytes).
	// We accept partial reads since utils.Recv may not get the full S1+S2.
	// Minimum: S0 (1) + some S1 timestamp (4) = 5 bytes.
	return true
}

func (p *RTMPPlugin) PortPriority(port uint16) bool {
	return port == DefaultPort
}

func (p *RTMPPlugin) Name() string {
	return RTMP
}

func (p *RTMPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *RTMPPlugin) Priority() int {
	return 200
}
