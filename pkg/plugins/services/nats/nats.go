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

package nats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

type NATSPlugin struct{}
type NATSTLSPlugin struct{}

const NATS = "nats"

// natsInfo represents the JSON structure of a NATS server INFO message
type natsInfo struct {
	ServerID     string   `json:"server_id"`
	ServerName   string   `json:"server_name"`
	Version      string   `json:"version"`
	Go           string   `json:"go"`
	Host         string   `json:"host"`
	Port         int      `json:"port"`
	MaxPayload   int64    `json:"max_payload"`
	Proto        int      `json:"proto"`
	Headers      bool     `json:"headers"`
	AuthRequired bool     `json:"auth_required"`
	TLSRequired  bool     `json:"tls_required"`
	TLSVerify    bool     `json:"tls_verify"`
	TLSAvailable bool     `json:"tls_available"`
	JetStream    bool     `json:"jetstream"`
	GitCommit    string   `json:"git_commit"`
	ClientID     uint64   `json:"client_id"`
	ClientIP     string   `json:"client_ip"`
	Cluster      string   `json:"cluster"`
	Domain       string   `json:"domain"`
	ConnectURLs  []string `json:"connect_urls"`
	Nonce        string   `json:"nonce"`
	LDM          bool     `json:"ldm"`
}

// checkNATSResponse validates that the response is a valid NATS INFO message
// and extracts the natsInfo structure
func checkNATSResponse(data []byte) (*natsInfo, error) {
	// NATS server sends INFO immediately on connect
	// Format: INFO <json>\r\n
	if len(data) < 5 {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: NATS,
			Info:    "response too short",
		}
	}

	// Check for "INFO " prefix (5 bytes)
	if !bytes.HasPrefix(data, []byte("INFO ")) {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: NATS,
			Info:    "missing INFO prefix",
		}
	}

	// Find \r\n terminator
	terminatorIdx := bytes.Index(data, []byte("\r\n"))
	if terminatorIdx == -1 {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: NATS,
			Info:    "missing CRLF terminator",
		}
	}

	// Extract JSON between "INFO " and \r\n
	jsonStart := 5 // len("INFO ")
	jsonData := data[jsonStart:terminatorIdx]

	// Parse JSON
	var info natsInfo
	if err := json.Unmarshal(jsonData, &info); err != nil {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: NATS,
			Info:    fmt.Sprintf("invalid JSON: %v", err),
		}
	}

	// Validate server_id is non-empty (required field)
	if info.ServerID == "" {
		return nil, &utils.InvalidResponseErrorInfo{
			Service: NATS,
			Info:    "missing server_id field",
		}
	}

	return &info, nil
}

// buildNATSCPE generates a CPE (Common Platform Enumeration) string for NATS servers.
// CPE format: cpe:2.3:a:nats:nats-server:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" wildcard to enable asset inventory use cases.
//
// Parameters:
//   - version: NATS version string (e.g., "2.10.7"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" wildcard
func buildNATSCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:nats:nats-server:%s:*:*:*:*:*:*:*", version)
}

func init() {
	plugins.RegisterPlugin(&NATSPlugin{})
	plugins.RegisterPlugin(&NATSTLSPlugin{})
}

func (p *NATSPlugin) PortPriority(port uint16) bool {
	return port == 4222 || port == 6222
}

func (p *NATSTLSPlugin) PortPriority(port uint16) bool {
	return port == 4222 || port == 6222
}

func (p *NATSTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return DetectNATS(conn, target, timeout, true)
}

func DetectNATS(conn net.Conn, target plugins.Target, timeout time.Duration, tls bool) (*plugins.Service, error) {
	// NATS server sends INFO immediately on connect (no probe needed)
	response, err := utils.Recv(conn, timeout)
	if err != nil {
		return nil, err
	}
	if len(response) == 0 {
		return nil, nil
	}

	// Validate and parse NATS INFO response
	info, err := checkNATSResponse(response)
	if err != nil {
		return nil, nil
	}

	// Generate CPE
	cpe := buildNATSCPE(info.Version)

	// Build ServiceNATS payload with all metadata
	payload := plugins.ServiceNATS{
		ServerID:     info.ServerID,
		ServerName:   info.ServerName,
		AuthRequired: info.AuthRequired,
		TLSRequired:  info.TLSRequired,
		TLSAvailable: info.TLSAvailable,
		JetStream:    info.JetStream,
		Headers:      info.Headers,
		Proto:        info.Proto,
		MaxPayload:   info.MaxPayload,
		GoVersion:    info.Go,
		GitCommit:    info.GitCommit,
		Cluster:      info.Cluster,
		Domain:       info.Domain,
		ConnectURLs:  info.ConnectURLs,
		ClientIP:     info.ClientIP,
		LDM:          info.LDM,
		CPEs:         []string{cpe},
	}

	if tls {
		return plugins.CreateServiceFrom(target, payload, true, info.Version, plugins.TCPTLS), nil
	}
	return plugins.CreateServiceFrom(target, payload, false, info.Version, plugins.TCP), nil
}

func (p *NATSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return DetectNATS(conn, target, timeout, false)
}

func (p *NATSPlugin) Name() string {
	return NATS
}

func (p *NATSTLSPlugin) Name() string {
	return NATS
}

func (p *NATSPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *NATSTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *NATSPlugin) Priority() int {
	return 415
}

func (p *NATSTLSPlugin) Priority() int {
	return 416
}
