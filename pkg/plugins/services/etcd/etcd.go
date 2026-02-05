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

/*
etcd Distributed Key-Value Store Fingerprinting

This plugin implements etcd fingerprinting using HTTP REST API detection.
etcd exposes version information and service identification through the
/version HTTP endpoint that requires no authentication.

Detection Strategy:
  PHASE 1 - DETECTION (determines if the service is etcd):
    PRIMARY METHOD (GET /version): Works on etcd 3.x+ versions
      - Send GET /version HTTP request to version endpoint
      - Parse JSON response for characteristic etcd markers
      - Validate json["etcdserver"] field exists and is non-empty
      - If check passes → etcd detected

  PHASE 2 - ENRICHMENT (attempts to retrieve version information):
    After etcd is detected, extract version from JSON response:
      - Primary: json["etcdserver"] field (e.g., "3.5.9")
      - Secondary: json["etcdcluster"] field for cluster version
      - Validate version format matches X.Y.Z pattern (regex: ^\d+\.\d+\.\d+$)
      - If version unavailable, use "*" wildcard in CPE

etcd Version Endpoint Response Structure:

 Example etcd 3.5.x Response:
   HTTP/1.1 200 OK
   Content-Type: application/json

   {
     "etcdserver": "3.5.9",
     "etcdcluster": "3.5.0"
   }

 Example etcd 3.4.x Response:
   {
     "etcdserver": "3.4.27",
     "etcdcluster": "3.4.0"
   }

Port Information:
  - Port 2379: Client communication port (default)
  - Port 2380: Peer communication port (cluster replication)

Version Compatibility Matrix:
  - etcd 3.x: Version endpoint returns etcdserver and etcdcluster
  - etcdserver: Server binary version (e.g., "3.5.9")
  - etcdcluster: Cluster API version (e.g., "3.5.0")
  - All 3.x versions: json["etcdserver"] field always present

False Positive Mitigation:
  - Require etcdserver field to be non-empty string
  - Validate version format with regex if present
  - Reject responses missing required JSON structure
  - Distinguish from generic HTTP servers and other key-value stores

CPE Format:
  - Vendor: etcd-io (GitHub organization)
  - Product: etcd
  - Version: Extracted from etcdserver field
  - Format: cpe:2.3:a:etcd-io:etcd:{version}:*:*:*:*:*:*:*
*/

package etcd

import (
	"encoding/json"
	"fmt"
	"net"
	"regexp"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const ETCD = "etcd"
const ETCDPEER = "etcd-peer"

type ETCDPlugin struct{}
type ETCDPeerPlugin struct{}

func init() {
	plugins.RegisterPlugin(&ETCDPlugin{})
	plugins.RegisterPlugin(&ETCDPeerPlugin{})
}

// etcdVersionResponse represents the JSON structure returned by GET /version
type etcdVersionResponse struct {
	ETCDServer  string `json:"etcdserver"`
	ETCDCluster string `json:"etcdcluster"`
}

// versionRegex validates etcd version format (X.Y.Z)
var versionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

// parseETCDResponse validates an etcd version endpoint response and extracts version information.
//
// Validation rules:
//   - json["etcdserver"] must be non-empty string
//   - Version must match X.Y.Z format if present
//
// Parameters:
//   - response: Raw HTTP response body (expected to be JSON)
//
// Returns:
//   - bool: true if etcd detected, false otherwise
//   - string: Server version string (empty if not found or detection failed)
//   - string: Cluster version string (empty if not found)
func parseETCDResponse(response []byte) (bool, string, string) {
	// Empty response check
	if len(response) == 0 {
		return false, "", ""
	}

	// Parse JSON
	var parsed etcdVersionResponse
	if err := json.Unmarshal(response, &parsed); err != nil {
		return false, "", ""
	}

	// Validate etcdserver marker (must be non-empty)
	if parsed.ETCDServer == "" {
		return false, "", ""
	}

	// Validate version format if present
	if parsed.ETCDServer != "" && !versionRegex.MatchString(parsed.ETCDServer) {
		return false, "", ""
	}

	// etcd detected! Extract versions
	return true, parsed.ETCDServer, parsed.ETCDCluster
}

// buildETCDCPE constructs a CPE (Common Platform Enumeration) string for etcd.
// CPE format: cpe:2.3:a:etcd-io:etcd:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to match other plugin
// behavior and enable asset inventory use cases.
//
// Parameters:
//   - version: etcd version string (e.g., "3.5.9"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" for unknown version
func buildETCDCPE(version string) string {
	// etcd product is always known when this is called, so always generate CPE
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:etcd-io:etcd:%s:*:*:*:*:*:*:*", version)
}

// buildETCDHTTPRequest constructs an HTTP/1.1 GET request for the specified path.
//
// Parameters:
//   - path: HTTP path (e.g., "/version")
//   - host: Target host:port (e.g., "localhost:2379")
//
// Returns:
//   - string: Complete HTTP request ready to send
func buildETCDHTTPRequest(path, host string) string {
	return fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: nerva/1.0\r\n"+
			"Accept: application/json\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		path, host)
}

// detectETCD performs etcd detection using HTTP REST API.
//
// Detection phases:
//  1. Send HTTP GET /version request
//  2. Receive and parse JSON response
//  3. Validate etcd markers (json["etcdserver"] non-empty)
//  4. Extract version from json["etcdserver"] field
//  5. Extract cluster version from json["etcdcluster"] field
//
// Parameters:
//   - conn: Network connection to the target service
//   - target: Target information for service creation
//   - timeout: Timeout duration for network operations
//   - portType: Type of port ("client" for 2379, "peer" for 2380)
//   - protocol: Protocol type (TCP or TCPTLS)
//
// Returns:
//   - *plugins.Service: Service information if etcd detected, nil otherwise
//   - error: Error details if detection failed
func detectETCD(conn net.Conn, target plugins.Target, timeout time.Duration, portType string, protocol plugins.Protocol) (*plugins.Service, error) {
	// Build host string for HTTP Host header
	host := fmt.Sprintf("%s:%d", target.Host, target.Address.Port())

	// Build HTTP GET /version request
	request := buildETCDHTTPRequest("/version", host)

	// Send request and receive response
	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return nil, err
	}

	// Empty response check
	if len(response) == 0 {
		return nil, nil
	}

	// HTTP responses typically have headers followed by blank line, then body
	// We need to extract just the JSON body part
	// Look for "\r\n\r\n" which separates headers from body
	bodyStart := 0
	for i := 0; i < len(response)-3; i++ {
		if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
			bodyStart = i + 4
			break
		}
	}

	// If we found the body separator, extract JSON body
	var jsonBody []byte
	if bodyStart > 0 && bodyStart < len(response) {
		jsonBody = response[bodyStart:]
	} else {
		// No HTTP headers found, treat entire response as JSON (edge case)
		jsonBody = response
	}

	// Parse etcd response
	detected, version, clusterVersion := parseETCDResponse(jsonBody)
	if !detected {
		return nil, nil
	}

	// Build service metadata
	cpe := buildETCDCPE(version)
	payload := plugins.ServiceEtcd{
		CPEs:           []string{cpe},
		ClusterVersion: clusterVersion,
		PortType:       portType,
	}

	return plugins.CreateServiceFrom(target, payload, protocol == plugins.TCPTLS, version, protocol), nil
}

// ETCDPlugin methods (port 2379 - client port)

func (p *ETCDPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectETCD(conn, target, timeout, "client", plugins.TCP)
}

func (p *ETCDPlugin) PortPriority(port uint16) bool {
	return port == 2379
}

func (p *ETCDPlugin) Name() string {
	return ETCD
}

func (p *ETCDPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *ETCDPlugin) Priority() int {
	return 100
}

// ETCDPeerPlugin methods (port 2380 - peer port)

func (p *ETCDPeerPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectETCD(conn, target, timeout, "peer", plugins.TCP)
}

func (p *ETCDPeerPlugin) PortPriority(port uint16) bool {
	return port == 2380
}

func (p *ETCDPeerPlugin) Name() string {
	return ETCDPEER
}

func (p *ETCDPeerPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *ETCDPeerPlugin) Priority() int {
	return 100
}
