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
CUPS (Common Unix Printing System) Fingerprinting

This plugin implements CUPS fingerprinting using HTTP detection.
Note: This does NOT implement IPP (Internet Printing Protocol) binary probing.
CUPS exposes its version through the Server header in HTTP responses,
making detection straightforward via a simple GET / request.

Detection Strategy:
  PHASE 1 - HTTP GET / REQUEST:
    - Send HTTP/1.1 GET / request to port 631
    - Parse HTTP response headers for "Server" header
    - Check if Server header contains "CUPS" (case-insensitive)
    - Extract version from "CUPS/X.Y.Z" pattern using regex
    - Generate CPE: cpe:2.3:a:apple:cups:{version}:*:*:*:*:*:*:*
    - If CUPS detected → return service with version info

CUPS HTTP Response Example:
    HTTP/1.1 200 OK
    Content-Language: en
    Content-Type: text/html; charset=UTF-8
    Server: CUPS/2.3.1 IPP/2.1
    X-Frame-Options: DENY
    Content-Security-Policy: frame-ancestors 'none'
    ...

Version Patterns Observed:
  - "CUPS/2.3.1" (simple)
  - "CUPS/2.4.2 IPP/2.1" (with IPP version)
  - "CUPS/2.4.2-163+eb63a8052" (Debian packaging suffix)

Port Configuration:
  - Port 631: Standard CUPS HTTP/IPP port (unencrypted)
  - Port 631: Standard CUPS HTTPS/IPP-over-TLS port (encrypted)

References:
  - https://openprinting.github.io/cups/
  - https://www.cups.org/
*/

package cups

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const defaultPort uint16 = 631

// cupsVersionRegex matches "CUPS/X.Y" or "CUPS/X.Y.Z" versions,
// ignoring any packaging suffixes like "-163+eb63a8052".
var cupsVersionRegex = regexp.MustCompile(`(?i)CUPS/(\d+\.\d+(?:\.\d+)?)`)

type CUPSPlugin struct{}
type CUPSTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&CUPSPlugin{})
	plugins.RegisterPlugin(&CUPSTLSPlugin{})
}

// buildCUPSHTTPRequest constructs an HTTP/1.1 GET request for the root path.
//
// Parameters:
//   - host: Target host:port (e.g., "192.168.1.10:631")
//
// Returns:
//   - string: Complete HTTP request ready to send over net.Conn
func buildCUPSHTTPRequest(host string) string {
	return fmt.Sprintf(
		"GET / HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: nerva/1.0\r\n"+
			"Accept: */*\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		host)
}

// extractServerHeader parses the raw HTTP response bytes and returns the value
// of the "Server" header, or an empty string if not found.
//
// Parameters:
//   - response: Raw HTTP response bytes (headers + optional body)
//
// Returns:
//   - string: Value of the Server header, or "" if absent
func extractServerHeader(response []byte) string {
	// Split on lines; headers end at blank line
	text := string(response)
	lines := strings.Split(text, "\r\n")
	for _, line := range lines {
		// Blank line signals end of headers
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "server:") {
			// Return the value after "Server: "
			return strings.TrimSpace(line[len("server:"):])
		}
	}
	return ""
}

// parseCUPSVersion extracts the numeric version from a Server header value.
// It matches "CUPS/X.Y" or "CUPS/X.Y.Z", ignoring packaging suffixes.
//
// Parameters:
//   - serverHeader: Value of the Server HTTP header (e.g., "CUPS/2.3.1 IPP/2.1")
//
// Returns:
//   - string: Version string (e.g., "2.3.1"), or "" if not a CUPS header
func parseCUPSVersion(serverHeader string) string {
	matches := cupsVersionRegex.FindStringSubmatch(serverHeader)
	if len(matches) < 2 {
		return ""
	}
	return matches[1]
}

// buildCUPSCPE constructs a CPE (Common Platform Enumeration) string for CUPS.
// CPE format: cpe:2.3:a:apple:cups:{version}:*:*:*:*:*:*:*
//
// Parameters:
//   - version: CUPS version string (e.g., "2.3.1"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" for unknown version
func buildCUPSCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:apple:cups:%s:*:*:*:*:*:*:*", version)
}

// detectCUPS performs CUPS detection by sending an HTTP GET / request and
// inspecting the Server response header for the "CUPS" identifier.
//
// Parameters:
//   - conn: Network connection to the target service
//   - target: Target information for service creation
//   - timeout: Timeout duration for network operations
//   - tls: Whether the connection uses TLS
//
// Returns:
//   - *plugins.Service: Service information if CUPS detected, nil otherwise
//   - error: Error details if detection failed at the network level
func detectCUPS(conn net.Conn, target plugins.Target, timeout time.Duration, tls bool) (*plugins.Service, error) {
	host := target.Host
	if host == "" {
		host = target.Address.Addr().String()
	}
	host = fmt.Sprintf("%s:%d", host, target.Address.Port())

	request := buildCUPSHTTPRequest(host)
	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, nil
	}

	serverHeader := extractServerHeader(response)
	if !strings.Contains(strings.ToLower(serverHeader), "cups") {
		return nil, nil
	}

	version := parseCUPSVersion(serverHeader)
	cpe := buildCUPSCPE(version)

	payload := plugins.ServiceCUPS{
		ServerHeader: serverHeader,
		CPEs:         []string{cpe},
	}

	transport := plugins.TCP
	if tls {
		transport = plugins.TCPTLS
	}

	return plugins.CreateServiceFrom(target, payload, tls, version, transport), nil
}

// CUPSPlugin methods (TCP - port 631)

func (p *CUPSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectCUPS(conn, target, timeout, false)
}

func (p *CUPSPlugin) PortPriority(port uint16) bool {
	return port == defaultPort
}

func (p *CUPSPlugin) Name() string {
	return plugins.ProtoCUPS
}

func (p *CUPSPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *CUPSPlugin) Priority() int {
	return 100
}

// CUPSTLSPlugin methods (TCPTLS - port 631)

func (p *CUPSTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectCUPS(conn, target, timeout, true)
}

func (p *CUPSTLSPlugin) PortPriority(port uint16) bool {
	return port == defaultPort
}

func (p *CUPSTLSPlugin) Name() string {
	return plugins.ProtoCUPS
}

func (p *CUPSTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *CUPSTLSPlugin) Priority() int {
	return 101
}
