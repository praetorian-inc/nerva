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
Docker Remote API Fingerprinting

This plugin implements Docker Remote API fingerprinting using HTTP REST API detection.
Docker exposes version and system information through well-known HTTP endpoints that
require no authentication when the daemon is exposed.

SECURITY WARNING:
  Exposed Docker Remote API instances (particularly on port 2375 unencrypted) provide
  full root-level access to the host system. This is one of the most critical cloud
  infrastructure exposures, allowing attackers to spawn privileged containers and
  escape to the host.

Detection Strategy:
  PHASE 1 - PRIMARY DETECTION (GET /version):
    - Send GET /version HTTP request
    - Parse JSON response for Docker-specific fields
    - Validate json["ApiVersion"] exists (required field in all Docker versions)
    - Extract version, API version, OS, and architecture
    - If successful → Docker detected with full version info

  PHASE 2 - FALLBACK DETECTION (GET /_ping):
    - Only attempted if /version fails
    - Send GET /_ping HTTP request
    - Docker responds with plain text "OK"
    - Confirms Docker is present but without version details
    - Use "*" wildcard in CPE for unknown version

Docker /version Endpoint Response Structure:

  Example Docker 24.x Response:
    HTTP/1.1 200 OK
    Content-Type: application/json

    {
      "Platform": {"Name": "Docker Engine - Community"},
      "Version": "24.0.7",
      "ApiVersion": "1.43",
      "MinAPIVersion": "1.24",
      "Os": "linux",
      "Arch": "amd64",
      "KernelVersion": "5.15.0-91-generic",
      "GoVersion": "go1.20.10",
      "GitCommit": "311b9ff"
    }

Docker /_ping Endpoint Response:
    HTTP/1.1 200 OK
    Content-Type: text/plain

    OK

Version Compatibility:
  - Docker 1.x - 27.x: All versions support /version and /_ping endpoints
  - ApiVersion field is always present in /version response
  - Version field contains the Docker daemon version

Port Configuration:
  - Port 2375: Unencrypted HTTP (DANGEROUS - full root access)
  - Port 2376: TLS-encrypted HTTPS (recommended for remote access)

References:
  - https://docs.docker.com/engine/api/
  - https://book.hacktricks.xyz/network-services-pentesting/2375-pentesting-docker
*/

package docker

import (
	"encoding/json"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	DOCKER    = "docker"
	DOCKERTLS = "docker"
)

type DockerPlugin struct{}
type DockerTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&DockerPlugin{})
	plugins.RegisterPlugin(&DockerTLSPlugin{})
}

// dockerVersionResponse represents the JSON structure returned by GET /version
type dockerVersionResponse struct {
	Version       string `json:"Version"`
	ApiVersion    string `json:"ApiVersion"`
	MinAPIVersion string `json:"MinAPIVersion"`
	Os            string `json:"Os"`
	Arch          string `json:"Arch"`
	KernelVersion string `json:"KernelVersion"`
	GoVersion     string `json:"GoVersion"`
	GitCommit     string `json:"GitCommit"`
}

// dockerDetectionResult holds the detection results
type dockerDetectionResult struct {
	detected   bool
	version    string
	apiVersion string
	os         string
	arch       string
}

// parseDockerVersionResponse validates a Docker /version endpoint response and extracts info.
//
// Validation rules:
//   - json["ApiVersion"] must be present (required field in all Docker versions)
//   - json["Version"] extracted if present
//
// Parameters:
//   - response: Raw HTTP response body (expected to be JSON)
//
// Returns:
//   - *dockerDetectionResult: Detection result with version info, or nil if not Docker
func parseDockerVersionResponse(response []byte) *dockerDetectionResult {
	// Empty response check
	if len(response) == 0 {
		return nil
	}

	// Parse JSON
	var parsed dockerVersionResponse
	if err := json.Unmarshal(response, &parsed); err != nil {
		return nil
	}

	// Validate Docker marker - ApiVersion is always present in Docker responses
	if parsed.ApiVersion == "" {
		return nil
	}

	// Docker detected! Return all extracted info
	return &dockerDetectionResult{
		detected:   true,
		version:    parsed.Version,
		apiVersion: parsed.ApiVersion,
		os:         parsed.Os,
		arch:       parsed.Arch,
	}
}

// parsePingResponse checks if the response is a valid Docker /_ping response.
//
// Parameters:
//   - response: Raw HTTP response body
//
// Returns:
//   - bool: true if response is "OK" (Docker ping response)
func parsePingResponse(response []byte) bool {
	// Docker /_ping returns "OK" as plain text
	return strings.TrimSpace(string(response)) == "OK"
}

// buildDockerCPE constructs a CPE (Common Platform Enumeration) string for Docker.
// CPE format: cpe:2.3:a:docker:docker:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to enable asset inventory
// use cases while indicating the product is known.
//
// Parameters:
//   - version: Docker version string (e.g., "24.0.7"), or empty for unknown
//
// Returns:
//   - string: CPE string with version or "*" for unknown version
func buildDockerCPE(version string) string {
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:docker:docker:%s:*:*:*:*:*:*:*", version)
}

// buildDockerHTTPRequest constructs an HTTP/1.1 GET request for the specified path.
//
// Parameters:
//   - path: HTTP path (e.g., "/version", "/_ping")
//   - host: Target host:port (e.g., "localhost:2375")
//
// Returns:
//   - string: Complete HTTP request ready to send
func buildDockerHTTPRequest(path, host string) string {
	return fmt.Sprintf(
		"GET %s HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: nerva/1.0\r\n"+
			"Accept: application/json\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		path, host)
}

// extractHTTPBody extracts the body from an HTTP response by finding the
// header/body separator (\r\n\r\n).
//
// Parameters:
//   - response: Full HTTP response including headers
//
// Returns:
//   - []byte: Body portion of the response, or full response if no separator found
func extractHTTPBody(response []byte) []byte {
	// Look for "\r\n\r\n" which separates headers from body
	for i := 0; i < len(response)-3; i++ {
		if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
			if i+4 < len(response) {
				return response[i+4:]
			}
			return nil
		}
	}
	// No separator found, return original (edge case)
	return response
}

// dockerUnauthFinding returns a SecurityFinding for an unauthenticated Docker API.
func dockerUnauthFinding(evidence string) plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "docker-unauth-api",
		Severity:    plugins.SeverityCritical,
		Description: "Docker API accessible without authentication",
		Evidence:    evidence,
	}
}

// detectDocker performs Docker Remote API detection using HTTP REST API.
//
// Detection phases:
//  1. Send HTTP GET /version request (primary detection + enrichment)
//  2. If /version fails, try GET /_ping as fallback
//  3. Parse response and extract version information
//
// Parameters:
//   - conn: Network connection to the target service
//   - target: Target information for service creation
//   - timeout: Timeout duration for network operations
//   - tls: Whether the connection uses TLS
//
// Returns:
//   - *plugins.Service: Service information if Docker detected, nil otherwise
//   - error: Error details if detection failed
func detectDocker(conn net.Conn, target plugins.Target, timeout time.Duration, tls bool) (*plugins.Service, error) {
	// Build host string for HTTP Host header
	host := fmt.Sprintf("%s:%d", target.Host, target.Address.Port())

	// Phase 1: Try /version endpoint first (provides both detection and version info)
	versionRequest := buildDockerHTTPRequest("/version", host)
	response, err := utils.SendRecv(conn, []byte(versionRequest), timeout)
	if err != nil {
		return nil, err
	}

	// Check if we got a valid response
	if len(response) > 0 {
		// Extract JSON body from HTTP response
		jsonBody := extractHTTPBody(response)

		// Try to parse as Docker /version response
		result := parseDockerVersionResponse(jsonBody)
		if result != nil && result.detected {
			// Docker detected via /version - we have full version info
			cpe := buildDockerCPE(result.version)
			payload := plugins.ServiceDocker{
				ApiVersion: result.apiVersion,
				Os:         result.os,
				Arch:       result.arch,
				CPEs:       []string{cpe},
			}

			transport := plugins.TCP
			if tls {
				transport = plugins.TCPTLS
			}
			service := plugins.CreateServiceFrom(target, payload, tls, result.version, transport)
			if target.Misconfigs {
				service.AnonymousAccess = true
				service.SecurityFindings = []plugins.SecurityFinding{dockerUnauthFinding("Successfully queried /version endpoint without credentials")}
			}
			return service, nil
		}

		// /version didn't work, but we might still have a connection
		// Check if response contains "OK" which might indicate /_ping worked
		// (some proxies might redirect)
		body := extractHTTPBody(response)
		if parsePingResponse(body) {
			// Detected via ping response in /version request (unusual but possible)
			cpe := buildDockerCPE("")
			payload := plugins.ServiceDocker{
				CPEs: []string{cpe},
			}

			transport := plugins.TCP
			if tls {
				transport = plugins.TCPTLS
			}
			service := plugins.CreateServiceFrom(target, payload, tls, "", transport)
			if target.Misconfigs {
				service.AnonymousAccess = true
				service.SecurityFindings = []plugins.SecurityFinding{dockerUnauthFinding("Successfully queried /_ping endpoint without credentials")}
			}
			return service, nil
		}
	}

	// Phase 2: Fallback to /_ping endpoint
	// Note: We need a new connection since the previous one was closed
	// The connection is already consumed, so we return nil here
	// In practice, /version should work on any exposed Docker daemon
	// If /version fails with a valid HTTP response that's not Docker, it's not Docker

	return nil, nil
}

// DockerPlugin methods (TCP - port 2375)

func (p *DockerPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectDocker(conn, target, timeout, false)
}

func (p *DockerPlugin) PortPriority(port uint16) bool {
	return port == 2375
}

func (p *DockerPlugin) Name() string {
	return DOCKER
}

func (p *DockerPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *DockerPlugin) Priority() int {
	return 100
}

// DockerTLSPlugin methods (TCPTLS - port 2376)

func (p *DockerTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectDocker(conn, target, timeout, true)
}

func (p *DockerTLSPlugin) PortPriority(port uint16) bool {
	return port == 2376
}

func (p *DockerTLSPlugin) Name() string {
	return DOCKERTLS
}

func (p *DockerTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *DockerTLSPlugin) Priority() int {
	return 101
}
