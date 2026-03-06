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
Package fingerprinters provides HTTP fingerprinting for Portainer.

# Detection Strategy

Portainer is a lightweight Docker management UI that provides a web interface
for managing Docker environments. Exposed instances represent a security concern
due to:
  - Full Docker environment management (containers, images, volumes, networks)
  - Credential and secret storage
  - Stack/compose deployment capabilities
  - Often exposed without strong authentication

Detection uses active probing:
  - Active: Query /api/system/status endpoint (no authentication required)
  - Response must contain both fields: Version and InstanceID

# API Response Format

The /api/system/status endpoint returns JSON without authentication:

	{
	  "Version": "2.21.0",
	  "InstanceID": "299ab403-70a8-4c05-92f7-bf7a994d50df"
	}

# Port Configuration

Portainer typically runs on:
  - 9000: Default HTTP port
  - 9443: Default HTTPS port
  - 8000: Edge agent server

# Example Usage

	fp := &PortainerFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s\n", result.Technology, result.Version)
		}
	}
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// PortainerFingerprinter detects Portainer instances via /api/system/status endpoint
type PortainerFingerprinter struct{}

// portainerStatusResponse represents the JSON structure from /api/system/status
type portainerStatusResponse struct {
	Version    string `json:"Version"`
	InstanceID string `json:"InstanceID"`
}

// portainerVersionRegex validates Portainer version format
// Accepts: 2.21.0, 2.19.4, 2.0.0
var portainerVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&PortainerFingerprinter{})
}

func (f *PortainerFingerprinter) Name() string {
	return "portainer"
}

func (f *PortainerFingerprinter) ProbeEndpoint() string {
	return "/api/system/status"
}

func (f *PortainerFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *PortainerFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var status portainerStatusResponse
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, nil
	}

	// Validate both required fields are present
	if status.Version == "" || status.InstanceID == "" {
		return nil, nil
	}

	// Validate version format to prevent CPE injection
	if !portainerVersionRegex.MatchString(status.Version) {
		return nil, nil
	}

	metadata := map[string]any{
		"instanceId": status.InstanceID,
	}

	return &FingerprintResult{
		Technology: "portainer",
		Version:    status.Version,
		CPEs:       []string{buildPortainerCPE(status.Version)},
		Metadata:   metadata,
	}, nil
}

func buildPortainerCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:portainer:portainer:%s:*:*:*:*:*:*:*", version)
}
