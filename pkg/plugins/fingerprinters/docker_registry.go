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
Package fingerprinters provides HTTP fingerprinting for Docker Registry v2.

# Detection Strategy

Docker Registry v2 exposes an unauthenticated ping endpoint at /v2/ that
returns the Docker-Distribution-Api-Version header on all responses (including
401 Unauthorized when auth is configured). An instance with anonymous access
returns 200 OK.

Detection uses active probing:
  - Active: probe /v2/ endpoint
  - Match: Docker-Distribution-Api-Version header contains "registry/2.0"

# Misconfig Check

When anonymous access is confirmed (200 from /v2/), probe /v2/_catalog to
detect unauthenticated repository enumeration.

# Port Configuration

Docker Registry typically runs on:
  - 5000: Default HTTP port
  - 443:  HTTPS in production
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

var dockerRegistryVersionRegex = regexp.MustCompile(`^\d+\.\d+$`)

// DockerRegistryFingerprinter detects Docker Registry v2 instances via /v2/ endpoint.
type DockerRegistryFingerprinter struct{}

// dockerCatalogResponse represents the JSON structure from /v2/_catalog
type dockerCatalogResponse struct {
	Repositories []string `json:"repositories"`
}

func init() {
	Register(&DockerRegistryFingerprinter{})
}

func (f *DockerRegistryFingerprinter) Name() string {
	return "docker-registry"
}

// ProbeEndpoint returns the endpoint needed for Docker Registry detection.
func (f *DockerRegistryFingerprinter) ProbeEndpoint() string {
	return "/v2/"
}

// Match returns true if the response contains the Docker Distribution API Version header.
func (f *DockerRegistryFingerprinter) Match(resp *http.Response) bool {
	apiVersion := resp.Header.Get("Docker-Distribution-Api-Version")
	return strings.Contains(strings.ToLower(apiVersion), "registry/2.0")
}

// Fingerprint detects Docker Registry v2 and extracts the version.
func (f *DockerRegistryFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	apiVersion := resp.Header.Get("Docker-Distribution-Api-Version")
	if !strings.Contains(strings.ToLower(apiVersion), "registry/2.0") {
		return nil, nil
	}

	// Extract version from the header value (e.g., "registry/2.0" → "2.0")
	version := "*"
	if parts := strings.SplitN(apiVersion, "/", 2); len(parts) == 2 && parts[1] != "" {
		if dockerRegistryVersionRegex.MatchString(parts[1]) {
			version = parts[1]
		}
	}

	metadata := map[string]any{
		"api_version": apiVersion,
	}

	return &FingerprintResult{
		Technology: "docker-registry",
		Version:    version,
		CPEs:       []string{buildDockerRegistryCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityCritical,
	}, nil
}

// CheckMisconfigs probes /v2/_catalog to detect unauthenticated repository enumeration.
func (f *DockerRegistryFingerprinter) CheckMisconfigs(client *http.Client, baseURL, host string) []plugins.SecurityFinding {
	req, err := http.NewRequest("GET", baseURL+"/v2/_catalog", nil)
	if err != nil {
		return nil
	}
	if host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil
	}

	var catalog dockerCatalogResponse
	if err := json.Unmarshal(body, &catalog); err != nil {
		return nil
	}

	// Only report if the response contains the "repositories" field
	if catalog.Repositories == nil {
		return nil
	}

	return []plugins.SecurityFinding{{
		ID:          "docker-registry-unauthenticated-catalog",
		Severity:    plugins.SeverityCritical,
		Description: "Docker Registry accessible without authentication — repository catalog exposed",
		Evidence:    "GET /v2/_catalog returned 200 with repositories field",
	}}
}

func buildDockerRegistryCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:docker:registry:%s:*:*:*:*:*:*:*", version)
}
