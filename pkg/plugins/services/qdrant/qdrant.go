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

package qdrant

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

/*
Qdrant Vector Database Fingerprinting

This plugin detects Qdrant vector database instances via HTTP REST API.

Qdrant is a vector similarity search engine used for:
- AI/ML embedding storage and retrieval
- Semantic search applications
- RAG (Retrieval Augmented Generation) pipelines

Security Risks:
- No authentication by default in self-hosted deployments
- Embedding data exposure can reveal sensitive training data
- AI system compromise via embedding manipulation

Detection Strategy:
  GET / HTTP/1.1
  Returns: {"title":"qdrant - vector search engine","version":"1.x.x"}

Default Port: 6333

CPE Format: cpe:2.3:a:qdrant:qdrant:{version}:*:*:*:*:*:*:*
*/

type QdrantPlugin struct{}

const QDRANT = "qdrant"

// qdrantVersionRegex validates version format to prevent CPE injection
// Allows: X.Y.Z or X.Y.Z-suffix (for pre-release versions like 1.7.4-beta)
var qdrantVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?$`)

// qdrantRootResponse represents the JSON response from Qdrant root endpoint
type qdrantRootResponse struct {
	Title   string `json:"title"`
	Version string `json:"version"`
}

func init() {
	plugins.RegisterPlugin(&QdrantPlugin{})
}

// DetectQdrant performs Qdrant fingerprinting via HTTP REST API.
func DetectQdrant(conn net.Conn, timeout time.Duration, target plugins.Target) (string, bool, error) {
	// Build URL using remote address from connection
	url := fmt.Sprintf("http://%s/", conn.RemoteAddr().String())

	// Create HTTP request
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", false, err
	}

	// Set Host header if target specifies one
	if target.Host != "" {
		req.Host = target.Host
	}

	// Set User-Agent header
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")

	// Create HTTP client with custom dialer to reuse the provided connection
	client := http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()

	// Read response body with limit
	maxResponseSize := int64(1 * 1024 * 1024) // 1MB limit
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	if err != nil {
		return "", false, err
	}

	// Try to parse JSON response
	var rootResp qdrantRootResponse
	if err := json.Unmarshal(body, &rootResp); err != nil {
		// Not valid JSON, try string matching
		bodyStr := string(body)
		if strings.Contains(strings.ToLower(bodyStr), "qdrant") {
			// Detected Qdrant but couldn't parse version
			version := extractVersionFromString(bodyStr)
			// Validate extracted version
			if version != "" && !qdrantVersionRegex.MatchString(version) {
				version = ""
			}
			return version, true, nil
		}
		return "", false, nil
	}

	// Check for Qdrant-specific response
	if strings.Contains(strings.ToLower(rootResp.Title), "qdrant") {
		version := rootResp.Version
		// Validate version format to prevent CPE injection
		if version != "" && !qdrantVersionRegex.MatchString(version) {
			version = "" // Invalid format, don't use in CPE
		}
		return version, true, nil
	}

	return "", false, nil
}

// extractVersionFromString extracts version from response string using regex
func extractVersionFromString(body string) string {
	versionRegex := regexp.MustCompile(`"version"\s*:\s*"v?([0-9]+\.[0-9]+\.[0-9]+(?:-[a-zA-Z0-9.]+)?)"`)
	matches := versionRegex.FindStringSubmatch(body)
	if len(matches) >= 2 {
		return strings.TrimPrefix(matches[1], "v")
	}
	return ""
}

// buildQdrantCPE constructs a CPE string for Qdrant.
// CPE format: cpe:2.3:a:qdrant:qdrant:{version}:*:*:*:*:*:*:*
func buildQdrantCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:qdrant:qdrant:%s:*:*:*:*:*:*:*", version)
}

func (p *QdrantPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	version, detected, err := DetectQdrant(conn, timeout, target)
	if !detected {
		return nil, err
	}

	// Qdrant detected - create service payload
	payload := plugins.ServiceQdrant{}
	cpe := buildQdrantCPE(version)
	payload.CPEs = []string{cpe}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *QdrantPlugin) PortPriority(port uint16) bool {
	return port == 6333
}

func (p *QdrantPlugin) Name() string {
	return QDRANT
}

func (p *QdrantPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *QdrantPlugin) Priority() int {
	return 50 // Run before generic HTTP (100)
}
