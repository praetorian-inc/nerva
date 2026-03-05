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

package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// CockroachDBFingerprinter detects CockroachDB via /api/v2/nodes/ endpoint
type CockroachDBFingerprinter struct{}

// cockroachDBResponse represents the JSON response from /api/v2/nodes/ endpoint
type cockroachDBResponse struct {
	Nodes []cockroachDBNode `json:"nodes"`
}

// cockroachDBNode represents a node in the CockroachDB cluster
type cockroachDBNode struct {
	NodeID        int                      `json:"node_id"`
	ServerVersion cockroachDBServerVersion `json:"ServerVersion"`
	BuildTag      string                   `json:"build_tag"`
}

// cockroachDBServerVersion represents version information
type cockroachDBServerVersion struct {
	Major    int `json:"major"`
	Minor    int `json:"minor"`
	Patch    int `json:"patch"`
	Internal int `json:"internal"`
}

// versionRegex validates version format (X.Y.Z) to prevent CPE injection
// Only allows digits separated by dots
var cockroachDBVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&CockroachDBFingerprinter{})
}

func (f *CockroachDBFingerprinter) Name() string {
	return "cockroachdb"
}

func (f *CockroachDBFingerprinter) ProbeEndpoint() string {
	return "/api/v2/nodes/"
}

func (f *CockroachDBFingerprinter) Match(resp *http.Response) bool {
	// CockroachDB returns JSON at /api/v2/nodes/ endpoint
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func (f *CockroachDBFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Parse JSON response
	var cockroachResponse cockroachDBResponse
	if err := json.Unmarshal(body, &cockroachResponse); err != nil {
		return nil, nil // Not valid JSON or not CockroachDB format
	}

	// CockroachDB detection: nodes array must have at least one node
	if len(cockroachResponse.Nodes) == 0 {
		return nil, nil
	}

	// Extract version from first node
	firstNode := cockroachResponse.Nodes[0]
	buildTag := firstNode.BuildTag

	var version string
	if buildTag != "" {
		// Primary: Extract version from build_tag by stripping leading "v"
		version = strings.TrimPrefix(buildTag, "v")
	} else if firstNode.ServerVersion.Major > 0 {
		// Fallback: Construct version from ServerVersion struct
		version = fmt.Sprintf("%d.%d.%d",
			firstNode.ServerVersion.Major,
			firstNode.ServerVersion.Minor,
			firstNode.ServerVersion.Patch)
	} else {
		return nil, nil // No version information available
	}

	// Validate version format to prevent CPE injection
	if !cockroachDBVersionRegex.MatchString(version) {
		return nil, nil
	}

	// Build metadata
	metadata := map[string]any{
		"node_count":    len(cockroachResponse.Nodes),
		"raw_build_tag": buildTag,
	}

	return &FingerprintResult{
		Technology: "cockroachdb",
		Version:    version,
		CPEs:       []string{buildCockroachDBCPE(version)},
		Metadata:   metadata,
	}, nil
}

// buildCockroachDBCPE generates a CPE (Common Platform Enumeration) string for CockroachDB.
// CPE format: cpe:2.3:a:cockroachdb:cockroachdb:{version}:*:*:*:*:*:*:*
//
// When version is unknown, uses "*" for version field to enable asset inventory use cases.
func buildCockroachDBCPE(version string) string {
	// CockroachDB product is always known when this is called, so always generate CPE
	if version == "" {
		version = "*" // Unknown version, but known product
	}
	return fmt.Sprintf("cpe:2.3:a:cockroachdb:cockroachdb:%s:*:*:*:*:*:*:*", version)
}
