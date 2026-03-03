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
Package fingerprinters provides HTTP fingerprinting for TiDB.

# Detection Strategy

TiDB is a MySQL-compatible distributed SQL database. Exposed instances
represent a security concern due to:
  - Database access with potentially sensitive data
  - Management interface exposure
  - Version disclosure
  - Often exposed without proper authentication

Detection uses active probing:
  - Active: Query /status endpoint (no authentication required)
  - Response must contain version with "TiDB" marker

# API Response Format

The /status endpoint returns JSON without authentication:

	{
	  "connections": 0,
	  "version": "8.0.11-TiDB-v7.5.1",
	  "git_hash": "7d16cc79e81bbf573124df3fd9351c26963f3e70"
	}

# Port Configuration

TiDB typically runs on:
  - 10080: Default TiDB Status API port
  - 4000:  TiDB SQL port
  - 443:   HTTPS in production

# Example Usage

	fp := &TiDBFingerprinter{}
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

// TiDBFingerprinter detects TiDB instances via /status endpoint
type TiDBFingerprinter struct{}

// tidbStatusResponse represents the JSON structure from /status
type tidbStatusResponse struct {
	Connections int    `json:"connections"`
	Version     string `json:"version"`
	GitHash     string `json:"git_hash"`
}

// tidbVersionFormatRegex validates the full version string format
// Expected: "X.Y.Z-TiDB-vA.B.C" or "X.Y.Z-TiDB-vA.B.C-suffix"
var tidbVersionFormatRegex = regexp.MustCompile(`^\d+\.\d+\.\d+-TiDB-v\d+\.\d+\.\d+(?:-[a-zA-Z0-9._-]+)?$`)

// tidbVersionRegex extracts the TiDB version from the full version string
// Example: "8.0.11-TiDB-v7.5.1" -> "v7.5.1"
// Accepts: v7.5.1 (standard), v7.5.1-alpha (pre-release)
var tidbVersionRegex = regexp.MustCompile(`-TiDB-(v\d+\.\d+\.\d+(?:-[a-zA-Z0-9._-]+)?)`)

func init() {
	Register(&TiDBFingerprinter{})
}

func (f *TiDBFingerprinter) Name() string {
	return "tidb"
}

func (f *TiDBFingerprinter) ProbeEndpoint() string {
	return "/status"
}

func (f *TiDBFingerprinter) Match(resp *http.Response) bool {
	// Check for application/json Content-Type header
	// This is present on TiDB API responses but not unique to TiDB
	// Use as weak pre-filter before active probe
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *TiDBFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Try to parse as TiDB status response
	var status tidbStatusResponse
	if err := json.Unmarshal(body, &status); err != nil {
		return nil, nil // Not TiDB format
	}

	// Validate version contains "TiDB" marker
	if !strings.Contains(status.Version, "TiDB") {
		return nil, nil
	}

	// Validate git_hash is present
	if status.GitHash == "" {
		return nil, nil
	}

	// Validate full version format to prevent CPE injection
	if !tidbVersionFormatRegex.MatchString(status.Version) {
		return nil, nil
	}

	// Extract TiDB version from the full version string
	matches := tidbVersionRegex.FindStringSubmatch(status.Version)
	if len(matches) < 2 {
		return nil, nil // Version format doesn't match expected pattern
	}
	tidbVersion := matches[1]

	// Build metadata
	metadata := map[string]any{
		"connections": status.Connections,
		"git_hash":    status.GitHash,
	}

	return &FingerprintResult{
		Technology: "tidb",
		Version:    tidbVersion,
		CPEs:       []string{buildTiDBCPE(tidbVersion)},
		Metadata:   metadata,
	}, nil
}

func buildTiDBCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:pingcap:tidb:%s:*:*:*:*:*:*:*", version)
}
