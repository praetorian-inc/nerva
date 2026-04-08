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
Package fingerprinters provides HTTP fingerprinting for Grafana.

# Detection Strategy

Grafana is an open-source analytics and monitoring platform. Exposed instances
represent a security concern due to:
  - Dashboard access with potentially sensitive data
  - Data source configurations with credentials
  - API key management
  - Often exposed without authentication

Detection uses active probing:
  - Active: Query /api/health endpoint (no authentication required)
  - Response must contain all three fields: database, version, commit

# API Response Format

The /api/health endpoint returns JSON without authentication:

	{
	  "commit": "abc123def456",
	  "database": "ok",
	  "version": "10.4.1"
	}

# Port Configuration

Grafana typically runs on:
  - 3000: Default Grafana HTTP port
  - 443:  HTTPS in production

# Example Usage

	fp := &GrafanaFingerprinter{}
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

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// GrafanaFingerprinter detects Grafana instances via /api/health endpoint
type GrafanaFingerprinter struct{}

// grafanaHealthResponse represents the JSON structure from /api/health
type grafanaHealthResponse struct {
	Database string `json:"database"`
	Version  string `json:"version"`
	Commit   string `json:"commit"`
}

// grafanaVersionRegex validates Grafana version format
// Accepts: 10.4.1 (standard), 12.3.2+security-01 (security patch)
var grafanaVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(\+[a-zA-Z0-9._-]+)?$`)

func init() {
	Register(&GrafanaFingerprinter{})
}

func (f *GrafanaFingerprinter) Name() string {
	return "grafana"
}

func (f *GrafanaFingerprinter) ProbeEndpoint() string {
	return "/api/health"
}

func (f *GrafanaFingerprinter) Match(resp *http.Response) bool {
	// Check for application/json Content-Type header
	// This is present on Grafana API responses but not unique to Grafana
	// Use as weak pre-filter before active probe
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *GrafanaFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Try to parse as Grafana health response
	var health grafanaHealthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		return nil, nil // Not Grafana format
	}

	// Validate it's actually Grafana by checking all three required fields
	// Grafana health endpoint always returns database, version, and commit
	if health.Database == "" || health.Version == "" || health.Commit == "" {
		return nil, nil
	}

	// Validate version format to prevent CPE injection
	if !grafanaVersionRegex.MatchString(health.Version) {
		return nil, nil
	}

	// Build metadata
	metadata := map[string]any{
		"commit":   health.Commit,
		"database": health.Database,
	}

	return &FingerprintResult{
		Technology: "grafana",
		Version:    health.Version,
		CPEs:       []string{buildGrafanaCPE(health.Version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityMedium,
	}, nil
}

func buildGrafanaCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:grafana:grafana:%s:*:*:*:*:*:*:*", version)
}
