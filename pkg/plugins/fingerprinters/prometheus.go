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
Package fingerprinters provides HTTP fingerprinting for Prometheus.

# Detection Strategy

Prometheus is a widely deployed monitoring and alerting system. Exposed instances
represent a security concern due to:
  - Access to infrastructure metrics and monitoring data
  - Potential information disclosure about system architecture
  - Query capabilities that could reveal sensitive information
  - Administrative endpoints that may be exposed

Detection uses a two-pronged approach:
1. Passive: Check for Content-Type: application/json header (weak pre-filter)
2. Active: Query /api/v1/status/buildinfo endpoint (no authentication required)

# API Response Format

The /api/v1/status/buildinfo endpoint returns JSON without authentication:

	{
	  "status": "success",
	  "data": {
	    "version": "2.45.0",
	    "revision": "abc123def456",
	    "branch": "HEAD",
	    "buildUser": "root@buildhost",
	    "buildDate": "20231215-08:42:32",
	    "goVersion": "go1.21.5"
	  }
	}

Format breakdown:
  - status: API response status (required, must be "success")
  - data: Build information object (required)
  - data.version: Prometheus version string (required for detection)
  - data.goVersion: Go version used to build (required, distinguishes from other APIs)
  - data.revision: Git commit hash (optional)
  - data.branch: Git branch (optional)
  - data.buildUser: User who built the binary (optional)
  - data.buildDate: Build timestamp (optional)

# Port Configuration

Prometheus typically runs on:
  - 9090: Default Prometheus HTTP API port
  - 443:  HTTPS in production deployments

# Example Usage

	fp := &PrometheusFingerprinter{}
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

// PrometheusFingerprinter detects Prometheus instances via /api/v1/status/buildinfo endpoint
type PrometheusFingerprinter struct{}

// prometheusBuildInfoResponse represents the JSON structure from /api/v1/status/buildinfo
type prometheusBuildInfoResponse struct {
	Status string                  `json:"status"`
	Data   prometheusBuildInfoData `json:"data"`
}

// prometheusBuildInfoData represents the nested data object
type prometheusBuildInfoData struct {
	Version   string `json:"version"`
	Revision  string `json:"revision"`
	Branch    string `json:"branch"`
	BuildUser string `json:"buildUser"`
	BuildDate string `json:"buildDate"`
	GoVersion string `json:"goVersion"`
}

// prometheusVersionRegex validates Prometheus version format
// Accepts: 2.45.0, 2.37.0, 2.50.0-rc.0, etc.
var prometheusVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(-[a-zA-Z0-9._-]+)?$`)

func init() {
	Register(&PrometheusFingerprinter{})
}

func (f *PrometheusFingerprinter) Name() string {
	return "prometheus"
}

func (f *PrometheusFingerprinter) ProbeEndpoint() string {
	return "/api/v1/status/buildinfo"
}

func (f *PrometheusFingerprinter) Match(resp *http.Response) bool {
	// Check for Content-Type: application/json header
	// This is present on all Prometheus API responses but not unique to Prometheus
	// Use as weak pre-filter before active probe
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *PrometheusFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Try to parse as Prometheus buildinfo response
	var buildInfo prometheusBuildInfoResponse
	if err := json.Unmarshal(body, &buildInfo); err != nil {
		return nil, nil // Not Prometheus format
	}

	// Validate it's actually Prometheus by checking required fields
	// Prometheus buildinfo always returns status=success, version, and goVersion
	if buildInfo.Status != "success" {
		return nil, nil
	}

	if buildInfo.Data.Version == "" || buildInfo.Data.GoVersion == "" {
		return nil, nil
	}

	// Validate version format to prevent CPE injection
	if !prometheusVersionRegex.MatchString(buildInfo.Data.Version) {
		return nil, nil
	}

	// Build metadata
	metadata := map[string]any{}

	// Add optional fields if present
	if buildInfo.Data.Revision != "" {
		metadata["revision"] = buildInfo.Data.Revision
	}
	if buildInfo.Data.Branch != "" {
		metadata["branch"] = buildInfo.Data.Branch
	}
	if buildInfo.Data.BuildDate != "" {
		metadata["build_date"] = buildInfo.Data.BuildDate
	}
	if buildInfo.Data.GoVersion != "" {
		metadata["go_version"] = buildInfo.Data.GoVersion
	}
	if buildInfo.Data.BuildUser != "" {
		metadata["build_user"] = buildInfo.Data.BuildUser
	}

	return &FingerprintResult{
		Technology: "prometheus",
		Version:    buildInfo.Data.Version,
		CPEs:       []string{buildPrometheusCPE(buildInfo.Data.Version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityLow,
	}, nil
}

func buildPrometheusCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:prometheus:prometheus:%s:*:*:*:*:*:*:*", version)
}
