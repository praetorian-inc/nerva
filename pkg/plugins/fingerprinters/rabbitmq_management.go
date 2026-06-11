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
Package fingerprinters provides HTTP fingerprinting for RabbitMQ Management.

Detection Strategy:
  - Active probe: /api/overview endpoint
  - Path 1 (JSON): 200 response with application/json content-type; parse
    rabbitmq_version, erlang_version, cluster_name, management_version fields
  - Path 2 (Auth Challenge): 401 response with WWW-Authenticate header
    containing realm="RabbitMQ Management" (case-insensitive)
  - Ports: 15672 (HTTP), 15671 (HTTPS)
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// RabbitMQManagementFingerprinter detects RabbitMQ Management via /api/overview
type RabbitMQManagementFingerprinter struct{}

type rabbitmqOverviewResponse struct {
	RabbitMQVersion   string `json:"rabbitmq_version"`
	ErlangVersion     string `json:"erlang_version"`
	ClusterName       string `json:"cluster_name"`
	ManagementVersion string `json:"management_version"`
}

var (
	rabbitmqVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)
	rabbitmqRealmRegex   = regexp.MustCompile(`(?i)realm="RabbitMQ Management"`)
)

func init() {
	Register(&RabbitMQManagementFingerprinter{})
}

func (f *RabbitMQManagementFingerprinter) Name() string {
	return "rabbitmq-management"
}

func (f *RabbitMQManagementFingerprinter) ProbeEndpoint() string {
	return "/api/overview"
}

// Match returns true when the response could be from RabbitMQ Management.
// Accepts 200 responses with application/json content-type (JSON path) or
// 401 responses with a WWW-Authenticate realm matching RabbitMQ Management
// (auth challenge path). Rejects status codes below 200 or 500 and above.
func (f *RabbitMQManagementFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	if resp.StatusCode == http.StatusOK {
		return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
	}

	if resp.StatusCode == http.StatusUnauthorized {
		return rabbitmqRealmRegex.MatchString(resp.Header.Get("WWW-Authenticate"))
	}

	return false
}

// Fingerprint performs RabbitMQ Management detection.
// For 200 JSON responses it delegates to fingerprintJSON; for 401 responses
// it delegates to fingerprintAuthChallenge.
func (f *RabbitMQManagementFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode == http.StatusOK {
		return fingerprintJSON(body)
	}
	return fingerprintAuthChallenge(resp), nil
}

// fingerprintJSON parses the /api/overview JSON response and extracts version
// metadata. Returns nil, nil when the required rabbitmq_version field is absent.
func fingerprintJSON(body []byte) (*FingerprintResult, error) {
	var overview rabbitmqOverviewResponse
	if err := json.Unmarshal(body, &overview); err != nil {
		return nil, nil
	}

	if overview.RabbitMQVersion == "" {
		return nil, nil
	}

	version := overview.RabbitMQVersion
	if !rabbitmqVersionRegex.MatchString(version) {
		version = "*"
	}

	metadata := map[string]any{
		"rabbitmq_version": overview.RabbitMQVersion,
	}
	if overview.ErlangVersion != "" {
		metadata["erlang_version"] = overview.ErlangVersion
	}
	if overview.ClusterName != "" {
		metadata["cluster_name"] = overview.ClusterName
	}
	if overview.ManagementVersion != "" {
		metadata["management_version"] = overview.ManagementVersion
	}

	return &FingerprintResult{
		Technology: "rabbitmq-management",
		Version:    version,
		CPEs:       []string{buildRabbitMQCPE(version)},
		Metadata:   metadata,
	}, nil
}

// fingerprintAuthChallenge handles 401 responses where the WWW-Authenticate
// header confirms RabbitMQ Management. Version is unknown in this path.
func fingerprintAuthChallenge(resp *http.Response) *FingerprintResult {
	if !rabbitmqRealmRegex.MatchString(resp.Header.Get("WWW-Authenticate")) {
		return nil
	}

	return &FingerprintResult{
		Technology: "rabbitmq-management",
		Version:    "*",
		CPEs:       []string{buildRabbitMQCPE("*")},
		Metadata:   map[string]any{},
	}
}

// buildRabbitMQCPE constructs the CPE 2.3 identifier for RabbitMQ.
func buildRabbitMQCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:vmware:rabbitmq:%s:*:*:*:*:*:*:*", version)
}
