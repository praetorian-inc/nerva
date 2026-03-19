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

// NATSFingerprinter detects NATS monitoring via /varz endpoint.
// Detection is based on the presence of "server_id" field in the JSON response.
type NATSFingerprinter struct{}

func init() {
	Register(&NATSFingerprinter{})
}

// natsVarzResponse represents the JSON response from /varz endpoint
type natsVarzResponse struct {
	ServerID   string `json:"server_id"`
	ServerName string `json:"server_name"`
	Version    string `json:"version"`
	Go         string `json:"go"`
	GitCommit  string `json:"git_commit"`
	JetStream  bool   `json:"jetstream"`
}

// versionRegex validates NATS version format (X.Y.Z)
var natsVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func (f *NATSFingerprinter) Name() string {
	return "nats"
}

// ProbeEndpoint returns the endpoint needed for NATS detection.
// NATS exposes monitoring info at /varz endpoint.
func (f *NATSFingerprinter) ProbeEndpoint() string {
	return "/varz"
}

// Match returns true if the response might be from NATS (JSON or HTML content type).
func (f *NATSFingerprinter) Match(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json") || strings.Contains(contentType, "text/html")
}

// Fingerprint performs NATS detection by parsing the response (JSON or HTML).
func (f *NATSFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	contentType := resp.Header.Get("Content-Type")

	if strings.Contains(contentType, "application/json") {
		return f.fingerprintJSON(body)
	}

	if strings.Contains(contentType, "text/html") {
		return f.fingerprintHTML(body)
	}

	return nil, nil
}

// fingerprintJSON performs NATS detection from /varz JSON endpoint.
func (f *NATSFingerprinter) fingerprintJSON(body []byte) (*FingerprintResult, error) {
	// Parse JSON response
	var data natsVarzResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, nil // Not valid JSON
	}

	// NATS detection: server_id field must be non-empty
	if data.ServerID == "" {
		return nil, nil
	}

	// Validate version format if present (X.Y.Z)
	if data.Version != "" && !natsVersionRegex.MatchString(data.Version) {
		return nil, nil
	}

	// Build metadata
	metadata := map[string]any{}
	if data.ServerName != "" {
		metadata["server_name"] = data.ServerName
	}
	if data.Go != "" {
		metadata["go_version"] = data.Go
	}
	if data.GitCommit != "" {
		metadata["git_commit"] = data.GitCommit
	}
	if data.JetStream {
		metadata["jetstream"] = true
	}

	return &FingerprintResult{
		Technology: "nats",
		Version:    data.Version,
		CPEs:       []string{buildNATSCPE(data.Version)},
		Metadata:   metadata,
	}, nil
}

// fingerprintHTML performs passive NATS detection from HTML monitoring page.
func (f *NATSFingerprinter) fingerprintHTML(body []byte) (*FingerprintResult, error) {
	s := string(body)

	// Require NATS-specific markers
	if !strings.Contains(s, "nats.io") && !strings.Contains(s, "nats-server") {
		return nil, nil
	}

	// Require monitoring endpoint markers
	if !strings.Contains(s, "/varz") {
		return nil, nil
	}

	// Extract version from GitHub link: nats-server/tree/v{version}
	version := ""
	if idx := strings.Index(s, "nats-server/tree/v"); idx != -1 {
		start := idx + len("nats-server/tree/v")
		end := strings.IndexAny(s[start:], "\" '<>")
		if end != -1 {
			candidate := s[start : start+end]
			if natsVersionRegex.MatchString(candidate) {
				version = candidate
			}
		}
	}

	return &FingerprintResult{
		Technology: "nats",
		Version:    version,
		CPEs:       []string{buildNATSCPE(version)},
		Metadata:   map[string]any{},
	}, nil
}

// buildNATSCPE generates CPE string for NATS.
// Format: cpe:2.3:a:nats:nats-server:{version}:*:*:*:*:*:*:*
func buildNATSCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:nats:nats-server:%s:*:*:*:*:*:*:*", version)
}
