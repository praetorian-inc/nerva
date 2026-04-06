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
Package fingerprinters provides HTTP fingerprinting for Backstage.

# Detection Strategy

Backstage is an open-source developer portal created by Spotify. Exposed
instances represent a security concern due to:
  - Access to internal software catalog and service registry
  - Potential exposure of infrastructure metadata
  - Plugin ecosystem with access to internal tooling

Detection uses active probing of the health endpoint:
  - Active: Query /.backstage/health/v1/readiness endpoint
  - The /.backstage/ path prefix is unique to Backstage

# API Response Format

The /.backstage/health/v1/readiness endpoint returns JSON:

Healthy instance:

	{"status": "ok"}

Starting up or shutting down:

	{"message": "Backend has not started yet", "status": "error"}
	{"message": "Backend is shutting down", "status": "error"}

# Version Detection

Backstage does not expose version information via the health endpoint.
Version is set to empty string; CPE uses wildcard (*) for version.

# CPE

cpe:2.3:a:spotify:backstage:*:*:*:*:*:*:*:*

# Example Usage

	fp := &BackstageFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s\n", result.Technology)
		}
	}
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// BackstageFingerprinter detects Backstage instances via /.backstage/health/v1/readiness endpoint
type BackstageFingerprinter struct{}

// backstageHealthResponse represents the JSON structure from /.backstage/health/v1/readiness
type backstageHealthResponse struct {
	Status  string `json:"status"`
	Message string `json:"message"`
}

func init() {
	Register(&BackstageFingerprinter{})
}

func (f *BackstageFingerprinter) Name() string {
	return "backstage"
}

func (f *BackstageFingerprinter) ProbeEndpoint() string {
	return "/.backstage/health/v1/readiness"
}

func (f *BackstageFingerprinter) Match(resp *http.Response) bool {
	// Check for application/json Content-Type header
	// This is present on Backstage API responses but not unique to Backstage
	// Use as weak pre-filter before active probe
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *BackstageFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Try to parse as Backstage health response
	var health backstageHealthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		return nil, nil // Not Backstage format
	}

	// Validate it's actually Backstage by checking the status field
	// Backstage health endpoint returns only "ok" or "error"
	if health.Status != "ok" && health.Status != "error" {
		return nil, nil
	}

	// For error status, require a message field containing "Backend"
	// to distinguish Backstage startup/shutdown from other services
	if health.Status == "error" && !strings.Contains(health.Message, "Backend") {
		return nil, nil
	}

	// Build metadata
	metadata := map[string]any{
		"status": health.Status,
	}
	if health.Message != "" {
		metadata["message"] = health.Message
	}

	return &FingerprintResult{
		Technology: "backstage",
		Version:    "",
		CPEs:       []string{buildBackstageCPE("")},
		Metadata:   metadata,
	}, nil
}

func buildBackstageCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:spotify:backstage:%s:*:*:*:*:*:*:*", version)
}
