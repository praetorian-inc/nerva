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
Package fingerprinters provides HTTP fingerprinting for Gradio ML web applications.

# What is Gradio

Gradio is a Python library for building machine learning web UIs. It allows data
scientists and ML engineers to quickly create interactive web interfaces for their
models with minimal code. Gradio apps are commonly deployed to Hugging Face Spaces
or self-hosted on arbitrary infrastructure.

# Security Risks

Exposed Gradio instances present several security concerns:
  - Unauthorized model access - arbitrary users can invoke ML model inference
  - File upload vulnerabilities - Gradio's file upload API has had multiple CVEs
    enabling path traversal and arbitrary file read/write
  - SSRF - Gradio can be coerced into fetching remote URLs as part of inference
  - Resource abuse - compute-intensive model inference without authentication
  - Information disclosure - the /config endpoint reveals application structure,
    component layout, and server-side dependencies
  - Hugging Face Spaces enumeration - is_space and space_id fields identify the
    HF organization and repository when hosted on HF infrastructure

# Detection Strategy

Detection uses active probing of the /config endpoint, available since Gradio 3.x.
This endpoint requires no authentication and returns a comprehensive JSON object
describing the application layout. Detection requires:
  1. Content-Type: application/json response header
  2. A "version" field present in the JSON body
  3. At least one Gradio-specific structural field (components, known mode value, or dependencies)
     to avoid false positives from generic JSON APIs that may return a "version" field

# API Response Format

The /config endpoint returns JSON like:

	{
	  "version": "4.44.1",
	  "mode": "blocks",
	  "title": "My ML App",
	  "protocol": "sse_v3",
	  "is_space": false,
	  "space_id": null,
	  "app_id": 1234567890,
	  "components": [...],
	  "dependencies": [...]
	}

Version patterns across major releases:
  - 3.x: No "protocol" field, has "enable_queue" field
  - 4.x: protocol = "sse_v3"
  - 5.x: protocol = "sse_v4"

# Port Configuration

Gradio typically runs on:
  - 7860: Default Gradio development server port
  - Custom ports: Configurable at launch time
  - 443/80: When deployed behind a reverse proxy or on Hugging Face Spaces

# Hugging Face Spaces Detection

When is_space is true, the space_id field contains "{user}/{space}" identifying
the Hugging Face organization and repository. This enables targeted reconnaissance
of an organization's ML infrastructure on Hugging Face.

# Example Usage

	fp := &GradioFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s\n", result.Technology, result.Version)
			if mode, ok := result.Metadata["mode"].(string); ok {
				fmt.Printf("App mode: %s\n", mode)
			}
			if isSpace, ok := result.Metadata["is_space"].(bool); ok && isSpace {
				fmt.Printf("Hosted on HF Spaces: %v\n", result.Metadata["space_id"])
			}
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

// GradioFingerprinter detects Gradio ML web UI instances via the /config endpoint
type GradioFingerprinter struct{}

// gradioConfigResponse represents the JSON structure from Gradio's /config endpoint.
// The /config endpoint is available since Gradio 3.x and requires no authentication.
type gradioConfigResponse struct {
	Version      string          `json:"version"`
	Mode         string          `json:"mode"`
	AppID        json.Number     `json:"app_id"`
	Title        string          `json:"title"`
	IsSpace      bool            `json:"is_space"`
	SpaceID      *string         `json:"space_id"`
	Protocol     string          `json:"protocol"`
	Components   json.RawMessage `json:"components"`
	Dependencies json.RawMessage `json:"dependencies"`
}

// gradioVersionRegex validates Gradio version format for CPE safety.
// Accepts: 3.50.2, 4.44.1, 5.12.0 (standard releases) and 4.0.0b1, 5.0.0rc1 (pre-releases).
// Rejects: special characters that could enable CPE injection attacks.
var gradioVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+[a-zA-Z0-9]*$`)

// gradioBaseVersionRegex extracts the base semver (digits only) for CPE construction
var gradioBaseVersionRegex = regexp.MustCompile(`^(\d+\.\d+\.\d+)`)

func init() {
	Register(&GradioFingerprinter{})
}

func (f *GradioFingerprinter) Name() string {
	return "gradio"
}

func (f *GradioFingerprinter) ProbeEndpoint() string {
	return "/config"
}

func (f *GradioFingerprinter) Match(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func (f *GradioFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var config gradioConfigResponse
	if err := json.Unmarshal(body, &config); err != nil {
		return nil, nil // Not valid JSON
	}

	// Require the version field — all Gradio /config responses include it
	if config.Version == "" {
		return nil, nil
	}

	// Require at least one Gradio-specific structural field to prevent false positives.
	// Generic JSON APIs may expose a "version" field; we need structural confirmation.
	hasComponents := len(config.Components) > 0 && string(config.Components) != "null"
	hasMode := config.Mode == "blocks" || config.Mode == "interface" || config.Mode == "chat_interface"
	hasDependencies := len(config.Dependencies) > 0 && string(config.Dependencies) != "null"

	// components must be a JSON array (not just any non-null value)
	if hasComponents {
		trimmed := strings.TrimSpace(string(config.Components))
		hasComponents = strings.HasPrefix(trimmed, "[")
	}
	// dependencies must be a JSON array
	if hasDependencies {
		trimmed := strings.TrimSpace(string(config.Dependencies))
		hasDependencies = strings.HasPrefix(trimmed, "[")
	}

	if !hasComponents && !hasMode && !hasDependencies {
		return nil, nil
	}

	// Validate version format to prevent CPE injection
	if !gradioVersionRegex.MatchString(config.Version) {
		return nil, nil
	}

	// Build metadata with security-relevant fields
	metadata := map[string]any{}

	if config.Mode != "" {
		metadata["mode"] = config.Mode
	}
	if config.Title != "" {
		metadata["title"] = config.Title
	}
	if config.Protocol != "" {
		metadata["protocol"] = config.Protocol
	}
	metadata["is_space"] = config.IsSpace
	if config.SpaceID != nil && *config.SpaceID != "" {
		metadata["space_id"] = *config.SpaceID
	}

	// Count components for attack surface assessment
	if hasComponents {
		var components []json.RawMessage
		if err := json.Unmarshal(config.Components, &components); err == nil {
			metadata["component_count"] = len(components)
		}
	}

	cpeVersion := config.Version
	if m := gradioBaseVersionRegex.FindString(config.Version); m != "" {
		cpeVersion = m
	}

	return &FingerprintResult{
		Technology: "gradio",
		Version:    config.Version,
		CPEs:       []string{buildGradioCPE(cpeVersion)},
		Metadata:   metadata,
	}, nil
}

func buildGradioCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:gradio_project:gradio:%s:*:*:*:*:python:*:*", version)
}
