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
Package fingerprinters provides HTTP fingerprinting for Jenkins CI/CD.

# Detection Strategy

Jenkins is an open-source automation server used for CI/CD. It's a critical
infrastructure component that represents a security concern due to:
  - Script Console access (Groovy RCE)
  - Build history with credentials
  - Pipeline configurations with secrets
  - Often exposed without authentication

Detection uses passive-only approach:
  - Check for Jenkins-specific response headers (X-Jenkins, X-Hudson)
  - Version extraction from X-Jenkins header (direct value, no parsing)
  - X-Hudson header indicates legacy Hudson compatibility

# Response Headers

Jenkins sends identifying headers on all HTTP responses:

	X-Jenkins: 2.541.1
	X-Hudson: 1.395
	X-Jenkins-Session: f55df8ea

Header breakdown:
  - X-Jenkins: Version string (primary detection and version extraction)
  - X-Hudson: Legacy Hudson compatibility version
  - X-Jenkins-Session: Session identifier (not used for detection)

# Port Configuration

Jenkins typically runs on:
  - 8080: Default Jenkins web port
  - 443:  HTTPS in production
  - 8443: Alternative HTTPS port

# Example Usage

	fp := &JenkinsFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s\n", result.Technology, result.Version)
		}
	}
*/
package fingerprinters

import (
	"fmt"
	"net/http"
)

// JenkinsFingerprinter detects Jenkins instances via X-Jenkins and X-Hudson headers
type JenkinsFingerprinter struct{}

func init() {
	Register(&JenkinsFingerprinter{})
}

func (f *JenkinsFingerprinter) Name() string {
	return "jenkins"
}

func (f *JenkinsFingerprinter) Match(resp *http.Response) bool {
	// Check for X-Jenkins header first (primary)
	if resp.Header.Get("X-Jenkins") != "" {
		return true
	}
	// Fall back to X-Hudson header (legacy Hudson compatibility)
	return resp.Header.Get("X-Hudson") != ""
}

func (f *JenkinsFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	metadata := make(map[string]any)

	// Extract version from X-Jenkins header (direct value)
	version := resp.Header.Get("X-Jenkins")

	// Store X-Hudson version in metadata if present
	if hudsonVersion := resp.Header.Get("X-Hudson"); hudsonVersion != "" {
		metadata["hudson_version"] = hudsonVersion
	}

	// If neither X-Jenkins nor X-Hudson is present, return nil
	if version == "" && len(metadata) == 0 {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "jenkins",
		Version:    version,
		CPEs:       []string{buildJenkinsCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildJenkinsCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:jenkins:jenkins:%s:*:*:*:*:*:*:*", version)
}
