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
Package fingerprinters provides HTTP fingerprinting for JFrog Artifactory.

# Detection Strategy

JFrog Artifactory is a universal artifact repository manager that stores and manages
software packages and dependencies. It's a critical infrastructure component that
represents a security concern due to:
  - Storage of proprietary software artifacts
  - Access to internal source code and binaries
  - Potential supply chain attack vector
  - Often contains credentials and API tokens

Detection uses a two-pronged approach:
1. Passive: Check for Artifactory-specific response headers (X-JFrog-Version, X-Artifactory-Id, X-Artifactory-Node-Id)
2. Active: Query /artifactory/api/system/ping endpoint (no authentication required)

# API Response Format

The /artifactory/api/system/ping endpoint returns "OK" with headers:

	X-JFrog-Version: Artifactory/7.136.0 83600900
	X-Artifactory-Id: 82452a18829b4122b65e8033d68e59c338b0cc06
	X-Artifactory-Node-Id: a0rnvpm6mmcdc-artifactory-primary-0

Format breakdown:
  - X-JFrog-Version: "Artifactory/<VERSION> <REVISION>"
  - X-Artifactory-Id: Unique instance identifier
  - X-Artifactory-Node-Id: Node identifier for clustered deployments

# Cloud vs On-Prem Differences

Both cloud and on-prem instances:
  - Use /artifactory/api/system/ping endpoint
  - Ping endpoint works WITHOUT authentication
  - Version information is provided in headers (X-JFrog-Version)

Cloud instances (e.g., jfrog.io):
  - Use /artifactory/ prefix for all API endpoints

On-prem instances (e.g., port 8081):
  - May use /api/ prefix directly for some endpoints
  - Ping endpoint still requires /artifactory/ prefix

# Port Configuration

Artifactory typically runs on:
  - 8081: Default Artifactory web port (on-prem)
  - 8082: JFrog Platform Router port
  - 443:  HTTPS in production and cloud deployments

# Example Usage

	fp := &ArtifactoryFingerprinter{}
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
	"strings"
)

// ArtifactoryFingerprinter detects JFrog Artifactory instances via /artifactory/api/system/ping endpoint
type ArtifactoryFingerprinter struct{}

func init() {
	Register(&ArtifactoryFingerprinter{})
}

func (f *ArtifactoryFingerprinter) Name() string {
	return "artifactory"
}

func (f *ArtifactoryFingerprinter) ProbeEndpoint() string {
	return "/artifactory/api/system/ping"
}

func (f *ArtifactoryFingerprinter) Match(resp *http.Response) bool {
	// Check for Artifactory-specific headers (passive detection)
	if resp.Header.Get("X-Artifactory-Id") != "" {
		return true
	}
	if resp.Header.Get("X-Artifactory-Node-Id") != "" {
		return true
	}

	// Check for X-JFrog-Version header containing "Artifactory"
	jfrogVersion := resp.Header.Get("X-JFrog-Version")
	return strings.HasPrefix(jfrogVersion, "Artifactory/")
}

// extractVersionFromXJFrogHeader extracts version from X-JFrog-Version header
// Returns (version string, detected bool)
func extractVersionFromXJFrogHeader(resp *http.Response) (string, bool) {
	jfrogVersion := resp.Header.Get("X-JFrog-Version")
	if jfrogVersion == "" || !strings.HasPrefix(jfrogVersion, "Artifactory/") {
		return "", false
	}

	// Parse version: "Artifactory/7.136.0 83600900" -> "7.136.0"
	versionPart := strings.TrimPrefix(jfrogVersion, "Artifactory/")
	if spaceIdx := strings.Index(versionPart, " "); spaceIdx > 0 {
		versionPart = versionPart[:spaceIdx]
	}

	// Only return detected=true if we extracted a non-empty version
	if versionPart == "" {
		return "", false
	}

	return versionPart, true
}

// checkArtifactoryIdentityHeaders checks for Artifactory identity headers
// Returns detected bool, modifies metadata map in place
func checkArtifactoryIdentityHeaders(resp *http.Response, metadata map[string]any) bool {
	detected := false

	if resp.Header.Get("X-Artifactory-Id") != "" {
		detected = true
	}
	if nodeId := resp.Header.Get("X-Artifactory-Node-Id"); nodeId != "" {
		detected = true
		metadata["nodeId"] = nodeId
	}

	return detected
}

func (f *ArtifactoryFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	metadata := make(map[string]any)

	// Phase 1: Extract version from X-JFrog-Version header
	version, detected := extractVersionFromXJFrogHeader(resp)

	// Phase 2: Check for Artifactory identity headers
	if checkArtifactoryIdentityHeaders(resp, metadata) {
		detected = true
	}

	if !detected {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "artifactory",
		Version:    version,
		CPEs:       []string{buildArtifactoryCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildArtifactoryCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:jfrog:artifactory:%s:*:*:*:*:*:*:*", version)
}
