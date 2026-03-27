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
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// MinIOFingerprinter detects MinIO object storage via /minio/health/live endpoint.
// Detection is based on the Server header containing "MinIO". Version extraction
// parses the RELEASE.YYYY-MM-DDTHH-MM-SSZ format from the Server header.
type MinIOFingerprinter struct{}

func init() {
	Register(&MinIOFingerprinter{})
}

// minioVersionRegex extracts version from Server header format: MinIO/RELEASE.YYYY-MM-DDTHH-MM-SSZ
// Strict pattern prevents CPE injection from malicious Server headers.
var minioVersionRegex = regexp.MustCompile(`(?i)MinIO/(RELEASE\.\d{4}-\d{2}-\d{2}T\d{2}-\d{2}-\d{2}Z)`)

func (f *MinIOFingerprinter) Name() string {
	return "minio"
}

// ProbeEndpoint returns the endpoint needed for MinIO detection.
// MinIO exposes an unauthenticated health check at /minio/health/live.
func (f *MinIOFingerprinter) ProbeEndpoint() string {
	return "/minio/health/live"
}

// Match returns true if the response might be from MinIO.
// Only checks the Server header - does not read the body, since the registry
// may have already consumed it before calling Match().
func (f *MinIOFingerprinter) Match(resp *http.Response) bool {
	serverHeader := resp.Header.Get("Server")
	return strings.Contains(strings.ToLower(serverHeader), "minio")
}

// Fingerprint performs MinIO detection by examining the Server header.
func (f *MinIOFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	serverHeader := resp.Header.Get("Server")

	// Check if Server header contains "MinIO" (case-insensitive)
	if !strings.Contains(strings.ToLower(serverHeader), "minio") {
		return nil, nil // Not MinIO
	}

	// Extract version from Server header if present
	version := ""
	matches := minioVersionRegex.FindStringSubmatch(serverHeader)
	if len(matches) > 1 {
		version = matches[1] // RELEASE.YYYY-MM-DDTHH-MM-SSZ
	}

	// If no version found, use wildcard
	if version == "" {
		version = "*"
	}

	// Build metadata
	metadata := map[string]any{
		"server_header": serverHeader,
	}

	return &FingerprintResult{
		Technology: "minio",
		Version:    version,
		CPEs:       []string{buildMinioCPE(version)},
		Metadata:   metadata,
	}, nil
}

// buildMinioCPE generates CPE string for MinIO.
// Format: cpe:2.3:a:minio:minio:{version}:*:*:*:*:*:*:*
func buildMinioCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:minio:minio:%s:*:*:*:*:*:*:*", version)
}
