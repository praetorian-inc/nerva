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

// MongooseFingerprinter detects Cesanta Mongoose embedded web server instances.
//
// Detection Strategy:
// Mongoose is a lightweight embedded web server/networking library by Cesanta,
// widely used in IoT devices, embedded systems, and network appliances.
// Exposed instances represent a security concern due to:
//   - Default or missing authentication on embedded device management interfaces
//   - Known CVEs including directory traversal and heap overflow vulnerabilities
//   - Firmware update endpoints that may expose sensitive images
//   - Often deployed in IoT/OT environments where compromise has physical impact
//
// Detection uses two passive signals:
//  1. Server header: "Mongoose/X.XX" (when configured by the application)
//  2. Directory listing footer: "<address>Mongoose v.X.XX</address>" (default HTML)
//
// Version Format:
// Mongoose uses two-part versioning: MAJOR.MINOR (e.g., 7.14, 7.21).
//
// Port Configuration:
// Mongoose has no fixed default port. Common ports include:
//   - 8000: Used in tutorials and examples
//   - 80/443: Production deployments
//   - Custom: Application-defined
package fingerprinters

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// MongooseFingerprinter detects Cesanta Mongoose embedded web server instances
type MongooseFingerprinter struct{}

// mongooseBodyVersionRegex extracts version from directory listing footer
// "<address>Mongoose v.7.21</address>"
var mongooseBodyVersionRegex = regexp.MustCompile(`<address>Mongoose v\.(\d+\.\d+(?:\.\d+)?)</address>`)

// mongooseVersionValidateRegex validates extracted version format for CPE safety
var mongooseVersionValidateRegex = regexp.MustCompile(`^\d+\.\d+(?:\.\d+)?$`)

func init() {
	Register(&MongooseFingerprinter{})
}

func (f *MongooseFingerprinter) Name() string {
	return "mongoose"
}

func (f *MongooseFingerprinter) Match(resp *http.Response) bool {
	// Fast path: check Server header
	server := resp.Header.Get("Server")
	if strings.Contains(strings.ToLower(server), "mongoose") {
		return true
	}

	// Body-based detection requires HTML content type
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "text/html")
}

func (f *MongooseFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	version := ""
	detected := false

	// Signal 1: Server header contains "Mongoose"
	server := resp.Header.Get("Server")
	if strings.Contains(strings.ToLower(server), "mongoose") {
		detected = true
		version = extractMongooseServerVersion(server)
		if version == "" && strings.Contains(strings.ToLower(server), "mongoose/") {
			// Has "Mongoose/" prefix but version extraction failed — likely injection
			return nil, nil
		}
	}

	// Signal 2: Directory listing footer "<address>Mongoose v.X.XX</address>"
	var bodyStr string
	if len(body) > 0 {
		bodyStr = string(body)
	}

	if !detected && bodyStr != "" {
		if matches := mongooseBodyVersionRegex.FindStringSubmatch(bodyStr); len(matches) >= 2 {
			detected = true
			candidate := matches[1]
			if mongooseVersionValidateRegex.MatchString(candidate) {
				version = candidate
			}
		}
	}

	if !detected {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":  "Cesanta",
		"product": "Mongoose",
	}

	// Check if directory listing is present (requires both the versioned footer
	// and a table element, matching Mongoose's actual directory listing output)
	if bodyStr != "" {
		if mongooseBodyVersionRegex.MatchString(bodyStr) && strings.Contains(bodyStr, "<table") {
			metadata["directory_listing"] = true
		}
	}

	return &FingerprintResult{
		Technology: "mongoose",
		Version:    version,
		CPEs:       []string{buildMongooseCPE(version)},
		Metadata:   metadata,
	}, nil
}

// extractMongooseServerVersion extracts and validates the version from a Server header.
// It finds "Mongoose/" (case-insensitive), extracts the token until the next space or
// end of string, and validates the entire token against the version regex.
// This prevents CPE injection where "Mongoose/7.14:*:*" would extract "7.14" if we
// only used a capturing group.
func extractMongooseServerVersion(server string) string {
	idx := strings.Index(strings.ToLower(server), "mongoose/")
	if idx == -1 {
		return ""
	}
	versionPart := server[idx+9:] // Skip "mongoose/"

	// Find end of version token (space, parenthesis, or end of string)
	endIdx := len(versionPart)
	for i, ch := range versionPart {
		if ch == ' ' || ch == '(' || ch == ')' {
			endIdx = i
			break
		}
	}
	candidate := versionPart[:endIdx]

	if mongooseVersionValidateRegex.MatchString(candidate) {
		return candidate
	}
	return ""
}

func buildMongooseCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:cesanta:mongoose:%s:*:*:*:*:*:*:*", version)
}
