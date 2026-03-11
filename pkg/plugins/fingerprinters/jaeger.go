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
Package fingerprinters provides HTTP fingerprinting for Jaeger.

# Detection Strategy

Jaeger is a widely deployed distributed tracing system. Exposed instances
represent a security concern due to:
  - Access to application tracing data revealing system architecture
  - Potential information disclosure about service dependencies
  - Exposure of performance metrics and call patterns
  - Query capabilities that could reveal sensitive information
  - Administrative endpoints that may be exposed

Detection uses two approaches:
1. Passive HTML detection: Check for <title>Jaeger UI</title> in root response and extract version from embedded JAEGER_VERSION JSON
2. Active JSON detection: Query /api/services endpoint (no authentication required)

# API Response Format

The /api/services endpoint returns JSON without authentication:

	{
	  "data": ["service-a", "service-b", "checkout", "frontend"],
	  "errors": null,
	  "limit": 0,
	  "offset": 0,
	  "total": 4
	}

Fresh instances with no traced services may return:

	{
	  "data": null,
	  "errors": null,
	  "limit": 0,
	  "offset": 0,
	  "total": 0
	}

Or:

	{
	  "data": [],
	  "errors": null,
	  "limit": 0,
	  "offset": 0,
	  "total": 0
	}

Format breakdown:
  - data: Array of service name strings, or null on fresh instances (required field)
  - errors: Error field, typically null (required field to exist - distinguishes from other JSON APIs)
  - total: Total count of services (required field)
  - limit: Pagination limit (required field)
  - offset: Pagination offset (required field)

Detection is based on the structural signature: the presence of all 5 fields
(data, errors, total, limit, offset) uniquely identifies Jaeger's /api/services
endpoint. No other common HTTP API returns this exact structure.

# Port Configuration

Jaeger typically runs on:
  - 16686: Default Jaeger Query service HTTP port
  - 443:   HTTPS in production deployments
  - 80:    HTTP in some deployments

# Example Usage

	fp := &JaegerFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s with %d services\n", result.Technology, result.Metadata["service_count"])
		}
	}
*/
package fingerprinters

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// JaegerFingerprinter detects Jaeger instances via /api/services endpoint
type JaegerFingerprinter struct{}

// jaegerServicesResponse represents the JSON structure from /api/services
type jaegerServicesResponse struct {
	Data   json.RawMessage `json:"data"`   // Can be null, [], or ["service1", ...]
	Errors json.RawMessage `json:"errors"` // Can be null or error object
	Limit  *int            `json:"limit"`  // Pointer to distinguish missing vs 0
	Offset *int            `json:"offset"` // Pointer to distinguish missing vs 0
	Total  *int            `json:"total"`  // Pointer to distinguish missing vs 0
}

// jaegerHTMLVersion represents the JAEGER_VERSION JSON embedded in HTML
type jaegerHTMLVersion struct {
	GitCommit  string `json:"gitCommit"`
	GitVersion string `json:"gitVersion"`
	BuildDate  string `json:"buildDate"`
}

// jaegerVersionRegex validates Jaeger version format and prevents CPE injection
// Accepts: 1.76.0, 1.35.0, 2.0.0-rc.1, etc.
var jaegerVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(-[a-zA-Z0-9._-]+)?$`)

// jaegerVersionJSONRegex extracts the JAEGER_VERSION JSON object from HTML
var jaegerVersionJSONRegex = regexp.MustCompile(`JAEGER_VERSION\s*=\s*(\{[^}]+\})`)

func init() {
	Register(&JaegerFingerprinter{})
}

func (f *JaegerFingerprinter) Name() string {
	return "jaeger"
}

func (f *JaegerFingerprinter) ProbeEndpoint() string {
	return "/api/services"
}

func buildJaegerCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:jaegertracing:jaeger:%s:*:*:*:*:*:*:*", version)
}

func (f *JaegerFingerprinter) Match(resp *http.Response) bool {
	// Accept both JSON (for /api/services endpoint) and HTML (for root page)
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "application/json") || strings.Contains(ct, "text/html")
}

func (f *JaegerFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	ct := resp.Header.Get("Content-Type")

	if strings.Contains(ct, "text/html") {
		return f.fingerprintHTML(body)
	}
	if strings.Contains(ct, "application/json") {
		return f.fingerprintJSON(body)
	}
	return nil, nil
}

// fingerprintHTML detects Jaeger from HTML root page
func (f *JaegerFingerprinter) fingerprintHTML(body []byte) (*FingerprintResult, error) {
	// Check for <title>Jaeger UI</title> marker (all Jaeger versions)
	if !bytes.Contains(body, []byte("<title>Jaeger UI</title>")) {
		return nil, nil
	}

	version := ""
	metadata := map[string]any{
		"service_count": 0, // HTML root page doesn't expose service list
	}

	// Try to extract version from embedded JAEGER_VERSION JSON
	if matches := jaegerVersionJSONRegex.FindSubmatch(body); len(matches) > 1 {
		var ver jaegerHTMLVersion
		if err := json.Unmarshal(matches[1], &ver); err == nil && ver.GitVersion != "" {
			// Strip "v" prefix (e.g., "v1.76.0" -> "1.76.0")
			v := strings.TrimPrefix(ver.GitVersion, "v")
			if jaegerVersionRegex.MatchString(v) {
				version = v
			}
			if ver.GitCommit != "" {
				metadata["git_commit"] = ver.GitCommit
			}
			if ver.BuildDate != "" {
				metadata["build_date"] = ver.BuildDate
			}
		}
	}

	return &FingerprintResult{
		Technology: "jaeger",
		Version:    version,
		CPEs:       []string{buildJaegerCPE(version)},
		Metadata:   metadata,
	}, nil
}

// fingerprintJSON detects Jaeger from /api/services JSON response
func (f *JaegerFingerprinter) fingerprintJSON(body []byte) (*FingerprintResult, error) {
	// First, verify structural signature: parse to map to check all 5 fields exist
	var rawMap map[string]json.RawMessage
	if err := json.Unmarshal(body, &rawMap); err != nil {
		return nil, nil // Not valid JSON
	}

	// Jaeger structural signature: all 5 fields must be present
	// The combination of these exact fields is unique to Jaeger's /api/services
	requiredFields := []string{"data", "errors", "total", "limit", "offset"}
	for _, field := range requiredFields {
		if _, exists := rawMap[field]; !exists {
			return nil, nil // Missing required field, not Jaeger
		}
	}

	// Now parse as typed structure
	var services jaegerServicesResponse
	if err := json.Unmarshal(body, &services); err != nil {
		return nil, nil // Failed to parse with expected types
	}

	// All 5 fields present = positive Jaeger detection
	// Now extract services if data is a non-null array
	metadata := map[string]any{
		"service_count": 0,
	}

	// Try to parse data as []string if it's not null
	if string(services.Data) != "null" && len(services.Data) > 0 {
		var serviceList []string
		if err := json.Unmarshal(services.Data, &serviceList); err == nil && len(serviceList) > 0 {
			metadata["services"] = serviceList
			metadata["service_count"] = len(serviceList)
		}
	}

	// Add optional numeric fields if their values are > 0
	if services.Total != nil && *services.Total > 0 {
		metadata["total"] = *services.Total
	}
	if services.Limit != nil && *services.Limit > 0 {
		metadata["limit"] = *services.Limit
	}
	if services.Offset != nil && *services.Offset > 0 {
		metadata["offset"] = *services.Offset
	}

	return &FingerprintResult{
		Technology: "jaeger",
		Version:    "", // Jaeger doesn't expose version via /api/services
		CPEs:       []string{buildJaegerCPE("")},
		Metadata:   metadata,
	}, nil
}
