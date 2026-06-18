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
Package fingerprinters provides HTTP fingerprinting for Spring Boot Actuator.

# Detection Strategy

Spring Boot Actuator is a production-ready feature of Spring Boot that exposes
operational endpoints for monitoring and managing applications. Exposed Actuator
endpoints represent a security concern because they may disclose:
  - Application configuration, environment variables, and secrets (/actuator/env)
  - Heap dumps and thread dumps (/actuator/heapdump, /actuator/threaddump)
  - Loaded bean definitions and application internals (/actuator/beans)
  - Log level manipulation (/actuator/loggers)

Detection uses two complementary active probes:

Primary: /actuator index endpoint.
Returns a HAL JSON document listing all exposed endpoints via _links.
Detection requires the _links key plus at least one known Actuator-specific
link name to distinguish from generic HAL APIs.

Secondary: /actuator/health endpoint.
Returns JSON with a status field constrained to the Spring Boot health
status enum: UP, DOWN, OUT_OF_SERVICE, UNKNOWN.

# Version Detection

Spring Boot Actuator does not expose the framework version through these
endpoints. The Version field is left empty in most cases.

# Port Configuration

Spring Boot applications typically run on:
  - 8080: Default embedded server port
  - 8443: Default embedded HTTPS port
  - 80/443: When deployed behind a reverse proxy
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// SpringBootActuatorFingerprinter detects Spring Boot Actuator via the /actuator index endpoint.
// The index returns a HAL JSON document listing all exposed management endpoints.
type SpringBootActuatorFingerprinter struct{}

// SpringBootActuatorHealthFingerprinter detects Spring Boot Actuator via the /actuator/health endpoint.
// The health endpoint returns the application health status in a structured JSON format.
type SpringBootActuatorHealthFingerprinter struct{}

// actuatorIndexResponse represents the minimal structure of the /actuator index response.
// The _links field is a HAL-style map of link name to link object.
type actuatorIndexResponse struct {
	Links map[string]json.RawMessage `json:"_links"`
}

// actuatorHealthResponse represents the minimal structure of the /actuator/health response.
type actuatorHealthResponse struct {
	Status     string                     `json:"status"`
	Components map[string]json.RawMessage `json:"components"`
}

// springBootVersionRegex validates Spring Boot version strings.
// Accepts: 3.2.0, 2.7.18, 3.0.0-RC1, 3.2.0.RELEASE
var springBootVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[.-][a-zA-Z0-9._-]+)?$`)

// actuatorKnownEndpoints is the set of Spring Boot Actuator-specific link names.
// The "self" link appears in any HAL API so it is excluded. Only names unique to
// the Spring Boot Actuator feature are listed.
var actuatorKnownEndpoints = map[string]bool{
	"health":         true,
	"beans":          true,
	"metrics":        true,
	"env":            true,
	"configprops":    true,
	"mappings":       true,
	"info":           true,
	"conditions":     true,
	"loggers":        true,
	"threaddump":     true,
	"heapdump":       true,
	"scheduledtasks": true,
}

// actuatorHealthStatuses is the set of valid Spring Boot health status values.
// This enum is defined by Spring Boot's HealthStatus class and has not changed
// across versions.
var actuatorHealthStatuses = map[string]bool{
	"UP":              true,
	"DOWN":            true,
	"OUT_OF_SERVICE":  true,
	"UNKNOWN":         true,
}

func init() {
	Register(&SpringBootActuatorFingerprinter{})
	Register(&SpringBootActuatorHealthFingerprinter{})
}

// isActuatorJSONContentType returns true if the Content-Type indicates a JSON response,
// including vendor media types like application/vnd.spring-boot.actuator.v3+json.
func isActuatorJSONContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "application/json") || strings.Contains(ct, "+json")
}

// --- SpringBootActuatorFingerprinter ---

func (f *SpringBootActuatorFingerprinter) Name() string {
	return "spring-boot-actuator"
}

func (f *SpringBootActuatorFingerprinter) ProbeEndpoint() string {
	return "/actuator"
}

func (f *SpringBootActuatorFingerprinter) Match(resp *http.Response) bool {
	return isActuatorJSONContentType(resp.Header.Get("Content-Type"))
}

func (f *SpringBootActuatorFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var index actuatorIndexResponse
	if err := json.Unmarshal(body, &index); err != nil {
		return nil, nil
	}

	if index.Links == nil {
		return nil, nil
	}

	// Collect the subset of link names that are known Actuator endpoints.
	// "self" is present in all HAL APIs so it is skipped.
	var exposedEndpoints []string
	for name := range index.Links {
		if actuatorKnownEndpoints[name] {
			exposedEndpoints = append(exposedEndpoints, name)
		}
	}

	// Require at least one Actuator-specific link to distinguish from generic HAL APIs.
	if len(exposedEndpoints) == 0 {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "spring-boot-actuator",
		Version:    "",
		CPEs:       []string{buildSpringBootCPE("")},
		Metadata: map[string]any{
			"exposed_endpoints": exposedEndpoints,
			"endpoint_count":    len(exposedEndpoints),
			"detection_method":  "actuator_index",
		},
	}, nil
}

// --- SpringBootActuatorHealthFingerprinter ---

func (f *SpringBootActuatorHealthFingerprinter) Name() string {
	return "spring-boot-actuator-health"
}

func (f *SpringBootActuatorHealthFingerprinter) ProbeEndpoint() string {
	return "/actuator/health"
}

func (f *SpringBootActuatorHealthFingerprinter) Match(resp *http.Response) bool {
	return isActuatorJSONContentType(resp.Header.Get("Content-Type"))
}

func (f *SpringBootActuatorHealthFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var health actuatorHealthResponse
	if err := json.Unmarshal(body, &health); err != nil {
		return nil, nil
	}

	if !actuatorHealthStatuses[health.Status] {
		return nil, nil
	}

	hasVendorCT := strings.Contains(
		strings.ToLower(resp.Header.Get("Content-Type")),
		"vnd.spring-boot.actuator",
	)
	hasComponents := len(health.Components) > 0

	if !hasVendorCT && !hasComponents {
		return nil, nil
	}

	componentCount := len(health.Components)

	return &FingerprintResult{
		Technology: "spring-boot-actuator",
		Version:    "",
		CPEs:       []string{buildSpringBootCPE("")},
		Metadata: map[string]any{
			"health_status":    health.Status,
			"has_details":      hasComponents,
			"component_count":  componentCount,
			"detection_method": "actuator_health",
		},
	}, nil
}

// --- Helper functions ---

// buildSpringBootCPE generates a CPE string for Spring Boot.
// CPE format: cpe:2.3:a:vmware:spring_boot:{version}:*:*:*:*:*:*:*
//
// The version parameter is validated against springBootVersionRegex.
// If empty or invalid, the wildcard "*" is used.
func buildSpringBootCPE(version string) string {
	if version != "" && springBootVersionRegex.MatchString(version) {
		return fmt.Sprintf("cpe:2.3:a:vmware:spring_boot:%s:*:*:*:*:*:*:*", version)
	}
	return "cpe:2.3:a:vmware:spring_boot:*:*:*:*:*:*:*:*"
}
