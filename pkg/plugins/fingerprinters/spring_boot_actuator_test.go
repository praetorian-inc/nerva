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
	"net/http"
	"testing"
)

// --- SpringBootActuatorFingerprinter tests ---

func TestSpringBootActuatorFingerprinter_Name(t *testing.T) {
	fp := &SpringBootActuatorFingerprinter{}
	if got := fp.Name(); got != "spring-boot-actuator" {
		t.Errorf("Name() = %q, want %q", got, "spring-boot-actuator")
	}
}

func TestSpringBootActuatorFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &SpringBootActuatorFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/actuator" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/actuator")
	}
}

func TestSpringBootActuatorFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "application/json returns true",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "application/json; charset=utf-8 returns true",
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "vendor JSON type v3 returns true",
			contentType: "application/vnd.spring-boot.actuator.v3+json",
			want:        true,
		},
		{
			name:        "vendor JSON type v2 returns true",
			contentType: "application/vnd.spring-boot.actuator.v2+json;charset=UTF-8",
			want:        true,
		},
		{
			name:        "text/html returns false",
			contentType: "text/html",
			want:        false,
		},
		{
			name:        "empty Content-Type returns false",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SpringBootActuatorFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSpringBootActuatorFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name              string
		body              string
		wantEndpoints     []string
		wantEndpointCount int
	}{
		{
			name: "actuator index with health and beans links",
			body: `{
				"_links": {
					"self": {"href": "http://localhost:8080/actuator", "templated": false},
					"health": {"href": "http://localhost:8080/actuator/health", "templated": false},
					"beans": {"href": "http://localhost:8080/actuator/beans", "templated": false}
				}
			}`,
			wantEndpoints:     []string{"health", "beans"},
			wantEndpointCount: 2,
		},
		{
			name: "actuator index with multiple standard endpoints",
			body: `{
				"_links": {
					"self": {"href": "http://localhost:8080/actuator", "templated": false},
					"health": {"href": "http://localhost:8080/actuator/health", "templated": false},
					"metrics": {"href": "http://localhost:8080/actuator/metrics", "templated": false},
					"env": {"href": "http://localhost:8080/actuator/env", "templated": false},
					"info": {"href": "http://localhost:8080/actuator/info", "templated": false},
					"loggers": {"href": "http://localhost:8080/actuator/loggers", "templated": false}
				}
			}`,
			wantEndpoints:     []string{"health", "metrics", "env", "info", "loggers"},
			wantEndpointCount: 5,
		},
		{
			name: "actuator index with only one known endpoint",
			body: `{
				"_links": {
					"self": {"href": "http://localhost:8080/actuator", "templated": false},
					"heapdump": {"href": "http://localhost:8080/actuator/heapdump", "templated": false}
				}
			}`,
			wantEndpoints:     []string{"heapdump"},
			wantEndpointCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SpringBootActuatorFingerprinter{}
			resp := &http.Response{}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want result")
			}

			if result.Technology != "spring-boot-actuator" {
				t.Errorf("Technology = %q, want %q", result.Technology, "spring-boot-actuator")
			}
			if result.Version != "" {
				t.Errorf("Version = %q, want empty string", result.Version)
			}
			if len(result.CPEs) != 1 || result.CPEs[0] != "cpe:2.3:a:vmware:spring_boot:*:*:*:*:*:*:*:*" {
				t.Errorf("CPEs = %v, want [cpe:2.3:a:vmware:spring_boot:*:*:*:*:*:*:*:*]", result.CPEs)
			}

			// Check metadata
			detectionMethod, ok := result.Metadata["detection_method"].(string)
			if !ok || detectionMethod != "actuator_index" {
				t.Errorf("detection_method = %q, want %q", detectionMethod, "actuator_index")
			}

			endpointCount, ok := result.Metadata["endpoint_count"].(int)
			if !ok || endpointCount != tt.wantEndpointCount {
				t.Errorf("endpoint_count = %v, want %d", result.Metadata["endpoint_count"], tt.wantEndpointCount)
			}

			exposedEndpoints, ok := result.Metadata["exposed_endpoints"].([]string)
			if !ok {
				t.Fatal("exposed_endpoints is not []string")
			}

			// Check each expected endpoint is present
			endpointSet := make(map[string]bool)
			for _, ep := range exposedEndpoints {
				endpointSet[ep] = true
			}
			for _, want := range tt.wantEndpoints {
				if !endpointSet[want] {
					t.Errorf("exposed_endpoints missing %q, got %v", want, exposedEndpoints)
				}
			}
		})
	}
}

func TestSpringBootActuatorFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "JSON without _links",
			body: `{"status": "UP", "components": {}}`,
		},
		{
			name: "empty JSON object",
			body: `{}`,
		},
		{
			name: "not JSON",
			body: `This is not JSON`,
		},
		{
			name: "empty body",
			body: ``,
		},
		{
			name: "_links present but no known Actuator endpoint names (generic HAL API)",
			body: `{
				"_links": {
					"self": {"href": "http://example.com/api", "templated": false},
					"orders": {"href": "http://example.com/api/orders", "templated": false},
					"customers": {"href": "http://example.com/api/customers", "templated": false}
				}
			}`,
		},
		{
			name: "_links present but only self link",
			body: `{
				"_links": {
					"self": {"href": "http://localhost:8080/actuator", "templated": false}
				}
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SpringBootActuatorFingerprinter{}
			resp := &http.Response{}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v, want nil", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil for input: %s", result, tt.name)
			}
		})
	}
}

func TestBuildSpringBootCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "valid semver version",
			version: "3.2.0",
			want:    "cpe:2.3:a:vmware:spring_boot:3.2.0:*:*:*:*:*:*:*",
		},
		{
			name:    "empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:vmware:spring_boot:*:*:*:*:*:*:*:*",
		},
		{
			name:    "invalid version falls back to wildcard",
			version: "3.2.0abc",
			want:    "cpe:2.3:a:vmware:spring_boot:*:*:*:*:*:*:*:*",
		},
		{
			name:    "pre-release version is accepted",
			version: "3.0.0-RC1",
			want:    "cpe:2.3:a:vmware:spring_boot:3.0.0-RC1:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildSpringBootCPE(tt.version); got != tt.want {
				t.Errorf("buildSpringBootCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

// --- SpringBootActuatorHealthFingerprinter tests ---

func TestSpringBootActuatorHealthFingerprinter_Name(t *testing.T) {
	fp := &SpringBootActuatorHealthFingerprinter{}
	if got := fp.Name(); got != "spring-boot-actuator-health" {
		t.Errorf("Name() = %q, want %q", got, "spring-boot-actuator-health")
	}
}

func TestSpringBootActuatorHealthFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &SpringBootActuatorHealthFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/actuator/health" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/actuator/health")
	}
}

func TestSpringBootActuatorHealthFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "application/json returns true",
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "application/json; charset=utf-8 returns true",
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "vendor JSON type v3 returns true",
			contentType: "application/vnd.spring-boot.actuator.v3+json",
			want:        true,
		},
		{
			name:        "vendor JSON type v2 returns true",
			contentType: "application/vnd.spring-boot.actuator.v2+json;charset=UTF-8",
			want:        true,
		},
		{
			name:        "text/plain returns false",
			contentType: "text/plain",
			want:        false,
		},
		{
			name:        "empty Content-Type returns false",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SpringBootActuatorHealthFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSpringBootActuatorHealthFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name               string
		body               string
		wantStatus         string
		wantHasDetails     bool
		wantComponentCount int
	}{
		{
			name:               "UP status, no details",
			body:               `{"status": "UP"}`,
			wantStatus:         "UP",
			wantHasDetails:     false,
			wantComponentCount: 0,
		},
		{
			name:               "DOWN status",
			body:               `{"status": "DOWN"}`,
			wantStatus:         "DOWN",
			wantHasDetails:     false,
			wantComponentCount: 0,
		},
		{
			name:               "OUT_OF_SERVICE status",
			body:               `{"status": "OUT_OF_SERVICE"}`,
			wantStatus:         "OUT_OF_SERVICE",
			wantHasDetails:     false,
			wantComponentCount: 0,
		},
		{
			name:               "UNKNOWN status",
			body:               `{"status": "UNKNOWN"}`,
			wantStatus:         "UNKNOWN",
			wantHasDetails:     false,
			wantComponentCount: 0,
		},
		{
			name: "UP with components (details exposed)",
			body: `{
				"status": "UP",
				"components": {
					"db": {"status": "UP"},
					"diskSpace": {"status": "UP"},
					"redis": {"status": "UP"}
				}
			}`,
			wantStatus:         "UP",
			wantHasDetails:     true,
			wantComponentCount: 3,
		},
		{
			name: "DOWN with components",
			body: `{
				"status": "DOWN",
				"components": {
					"db": {"status": "DOWN"},
					"diskSpace": {"status": "UP"}
				}
			}`,
			wantStatus:         "DOWN",
			wantHasDetails:     true,
			wantComponentCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SpringBootActuatorHealthFingerprinter{}
			resp := &http.Response{}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want result")
			}

			if result.Technology != "spring-boot-actuator" {
				t.Errorf("Technology = %q, want %q", result.Technology, "spring-boot-actuator")
			}
			if result.Version != "" {
				t.Errorf("Version = %q, want empty string", result.Version)
			}
			if len(result.CPEs) != 1 || result.CPEs[0] != "cpe:2.3:a:vmware:spring_boot:*:*:*:*:*:*:*:*" {
				t.Errorf("CPEs = %v, want [cpe:2.3:a:vmware:spring_boot:*:*:*:*:*:*:*:*]", result.CPEs)
			}

			detectionMethod, ok := result.Metadata["detection_method"].(string)
			if !ok || detectionMethod != "actuator_health" {
				t.Errorf("detection_method = %q, want %q", detectionMethod, "actuator_health")
			}

			healthStatus, ok := result.Metadata["health_status"].(string)
			if !ok || healthStatus != tt.wantStatus {
				t.Errorf("health_status = %q, want %q", healthStatus, tt.wantStatus)
			}

			hasDetails, ok := result.Metadata["has_details"].(bool)
			if !ok || hasDetails != tt.wantHasDetails {
				t.Errorf("has_details = %v, want %v", result.Metadata["has_details"], tt.wantHasDetails)
			}

			componentCount, ok := result.Metadata["component_count"].(int)
			if !ok || componentCount != tt.wantComponentCount {
				t.Errorf("component_count = %v, want %d", result.Metadata["component_count"], tt.wantComponentCount)
			}
		})
	}
}

func TestSpringBootActuatorHealthFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "status not in Spring Boot enum (custom value)",
			body: `{"status": "HEALTHY"}`,
		},
		{
			name: "status not in Spring Boot enum (lowercase)",
			body: `{"status": "up"}`,
		},
		{
			name: "missing status field",
			body: `{"components": {"db": {"status": "UP"}}}`,
		},
		{
			name: "empty JSON object",
			body: `{}`,
		},
		{
			name: "not JSON",
			body: `This is not JSON`,
		},
		{
			name: "empty body",
			body: ``,
		},
		{
			name: "generic service with different status format",
			body: `{"status": "ok", "version": "1.0"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &SpringBootActuatorHealthFingerprinter{}
			resp := &http.Response{}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v, want nil", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil for input: %s", result, tt.name)
			}
		})
	}
}
