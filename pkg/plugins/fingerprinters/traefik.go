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
Package fingerprinters provides HTTP fingerprinting for Traefik.

# Detection Strategy

Traefik is a cloud-native reverse proxy and load balancer. Its dashboard API
exposes unauthenticated management endpoints by default. Detection uses two
complementary active probes:

Primary: /api/overview endpoint.
Returns a JSON document with http, tcp, and udp protocol sections, each
containing routers, services, and middlewares sub-keys with numeric counts.
This triple-protocol structure is unique to Traefik.

Secondary: /api/version endpoint.
Returns JSON with Version (capital V) and Codename (capital C) fields.
The Codename field is specific to Traefik releases (e.g., "rocamadour").

# CPE

  - Vendor: traefik
  - Product: traefik
  - CPE 2.3 format: cpe:2.3:a:traefik:traefik:{version}:*:*:*:*:*:*:*

# Port Configuration

Traefik typically runs on:
  - 8080: Default dashboard/API port
  - 80/443: Routed traffic
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// TraefikOverviewFingerprinter detects Traefik via the /api/overview endpoint.
// The overview returns a JSON document listing router, service, and middleware
// counts for http, tcp, and udp protocols — a structure unique to Traefik.
type TraefikOverviewFingerprinter struct{}

// TraefikVersionFingerprinter detects Traefik via the /api/version endpoint.
// The version endpoint returns JSON with Version and Codename fields; the
// Codename field is unique to Traefik release naming.
type TraefikVersionFingerprinter struct{}

// traefikProtocolSection represents a single protocol's count block in /api/overview.
type traefikProtocolSection struct {
	Routers     *traefikCountBlock `json:"routers"`
	Services    *traefikCountBlock `json:"services"`
	Middlewares *traefikCountBlock `json:"middlewares"`
}

// traefikCountBlock represents a count entry (e.g., routers: {total, warnings, errors}).
type traefikCountBlock struct {
	Total    int `json:"total"`
	Warnings int `json:"warnings"`
	Errors   int `json:"errors"`
}

// traefikOverviewResponse represents the minimal structure of the /api/overview response.
type traefikOverviewResponse struct {
	HTTP *traefikProtocolSection `json:"http"`
	TCP  *traefikProtocolSection `json:"tcp"`
	UDP  *traefikProtocolSection `json:"udp"`
}

// traefikVersionResponse represents the minimal structure of the /api/version response.
type traefikVersionResponse struct {
	Version   string `json:"Version"`
	Codename  string `json:"Codename"`
	StartDate string `json:"startDate"`
}

// traefikVersionRegex validates Traefik version strings for CPE inclusion.
// Strict semver only (digits and dots, no qualifiers) to avoid CPE injection.
var traefikVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&TraefikOverviewFingerprinter{})
	Register(&TraefikVersionFingerprinter{})
}

// isTraefikJSONContentType returns true if the Content-Type indicates a JSON response,
// including vendor media types that end in +json.
func isTraefikJSONContentType(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "application/json") || strings.Contains(ct, "+json")
}

// buildTraefikCPE generates a CPE 2.3 string for Traefik.
// The version is validated against traefikVersionRegex and checked for CPE
// metacharacters. Empty, invalid, or metacharacter-containing versions use "*".
func buildTraefikCPE(version string) string {
	if version != "" && !strings.ContainsAny(version, ":*?") && traefikVersionRegex.MatchString(version) {
		return fmt.Sprintf("cpe:2.3:a:traefik:traefik:%s:*:*:*:*:*:*:*", version)
	}
	return "cpe:2.3:a:traefik:traefik:*:*:*:*:*:*:*:*"
}

// --- TraefikOverviewFingerprinter ---

func (f *TraefikOverviewFingerprinter) Name() string {
	return "traefik-dashboard"
}

func (f *TraefikOverviewFingerprinter) ProbeEndpoint() string {
	return "/api/overview"
}

func (f *TraefikOverviewFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode >= 500 {
		return false
	}
	return isTraefikJSONContentType(resp.Header.Get("Content-Type"))
}

func (f *TraefikOverviewFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode >= 500 {
		return nil, nil
	}

	// 1 MiB body cap — Traefik overview responses are small JSON documents.
	if len(body) > 1*1024*1024 {
		return nil, nil
	}

	if len(body) == 0 {
		return nil, nil
	}

	var overview traefikOverviewResponse
	if err := json.Unmarshal(body, &overview); err != nil {
		return nil, nil
	}

	// Require all three protocol sections (http, tcp, udp) to be present.
	if overview.HTTP == nil || overview.TCP == nil || overview.UDP == nil {
		return nil, nil
	}

	// HTTP and TCP require all three sub-keys (routers, services, middlewares).
	// UDP has no middleware support in Traefik, so only routers and services are required.
	if !hasAllSections(overview.HTTP) || !hasAllSections(overview.TCP) {
		return nil, nil
	}
	if overview.UDP.Routers == nil || overview.UDP.Services == nil {
		return nil, nil
	}

	// For UDP, middlewares may be nil (Traefik doesn't support UDP middlewares).
	udpMiddlewares := 0
	if overview.UDP.Middlewares != nil {
		udpMiddlewares = overview.UDP.Middlewares.Total
	}

	return &FingerprintResult{
		Technology: "traefik-dashboard",
		Version:    "",
		CPEs:       []string{buildTraefikCPE("")},
		Metadata: map[string]any{
			"http_routers":     overview.HTTP.Routers.Total,
			"http_services":    overview.HTTP.Services.Total,
			"http_middlewares": overview.HTTP.Middlewares.Total,
			"tcp_routers":      overview.TCP.Routers.Total,
			"tcp_services":     overview.TCP.Services.Total,
			"tcp_middlewares":  overview.TCP.Middlewares.Total,
			"udp_routers":      overview.UDP.Routers.Total,
			"udp_services":     overview.UDP.Services.Total,
			"udp_middlewares":  udpMiddlewares,
			"detection_method": "api_overview",
		},
	}, nil
}

// hasAllSections returns true if all three required sub-keys are non-nil.
func hasAllSections(s *traefikProtocolSection) bool {
	return s.Routers != nil && s.Services != nil && s.Middlewares != nil
}

// --- TraefikVersionFingerprinter ---

func (f *TraefikVersionFingerprinter) Name() string {
	return "traefik-api"
}

func (f *TraefikVersionFingerprinter) ProbeEndpoint() string {
	return "/api/version"
}

func (f *TraefikVersionFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode >= 500 {
		return false
	}
	return isTraefikJSONContentType(resp.Header.Get("Content-Type"))
}

func (f *TraefikVersionFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp.StatusCode >= 500 {
		return nil, nil
	}

	// 1 MiB body cap — Traefik version responses are small JSON documents.
	if len(body) > 1*1024*1024 {
		return nil, nil
	}

	if len(body) == 0 {
		return nil, nil
	}

	var ver traefikVersionResponse
	if err := json.Unmarshal(body, &ver); err != nil {
		return nil, nil
	}

	// Codename is required; it is the uniquely Traefik-specific field.
	if ver.Codename == "" {
		return nil, nil
	}

	// Extract and validate version for CPE. Strip a leading v/V prefix (Traefik's
	// /api/version endpoint returns versions like "v3.2.0"). An absent or non-semver
	// version uses a wildcard CPE; detection still fires because Codename is present.
	version := ""
	rawVersion := strings.TrimPrefix(ver.Version, "v")
	rawVersion = strings.TrimPrefix(rawVersion, "V")
	if !strings.ContainsAny(rawVersion, ":*?") && traefikVersionRegex.MatchString(rawVersion) {
		version = rawVersion
	}

	metadata := map[string]any{
		"codename":         sanitizeHTTPHeaderValue(ver.Codename),
		"detection_method": "api_version",
	}
	if ver.StartDate != "" {
		metadata["startDate"] = sanitizeHTTPHeaderValue(ver.StartDate)
	}

	return &FingerprintResult{
		Technology: "traefik-api",
		Version:    version,
		CPEs:       []string{buildTraefikCPE(version)},
		Metadata:   metadata,
	}, nil
}
