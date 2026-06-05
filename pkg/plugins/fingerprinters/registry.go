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

// Package fingerprinters provides HTTP application fingerprinting.
// These fingerprinters detect applications running over HTTP and return
// technology/CPE metadata to attach to the HTTP service payload.
package fingerprinters

import (
	"net/http"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// FingerprintResult contains the detected technology information
type FingerprintResult struct {
	Technology       string                    // e.g., "kubernetes"
	Version          string                    // e.g., "1.29.0"
	CPEs             []string                  // e.g., ["cpe:2.3:a:kubernetes:kubernetes:1.29.0:*:*:*:*:*:*:*"]
	Metadata         map[string]any            // service-specific additional data
	Severity         plugins.Severity          // severity for anonymous access finding if detected
	SecurityFindings []plugins.SecurityFinding // custom findings (used instead of generic anon-access when non-empty)
}

// HTTPFingerprinter detects applications running over HTTP
type HTTPFingerprinter interface {
	// Name returns the fingerprinter identifier
	Name() string

	// Match returns true if this fingerprinter should attempt detection
	// This is a fast pre-filter based on headers/status before reading body
	Match(resp *http.Response) bool

	// Fingerprint performs full detection and extracts technology info
	// body is the response body (already read)
	Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error)
}

// ActiveHTTPFingerprinter extends HTTPFingerprinter with the ability to make
// additional HTTP requests for enrichment. Use this when detection requires
// querying specific endpoints (e.g., Kubernetes /version).
type ActiveHTTPFingerprinter interface {
	HTTPFingerprinter

	// ProbeEndpoint returns the endpoint path to probe for this fingerprinter.
	// Return "" to use the default "/" endpoint.
	// Examples: "/version", "/api/v1/version", "/_cluster/health"
	ProbeEndpoint() string
}

// AcceptHeaderProvider is an optional interface that ActiveHTTPFingerprinters
// can implement to specify a custom Accept header for their probe requests.
// If not implemented, the default "application/json" is used.
type AcceptHeaderProvider interface {
	// ProbeAccept returns the Accept header value to use for the probe request.
	ProbeAccept() string
}

// MisconfigHTTPFingerprinter extends HTTPFingerprinter with security
// misconfiguration checks that require additional HTTP requests.
// CheckMisconfigs is called by the HTTP service layer when target.Misconfigs
// is true, after the fingerprinter has already matched and fingerprinted.
type MisconfigHTTPFingerprinter interface {
	HTTPFingerprinter
	CheckMisconfigs(client *http.Client, baseURL, host string) []plugins.SecurityFinding
}

var httpFingerprinters []HTTPFingerprinter

// Register adds a fingerprinter to the registry
func Register(fp HTTPFingerprinter) {
	httpFingerprinters = append(httpFingerprinters, fp)
}

// GetFingerprinters returns all registered fingerprinters
func GetFingerprinters() []HTTPFingerprinter {
	return httpFingerprinters
}

// RunFingerprinters executes all matching passive fingerprinters and returns results.
// Active fingerprinters with a dedicated probe endpoint (not "/" or "") are skipped
// here and run separately in the active phase against their specific endpoint response.
func RunFingerprinters(resp *http.Response, body []byte) []*FingerprintResult {
	var results []*FingerprintResult
	for _, fp := range httpFingerprinters {
		if active, ok := fp.(ActiveHTTPFingerprinter); ok {
			if endpoint := active.ProbeEndpoint(); endpoint != "" && endpoint != "/" {
				continue
			}
		}
		if fp.Match(resp) {
			if result, err := fp.Fingerprint(resp, body); err == nil && result != nil {
				results = append(results, result)
			}
		}
	}
	return results
}

// GetProbeEndpoints returns a map of fingerprinter name to probe endpoint
// for all registered ActiveHTTPFingerprinters.
func GetProbeEndpoints() map[string]string {
	endpoints := make(map[string]string)
	for _, fp := range httpFingerprinters {
		if active, ok := fp.(ActiveHTTPFingerprinter); ok {
			if endpoint := active.ProbeEndpoint(); endpoint != "" {
				endpoints[fp.Name()] = endpoint
			}
		}
	}
	return endpoints
}

// GetFingerprinterByName returns the fingerprinter with the given name
func GetFingerprinterByName(name string) HTTPFingerprinter {
	for _, fp := range httpFingerprinters {
		if fp.Name() == name {
			return fp
		}
	}
	return nil
}
