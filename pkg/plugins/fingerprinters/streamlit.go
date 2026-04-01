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
Package fingerprinters provides HTTP fingerprinting for Streamlit.

# Detection Strategy

Streamlit is an open-source Python framework for building interactive web
applications for data science and machine learning. Exposed instances
represent a security concern due to:
  - Direct access to Python application logic
  - Potential access to sensitive data and ML models
  - Often deployed without authentication in internal environments
  - Can execute arbitrary code through interactive widgets

Detection uses active probing:
  - Active: Query /_stcore/health endpoint (no authentication required)
  - Response body must be exactly "ok" (2 bytes, no JSON)

# Health Endpoint Response Format

The /_stcore/health endpoint returns a plain text response:

	ok

Content-Type: text/html; charset=UTF-8
Server: TornadoServer/6.x (when not behind reverse proxy)
Cache-Control: no-cache

# Version Notes

Streamlit does NOT expose version information via the health endpoint.
Version detection is not available without authentication.

# Port Configuration

Streamlit typically runs on:
  - 8501: Default Streamlit port
  - 80/443: When behind reverse proxy

# Example Usage

	fp := &StreamlitFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s\n", result.Technology)
		}
	}
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"strings"
)

// StreamlitFingerprinter detects Streamlit instances via /_stcore/health endpoint
type StreamlitFingerprinter struct{}

func init() {
	Register(&StreamlitFingerprinter{})
}

func (f *StreamlitFingerprinter) Name() string {
	return "streamlit"
}

func (f *StreamlitFingerprinter) ProbeEndpoint() string {
	return "/_stcore/health"
}

func (f *StreamlitFingerprinter) Match(resp *http.Response) bool {
	// Check for text/html Content-Type header
	// Streamlit health endpoint returns text/html, not JSON
	// Use as pre-filter to avoid false positives on JSON APIs
	return strings.Contains(resp.Header.Get("Content-Type"), "text/html")
}

func (f *StreamlitFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Streamlit health endpoint returns exactly "ok" (plain text, possibly with whitespace)
	trimmed := strings.TrimSpace(string(body))
	if trimmed != "ok" {
		return nil, nil // Not Streamlit
	}

	// Extract TornadoServer version from Server header if present (metadata only)
	metadata := map[string]any{}
	if server := resp.Header.Get("Server"); strings.HasPrefix(server, "TornadoServer/") {
		metadata["server"] = server
	}

	return &FingerprintResult{
		Technology: "streamlit",
		Version:    "",
		CPEs:       []string{buildStreamlitCPE("")},
		Metadata:   metadata,
	}, nil
}

func buildStreamlitCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:streamlit:streamlit:%s:*:*:*:*:*:*:*", version)
}
