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
)

// PineconeFingerprinter detects Pinecone Vector Database instances via header-based detection.
//
// Detection Strategy:
// Pinecone is a managed vector database (SaaS) that runs on HTTPS. When an unauthenticated
// request is sent to a Pinecone endpoint, the service returns a 401 Unauthorized response
// with Pinecone-specific headers:
//   - X-Pinecone-Api-Version (PRIMARY marker - unique to Pinecone)
//   - X-Pinecone-Auth-Rejected-Reason (SECONDARY marker)
//
// Version Detection:
// The X-Pinecone-Api-Version header contains the API version (e.g., "2025-01"), not the
// internal Pinecone service version. Since Pinecone is closed-source SaaS, the internal
// version cannot be determined. Therefore, the CPE uses a wildcard version.
type PineconeFingerprinter struct{}

const (
	// Header constants for detection
	headerAPIVersion   = "X-Pinecone-Api-Version"
	headerAuthRejected = "X-Pinecone-Auth-Rejected-Reason"
)

func init() {
	Register(&PineconeFingerprinter{})
}

func (f *PineconeFingerprinter) Name() string {
	return "pinecone"
}

// Match returns true for ALL responses.
// We need to check headers regardless of content type since detection is header-based.
func (f *PineconeFingerprinter) Match(resp *http.Response) bool {
	return true
}

// Fingerprint performs detection by checking for Pinecone-specific headers.
//
// Detection Phases:
//   1. PRIMARY: Check for X-Pinecone-Api-Version header (unique to Pinecone)
//   2. SECONDARY: Check for X-Pinecone-Auth-Rejected-Reason header (fallback)
//
// Returns:
//   - *FingerprintResult with Pinecone detection if headers present
//   - nil if not detected
//   - error is always nil (no parsing errors possible for header-based detection)
func (f *PineconeFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// PRIMARY detection: X-Pinecone-Api-Version header (unique to Pinecone)
	apiVersion := resp.Header.Get(headerAPIVersion)
	if apiVersion != "" {
		return &FingerprintResult{
			Technology: "pinecone",
			Version:    "*", // Internal version unknown for closed-source SaaS
			CPEs:       []string{buildPineconeCPE()},
			Metadata: map[string]any{
				"api_version": apiVersion,
			},
		}, nil
	}

	// SECONDARY detection: X-Pinecone-Auth-Rejected-Reason (fallback)
	authRejected := resp.Header.Get(headerAuthRejected)
	if authRejected != "" {
		return &FingerprintResult{
			Technology: "pinecone",
			Version:    "*",
			CPEs:       []string{buildPineconeCPE()},
			Metadata:   map[string]any{},
		}, nil
	}

	// Not a Pinecone instance
	return nil, nil
}

// buildPineconeCPE constructs the CPE for Pinecone.
//
// CPE Format: cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*
//   - Version field is wildcard (*) because internal service version is unavailable
//   - Only API version (from header) is known, which represents API contract not service version
func buildPineconeCPE() string {
	return "cpe:2.3:a:pinecone:pinecone:*:*:*:*:*:*:*:*"
}
