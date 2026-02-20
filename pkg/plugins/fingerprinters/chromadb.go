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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// ChromaDBFingerprinter detects ChromaDB vector database via /api/v1/heartbeat endpoint
type ChromaDBFingerprinter struct{}

// chromadbHeartbeatResponse from the /api/v1/heartbeat endpoint
type chromadbHeartbeatResponse struct {
	NanosecondHeartbeat int64 `json:"nanosecond heartbeat"`
}

func init() {
	Register(&ChromaDBFingerprinter{})
}

func (f *ChromaDBFingerprinter) Name() string {
	return "chromadb"
}

func (f *ChromaDBFingerprinter) ProbeEndpoint() string {
	return "/api/v1/heartbeat"
}

func (f *ChromaDBFingerprinter) Match(resp *http.Response) bool {
	// ChromaDB API returns JSON
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

func (f *ChromaDBFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Try to parse as ChromaDB heartbeat response
	var heartbeat chromadbHeartbeatResponse
	if err := json.Unmarshal(body, &heartbeat); err != nil {
		return nil, nil // Not ChromaDB format
	}

	// Validate it's actually ChromaDB by checking the unique "nanosecond heartbeat" field
	// ChromaDB returns Unix nanosecond timestamps (> 1e18)
	const minNanosecondTimestamp = 1_000_000_000_000_000_000 // 1e18
	if heartbeat.NanosecondHeartbeat < minNanosecondTimestamp {
		return nil, nil
	}

	// ChromaDB detected! Return result with empty version (no version in heartbeat)
	// Note: Version extraction would require a separate call to /api/v1/version
	// which the HTTP plugin could implement separately
	return &FingerprintResult{
		Technology: "chromadb",
		Version:    "", // Version not available in heartbeat response
		CPEs:       []string{buildChromaDBCPE("")},
		Metadata: map[string]any{
			"heartbeat": heartbeat.NanosecondHeartbeat,
		},
	}, nil
}

func buildChromaDBCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:chroma:chromadb:%s:*:*:*:*:*:*:*", version)
}
