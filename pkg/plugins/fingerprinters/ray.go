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
Package fingerprinters provides HTTP fingerprinting for Ray AI/ML compute clusters.

# What We Detect

  - Ray dashboard instances via the /api/version endpoint, which returns JSON
    containing ray_version and ray_commit fields unique to Ray.

# What We Do NOT Detect

  - Ray GCS (gRPC on port 6379) — not HTTP
  - Ray Serve proxy (Uvicorn on port 8000) — separate service
  - Ray deployments that restrict the /api/version endpoint

# CPE

cpe:2.3:a:anyscale:ray:{version}:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// RayFingerprinter detects Ray AI/ML compute clusters via the /api/version
// endpoint on the Ray dashboard (default port 8265).
type RayFingerprinter struct{}

type rayVersionResponse struct {
	Version     string `json:"version"`
	RayVersion  string `json:"ray_version"`
	RayCommit   string `json:"ray_commit"`
	SessionName string `json:"session_name"`
}

var rayVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func init() {
	Register(&RayFingerprinter{})
}

func (f *RayFingerprinter) Name() string {
	return "ray"
}

func (f *RayFingerprinter) ProbeEndpoint() string {
	return "/api/version"
}

func (f *RayFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode != http.StatusOK {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "application/json")
}

func (f *RayFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if len(body) > 2*1024*1024 {
		return nil, nil
	}

	var vResp rayVersionResponse
	if err := json.Unmarshal(body, &vResp); err != nil {
		return nil, nil
	}

	if vResp.RayVersion == "" || vResp.RayCommit == "" {
		return nil, nil
	}

	version := vResp.RayVersion
	if !rayVersionRegex.MatchString(version) {
		version = ""
	}
	if strings.ContainsAny(version, ":*") {
		version = ""
	}

	metadata := map[string]any{
		"ray_version": vResp.RayVersion,
		"ray_commit":  vResp.RayCommit,
	}
	if vResp.Version != "" {
		metadata["api_version"] = vResp.Version
	}
	if vResp.SessionName != "" {
		metadata["session_name"] = vResp.SessionName
	}

	return &FingerprintResult{
		Technology: "ray",
		Version:    version,
		CPEs:       []string{buildRayCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildRayCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:anyscale:ray:%s:*:*:*:*:*:*:*", version)
}
