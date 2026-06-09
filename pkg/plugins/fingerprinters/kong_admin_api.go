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
Package fingerprinters provides HTTP fingerprinting for the Kong Admin API.

Detection Strategy:
  - Passive: root "/" response only — zero extra probes.
  - Required fields: tagline == "Welcome to kong" AND non-empty version.
  - Version extraction: root.version, validated against 2–4 dotted-segment
    pattern (3-part OSS, 4-part Enterprise). Falls back to "*" on mismatch.
  - Plugin inventory: sorted list from plugins.available_on_server map.
  - Ports: 8001 (HTTP Admin), 8444 (HTTPS Admin).
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"sort"
	"strings"
)

// KongAdminAPIFingerprinter detects Kong Gateway via the Admin API root response.
type KongAdminAPIFingerprinter struct{}

type kongRootResponse struct {
	Version       string `json:"version"`
	Tagline       string `json:"tagline"`
	NodeID        string `json:"node_id"`
	Hostname      string `json:"hostname"`
	LuaVersion    string `json:"lua_version"`
	Configuration struct {
		Database string `json:"database"`
	} `json:"configuration"`
	Plugins struct {
		AvailableOnServer map[string]json.RawMessage `json:"available_on_server"`
	} `json:"plugins"`
}

// kongVersionRegex accepts 2–4 dotted numeric segments: matches OSS (3-part)
// and Enterprise (4-part) version strings.
var kongVersionRegex = regexp.MustCompile(`^\d+\.\d+(\.\d+){0,2}$`)

func init() {
	Register(&KongAdminAPIFingerprinter{})
}

func (f *KongAdminAPIFingerprinter) Name() string {
	return "kong"
}

func (f *KongAdminAPIFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "application/json")
}

func (f *KongAdminAPIFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var root kongRootResponse
	if err := json.Unmarshal(body, &root); err != nil {
		return nil, nil
	}

	// Anchored detection: both fields required to avoid false positives.
	if root.Tagline != "Welcome to kong" || root.Version == "" {
		return nil, nil
	}

	version := root.Version
	if !kongVersionRegex.MatchString(version) {
		version = "*"
	}

	metadata := map[string]any{
		"node_id":     root.NodeID,
		"hostname":    root.Hostname,
		"lua_version": root.LuaVersion,
		"database":    root.Configuration.Database,
	}

	if len(root.Plugins.AvailableOnServer) > 0 {
		names := make([]string, 0, len(root.Plugins.AvailableOnServer))
		for name := range root.Plugins.AvailableOnServer {
			names = append(names, name)
		}
		sort.Strings(names)
		metadata["plugins"] = names
		metadata["plugin_count"] = len(names)
	}

	return &FingerprintResult{
		Technology: "kong",
		Version:    version,
		CPEs:       []string{buildKongCPE(version)},
		Metadata:   metadata,
	}, nil
}

// buildKongCPE returns the NVD-correct CPE 2.3 string for Kong Gateway.
// Vendor: konghq, Product: kong.
func buildKongCPE(version string) string {
	if version == "" || version == "*" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:konghq:kong:%s:*:*:*:*:*:*:*", version)
}
