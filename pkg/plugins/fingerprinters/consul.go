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
Package fingerprinters provides HTTP fingerprinting for HashiCorp Consul.

Detection Strategy:
  - Active probe: /v1/agent/self endpoint
  - Required field: Config.Datacenter (Consul-specific)
  - Version extraction: Config.Version with Enterprise (+ent) detection
  - Ports: 8500 (HTTP), 8501 (HTTPS)
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// ConsulFingerprinter detects HashiCorp Consul via /v1/agent/self
type ConsulFingerprinter struct{}

type consulAgentResponse struct {
	Config struct {
		Datacenter string `json:"Datacenter"`
		NodeName   string `json:"NodeName"`
		Version    string `json:"Version"`
		Server     bool   `json:"Server"`
	} `json:"Config"`
}

var consulVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+(\+[a-zA-Z0-9._-]+)?$`)

func init() {
	Register(&ConsulFingerprinter{})
}

func (f *ConsulFingerprinter) Name() string {
	return "consul"
}

func (f *ConsulFingerprinter) ProbeEndpoint() string {
	return "/v1/agent/self"
}

func (f *ConsulFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *ConsulFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var agent consulAgentResponse
	if err := json.Unmarshal(body, &agent); err != nil {
		return nil, nil
	}

	if agent.Config.Datacenter == "" {
		return nil, nil
	}

	version := agent.Config.Version
	enterprise := false

	if strings.Contains(version, "+ent") {
		parts := strings.Split(version, "+")
		version = parts[0]
		enterprise = true
	}

	if version != "" && !consulVersionRegex.MatchString(version) {
		version = ""
	}

	if version == "" {
		version = "*"
	}

	metadata := map[string]any{
		"datacenter": agent.Config.Datacenter,
		"node_name":   agent.Config.NodeName,
		"server":     agent.Config.Server,
		"enterprise": enterprise,
	}

	return &FingerprintResult{
		Technology: "consul",
		Version:    version,
		CPEs:       []string{buildConsulCPE(version)},
		Metadata:   metadata,
		Severity:   plugins.SeverityMedium,
	}, nil
}

func buildConsulCPE(version string) string {
	if version == "" || version == "*" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:hashicorp:consul:%s:*:*:*:*:*:*:*", version)
}
