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
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// EtcdFingerprinter detects etcd distributed key-value store via /version endpoint.
// Detection is based on the presence of "etcdserver" field in the JSON response.
type EtcdFingerprinter struct{}

func init() {
	Register(&EtcdFingerprinter{})
}

// etcdVersionResponse represents the JSON response from /version endpoint
type etcdVersionResponse struct {
	ETCDServer  string `json:"etcdserver"`
	ETCDCluster string `json:"etcdcluster"`
}

// versionRegex validates etcd version format (X.Y.Z)
var etcdVersionRegex = regexp.MustCompile(`^\d+\.\d+\.\d+$`)

func (f *EtcdFingerprinter) Name() string {
	return "etcd"
}

// ProbeEndpoint returns the endpoint needed for etcd detection.
// etcd exposes version info at /version endpoint.
func (f *EtcdFingerprinter) ProbeEndpoint() string {
	return "/version"
}

// Match returns true if the response might be from etcd (JSON content type).
func (f *EtcdFingerprinter) Match(resp *http.Response) bool {
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "application/json")
}

// Fingerprint performs etcd detection by parsing the /version JSON response.
func (f *EtcdFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Parse JSON response
	var data etcdVersionResponse
	if err := json.Unmarshal(body, &data); err != nil {
		return nil, nil // Not valid JSON
	}

	// etcd detection: etcdserver field must be non-empty
	if data.ETCDServer == "" {
		return nil, nil
	}

	// Validate version format (X.Y.Z)
	if !etcdVersionRegex.MatchString(data.ETCDServer) {
		return nil, nil
	}

	// Build metadata
	metadata := map[string]any{}
	if data.ETCDCluster != "" {
		metadata["cluster_version"] = data.ETCDCluster
	}

	return &FingerprintResult{
		Technology: "etcd",
		Version:    data.ETCDServer,
		CPEs:       []string{buildEtcdCPE(data.ETCDServer)},
		Metadata:   metadata,
		Severity:   plugins.SeverityHigh,
	}, nil
}

// buildEtcdCPE generates CPE string for etcd.
// Format: cpe:2.3:a:etcd-io:etcd:{version}:*:*:*:*:*:*:*
func buildEtcdCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:etcd-io:etcd:%s:*:*:*:*:*:*:*", version)
}
