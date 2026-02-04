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

package etcd

import (
	"regexp"
	"testing"
)

// Test parseETCDResponse with valid etcd version response
func TestParseETCDResponse_Valid(t *testing.T) {
	response := []byte(`{
		"etcdserver": "3.5.9",
		"etcdcluster": "3.5.0"
	}`)

	detected, version, clusterVersion := parseETCDResponse(response)

	if !detected {
		t.Error("Expected etcd to be detected")
	}

	if version != "3.5.9" {
		t.Errorf("Expected version 3.5.9, got %s", version)
	}

	if clusterVersion != "3.5.0" {
		t.Errorf("Expected cluster version 3.5.0, got %s", clusterVersion)
	}
}

// Test parseETCDResponse with missing etcdserver field
func TestParseETCDResponse_MissingETCDServer(t *testing.T) {
	response := []byte(`{
		"etcdcluster": "3.5.0"
	}`)

	detected, _, _ := parseETCDResponse(response)

	if detected {
		t.Error("Expected etcd to NOT be detected when etcdserver field is missing")
	}
}

// Test parseETCDResponse with empty response
func TestParseETCDResponse_Empty(t *testing.T) {
	response := []byte("")

	detected, _, _ := parseETCDResponse(response)

	if detected {
		t.Error("Expected etcd to NOT be detected with empty response")
	}
}

// Test parseETCDResponse with invalid JSON
func TestParseETCDResponse_InvalidJSON(t *testing.T) {
	response := []byte(`not valid json`)

	detected, _, _ := parseETCDResponse(response)

	if detected {
		t.Error("Expected etcd to NOT be detected with invalid JSON")
	}
}

// Test buildETCDCPE with valid version
func TestBuildETCDCPE_ValidVersion(t *testing.T) {
	cpe := buildETCDCPE("3.5.9")
	expected := "cpe:2.3:a:etcd-io:etcd:3.5.9:*:*:*:*:*:*:*"

	if cpe != expected {
		t.Errorf("Expected CPE %s, got %s", expected, cpe)
	}
}

// Test buildETCDCPE with empty version (unknown)
func TestBuildETCDCPE_UnknownVersion(t *testing.T) {
	cpe := buildETCDCPE("")
	expected := "cpe:2.3:a:etcd-io:etcd:*:*:*:*:*:*:*:*"

	if cpe != expected {
		t.Errorf("Expected CPE %s, got %s", expected, cpe)
	}
}

// Test version validation regex
func TestVersionValidation(t *testing.T) {
	versionRegex := regexp.MustCompile(`^\d+\.\d+\.\d+$`)

	validVersions := []string{"3.5.9", "1.0.0", "10.20.30"}
	for _, v := range validVersions {
		if !versionRegex.MatchString(v) {
			t.Errorf("Expected version %s to be valid", v)
		}
	}

	invalidVersions := []string{"3.5", "3.5.9.1", "abc", "", "v3.5.9"}
	for _, v := range invalidVersions {
		if versionRegex.MatchString(v) {
			t.Errorf("Expected version %s to be invalid", v)
		}
	}
}

// Test buildETCDHTTPRequest
func TestBuildETCDHTTPRequest(t *testing.T) {
	request := buildETCDHTTPRequest("/version", "localhost:2379")

	// Check that request contains required HTTP headers
	if !regexp.MustCompile(`GET /version HTTP/1\.1`).MatchString(request) {
		t.Error("Expected GET /version HTTP/1.1 in request")
	}

	if !regexp.MustCompile(`Host: localhost:2379`).MatchString(request) {
		t.Error("Expected Host: localhost:2379 in request")
	}

	if !regexp.MustCompile(`Connection: close`).MatchString(request) {
		t.Error("Expected Connection: close in request")
	}
}
