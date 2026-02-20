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
	"testing"
)

func TestTeamCityFingerprinter_Name(t *testing.T) {
	fp := &TeamCityFingerprinter{}
	if got := fp.Name(); got != "teamcity" {
		t.Errorf("Name() = %q, want %q", got, "teamcity")
	}
}

func TestTeamCityFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &TeamCityFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/app/rest/server" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/app/rest/server")
	}
}

func TestTeamCityFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string]string
		want    bool
	}{
		{
			name:    "TeamCity-Node-Id header present returns true",
			headers: map[string]string{"TeamCity-Node-Id": "MAIN_SERVER"},
			want:    true,
		},
		{
			name:    "X-TC-CSRF-Token header present returns true",
			headers: map[string]string{"X-TC-CSRF-Token": "abc123def456"},
			want:    true,
		},
		{
			name: "Both TeamCity headers present returns true",
			headers: map[string]string{
				"TeamCity-Node-Id": "MAIN_SERVER",
				"X-TC-CSRF-Token":  "abc123def456",
			},
			want: true,
		},
		{
			name:    "No TeamCity headers returns false",
			headers: map[string]string{"Content-Type": "text/html"},
			want:    false,
		},
		{
			name:    "Empty headers returns false",
			headers: map[string]string{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TeamCityFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCleanTeamCityVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Version with build suffix",
			version: "2023.11.4 (build 147571)",
			want:    "2023.11.4",
		},
		{
			name:    "Version without build suffix",
			version: "2023.11.4",
			want:    "2023.11.4",
		},
		{
			name:    "Two-part version with build suffix",
			version: "2024.1 (build 150000)",
			want:    "2024.1",
		},
		{
			name:    "Empty string",
			version: "",
			want:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cleanTeamCityVersion(tt.version); got != tt.want {
				t.Errorf("cleanTeamCityVersion(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestTeamCityVersionRegex(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    bool
	}{
		{name: "Valid three-part", version: "2023.11.4", want: true},
		{name: "Valid two-part", version: "2024.1", want: true},
		{name: "Valid two-part double digit minor", version: "2023.11", want: true},
		{name: "Reject CPE injection", version: "10.0.0:*:*:*:*:*:*:*", want: false},
		{name: "Reject non-year prefix", version: "10.4.1", want: false},
		{name: "Reject uncleaned with build suffix", version: "2023.11.4 (build 147571)", want: false},
		{name: "Reject empty", version: "", want: false},
		{name: "Reject alphabetic", version: "abc", want: false},
		{name: "Reject year only", version: "2023", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := teamcityVersionRegex.MatchString(tt.version); got != tt.want {
				t.Errorf("teamcityVersionRegex.MatchString(%q) = %v, want %v", tt.version, got, tt.want)
			}
		})
	}
}

func TestBuildTeamCityCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "2023.11.4",
			want:    "cpe:2.3:a:jetbrains:teamcity:2023.11.4:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:jetbrains:teamcity:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildTeamCityCPE(tt.version); got != tt.want {
				t.Errorf("buildTeamCityCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestParseTeamCityJSON(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantVersion     string
		wantBuildNumber string
		wantInternalID  string
	}{
		{
			name: "Full JSON response",
			body: `{
				"version": "2023.11.4 (build 147571)",
				"versionMajor": 2023,
				"versionMinor": 11,
				"buildNumber": "147571",
				"buildDate": "20240301T000000+0000",
				"internalId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
				"webUrl": "https://teamcity.example.com"
			}`,
			wantVersion:     "2023.11.4 (build 147571)",
			wantBuildNumber: "147571",
			wantInternalID:  "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
		},
		{
			name:            "Minimal JSON response (version only)",
			body:            `{"version": "2024.1 (build 150000)"}`,
			wantVersion:     "2024.1 (build 150000)",
			wantBuildNumber: "",
			wantInternalID:  "",
		},
		{
			name:            "Invalid JSON",
			body:            "not json",
			wantVersion:     "",
			wantBuildNumber: "",
			wantInternalID:  "",
		},
		{
			name:            "JSON without version",
			body:            `{"buildNumber": "147571"}`,
			wantVersion:     "",
			wantBuildNumber: "",
			wantInternalID:  "",
		},
		{
			name:            "Empty body",
			body:            "",
			wantVersion:     "",
			wantBuildNumber: "",
			wantInternalID:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, buildNumber, internalID := parseTeamCityJSON([]byte(tt.body))
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
			if buildNumber != tt.wantBuildNumber {
				t.Errorf("buildNumber = %q, want %q", buildNumber, tt.wantBuildNumber)
			}
			if internalID != tt.wantInternalID {
				t.Errorf("internalID = %q, want %q", internalID, tt.wantInternalID)
			}
		})
	}
}

func TestParseTeamCityXML(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantVersion     string
		wantBuildNumber string
		wantInternalID  string
	}{
		{
			name:            "Full XML response (self-closing)",
			body:            `<server version="2023.11.4 (build 147571)" buildNumber="147571" internalId="a1b2c3d4" webUrl="https://tc.example.com"/>`,
			wantVersion:     "2023.11.4 (build 147571)",
			wantBuildNumber: "147571",
			wantInternalID:  "a1b2c3d4",
		},
		{
			name:            "XML response with closing tag",
			body:            `<server version="2024.1 (build 150000)" buildNumber="150000"></server>`,
			wantVersion:     "2024.1 (build 150000)",
			wantBuildNumber: "150000",
			wantInternalID:  "",
		},
		{
			name:            "Invalid XML",
			body:            "not xml",
			wantVersion:     "",
			wantBuildNumber: "",
			wantInternalID:  "",
		},
		{
			name:            "XML without version attribute",
			body:            `<server buildNumber="147571"/>`,
			wantVersion:     "",
			wantBuildNumber: "",
			wantInternalID:  "",
		},
		{
			name:            "Empty body",
			body:            "",
			wantVersion:     "",
			wantBuildNumber: "",
			wantInternalID:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			version, buildNumber, internalID := parseTeamCityXML([]byte(tt.body))
			if version != tt.wantVersion {
				t.Errorf("version = %q, want %q", version, tt.wantVersion)
			}
			if buildNumber != tt.wantBuildNumber {
				t.Errorf("buildNumber = %q, want %q", buildNumber, tt.wantBuildNumber)
			}
			if internalID != tt.wantInternalID {
				t.Errorf("internalID = %q, want %q", internalID, tt.wantInternalID)
			}
		})
	}
}

func TestTeamCityFingerprinter_Fingerprint_ValidJSON(t *testing.T) {
	tests := []struct {
		name            string
		headers         map[string]string
		body            string
		wantVersion     string
		wantBuildNumber string
		wantInternalID  string
		wantNodeID      string
	}{
		{
			name:    "Full JSON response with headers",
			headers: map[string]string{"TeamCity-Node-Id": "MAIN_SERVER"},
			body: `{
				"version": "2023.11.4 (build 147571)",
				"versionMajor": 2023,
				"versionMinor": 11,
				"buildNumber": "147571",
				"internalId": "a1b2c3d4-e5f6-7890-abcd-ef1234567890"
			}`,
			wantVersion:     "2023.11.4",
			wantBuildNumber: "147571",
			wantInternalID:  "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
			wantNodeID:      "MAIN_SERVER",
		},
		{
			name: "Two-part version (2024.1)",
			body: `{
				"version": "2024.1 (build 150000)",
				"buildNumber": "150000"
			}`,
			wantVersion:     "2024.1",
			wantBuildNumber: "150000",
		},
		{
			name: "Version without build suffix",
			body: `{
				"version": "2023.11",
				"buildNumber": "140000"
			}`,
			wantVersion:     "2023.11",
			wantBuildNumber: "140000",
		},
		{
			name: "Older version (2019.2.3)",
			body: `{
				"version": "2019.2.3 (build 72059)",
				"buildNumber": "72059",
				"internalId": "deadbeef-1234"
			}`,
			wantVersion:     "2019.2.3",
			wantBuildNumber: "72059",
			wantInternalID:  "deadbeef-1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TeamCityFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "teamcity" {
				t.Errorf("Technology = %q, want %q", result.Technology, "teamcity")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check CPE
			expectedCPE := "cpe:2.3:a:jetbrains:teamcity:" + tt.wantVersion + ":*:*:*:*:*:*:*"
			if len(result.CPEs) == 0 || result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %v, want [%q]", result.CPEs, expectedCPE)
			}

			// Check metadata
			if tt.wantBuildNumber != "" {
				if bn, ok := result.Metadata["buildNumber"].(string); !ok || bn != tt.wantBuildNumber {
					t.Errorf("Metadata[buildNumber] = %v, want %q", result.Metadata["buildNumber"], tt.wantBuildNumber)
				}
			}
			if tt.wantInternalID != "" {
				if id, ok := result.Metadata["internalId"].(string); !ok || id != tt.wantInternalID {
					t.Errorf("Metadata[internalId] = %v, want %q", result.Metadata["internalId"], tt.wantInternalID)
				}
			}
			if tt.wantNodeID != "" {
				if nid, ok := result.Metadata["nodeId"].(string); !ok || nid != tt.wantNodeID {
					t.Errorf("Metadata[nodeId] = %v, want %q", result.Metadata["nodeId"], tt.wantNodeID)
				}
			}
		})
	}
}

func TestTeamCityFingerprinter_Fingerprint_ValidXML(t *testing.T) {
	fp := &TeamCityFingerprinter{}
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("TeamCity-Node-Id", "NODE_1")

	body := `<server version="2023.11.4 (build 147571)" buildNumber="147571" internalId="abc123" webUrl="https://tc.example.com"/>`

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil for valid XML")
	}
	if result.Version != "2023.11.4" {
		t.Errorf("Version = %q, want %q", result.Version, "2023.11.4")
	}
	if result.Metadata["nodeId"] != "NODE_1" {
		t.Errorf("Metadata[nodeId] = %v, want %q", result.Metadata["nodeId"], "NODE_1")
	}
	if result.Metadata["buildNumber"] != "147571" {
		t.Errorf("Metadata[buildNumber] = %v, want %q", result.Metadata["buildNumber"], "147571")
	}
}

func TestTeamCityFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Non-JSON/XML body",
			body: "OK",
		},
		{
			name: "JSON without version",
			body: `{"buildNumber": "147571"}`,
		},
		{
			name: "Empty JSON object",
			body: `{}`,
		},
		{
			name: "Empty string",
			body: "",
		},
		{
			name: "Version with CPE injection attempt",
			body: `{"version": "10.0.0:*:*:*:*:*:*:*"}`,
		},
		{
			name: "Non-year version format",
			body: `{"version": "10.4.1"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &TeamCityFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

func TestTeamCityFingerprinter_Integration(t *testing.T) {
	fp := &TeamCityFingerprinter{}
	Register(fp)

	body := []byte(`{
		"version": "2023.11.4 (build 147571)",
		"versionMajor": 2023,
		"versionMinor": 11,
		"buildNumber": "147571",
		"internalId": "a1b2c3d4"
	}`)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("TeamCity-Node-Id", "MAIN_SERVER")

	results := RunFingerprinters(resp, body)

	found := false
	for _, result := range results {
		if result.Technology == "teamcity" {
			found = true
			if result.Version != "2023.11.4" {
				t.Errorf("Version = %q, want %q", result.Version, "2023.11.4")
			}
		}
	}

	if !found {
		t.Error("TeamCityFingerprinter not found in RunFingerprinters results")
	}
}

func TestTeamCityFingerprinter_Fingerprint_HeaderOnly(t *testing.T) {
	fp := &TeamCityFingerprinter{}
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("TeamCity-Node-Id", "MAIN_SERVER")

	// Body is plain text (like a 401 response)
	body := []byte("There is no administrator account on the server")

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil for header-only detection")
	}
	if result.Technology != "teamcity" {
		t.Errorf("Technology = %q, want %q", result.Technology, "teamcity")
	}
	if result.Version != "" {
		t.Errorf("Version = %q, want empty string", result.Version)
	}
	// CPE should use wildcard for unknown version
	expectedCPE := "cpe:2.3:a:jetbrains:teamcity:*:*:*:*:*:*:*:*"
	if len(result.CPEs) == 0 || result.CPEs[0] != expectedCPE {
		t.Errorf("CPE = %v, want [%q]", result.CPEs, expectedCPE)
	}
	if result.Metadata["nodeId"] != "MAIN_SERVER" {
		t.Errorf("Metadata[nodeId] = %v, want %q", result.Metadata["nodeId"], "MAIN_SERVER")
	}
}

func TestTeamCityFingerprinter_Fingerprint_HeaderWithInvalidVersion(t *testing.T) {
	fp := &TeamCityFingerprinter{}
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("TeamCity-Node-Id", "MAIN_SERVER")

	// Body has CPE injection attempt, but header is present
	body := []byte(`{"version": "10.0.0:*:*:*:*:*:*:*"}`)

	result, err := fp.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil despite header detection")
	}
	if result.Version != "" {
		t.Errorf("Version = %q, want empty (invalid version should be discarded)", result.Version)
	}
	if result.Metadata["nodeId"] != "MAIN_SERVER" {
		t.Errorf("Metadata[nodeId] = %v, want %q", result.Metadata["nodeId"], "MAIN_SERVER")
	}
}
