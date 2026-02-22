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

func TestVMwareHorizonFingerprinter_Name(t *testing.T) {
	fp := &VMwareHorizonFingerprinter{}
	if got := fp.Name(); got != "vmware-horizon" {
		t.Errorf("Name() = %q, want %q", got, "vmware-horizon")
	}
}

func TestVMwareHorizonFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &VMwareHorizonFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/portal/webclient/index.html" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/portal/webclient/index.html")
	}
}

func TestVMwareHorizonFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{
			name:       "200 status code - accept",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "404 status code - accept",
			statusCode: 404,
			want:       true,
		},
		{
			name:       "302 redirect - accept",
			statusCode: 302,
			want:       true,
		},
		{
			name:       "5xx server error - reject",
			statusCode: 500,
			want:       false,
		},
		{
			name:       "503 service unavailable - reject",
			statusCode: 503,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &VMwareHorizonFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}

			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVMwareHorizonFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name          string
		body          string
		wantComponent string
		wantVersion   string
	}{
		{
			name:          "UAG Blast endpoint",
			body:          "Missing route token in request",
			wantComponent: "UAG",
			wantVersion:   "",
		},
		{
			name:          "Connection Server HTML",
			body:          "<html><head><title>VMware Horizon</title></head><body></body></html>",
			wantComponent: "Connection Server",
			wantVersion:   "",
		},
		{
			name: "Info.jsp with clientVersion",
			body: `{
				"clientVersion": "8.10.0",
				"serverVersion": "8.10.0"
			}`,
			wantComponent: "Connection Server",
			wantVersion:   "8.10.0",
		},
		{
			name: "HTML with version reference",
			body: `<html>
				<head><title>VMware Horizon</title></head>
				<body>
					<script>var version = "2111.1";</script>
				</body>
			</html>`,
			wantComponent: "Connection Server",
			wantVersion:   "2111.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &VMwareHorizonFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "vmware-horizon" {
				t.Errorf("Technology = %q, want %q", result.Technology, "vmware-horizon")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check metadata
			if vendor, ok := result.Metadata["vendor"].(string); !ok || vendor != "VMware" {
				t.Errorf("Metadata[vendor] = %v, want %v", vendor, "VMware")
			}
			if product, ok := result.Metadata["product"].(string); !ok || product != "Horizon" {
				t.Errorf("Metadata[product] = %v, want %v", product, "Horizon")
			}
			if component, ok := result.Metadata["component"].(string); !ok || component != tt.wantComponent {
				t.Errorf("Metadata[component] = %v, want %v", component, tt.wantComponent)
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := buildVMwareHorizonCPE(tt.wantVersion)
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestVMwareHorizonFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Random HTML without Horizon markers",
			body: "<html><head><title>Apache Server</title></head></html>",
		},
		{
			name: "Empty body",
			body: "",
		},
		{
			name: "JSON without clientVersion",
			body: `{"serverVersion": "8.10.0"}`,
		},
		{
			name: "Body with just 'VMware' but not 'Horizon'",
			body: "<title>VMware vCenter</title>",
		},
		{
			name: "Version with CPE injection",
			body: `{"clientVersion": "8.0:*:*:*:*:*:*:*"}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &VMwareHorizonFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
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

func TestBuildVMwareHorizonCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "8.10.0",
			want:    "cpe:2.3:a:vmware:horizon:8.10.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:vmware:horizon:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildVMwareHorizonCPE(tt.version); got != tt.want {
				t.Errorf("buildVMwareHorizonCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestVMwareHorizonFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &VMwareHorizonFingerprinter{}
	Register(fp)

	// Create a valid UAG response
	body := []byte("Missing route token in request")

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	results := RunFingerprinters(resp, body)

	// Should find at least the VMware Horizon fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "vmware-horizon" {
			found = true
			if component, ok := result.Metadata["component"].(string); !ok || component != "UAG" {
				t.Errorf("component = %q, want %q", component, "UAG")
			}
		}
	}

	if !found {
		t.Error("VMwareHorizonFingerprinter not found in results")
	}
}
