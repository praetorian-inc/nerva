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

func TestCiscoExpresswayFingerprinter_Name(t *testing.T) {
	fp := &CiscoExpresswayFingerprinter{}
	if got := fp.Name(); got != "cisco-expressway" {
		t.Errorf("Name() = %q, want %q", got, "cisco-expressway")
	}
}

func TestCiscoExpresswayFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &CiscoExpresswayFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/login" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/login")
	}
}

func TestCiscoExpresswayFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		server     string
		want       bool
	}{
		{
			name:       "Server header contains 'Cisco'",
			statusCode: 200,
			server:     "Cisco/Expressway",
			want:       true,
		},
		{
			name:       "Server header contains 'Expressway'",
			statusCode: 200,
			server:     "Expressway-C",
			want:       true,
		},
		{
			name:       "Server header with 'cisco' (lowercase)",
			statusCode: 200,
			server:     "cisco",
			want:       true,
		},
		{
			name:       "Server header CE_E (Expressway-E)",
			statusCode: 200,
			server:     "CE_E",
			want:       true,
		},
		{
			name:       "Server header CE_C (Expressway-C)",
			statusCode: 200,
			server:     "CE_C",
			want:       true,
		},
		{
			name:       "Server header ce_e (lowercase)",
			statusCode: 200,
			server:     "ce_e",
			want:       true,
		},
		{
			name:       "Status code 200 with no matching header accepts for body check",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "Status code 500 returns false",
			statusCode: 500,
			want:       false,
		},
		{
			name:       "Status code 400 accepts for body check",
			statusCode: 400,
			want:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CiscoExpresswayFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			// Match() only checks headers/status, not body yet
			// We pass body to Fingerprint later
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCiscoExpresswayFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name        string
		body        string
		server      string
		wantVersion string
	}{
		{
			name:        "Cisco Expressway login page",
			body:        `<html><head><title>Cisco Expressway - Login</title></head><body><div class="expressway-header">Cisco Expressway</div></body></html>`,
			wantVersion: "",
		},
		{
			name:        "TelePresence VCS login page",
			body:        `<html><head><title>TelePresence Video Communication Server</title></head><body><div>TelePresence VCS</div></body></html>`,
			wantVersion: "",
		},
		{
			name:        "TANDBERG VCS (legacy)",
			body:        `<html><head><title>TANDBERG VCS</title></head><body>TANDBERG Video Communication Server</body></html>`,
			wantVersion: "",
		},
		{
			name:        "With version X14.3.2",
			body:        `<html><head><title>Cisco Expressway</title></head><body>Version X14.3.2</body></html>`,
			wantVersion: "X14.3.2",
		},
		{
			name:        "With version X15.0.1",
			body:        `<html><head><title>Expressway Login</title></head><body>Expressway version: X15.0.1</body></html>`,
			wantVersion: "X15.0.1",
		},
		{
			name:        "With version 14.3.2 (no X prefix)",
			body:        `<html><head><title>Expressway</title></head><body>VCS version 14.3.2</body></html>`,
			wantVersion: "14.3.2",
		},
		{
			name:        "Invalid version format ignored (alphabetic)",
			body:        `<html><head><title>Expressway</title></head><body>Version: ABC.DEF.GHI</body></html>`,
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CiscoExpresswayFingerprinter{}
			resp := &http.Response{
				StatusCode: 200,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "cisco-expressway" {
				t.Errorf("Technology = %q, want %q", result.Technology, "cisco-expressway")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check metadata
			if vendor, ok := result.Metadata["vendor"].(string); !ok || vendor != "Cisco" {
				t.Errorf("Metadata[vendor] = %v, want %v", vendor, "Cisco")
			}
			if product, ok := result.Metadata["product"].(string); !ok || product != "Expressway" {
				t.Errorf("Metadata[product] = %v, want %v", product, "Expressway")
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}

			expectedCPE := buildCiscoExpresswayCPE(tt.wantVersion)
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestCiscoExpresswayFingerprinter_Fingerprint_ServerHeaderOnly(t *testing.T) {
	tests := []struct {
		name   string
		server string
		body   string
	}{
		{
			name:   "CE_E header with Bad Request body",
			server: "CE_E",
			body:   `<html><head><title>Bad Request</title></head><body></body></html>`,
		},
		{
			name:   "CE_C header with Bad Request body",
			server: "CE_C",
			body:   `<html><head><title>Bad Request</title></head><body></body></html>`,
		},
		{
			name:   "ce_e header (lowercase) with generic body",
			server: "ce_e",
			body:   `<html><head><title>Error</title></head><body>An error occurred</body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CiscoExpresswayFingerprinter{}
			resp := &http.Response{
				StatusCode: 400,
				Header:     make(http.Header),
			}
			resp.Header.Set("Server", tt.server)

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want result for CE_E/CE_C header")
			}

			if result.Technology != "cisco-expressway" {
				t.Errorf("Technology = %q, want %q", result.Technology, "cisco-expressway")
			}

			// Check metadata
			if vendor, ok := result.Metadata["vendor"].(string); !ok || vendor != "Cisco" {
				t.Errorf("Metadata[vendor] = %v, want %v", vendor, "Cisco")
			}
			if product, ok := result.Metadata["product"].(string); !ok || product != "Expressway" {
				t.Errorf("Metadata[product] = %v, want %v", product, "Expressway")
			}
		})
	}
}

func TestCiscoExpresswayFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "Generic Bad Request page (too generic)",
			body: `<html><head><title>Bad Request</title></head><body></body></html>`,
		},
		{
			name: "Random HTML",
			body: `<html><head><title>Random Page</title></head><body></body></html>`,
		},
		{
			name: "Empty body",
			body: "",
		},
		{
			name: "Just 'Cisco' but no Expressway/TelePresence/TANDBERG",
			body: `<html><head><title>Cisco Router</title></head><body>Cisco IOS</body></html>`,
		},
		{
			name: "Server header with Cisco but no body markers",
			body: `<html><head><title>Login</title></head><body>/login redirect</body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CiscoExpresswayFingerprinter{}
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

func TestBuildCiscoExpresswayCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version X14.3.2",
			version: "X14.3.2",
			want:    "cpe:2.3:a:cisco:expressway:X14.3.2:*:*:*:*:*:*:*",
		},
		{
			name:    "With version 14.3.2 (no X prefix)",
			version: "14.3.2",
			want:    "cpe:2.3:a:cisco:expressway:14.3.2:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:cisco:expressway:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildCiscoExpresswayCPE(tt.version); got != tt.want {
				t.Errorf("buildCiscoExpresswayCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCiscoExpresswayFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter (should happen in init(), but we test it anyway)
	fp := &CiscoExpresswayFingerprinter{}
	Register(fp)

	// Create a valid Cisco Expressway response
	body := []byte(`<html><head><title>Cisco Expressway - Login</title></head><body>Cisco Expressway Version X14.3.2</body></html>`)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	results := RunFingerprinters(resp, body)

	// Should find at least the Cisco Expressway fingerprinter
	found := false
	for _, result := range results {
		if result.Technology == "cisco-expressway" {
			found = true
			if result.Version != "X14.3.2" {
				t.Errorf("Version = %q, want %q", result.Version, "X14.3.2")
			}
		}
	}

	if !found {
		t.Error("CiscoExpresswayFingerprinter not found in results")
	}
}
