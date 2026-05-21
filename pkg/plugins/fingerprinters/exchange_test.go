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

	"github.com/stretchr/testify/require"
)

func TestExchangeFingerprinter_Name(t *testing.T) {
	fp := &ExchangeFingerprinter{}
	if got := fp.Name(); got != "exchange" {
		t.Errorf("Name() = %q, want %q", got, "exchange")
	}
}

func TestExchangeFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ExchangeFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/owa/" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/owa/")
	}
}

func TestExchangeFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		want     bool
	}{
		{
			name: "X-OWA-Version present returns true",
			headers: map[string]string{
				"X-OWA-Version": "15.2.1544.11",
			},
			want: true,
		},
		{
			name: "X-FEServer present returns true",
			headers: map[string]string{
				"X-FEServer": "MAIL-SRV01",
			},
			want: true,
		},
		{
			name: "IIS with /owa/ redirect returns true",
			headers: map[string]string{
				"Server":   "Microsoft-IIS/10.0",
				"Location": "https://mail.example.com/owa/",
			},
			want: true,
		},
		{
			name: "IIS with X-AspNet-Version returns true",
			headers: map[string]string{
				"Server":           "Microsoft-IIS/10.0",
				"X-AspNet-Version": "4.0.30319",
			},
			want: true,
		},
		{
			name: "Plain IIS without Exchange indicators returns false",
			headers: map[string]string{
				"Server": "Microsoft-IIS/10.0",
			},
			want: false,
		},
		{
			name: "nginx returns false",
			headers: map[string]string{
				"Server": "nginx/1.18.0",
			},
			want: false,
		},
		{
			name: "No headers returns false",
			headers: map[string]string{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ExchangeFingerprinter{}
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

func TestExchangeFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name             string
		headers          map[string]string
		wantVersion      string
		wantFEServer     string
		wantIISVersion   string
		wantASPNET       string
		wantEdition      string
	}{
		{
			name: "Full Exchange 2019 response (15.2.1544.11)",
			headers: map[string]string{
				"X-OWA-Version":    "15.2.1544.11",
				"X-FEServer":       "MAIL-SRV01",
				"Server":           "Microsoft-IIS/10.0",
				"X-AspNet-Version": "4.0.30319",
			},
			wantVersion:    "15.2.1544.11",
			wantFEServer:   "MAIL-SRV01",
			wantIISVersion: "Microsoft-IIS/10.0",
			wantASPNET:     "4.0.30319",
			wantEdition:    "Exchange Server 2019",
		},
		{
			name: "Exchange 2016 response (15.1.2507.6)",
			headers: map[string]string{
				"X-OWA-Version": "15.1.2507.6",
				"X-FEServer":    "EX2016-01",
			},
			wantVersion:  "15.1.2507.6",
			wantFEServer: "EX2016-01",
			wantEdition:  "Exchange Server 2016",
		},
		{
			name: "Exchange 2013 response (15.0.1497.2)",
			headers: map[string]string{
				"X-OWA-Version": "15.0.1497.2",
			},
			wantVersion: "15.0.1497.2",
			wantEdition: "Exchange Server 2013",
		},
		{
			name: "Minimal Exchange response (version only)",
			headers: map[string]string{
				"X-OWA-Version": "15.2.1118.7",
			},
			wantVersion: "15.2.1118.7",
			wantEdition: "Exchange Server 2019",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ExchangeFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}

			result, err := fp.Fingerprint(resp, []byte{})
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "exchange_server" {
				t.Errorf("Technology = %q, want %q", result.Technology, "exchange_server")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Check metadata
			if tt.wantFEServer != "" {
				if feServer, ok := result.Metadata["fe_server"].(string); !ok || feServer != tt.wantFEServer {
					t.Errorf("Metadata[fe_server] = %v, want %v", feServer, tt.wantFEServer)
				}
			}
			if tt.wantIISVersion != "" {
				if iis, ok := result.Metadata["iis_version"].(string); !ok || iis != tt.wantIISVersion {
					t.Errorf("Metadata[iis_version] = %v, want %v", iis, tt.wantIISVersion)
				}
			}
			if tt.wantASPNET != "" {
				if aspnet, ok := result.Metadata["aspnet_version"].(string); !ok || aspnet != tt.wantASPNET {
					t.Errorf("Metadata[aspnet_version] = %v, want %v", aspnet, tt.wantASPNET)
				}
			}
			if tt.wantEdition != "" {
				if edition, ok := result.Metadata["exchange_edition"].(string); !ok || edition != tt.wantEdition {
					t.Errorf("Metadata[exchange_edition] = %v, want %v", edition, tt.wantEdition)
				}
			}

			// Check CPE
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:microsoft:exchange_server:" + tt.wantVersion + ":*:*:*:*:*:*:*"
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestExchangeFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name             string
		headers          map[string]string
		wantVersion      string
		wantNonNilResult bool
	}{
		{
			name: "Version with CPE injection attempt returns result with empty version",
			headers: map[string]string{
				"X-OWA-Version": "15.2.0:*:*:*:*:*:*:*",
			},
			wantVersion:      "",
			wantNonNilResult: true,
		},
		{
			name: "Malformed version returns result with empty version",
			headers: map[string]string{
				"X-OWA-Version": "invalid.version",
			},
			wantVersion:      "",
			wantNonNilResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ExchangeFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}

			result, err := fp.Fingerprint(resp, []byte{})
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}

			if tt.wantNonNilResult && result == nil {
				t.Error("Fingerprint() returned nil, want non-nil result")
			}

			if result != nil {
				if result.Technology != "exchange_server" {
					t.Errorf("Technology = %q, want %q", result.Technology, "exchange_server")
				}
				if result.Version != tt.wantVersion {
					t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
				}
				// With empty/invalid version, CPE should use wildcard
				expectedCPE := "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"
				if len(result.CPEs) == 0 || result.CPEs[0] != expectedCPE {
					t.Errorf("CPE = %v, want %q", result.CPEs, expectedCPE)
				}
			}
		})
	}
}

func TestBuildExchangeCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "15.2.1544.11",
			want:    "cpe:2.3:a:microsoft:exchange_server:15.2.1544.11:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildExchangeCPE(tt.version); got != tt.want {
				t.Errorf("buildExchangeCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMapExchangeEdition(t *testing.T) {
	tests := []struct {
		name       string
		owaVersion string
		want       string
	}{
		{
			name:       "Exchange 2019 (15.2.x)",
			owaVersion: "15.2.1544.11",
			want:       "Exchange Server 2019",
		},
		{
			name:       "Exchange 2016 (15.1.x)",
			owaVersion: "15.1.2507.6",
			want:       "Exchange Server 2016",
		},
		{
			name:       "Exchange 2013 (15.0.x)",
			owaVersion: "15.0.1497.2",
			want:       "Exchange Server 2013",
		},
		{
			name:       "Unknown version",
			owaVersion: "16.0.1000.0",
			want:       "",
		},
		{
			name:       "Malformed version",
			owaVersion: "invalid",
			want:       "",
		},
		{
			name:       "Empty version",
			owaVersion: "",
			want:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := mapExchangeEdition(tt.owaVersion); got != tt.want {
				t.Errorf("mapExchangeEdition() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestExchangeFingerprinter_Integration(t *testing.T) {
	fp := &ExchangeFingerprinter{}

	// Create a valid Exchange response
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("X-OWA-Version", "15.2.1544.11")
	resp.Header.Set("X-FEServer", "MAIL-SRV01")
	resp.Header.Set("Server", "Microsoft-IIS/10.0")

	require.True(t, fp.Match(resp))
	result, err := fp.Fingerprint(resp, []byte{})
	require.NoError(t, err)
	require.NotNil(t, result)
	if result.Version != "15.2.1544.11" {
		t.Errorf("Version = %q, want %q", result.Version, "15.2.1544.11")
	}
	if edition, ok := result.Metadata["exchange_edition"].(string); !ok || edition != "Exchange Server 2019" {
		t.Errorf("exchange_edition = %v, want %v", edition, "Exchange Server 2019")
	}
}

func TestExchangeFingerprinter_Fingerprint_NoVersionHeader(t *testing.T) {
	// Test the scenario where Match() succeeds via X-FEServer, but X-OWA-Version is absent
	// This is the bug reported for 173.209.208.128:443 which returns:
	// - Server: Microsoft-IIS/10.0
	// - X-FEServer: DA1P-ITS-EXH001
	// - Location: https://173.209.208.128/owa/
	// But NO X-OWA-Version header
	tests := []struct {
		name             string
		headers          map[string]string
		wantNonNil       bool
		wantTechnology   string
		wantVersion      string
		wantFEServer     string
		wantIISVersion   string
	}{
		{
			name: "X-FEServer without X-OWA-Version should still return result",
			headers: map[string]string{
				"X-FEServer": "DA1P-ITS-EXH001",
				"Server":     "Microsoft-IIS/10.0",
				"Location":   "https://173.209.208.128/owa/",
			},
			wantNonNil:     true,
			wantTechnology: "exchange_server",
			wantVersion:    "",
			wantFEServer:   "DA1P-ITS-EXH001",
			wantIISVersion: "Microsoft-IIS/10.0",
		},
		{
			name: "IIS with /owa/ redirect without X-OWA-Version should return result",
			headers: map[string]string{
				"Server":   "Microsoft-IIS/10.0",
				"Location": "https://mail.example.com/owa/",
			},
			wantNonNil:     true,
			wantTechnology: "exchange_server",
			wantVersion:    "",
			wantIISVersion: "Microsoft-IIS/10.0",
		},
		{
			name: "IIS with ASP.NET without X-OWA-Version should return result",
			headers: map[string]string{
				"Server":           "Microsoft-IIS/10.0",
				"X-AspNet-Version": "4.0.30319",
			},
			wantNonNil:     true,
			wantTechnology: "exchange_server",
			wantVersion:    "",
			wantIISVersion: "Microsoft-IIS/10.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ExchangeFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			for k, v := range tt.headers {
				resp.Header.Set(k, v)
			}

			// First verify that Match() succeeds
			if !fp.Match(resp) {
				t.Fatal("Match() should return true for this test case")
			}

			// Now test Fingerprint()
			result, err := fp.Fingerprint(resp, []byte{})
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}

			if tt.wantNonNil && result == nil {
				t.Fatal("Fingerprint() returned nil result, expected non-nil when Match() succeeds")
			}

			if result != nil {
				if result.Technology != tt.wantTechnology {
					t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTechnology)
				}
				if result.Version != tt.wantVersion {
					t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
				}

				// Check metadata
				if tt.wantFEServer != "" {
					if feServer, ok := result.Metadata["fe_server"].(string); !ok || feServer != tt.wantFEServer {
						t.Errorf("Metadata[fe_server] = %v, want %v", feServer, tt.wantFEServer)
					}
				}
				if tt.wantIISVersion != "" {
					if iis, ok := result.Metadata["iis_version"].(string); !ok || iis != tt.wantIISVersion {
						t.Errorf("Metadata[iis_version] = %v, want %v", iis, tt.wantIISVersion)
					}
				}

				// Check CPE with wildcard version
				if len(result.CPEs) == 0 {
					t.Error("Expected at least one CPE")
				}
				expectedCPE := "cpe:2.3:a:microsoft:exchange_server:*:*:*:*:*:*:*:*"
				if result.CPEs[0] != expectedCPE {
					t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
				}
			}
		})
	}
}
