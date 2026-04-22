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
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// HPiLOFingerprinter — Name
// ─────────────────────────────────────────────────────────────────────────────

func TestHPiLOFingerprinter_Name(t *testing.T) {
	fp := &HPiLOFingerprinter{}
	if got := fp.Name(); got != "hp-ilo" {
		t.Errorf("Name() = %q, want %q", got, "hp-ilo")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HPiLOFingerprinter — Match
// ─────────────────────────────────────────────────────────────────────────────

func TestHPiLOFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
		want       bool
	}{
		// Positive
		{name: "HP-iLO-Server/2.82.5", server: "HP-iLO-Server/2.82.5", statusCode: 200, want: true},
		{name: "HPE-iLO-Server/3.18", server: "HPE-iLO-Server/3.18", statusCode: 200, want: true},
		{name: "HP-iLO-Server/1.30", server: "HP-iLO-Server/1.30", statusCode: 200, want: true},
		{name: "HPE-iLO-Server/1.74", server: "HPE-iLO-Server/1.74", statusCode: 200, want: true},
		{name: "status 401 accepted", server: "HP-iLO-Server/2.82.5", statusCode: 401, want: true},
		{name: "status 403 accepted", server: "HP-iLO-Server/2.82.5", statusCode: 403, want: true},
		{name: "status 404 accepted", server: "HP-iLO-Server/2.82.5", statusCode: 404, want: true},
		// Negative — status
		{name: "status 500 rejected", server: "HP-iLO-Server/2.82.5", statusCode: 500, want: false},
		{name: "status 503 rejected", server: "HP-iLO-Server/2.82.5", statusCode: 503, want: false},
		{name: "status 199 rejected", server: "HP-iLO-Server/2.82.5", statusCode: 199, want: false},
		// Negative — wrong headers
		{name: "nginx/1.18.0", server: "nginx/1.18.0", statusCode: 200, want: false},
		{name: "Apache/2.4.41", server: "Apache/2.4.41", statusCode: 200, want: false},
		{name: "Microsoft-IIS/10.0", server: "Microsoft-IIS/10.0", statusCode: 200, want: false},
		{name: "cloudflare", server: "cloudflare", statusCode: 200, want: false},
		{name: "HPE SiteScope Server", server: "HPE SiteScope Server", statusCode: 200, want: false},
		{name: "HP-iLO-Server no slash", server: "HP-iLO-Server", statusCode: 200, want: false},
		{name: "empty server", server: "", statusCode: 200, want: false},
		{name: "HP-iLO-Server/abc non-numeric", server: "HP-iLO-Server/abc", statusCode: 200, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HPiLOFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HPiLOFingerprinter — Fingerprint (valid inputs)
// ─────────────────────────────────────────────────────────────────────────────

func TestHPiLOFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		wantVersion string
		wantCPE     string
	}{
		{
			name:        "HP-iLO-Server/1.30",
			server:      "HP-iLO-Server/1.30",
			wantVersion: "1.30",
			wantCPE:     "cpe:2.3:o:hp:integrated_lights_out_firmware:1.30:*:*:*:*:*:*:*",
		},
		{
			name:        "HP-iLO-Server/2.55",
			server:      "HP-iLO-Server/2.55",
			wantVersion: "2.55",
			wantCPE:     "cpe:2.3:o:hp:integrated_lights_out_firmware:2.55:*:*:*:*:*:*:*",
		},
		{
			name:        "HP-iLO-Server/2.82.5",
			server:      "HP-iLO-Server/2.82.5",
			wantVersion: "2.82.5",
			wantCPE:     "cpe:2.3:o:hp:integrated_lights_out_firmware:2.82.5:*:*:*:*:*:*:*",
		},
		{
			name:        "HPE-iLO-Server/3.18",
			server:      "HPE-iLO-Server/3.18",
			wantVersion: "3.18",
			wantCPE:     "cpe:2.3:o:hp:integrated_lights_out_firmware:3.18:*:*:*:*:*:*:*",
		},
		{
			name:        "HPE-iLO-Server/1.74",
			server:      "HPE-iLO-Server/1.74",
			wantVersion: "1.74",
			wantCPE:     "cpe:2.3:o:hp:integrated_lights_out_firmware:1.74:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HPiLOFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
			resp.Header.Set("Server", tt.server)

			result, err := fp.Fingerprint(resp, nil)
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "hp-ilo" {
				t.Errorf("Technology = %q, want %q", result.Technology, "hp-ilo")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) == 0 {
				t.Fatal("CPEs is empty")
			}
			if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], tt.wantCPE)
			}
			// Metadata checks
			if v, ok := result.Metadata["vendor"].(string); !ok || v != "HP" {
				t.Errorf("Metadata[vendor] = %v, want %q", result.Metadata["vendor"], "HP")
			}
			if p, ok := result.Metadata["product"].(string); !ok || p != "iLO" {
				t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], "iLO")
			}
			if got := result.Metadata["version"]; got != tt.wantVersion {
				t.Errorf("Metadata[version] = %v, want %q", got, tt.wantVersion)
			}
			if got := result.Metadata["firmware_version"]; got != tt.wantVersion {
				t.Errorf("Metadata[firmware_version] = %v, want %q", got, tt.wantVersion)
			}
			if sh, ok := result.Metadata["server_header"].(string); !ok || sh == "" {
				t.Errorf("Metadata[server_header] missing or empty")
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HPiLOFingerprinter — Fingerprint (invalid / negative inputs)
// ─────────────────────────────────────────────────────────────────────────────

func TestHPiLOFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
	}{
		{name: "nginx/1.18.0", server: "nginx/1.18.0", statusCode: 200},
		{name: "Apache/2.4.41", server: "Apache/2.4.41", statusCode: 200},
		{name: "Microsoft-IIS/10.0", server: "Microsoft-IIS/10.0", statusCode: 200},
		{name: "cloudflare", server: "cloudflare", statusCode: 200},
		{name: "HPE SiteScope Server", server: "HPE SiteScope Server", statusCode: 200},
		{name: "HP-iLO-Server no slash", server: "HP-iLO-Server", statusCode: 200},
		{name: "HP-iLO-Server/abc non-numeric", server: "HP-iLO-Server/abc", statusCode: 200},
		{name: "HP-iLO-Server dot-only", server: "HP-iLO-Server/...", statusCode: 200},
		{name: "HP-iLO-Server single dot", server: "HP-iLO-Server/.", statusCode: 200},
		{name: "CPE injection attempt", server: "HP-iLO-Server/1.0:*:*:*:*:*:*:*", statusCode: 200},
		{name: "empty server", server: "", statusCode: 200},
		{name: "status 500", server: "HP-iLO-Server/2.82.5", statusCode: 500},
		{name: "status 503", server: "HP-iLO-Server/2.82.5", statusCode: 503},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HPiLOFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, nil)
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HPLaserJetFingerprinter — Name
// ─────────────────────────────────────────────────────────────────────────────

func TestHPLaserJetFingerprinter_Name(t *testing.T) {
	fp := &HPLaserJetFingerprinter{}
	if got := fp.Name(); got != "hp-ews" {
		t.Errorf("Name() = %q, want %q", got, "hp-ews")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HPLaserJetFingerprinter — Match
// ─────────────────────────────────────────────────────────────────────────────

func TestHPLaserJetFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
		want       bool
	}{
		// Positive
		{name: "LaserJet Enterprise M553", server: "HP HTTP Server; HP LaserJet Enterprise M553", statusCode: 200, want: true},
		{name: "LaserJet Pro 400", server: "HP HTTP Server; HP LaserJet Pro 400", statusCode: 200, want: true},
		{name: "PageWide Pro 477dw", server: "HP HTTP Server; HP PageWide Pro 477dw", statusCode: 200, want: true},
		{name: "OfficeJet Pro 8710", server: "HP HTTP Server; HP OfficeJet Pro 8710", statusCode: 200, want: true},
		{name: "DesignJet T630", server: "HP HTTP Server; HP DesignJet T630", statusCode: 200, want: true},
		{name: "status 404 accepted", server: "HP HTTP Server; HP LaserJet Pro 400", statusCode: 404, want: true},
		// Negative — status
		{name: "status 500 rejected", server: "HP HTTP Server; HP LaserJet M553", statusCode: 500, want: false},
		{name: "status 199 rejected", server: "HP HTTP Server; HP LaserJet M553", statusCode: 199, want: false},
		// Negative — wrong headers
		{name: "nginx/1.18.0", server: "nginx/1.18.0", statusCode: 200, want: false},
		{name: "Apache/2.4.41", server: "Apache/2.4.41", statusCode: 200, want: false},
		{name: "Microsoft-IIS/10.0", server: "Microsoft-IIS/10.0", statusCode: 200, want: false},
		{name: "cloudflare", server: "cloudflare", statusCode: 200, want: false},
		{name: "HP HTTP Server no model", server: "HP HTTP Server;", statusCode: 200, want: false},
		{name: "HP HTTP Server; HP trailing space only", server: "HP HTTP Server; HP ", statusCode: 200, want: false},
		{name: "empty server", server: "", statusCode: 200, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HPLaserJetFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HPLaserJetFingerprinter — Fingerprint (valid inputs)
// ─────────────────────────────────────────────────────────────────────────────

func TestHPLaserJetFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name      string
		server    string
		wantModel string
		wantCPE   string
	}{
		{
			name:      "LaserJet Enterprise M553",
			server:    "HP HTTP Server; HP LaserJet Enterprise M553",
			wantModel: "LaserJet Enterprise M553",
			wantCPE:   "cpe:2.3:o:hp:laserjet_enterprise_m553_firmware:*:*:*:*:*:*:*:*",
		},
		{
			name:      "LaserJet Pro E40xx",
			server:    "HP HTTP Server; HP LaserJet Pro E40xx",
			wantModel: "LaserJet Pro E40xx",
			wantCPE:   "cpe:2.3:o:hp:laserjet_pro_e40xx_firmware:*:*:*:*:*:*:*:*",
		},
		{
			name:      "PageWide Pro 477dw",
			server:    "HP HTTP Server; HP PageWide Pro 477dw",
			wantModel: "PageWide Pro 477dw",
			wantCPE:   "cpe:2.3:o:hp:pagewide_pro_477dw_firmware:*:*:*:*:*:*:*:*",
		},
		{
			name:      "OfficeJet Pro 8710",
			server:    "HP HTTP Server; HP OfficeJet Pro 8710",
			wantModel: "OfficeJet Pro 8710",
			wantCPE:   "cpe:2.3:o:hp:officejet_pro_8710_firmware:*:*:*:*:*:*:*:*",
		},
		{
			name:      "DesignJet T630",
			server:    "HP HTTP Server; HP DesignJet T630",
			wantModel: "DesignJet T630",
			wantCPE:   "cpe:2.3:o:hp:designjet_t630_firmware:*:*:*:*:*:*:*:*",
		},
		{
			name:      "no space after semicolon (NF-1)",
			server:    "HP HTTP Server;HP LaserJet Enterprise M553",
			wantModel: "LaserJet Enterprise M553",
			wantCPE:   "cpe:2.3:o:hp:laserjet_enterprise_m553_firmware:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HPLaserJetFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
			resp.Header.Set("Server", tt.server)

			result, err := fp.Fingerprint(resp, nil)
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "hp-ews" {
				t.Errorf("Technology = %q, want %q", result.Technology, "hp-ews")
			}
			if result.Version != "" {
				t.Errorf("Version = %q, want empty (EWS headers carry no firmware version)", result.Version)
			}
			if len(result.CPEs) == 0 {
				t.Fatal("CPEs is empty")
			}
			if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], tt.wantCPE)
			}
			// Metadata checks
			if v, ok := result.Metadata["vendor"].(string); !ok || v != "HP" {
				t.Errorf("Metadata[vendor] = %v, want %q", result.Metadata["vendor"], "HP")
			}
			if p, ok := result.Metadata["product"].(string); !ok || p != "EWS" {
				t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], "EWS")
			}
			if model, ok := result.Metadata["model"].(string); !ok || model != tt.wantModel {
				t.Errorf("Metadata[model] = %v, want %q", result.Metadata["model"], tt.wantModel)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HPLaserJetFingerprinter — Fingerprint (invalid / negative)
// ─────────────────────────────────────────────────────────────────────────────

func TestHPLaserJetFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
	}{
		{name: "nginx/1.18.0", server: "nginx/1.18.0", statusCode: 200},
		{name: "Apache/2.4.41", server: "Apache/2.4.41", statusCode: 200},
		{name: "Microsoft-IIS/10.0", server: "Microsoft-IIS/10.0", statusCode: 200},
		{name: "cloudflare", server: "cloudflare", statusCode: 200},
		{name: "HPE SiteScope Server", server: "HPE SiteScope Server", statusCode: 200},
		{name: "HP HTTP Server semicolon only", server: "HP HTTP Server;", statusCode: 200},
		{name: "empty server", server: "", statusCode: 200},
		{name: "status 500", server: "HP HTTP Server; HP LaserJet M553", statusCode: 500},
		{name: "CPE injection in model", server: "HP HTTP Server; HP M553:*:*:*:*:*:*:*", statusCode: 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HPLaserJetFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, nil)
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HPChaiSOEFingerprinter — Name
// ─────────────────────────────────────────────────────────────────────────────

func TestHPChaiSOEFingerprinter_Name(t *testing.T) {
	fp := &HPChaiSOEFingerprinter{}
	if got := fp.Name(); got != "hp-chaisoe" {
		t.Errorf("Name() = %q, want %q", got, "hp-chaisoe")
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HPChaiSOEFingerprinter — Match
// ─────────────────────────────────────────────────────────────────────────────

func TestHPChaiSOEFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
		want       bool
	}{
		// Positive
		{name: "HP-ChaiSOE/1.0", server: "HP-ChaiSOE/1.0", statusCode: 200, want: true},
		{name: "HP-ChaiServer/3.0", server: "HP-ChaiServer/3.0", statusCode: 200, want: true},
		{name: "HP-ChaiSOE/2.4.1", server: "HP-ChaiSOE/2.4.1", statusCode: 200, want: true},
		{name: "status 404 accepted", server: "HP-ChaiSOE/1.0", statusCode: 404, want: true},
		// Negative — status
		{name: "status 500 rejected", server: "HP-ChaiSOE/1.0", statusCode: 500, want: false},
		{name: "status 199 rejected", server: "HP-ChaiSOE/1.0", statusCode: 199, want: false},
		// Negative — wrong headers
		{name: "nginx/1.18.0", server: "nginx/1.18.0", statusCode: 200, want: false},
		{name: "Apache/2.4.41", server: "Apache/2.4.41", statusCode: 200, want: false},
		{name: "Microsoft-IIS/10.0", server: "Microsoft-IIS/10.0", statusCode: 200, want: false},
		{name: "cloudflare", server: "cloudflare", statusCode: 200, want: false},
		{name: "HPE SiteScope Server", server: "HPE SiteScope Server", statusCode: 200, want: false},
		{name: "HP-ChaiSOE no version", server: "HP-ChaiSOE", statusCode: 200, want: false},
		{name: "empty server", server: "", statusCode: 200, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HPChaiSOEFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HPChaiSOEFingerprinter — Fingerprint (valid)
// ─────────────────────────────────────────────────────────────────────────────

func TestHPChaiSOEFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		wantVersion string
		wantCPE     string
	}{
		{
			name:        "HP-ChaiSOE/1.0",
			server:      "HP-ChaiSOE/1.0",
			wantVersion: "1.0",
			wantCPE:     "cpe:2.3:a:hp:chaisoe:1.0:*:*:*:*:*:*:*",
		},
		{
			name:        "HP-ChaiServer/3.0",
			server:      "HP-ChaiServer/3.0",
			wantVersion: "3.0",
			wantCPE:     "cpe:2.3:a:hp:chaisoe:3.0:*:*:*:*:*:*:*",
		},
		{
			name:        "HP-ChaiSOE/2.4.1",
			server:      "HP-ChaiSOE/2.4.1",
			wantVersion: "2.4.1",
			wantCPE:     "cpe:2.3:a:hp:chaisoe:2.4.1:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HPChaiSOEFingerprinter{}
			resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
			resp.Header.Set("Server", tt.server)

			result, err := fp.Fingerprint(resp, nil)
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "hp-chaisoe" {
				t.Errorf("Technology = %q, want %q", result.Technology, "hp-chaisoe")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) == 0 {
				t.Fatal("CPEs is empty")
			}
			if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], tt.wantCPE)
			}
			// Metadata checks
			if v, ok := result.Metadata["vendor"].(string); !ok || v != "HP" {
				t.Errorf("Metadata[vendor] = %v, want %q", result.Metadata["vendor"], "HP")
			}
			if p, ok := result.Metadata["product"].(string); !ok || p != "ChaiSOE" {
				t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], "ChaiSOE")
			}
			if got := result.Metadata["version"]; got != tt.wantVersion {
				t.Errorf("Metadata[version] = %v, want %q", got, tt.wantVersion)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// HPChaiSOEFingerprinter — Fingerprint (invalid / negative)
// ─────────────────────────────────────────────────────────────────────────────

func TestHPChaiSOEFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		server     string
		statusCode int
	}{
		{name: "nginx/1.18.0", server: "nginx/1.18.0", statusCode: 200},
		{name: "Apache/2.4.41", server: "Apache/2.4.41", statusCode: 200},
		{name: "Microsoft-IIS/10.0", server: "Microsoft-IIS/10.0", statusCode: 200},
		{name: "cloudflare", server: "cloudflare", statusCode: 200},
		{name: "HPE SiteScope Server", server: "HPE SiteScope Server", statusCode: 200},
		{name: "HP-ChaiSOE no version", server: "HP-ChaiSOE", statusCode: 200},
		{name: "HP-ChaiSOE dot-only version", server: "HP-ChaiSOE/...", statusCode: 200},
		{name: "HP-ChaiSOE/abc non-numeric", server: "HP-ChaiSOE/abc", statusCode: 200},
		{name: "CPE injection attempt", server: "HP-ChaiSOE/1.0:*:*:*:*:*:*:*", statusCode: 200},
		{name: "empty server", server: "", statusCode: 200},
		{name: "status 500", server: "HP-ChaiSOE/1.0", statusCode: 500},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &HPChaiSOEFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}

			result, err := fp.Fingerprint(resp, nil)
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// CPE builder tests
// ─────────────────────────────────────────────────────────────────────────────

func TestBuildIloCPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"2.82.5", "cpe:2.3:o:hp:integrated_lights_out_firmware:2.82.5:*:*:*:*:*:*:*"},
		{"3.18", "cpe:2.3:o:hp:integrated_lights_out_firmware:3.18:*:*:*:*:*:*:*"},
		{"", "cpe:2.3:o:hp:integrated_lights_out_firmware:*:*:*:*:*:*:*:*"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("version=%q", tt.version), func(t *testing.T) {
			if got := buildiLOCPE(tt.version); got != tt.want {
				t.Errorf("buildiLOCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestBuildEWSCPE(t *testing.T) {
	tests := []struct {
		slug string
		want string
	}{
		{"laserjet_enterprise_m553", "cpe:2.3:o:hp:laserjet_enterprise_m553_firmware:*:*:*:*:*:*:*:*"},
		{"pagewide_pro_477dw", "cpe:2.3:o:hp:pagewide_pro_477dw_firmware:*:*:*:*:*:*:*:*"},
		{"", "cpe:2.3:o:hp:laserjet_firmware:*:*:*:*:*:*:*:*"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("slug=%q", tt.slug), func(t *testing.T) {
			if got := buildEWSCPE(tt.slug); got != tt.want {
				t.Errorf("buildEWSCPE(%q) = %q, want %q", tt.slug, got, tt.want)
			}
		})
	}
}

func TestBuildChaiSOECPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"1.0", "cpe:2.3:a:hp:chaisoe:1.0:*:*:*:*:*:*:*"},
		{"3.0", "cpe:2.3:a:hp:chaisoe:3.0:*:*:*:*:*:*:*"},
		{"", "cpe:2.3:a:hp:chaisoe:*:*:*:*:*:*:*:*"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("version=%q", tt.version), func(t *testing.T) {
			if got := buildChaiSOECPE(tt.version); got != tt.want {
				t.Errorf("buildChaiSOECPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// normalizeEWSModelSlug
// ─────────────────────────────────────────────────────────────────────────────

func TestNormalizeEWSModelSlug(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"LaserJet Enterprise M553", "laserjet_enterprise_m553"},
		{"  LaserJet Pro E40xx  ", "laserjet_pro_e40xx"},
		{"PageWide Pro 477dw", "pagewide_pro_477dw"},
		{"OfficeJet Pro 8710", "officejet_pro_8710"},
		{"DesignJet T630", "designjet_t630"},
		{"LaserJet M553n+extra—unicode", "laserjet_m553nextraunicode"},
		{"!!!", ""},
		{"   ", ""},
		{"a", ""}, // too short (len < 2)
		{"ab", "ab"},
	}
	for _, tt := range tests {
		t.Run(fmt.Sprintf("input=%q", tt.input), func(t *testing.T) {
			if got := normalizeEWSModelSlug(tt.input); got != tt.want {
				t.Errorf("normalizeEWSModelSlug(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// sanitizeHeaderValue
// ─────────────────────────────────────────────────────────────────────────────

func TestSanitizeHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain ASCII passes through",
			input: "HP-iLO-Server/2.82.5",
			want:  "HP-iLO-Server/2.82.5",
		},
		{
			name:  "control character stripped",
			input: "HP\x01Server",
			want:  "HPServer",
		},
		{
			name:  "DEL (0x7F) stripped",
			input: "HP\x7FServer",
			want:  "HPServer",
		},
		{
			name:  "capped at 512 bytes",
			input: strings.Repeat("A", 600),
			want:  strings.Repeat("A", 512),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := sanitizeHeaderValue(tt.input); got != tt.want {
				t.Errorf("sanitizeHeaderValue() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Integration: RunFingerprinters registry
// ─────────────────────────────────────────────────────────────────────────────

func TestHPFingerprinters_Integration(t *testing.T) {
	// Register each fingerprinter explicitly (mirrors boa_test.go pattern) to
	// tolerate registry_test.go setting httpFingerprinters = nil before this test.
	iloFP := &HPiLOFingerprinter{}
	ewsFP := &HPLaserJetFingerprinter{}
	chaiFP := &HPChaiSOEFingerprinter{}
	Register(iloFP)
	Register(ewsFP)
	Register(chaiFP)

	t.Run("ilo", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
		resp.Header.Set("Server", "HPE-iLO-Server/3.18")
		results := RunFingerprinters(resp, nil)
		found := false
		for _, r := range results {
			if r.Technology == "hp-ilo" {
				found = true
				if r.Version != "3.18" {
					t.Errorf("Version = %q, want %q", r.Version, "3.18")
				}
				if !strings.HasPrefix(r.CPEs[0], "cpe:2.3:o:hp:integrated_lights_out_firmware:") {
					t.Errorf("CPE prefix mismatch: %q", r.CPEs[0])
				}
			}
		}
		if !found {
			t.Error("hp-ilo not found in RunFingerprinters results")
		}
	})

	t.Run("ews", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
		resp.Header.Set("Server", "HP HTTP Server; HP LaserJet Enterprise M553")
		results := RunFingerprinters(resp, nil)
		found := false
		for _, r := range results {
			if r.Technology == "hp-ews" {
				found = true
				if !strings.HasPrefix(r.CPEs[0], "cpe:2.3:o:hp:laserjet_") {
					t.Errorf("CPE prefix mismatch: %q", r.CPEs[0])
				}
			}
		}
		if !found {
			t.Error("hp-ews not found in RunFingerprinters results")
		}
	})

	t.Run("chaisoe", func(t *testing.T) {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
		resp.Header.Set("Server", "HP-ChaiSOE/1.0")
		results := RunFingerprinters(resp, nil)
		found := false
		for _, r := range results {
			if r.Technology == "hp-chaisoe" {
				found = true
				if r.Version != "1.0" {
					t.Errorf("Version = %q, want %q", r.Version, "1.0")
				}
				if !strings.HasPrefix(r.CPEs[0], "cpe:2.3:a:hp:chaisoe:") {
					t.Errorf("CPE prefix mismatch: %q", r.CPEs[0])
				}
			}
		}
		if !found {
			t.Error("hp-chaisoe not found in RunFingerprinters results")
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// EWS fallback CPE for empty slug
// ─────────────────────────────────────────────────────────────────────────────

func TestHPLaserJetFingerprinter_FallbackCPE(t *testing.T) {
	// A header whose model portion normalizes to a single-character slug triggers
	// the generic fallback CPE.
	fp := &HPLaserJetFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	// Model "X" normalizes to "x" which is only 1 char — below the 2-char minimum.
	resp.Header.Set("Server", "HP HTTP Server; HP X")
	result, err := fp.Fingerprint(resp, nil)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, want detection with fallback CPE")
	}
	want := "cpe:2.3:o:hp:laserjet_firmware:*:*:*:*:*:*:*:*"
	if result.CPEs[0] != want {
		t.Errorf("CPE = %q, want fallback %q", result.CPEs[0], want)
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// Server-header length cap
// ─────────────────────────────────────────────────────────────────────────────

func TestHPFingerprinters_LengthCap(t *testing.T) {
	long := strings.Repeat("A", 600)
	variants := []struct {
		fp     HTTPFingerprinter
		header string
	}{
		{&HPiLOFingerprinter{}, long},
		{&HPLaserJetFingerprinter{}, long},
		{&HPChaiSOEFingerprinter{}, long},
	}
	for _, v := range variants {
		resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
		resp.Header.Set("Server", v.header)
		if v.fp.Match(resp) {
			t.Errorf("%T.Match() returned true for 600-byte server header, want false", v.fp)
		}
		result, err := v.fp.Fingerprint(resp, nil)
		if err != nil {
			t.Errorf("%T.Fingerprint() unexpected error = %v", v.fp, err)
		}
		if result != nil {
			t.Errorf("%T.Fingerprint() returned non-nil for 600-byte header, want nil", v.fp)
		}
	}
}
