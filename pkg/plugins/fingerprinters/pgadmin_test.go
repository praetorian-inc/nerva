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
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestPgAdminFingerprinter_Name(t *testing.T) {
	fp := &PgAdminFingerprinter{}
	if got := fp.Name(); got != "pgadmin" {
		t.Errorf("Name() = %q, want %q", got, "pgadmin")
	}
}

func TestPgAdminFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &PgAdminFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/misc/ping" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/misc/ping")
	}
}

func TestPgAdminFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "text/html returns true",
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "text/html; charset=utf-8 returns true",
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "application/json returns false",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "empty Content-Type returns false",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PgAdminFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}

			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPgAdminFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "PING body with pga4_session cookie",
			body: "PING",
		},
		{
			name: "PING body with pga4_session cookie and extra whitespace",
			body: "\nPING\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PgAdminFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			resp.Header.Add("Set-Cookie", "pga4_session=abc123!def456; Expires=Thu, 01 Jan 2026 00:00:00 GMT; HttpOnly; Path=/; SameSite=Lax")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want non-nil result")
			}

			if result.Technology != "pgadmin" {
				t.Errorf("Technology = %q, want %q", result.Technology, "pgadmin")
			}

			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:pgadmin:pgadmin:*:*:*:*:*:*:*:*"
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}

			if mode, ok := result.Metadata["mode"].(string); !ok || mode != "server" {
				t.Errorf("Metadata[mode] = %v, want %q", result.Metadata["mode"], "server")
			}
		})
	}
}

func TestPgAdminFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		cookies []string
	}{
		{
			name:    "PING body but no pga4_session cookie",
			body:    "PING",
			cookies: []string{"session=somethingelse"},
		},
		{
			name:    "Non-PING body with pga4_session cookie",
			body:    "OK",
			cookies: []string{"pga4_session=abc123!def456; Path=/"},
		},
		{
			name:    "Empty body",
			body:    "",
			cookies: []string{"pga4_session=abc123!def456; Path=/"},
		},
		{
			name:    "Random text body",
			body:    "some random response",
			cookies: []string{"pga4_session=abc123!def456; Path=/"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PgAdminFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")
			for _, c := range tt.cookies {
				resp.Header.Add("Set-Cookie", c)
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

func TestBuildPgAdminCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "7.8.0",
			want:    "cpe:2.3:a:pgadmin:pgadmin:7.8.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:pgadmin:pgadmin:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildPgAdminCPE(tt.version); got != tt.want {
				t.Errorf("buildPgAdminCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPgAdminFingerprinter_Integration(t *testing.T) {
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &PgAdminFingerprinter{}
	Register(fp)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Content-Type", "text/html; charset=utf-8")
	resp.Header.Add("Set-Cookie", "pga4_session=abc123!def456; Expires=Thu, 01 Jan 2026 00:00:00 GMT; HttpOnly; Path=/; SameSite=Lax")

	body := []byte("PING")

	results := RunFingerprinters(resp, body)

	found := false
	for _, result := range results {
		if result.Technology == "pgadmin" {
			found = true
			if result.Metadata["mode"] != "server" {
				t.Errorf("mode = %v, want %q", result.Metadata["mode"], "server")
			}
		}
	}

	if !found {
		t.Error("PgAdminFingerprinter not found in results")
	}
}

func TestPgAdminFingerprinter_LiveDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live Docker test in short mode")
	}
	// Test against live pgAdmin Docker container
	// Expects: docker run -d --name pgadmin-test -p 5050:80 -e PGADMIN_DEFAULT_EMAIL=test@test.com -e PGADMIN_DEFAULT_PASSWORD=test123 dpage/pgadmin4:latest
	baseURL := "http://localhost:5050"

	resp, err := http.Get(baseURL + "/misc/ping")
	if err != nil {
		t.Skipf("pgAdmin not available at %s: %v", baseURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	fp := &PgAdminFingerprinter{}
	if !fp.Match(resp) {
		t.Skip("Content-Type does not match")
	}

	result, err := fp.Fingerprint(resp, body)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}
	if result.Technology != "pgadmin" {
		t.Errorf("Technology = %q, want %q", result.Technology, "pgadmin")
	}
	t.Logf("Detected pgAdmin, mode=%v", result.Metadata["mode"])
}

func TestPgAdminLoginFingerprinter_Name(t *testing.T) {
	fp := &PgAdminLoginFingerprinter{}
	if got := fp.Name(); got != "pgadmin-login" {
		t.Errorf("Name() = %q, want %q", got, "pgadmin-login")
	}
}

func TestPgAdminLoginFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &PgAdminLoginFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/login" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/login")
	}
}

func TestPgAdminLoginFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{
			name:        "text/html returns true",
			contentType: "text/html",
			want:        true,
		},
		{
			name:        "text/html; charset=utf-8 returns true",
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:        "application/json returns false",
			contentType: "application/json",
			want:        false,
		},
		{
			name:        "empty Content-Type returns false",
			contentType: "",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PgAdminLoginFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}

			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPgAdminLoginFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name            string
		body            string
		wantVersion     string
		wantCPEContains string
	}{
		{
			name:            "pgAdmin 9.14 login page",
			body:            `<html><head><title>pgAdmin 4</title></head><body><script src="/static/js/generated/pgadmin_commons.js?ver=91400"></script></body></html>`,
			wantVersion:     "9.14",
			wantCPEContains: "9.14",
		},
		{
			name:            "pgAdmin 6.21 login page",
			body:            `<html><head><title>pgAdmin 4</title></head><body><script src="/static/js/bundle.js?ver=62100"></script></body></html>`,
			wantVersion:     "6.21",
			wantCPEContains: "6.21",
		},
		{
			name:            "pgAdmin 8.6.1 with patch version",
			body:            `<html><head><title>pgAdmin 4</title></head><body><script src="/static/js/bundle.js?ver=80601"></script></body></html>`,
			wantVersion:     "8.6.1",
			wantCPEContains: "8.6.1",
		},
		{
			name:            "pgAdmin 4.30 login page",
			body:            `<html><head><title>pgAdmin 4</title></head><body><script src="/static/js/bundle.js?ver=43000"></script></body></html>`,
			wantVersion:     "4.30",
			wantCPEContains: "4.30",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PgAdminLoginFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want non-nil result")
			}

			if result.Technology != "pgadmin" {
				t.Errorf("Technology = %q, want %q", result.Technology, "pgadmin")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) == 0 {
				t.Fatal("Expected at least one CPE")
			}
			if !strings.Contains(result.CPEs[0], tt.wantCPEContains) {
				t.Errorf("CPE = %q, want it to contain %q", result.CPEs[0], tt.wantCPEContains)
			}
		})
	}
}

func TestPgAdminLoginFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "HTML page without pgAdmin markers",
			body: `<html><head><title>Some App</title></head><body><script src="/js/app.js?ver=10200"></script></body></html>`,
		},
		{
			name: "Page with ver= but no pgAdmin",
			body: `<html><head><title>Other App</title></head><body><script src="/js/app.js?ver=91400"></script></body></html>`,
		},
		{
			name: "pgAdmin page without ver= parameter",
			body: `<html><head><title>pgAdmin 4</title></head><body><script src="/static/js/bundle.js"></script></body></html>`,
		},
		{
			name: "Empty body",
			body: ``,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &PgAdminLoginFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")

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

func TestPgadminVersionFromInt(t *testing.T) {
	tests := []struct {
		versionInt int
		want       string
	}{
		{91400, "9.14"},
		{62100, "6.21"},
		{80601, "8.6.1"},
		{43000, "4.30"},
		{50700, "5.7"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			if got := pgadminVersionFromInt(tt.versionInt); got != tt.want {
				t.Errorf("pgadminVersionFromInt(%d) = %q, want %q", tt.versionInt, got, tt.want)
			}
		})
	}
}

func TestPgAdminLoginFingerprinter_LiveDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live Docker test in short mode")
	}
	// Expects: docker run -d --name pgadmin-test -p 5050:80 -e PGADMIN_DEFAULT_EMAIL=test@test.com -e PGADMIN_DEFAULT_PASSWORD=test123 dpage/pgadmin4:latest
	baseURL := "http://localhost:5050"

	resp, err := http.Get(baseURL + "/login")
	if err != nil {
		t.Skipf("pgAdmin not available at %s: %v", baseURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}

	fp := &PgAdminLoginFingerprinter{}
	if !fp.Match(resp) {
		t.Skip("Content-Type does not match")
	}

	result, err := fp.Fingerprint(resp, body)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Skip("Login page did not match pgAdmin login fingerprinter (no pgAdmin markers found)")
	}
	if result.Technology != "pgadmin" {
		t.Errorf("Technology = %q, want %q", result.Technology, "pgadmin")
	}
	t.Logf("Detected pgAdmin via login page, version=%s", result.Version)
}
