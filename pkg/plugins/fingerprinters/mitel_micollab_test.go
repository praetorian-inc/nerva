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
	"strings"
	"testing"
)

func TestMitelMicollabFingerprinter_Name(t *testing.T) {
	f := &MitelMicollabFingerprinter{}
	if got := f.Name(); got != "mitel-micollab" {
		t.Errorf("Name() = %q, want %q", got, "mitel-micollab")
	}
}

func TestMitelMicollabFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &MitelMicollabFingerprinter{}
	if got := f.ProbeEndpoint(); got != "/ucs/micollab/version.json" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/ucs/micollab/version.json")
	}
}

func TestMitelMicollabFingerprinter_Match(t *testing.T) {
	f := &MitelMicollabFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "accepts application/json 200",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"application/json"}},
			want:       true,
		},
		{
			name:       "accepts text/html 200",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			want:       true,
		},
		{
			name:       "accepts text/html 401",
			statusCode: 401,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			want:       true,
		},
		{
			name:       "FP prevention: 302 redirect to /portal/ is not MiCollab-specific",
			statusCode: 302,
			headers:    http.Header{"Location": []string{"/portal/index.html"}},
			want:       false,
		},
		{
			name:       "accepts 302 redirect to /awc/",
			statusCode: 302,
			headers:    http.Header{"Location": []string{"/awc/login"}},
			want:       true,
		},
		{
			name:       "rejects 302 redirect to unrelated path",
			statusCode: 302,
			headers:    http.Header{"Location": []string{"/login"}},
			want:       false,
		},
		{
			name:       "rejects 500 server error",
			statusCode: 500,
			headers:    http.Header{"Content-Type": []string{"application/json"}},
			want:       false,
		},
		{
			name:       "rejects 503 server error",
			statusCode: 503,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.headers,
			}
			if got := f.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestMitelMicollabFingerprinter_Fingerprint(t *testing.T) {
	f := &MitelMicollabFingerprinter{}

	tests := []struct {
		name        string
		statusCode  int
		headers     http.Header
		body        string
		wantResult  bool
		wantVersion string
	}{
		// Signal 1 standalone: JSON probe with "version" key
		{
			name:        "standalone: JSON version.json response with version",
			statusCode:  200,
			headers:     http.Header{"Content-Type": []string{"application/json"}},
			body:        `{"version": "9.8.1.201", "build": "12345"}`,
			wantResult:  true,
			wantVersion: "9.8.1.201",
		},
		// Signal 1 standalone: three-segment version
		{
			name:        "standalone: JSON version.json with 3-segment version",
			statusCode:  200,
			headers:     http.Header{"Content-Type": []string{"application/json"}},
			body:        `{"version": "9.8.1"}`,
			wantResult:  true,
			wantVersion: "9.8.1",
		},
		// Signal 1 standalone: version key with non-numeric string still detects
		{
			name:       "standalone: version key with non-numeric string still detects",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"application/json"}},
			body:       `{"version": "unknown"}`,
			wantResult: true,
		},
		// Signal 1: JSON without "version" key — not MiCollab
		{
			name:       "negative: JSON without version key returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"application/json"}},
			body:       `{"status": "ok", "name": "some-api"}`,
			wantResult: false,
		},
		// Signal 2 corroborated: MiCollab End User Portal phrase
		{
			name:       "corroborated: MiCollab End User Portal phrase",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><h1>MiCollab End User Portal</h1></body></html>`,
			wantResult: true,
		},
		// Signal 2 corroborated: AWC User Portal phrase
		{
			name:       "corroborated: AWC User Portal phrase",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><title>AWC User Portal</title></body></html>`,
			wantResult: true,
		},
		// Signal 3 corroborated: /awc/ path + Mitel brand
		{
			name:       "corroborated: /awc/ path + Mitel brand",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/awc/login">Login</a><p>Mitel Networks</p></body></html>`,
			wantResult: true,
		},
		// FP prevention: Mitel brand alone — not sufficient
		{
			name:       "FP prevention: Mitel brand alone returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>Mitel was affected by a critical vulnerability.</body></html>`,
			wantResult: false,
		},
		// FP prevention: /awc/ path alone without brand — not sufficient
		{
			name:       "FP prevention: /awc/ path alone without brand returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/awc/login">Login</a></body></html>`,
			wantResult: false,
		},
		// FP prevention: /portal/ is generic, must not match
		{
			name:       "FP prevention: redirect to /portal/login returns nil",
			statusCode: 302,
			headers:    http.Header{"Location": []string{"/portal/login"}},
			body:       ``,
			wantResult: false,
		},
		// Redirect to /awc/
		{
			name:       "redirect to /awc/ detected",
			statusCode: 302,
			headers:    http.Header{"Location": []string{"/awc/login"}},
			body:       ``,
			wantResult: true,
		},
		// Negative: 500 error
		{
			name:       "negative: 500 error returns nil",
			statusCode: 500,
			headers:    http.Header{"Content-Type": []string{"application/json"}},
			body:       `{"version": "9.8.1.201"}`,
			wantResult: false,
		},
		// Negative: unrelated JSON
		{
			name:       "negative: unrelated JSON returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"application/json"}},
			body:       `{"status": "healthy"}`,
			wantResult: false,
		},
		// Negative: unrelated HTML
		{
			name:       "negative: unrelated HTML returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><h1>Login</h1><form action="/login">Username</form></body></html>`,
			wantResult: false,
		},
		// Case insensitive Mitel brand
		{
			name:       "case-insensitive: MITEL brand + /awc/ path",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/awc/home">Home</a><p>MITEL Communications</p></body></html>`,
			wantResult: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     tt.headers,
			}
			result, err := f.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Errorf("Fingerprint() error = %v", err)
				return
			}
			if tt.wantResult && result == nil {
				t.Error("Fingerprint() returned nil, expected a result")
				return
			}
			if !tt.wantResult && result != nil {
				t.Errorf("Fingerprint() returned result, expected nil; Technology=%q", result.Technology)
				return
			}
			if result == nil {
				return
			}

			// Mandatory: Severity must be unset (empty).
			if result.Severity != "" {
				t.Errorf("Severity = %q, want empty string (fingerprinter-only, no severity)", result.Severity)
			}

			if result.Technology != "mitel-micollab" {
				t.Errorf("Technology = %q, want %q", result.Technology, "mitel-micollab")
			}

			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			if len(result.SecurityFindings) != 0 {
				t.Errorf("SecurityFindings = %v, want empty", result.SecurityFindings)
			}
		})
	}
}

func TestMitelMicollabFingerprinter_VersionExtraction(t *testing.T) {
	tests := []struct {
		name  string
		value any
		want  string
	}{
		{
			name:  "four-segment version string",
			value: "9.8.1.201",
			want:  "9.8.1.201",
		},
		{
			name:  "three-segment version string",
			value: "9.8.1",
			want:  "9.8.1",
		},
		{
			name:  "two-segment version string",
			value: "9.8",
			want:  "9.8",
		},
		{
			name:  "version with letters — rejected by validation",
			value: "9.8.1-beta",
			want:  "",
		},
		{
			name:  "non-string value (number) — rejected",
			value: float64(9),
			want:  "",
		},
		{
			name:  "empty string — rejected by validation",
			value: "",
			want:  "",
		},
		{
			name:  "version with CPE injection characters — rejected",
			value: "9.8.1:*:*:*",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractMitelVersion(tt.value); got != tt.want {
				t.Errorf("extractMitelVersion(%v) = %q, want %q", tt.value, got, tt.want)
			}
		})
	}
}

func TestMitelMicollabFingerprinter_CPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantCPE string
	}{
		{
			name:    "with four-segment version",
			version: "9.8.1.201",
			wantCPE: "cpe:2.3:a:mitel:micollab:9.8.1.201:*:*:*:*:*:*:*",
		},
		{
			name:    "with three-segment version",
			version: "9.8.1",
			wantCPE: "cpe:2.3:a:mitel:micollab:9.8.1:*:*:*:*:*:*:*",
		},
		{
			name:    "without version uses wildcard",
			version: "",
			wantCPE: "cpe:2.3:a:mitel:micollab:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildMitelResult(tt.version)
			if len(result.CPEs) != 1 {
				t.Fatalf("CPEs length = %d, want 1", len(result.CPEs))
			}
			if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], tt.wantCPE)
			}
			// Mandatory severity check
			if result.Severity != "" {
				t.Errorf("Severity = %q, want empty string", result.Severity)
			}
		})
	}
}

// TestMitelMicollabFingerprinter_ActiveInterface verifies that MitelMicollabFingerprinter
// implements the ActiveHTTPFingerprinter interface.
func TestMitelMicollabFingerprinter_ActiveInterface(t *testing.T) {
	var _ ActiveHTTPFingerprinter = (*MitelMicollabFingerprinter)(nil)
}

// TestMitelMicollabFingerprinter_CPEVendor verifies the CPE uses "mitel" as vendor.
func TestMitelMicollabFingerprinter_CPEVendor(t *testing.T) {
	f := &MitelMicollabFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}
	body := []byte(`{"version": "9.8.1.201"}`)
	result, err := f.Fingerprint(resp, body)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}
	if len(result.CPEs) == 0 {
		t.Fatal("CPEs is empty")
	}
	if !strings.HasPrefix(result.CPEs[0], "cpe:2.3:a:mitel:micollab:") {
		t.Errorf("CPE[0] = %q, want prefix cpe:2.3:a:mitel:micollab:", result.CPEs[0])
	}
}
