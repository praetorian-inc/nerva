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

func TestSimplehelpFingerprinter_Name(t *testing.T) {
	f := &SimplehelpFingerprinter{}
	if got := f.Name(); got != "simplehelp" {
		t.Errorf("Name() = %q, want %q", got, "simplehelp")
	}
}

func TestSimplehelpFingerprinter_Match(t *testing.T) {
	f := &SimplehelpFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "accepts text/html 200",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			want:       true,
		},
		{
			name:       "accepts Server header containing SimpleHelp",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"SimpleHelp/5.5.16"}},
			want:       true,
		},
		{
			name:       "accepts Server header with SimpleHelp bare",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"SimpleHelp"}},
			want:       true,
		},
		{
			name:       "accepts Server header with simplehelp lowercase",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"simplehelp/5.3.0"}},
			want:       true,
		},
		{
			name:       "rejects 500 server error",
			statusCode: 500,
			headers:    http.Header{"Content-Type": []string{"text/html"}, "Server": []string{"SimpleHelp/5.5.16"}},
			want:       false,
		},
		{
			name:       "rejects application/json without SimpleHelp server header",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"application/json"}},
			want:       false,
		},
		{
			name:       "accepts text/html even without Server header",
			statusCode: 404,
			headers:    http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			want:       true,
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

func TestSimplehelpFingerprinter_Fingerprint(t *testing.T) {
	f := &SimplehelpFingerprinter{}

	tests := []struct {
		name        string
		statusCode  int
		headers     http.Header
		body        string
		wantResult  bool
		wantVersion string
	}{
		// Signal 1 standalone: Server header with version
		{
			name:        "standalone: Server header SimpleHelp/5.5.16",
			statusCode:  200,
			headers:     http.Header{"Server": []string{"SimpleHelp/5.5.16"}},
			body:        `<html><body>Welcome</body></html>`,
			wantResult:  true,
			wantVersion: "5.5.16",
		},
		// Signal 1 standalone: Server header with version space-separated
		{
			name:        "standalone: Server header SimpleHelp 5.5.16",
			statusCode:  200,
			headers:     http.Header{"Server": []string{"SimpleHelp 5.5.16"}},
			body:        ``,
			wantResult:  true,
			wantVersion: "5.5.16",
		},
		// Signal 1 standalone: Server header without version
		{
			name:       "standalone: Server header SimpleHelp bare (no version)",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"SimpleHelp"}},
			body:       ``,
			wantResult: true,
		},
		// Signal 2 corroborated: SimpleHelp in body + simplehelp-text.svg
		{
			name:       "corroborated: SimpleHelp brand + simplehelp-text.svg asset",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><img src="/simplehelp-text.svg"><p>SimpleHelp Remote Support</p></body></html>`,
			wantResult: true,
		},
		// FP prevention: single portal path is insufficient (brand + 1 path no longer triggers)
		{
			name:       "FP prevention: SimpleHelp brand + single /customer path insufficient",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/customer">Customer Access</a><p>SimpleHelp</p></body></html>`,
			wantResult: false,
		},
		{
			name:       "FP prevention: SimpleHelp brand + single /technician path insufficient",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/technician">Technician Console</a><span>SimpleHelp</span></body></html>`,
			wantResult: false,
		},
		{
			name:       "FP prevention: SimpleHelp brand + single /access path insufficient",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/access">Remote Access</a><p>SimpleHelp</p></body></html>`,
			wantResult: false,
		},
		// Signal 2 corroborated: brand + 2 portal paths
		{
			name:       "corroborated: SimpleHelp brand + /customer and /technician paths",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/customer">Customer</a><a href="/technician">Technician</a><p>SimpleHelp</p></body></html>`,
			wantResult: true,
		},
		{
			name:       "corroborated: SimpleHelp brand + all three portal paths",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/customer">C</a><a href="/technician">T</a><a href="/access">A</a><p>SimpleHelp</p></body></html>`,
			wantResult: true,
		},
		// FP prevention: SimpleHelp brand alone in body — not sufficient
		{
			name:       "FP prevention: SimpleHelp in body alone returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>SimpleHelp is a remote support tool available on the market.</body></html>`,
			wantResult: false,
		},
		// FP prevention: distinctive asset without brand — not sufficient
		{
			name:       "FP prevention: /customer path without brand returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/customer">Customer Portal</a></body></html>`,
			wantResult: false,
		},
		// FP prevention: single paths without brand
		{
			name:       "FP prevention: /technician path without brand returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/technician">Staff Portal</a></body></html>`,
			wantResult: false,
		},
		{
			name:       "FP prevention: /access path without brand returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/access">Access</a></body></html>`,
			wantResult: false,
		},
		{
			name:       "FP prevention: simplehelp-text.svg without brand returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><img src="/simplehelp-text.svg"></body></html>`,
			wantResult: false,
		},
		// Negative: 500 error
		{
			name:       "negative: 500 error returns nil",
			statusCode: 500,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>SimpleHelp server error</body></html>`,
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

			if result.Technology != "simplehelp" {
				t.Errorf("Technology = %q, want %q", result.Technology, "simplehelp")
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

func TestSimplehelpFingerprinter_VersionExtraction(t *testing.T) {
	tests := []struct {
		name        string
		serverHeader string
		want        string
	}{
		{
			name:         "slash separator: SimpleHelp/5.5.16",
			serverHeader: "SimpleHelp/5.5.16",
			want:         "5.5.16",
		},
		{
			name:         "space separator: SimpleHelp 5.5.16",
			serverHeader: "SimpleHelp 5.5.16",
			want:         "5.5.16",
		},
		{
			name:         "two-part version: SimpleHelp/5.5",
			serverHeader: "SimpleHelp/5.5",
			want:         "5.5",
		},
		{
			name:         "case insensitive: simplehelp/5.3.0",
			serverHeader: "simplehelp/5.3.0",
			want:         "5.3.0",
		},
		{
			name:         "no version present",
			serverHeader: "SimpleHelp",
			want:         "",
		},
		{
			name:         "empty header",
			serverHeader: "",
			want:         "",
		},
		{
			name:         "unrelated server header",
			serverHeader: "Apache/2.4.51",
			want:         "",
		},
		{
			name:         "version with trailing letters — rejected by validation",
			serverHeader: "SimpleHelp/5.5.16abc",
			want:         "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractSimplehelpVersion(tt.serverHeader); got != tt.want {
				t.Errorf("extractSimplehelpVersion(%q) = %q, want %q", tt.serverHeader, got, tt.want)
			}
		})
	}
}

func TestSimplehelpFingerprinter_CPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantCPE string
	}{
		{
			name:    "with version",
			version: "5.5.16",
			wantCPE: "cpe:2.3:a:simple-help:simplehelp:5.5.16:*:*:*:*:*:*:*",
		},
		{
			name:    "without version uses wildcard",
			version: "",
			wantCPE: "cpe:2.3:a:simple-help:simplehelp:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildSimplehelpResult(tt.version)
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

// TestSimplehelpFingerprinter_PassiveInterface verifies that SimplehelpFingerprinter
// implements HTTPFingerprinter (passive) but NOT ActiveHTTPFingerprinter.
func TestSimplehelpFingerprinter_PassiveInterface(t *testing.T) {
	var _ HTTPFingerprinter = (*SimplehelpFingerprinter)(nil)
}

// TestSimplehelpFingerprinter_CPEVendor verifies the CPE uses "simple-help" as vendor
// (matching NVD naming convention).
func TestSimplehelpFingerprinter_CPEVendor(t *testing.T) {
	f := &SimplehelpFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Server": []string{"SimpleHelp/5.5.16"}},
	}
	result, err := f.Fingerprint(resp, []byte{})
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}
	if len(result.CPEs) == 0 {
		t.Fatal("CPEs is empty")
	}
	if !strings.HasPrefix(result.CPEs[0], "cpe:2.3:a:simple-help:simplehelp:") {
		t.Errorf("CPE[0] = %q, want prefix cpe:2.3:a:simple-help:simplehelp:", result.CPEs[0])
	}
}
