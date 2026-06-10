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

func TestBeyondtrustPRAFingerprinter_Name(t *testing.T) {
	f := &BeyondtrustPRAFingerprinter{}
	if got := f.Name(); got != "beyondtrust-pra" {
		t.Errorf("Name() = %q, want %q", got, "beyondtrust-pra")
	}
}

func TestBeyondtrustPRAFingerprinter_Match(t *testing.T) {
	f := &BeyondtrustPRAFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "accepts text/html 200",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html; charset=UTF-8"}},
			want:       true,
		},
		{
			name:       "accepts text/html 302",
			statusCode: 302,
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
			name:       "accepts text/html 404",
			statusCode: 404,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			want:       true,
		},
		{
			name:       "rejects 500 server error",
			statusCode: 500,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			want:       false,
		},
		{
			name:       "rejects 503 server error",
			statusCode: 503,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			want:       false,
		},
		{
			name:       "rejects application/json without text/html",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"application/json"}},
			want:       false,
		},
		{
			name:       "rejects 100 informational",
			statusCode: 100,
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

func TestBeyondtrustPRAFingerprinter_Fingerprint(t *testing.T) {
	f := &BeyondtrustPRAFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		body       string
		wantResult bool
	}{
		// Signal 1 standalone: exact product phrase
		{
			name:       "standalone: exact product name in body",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><h1>BeyondTrust Privileged Remote Access</h1></body></html>`,
			wantResult: true,
		},
		// Signal 2 corroborated: BeyondTrust brand + /appliance path
		{
			name:       "corroborated: BeyondTrust brand + /appliance path",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/appliance">Settings</a><span>BeyondTrust</span></body></html>`,
			wantResult: true,
		},
		// Signal 2 corroborated: BeyondTrust brand + /api/client_script path
		{
			name:       "corroborated: BeyondTrust brand + /api/client_script path",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><script src="/api/client_script"></script><p>BeyondTrust Remote Support</p></body></html>`,
			wantResult: true,
		},
		// Signal 3 corroborated: Bomgar brand + powered_by_text
		{
			name:       "corroborated: Bomgar brand + powered_by_text pattern",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><span id="powered_by_text">Bomgar Remote Support</span></body></html>`,
			wantResult: true,
		},
		// Signal 3 corroborated: Bomgar brand + %POWERED_BY%
		{
			name:       "corroborated: Bomgar brand + %POWERED_BY% template marker",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>%POWERED_BY% <span>Bomgar Corporation</span></body></html>`,
			wantResult: true,
		},
		// FP prevention: powered_by_text without Bomgar brand — not sufficient
		{
			name:       "FP prevention: powered_by_text without Bomgar brand returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><span id="powered_by_text">Some Other Vendor</span></body></html>`,
			wantResult: false,
		},
		// FP prevention: BeyondTrust brand alone — not sufficient
		{
			name:       "FP prevention: BeyondTrust brand alone returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>BeyondTrust was affected by a critical vulnerability this year.</body></html>`,
			wantResult: false,
		},
		// FP prevention: Bomgar brand alone — not sufficient
		{
			name:       "FP prevention: Bomgar brand alone returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>Bomgar was rebranded to BeyondTrust in 2018.</body></html>`,
			wantResult: false,
		},
		// FP prevention: /appliance path alone — not sufficient
		{
			name:       "FP prevention: /appliance path alone without brand returns nil",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/appliance">My Network Appliance</a></body></html>`,
			wantResult: false,
		},
		// Negative: 500 error returns nil
		{
			name:       "negative: 500 error returns nil",
			statusCode: 500,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>BeyondTrust Privileged Remote Access</body></html>`,
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
		// Case insensitive: BEYONDTRUST in all caps
		{
			name:       "case-insensitive: BEYONDTRUST brand + /appliance",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><a href="/appliance">Admin</a><p>BEYONDTRUST Security</p></body></html>`,
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

			if result.Technology != "beyondtrust-pra" {
				t.Errorf("Technology = %q, want %q", result.Technology, "beyondtrust-pra")
			}

			if len(result.CPEs) == 0 {
				t.Fatal("CPEs is empty")
			}
			if result.CPEs[0] != "cpe:2.3:a:beyondtrust:privileged_remote_access:*:*:*:*:*:*:*:*" {
				t.Errorf("CPE[0] = %q, want %q", result.CPEs[0], "cpe:2.3:a:beyondtrust:privileged_remote_access:*:*:*:*:*:*:*:*")
			}

			if len(result.SecurityFindings) != 0 {
				t.Errorf("SecurityFindings = %v, want empty", result.SecurityFindings)
			}
		})
	}
}

func TestBeyondtrustPRAFingerprinter_CPE(t *testing.T) {
	f := &BeyondtrustPRAFingerprinter{}

	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	body := []byte(`<html><body>BeyondTrust Privileged Remote Access</body></html>`)

	result, err := f.Fingerprint(resp, body)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}

	wantCPE := "cpe:2.3:a:beyondtrust:privileged_remote_access:*:*:*:*:*:*:*:*"
	if len(result.CPEs) != 1 {
		t.Fatalf("CPEs length = %d, want 1", len(result.CPEs))
	}
	if result.CPEs[0] != wantCPE {
		t.Errorf("CPE = %q, want %q", result.CPEs[0], wantCPE)
	}

	// Version should be empty (not extractable unauthenticated)
	if result.Version != "" {
		t.Errorf("Version = %q, want empty string (not extractable unauthenticated)", result.Version)
	}
}

// TestBeyondtrustPRAFingerprinter_PassiveInterface verifies that BeyondtrustPRAFingerprinter
// implements HTTPFingerprinter (passive) but NOT ActiveHTTPFingerprinter.
func TestBeyondtrustPRAFingerprinter_PassiveInterface(t *testing.T) {
	var _ HTTPFingerprinter = (*BeyondtrustPRAFingerprinter)(nil)
}
