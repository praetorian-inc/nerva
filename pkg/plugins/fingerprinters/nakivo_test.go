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

var _ ActiveHTTPFingerprinter = (*NAKIVOFingerprinter)(nil)

func TestNAKIVOFingerprinter_Name(t *testing.T) {
	f := &NAKIVOFingerprinter{}
	if got := f.Name(); got != "nakivo" {
		t.Errorf("Name() = %q, want %q", got, "nakivo")
	}
}

func TestNAKIVOFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &NAKIVOFingerprinter{}
	if got := f.ProbeEndpoint(); got != "/c/login" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/c/login")
	}
}

func TestNAKIVOFingerprinter_Match(t *testing.T) {
	f := &NAKIVOFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "accepts 200 text/html",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			want:       true,
		},
		{
			name:       "accepts 404 text/html",
			statusCode: 404,
			headers:    http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			want:       true,
		},
		{
			name:       "accepts 499 text/html",
			statusCode: 499,
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
			name:       "rejects application/json",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"application/json"}},
			want:       false,
		},
		{
			name:       "rejects missing content-type",
			statusCode: 200,
			headers:    http.Header{},
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

func TestNAKIVOFingerprinter_Fingerprint(t *testing.T) {
	f := &NAKIVOFingerprinter{}

	tests := []struct {
		name        string
		statusCode  int
		headers     http.Header
		body        string
		wantResult  bool
		wantVersion string
	}{
		{
			name:       "standalone: title NAKIVO Backup &amp; Replication",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><head><title>NAKIVO Backup &amp; Replication</title></head><body></body></html>`,
			wantResult: true,
		},
		{
			name:        "standalone: title with version extracts version",
			statusCode:  200,
			headers:     http.Header{"Content-Type": []string{"text/html"}},
			body:        `<html><head><title>NAKIVO Backup & Replication v10.11.3</title></head><body></body></html>`,
			wantResult:  true,
			wantVersion: "10.11.3",
		},
		{
			name:       "corroborated: /c/router + AuthenticationManagement, no title",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><script>Ext.direct.Manager.addProvider({"url":"/c/router","actions":{"AuthenticationManagement":[]}});</script></body></html>`,
			wantResult: true,
		},
		{
			name:        "positive: version 10.11.3 in body reflected in CPE",
			statusCode:  200,
			headers:     http.Header{"Content-Type": []string{"text/html"}},
			body:        `<html><head><title>NAKIVO Backup</title></head><body>Version 10.11.3</body></html>`,
			wantResult:  true,
			wantVersion: "10.11.3",
		},
		{
			name:       "negative: title NAKIVO without Backup",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><head><title>NAKIVO</title></head><body></body></html>`,
			wantResult: false,
		},
		{
			name:       "negative: status 500",
			statusCode: 500,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><head><title>NAKIVO Backup</title></head><body></body></html>`,
			wantResult: false,
		},
		{
			name:       "negative: /c/router without AuthenticationManagement",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><script>var x = "/c/router";</script></body></html>`,
			wantResult: false,
		},
		{
			name:       "negative: content-type application/json",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"application/json"}},
			body:       `{"title":"NAKIVO Backup"}`,
			wantResult: false,
		},
		{
			name:       "version guard: colon in version yields empty version",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><head><title>NAKIVO Backup</title></head><body>Build 10:11.3</body></html>`,
			wantResult: true,
		},
		{
			name:        "version extraction ignores preceding JS library version",
			statusCode:  200,
			headers:     http.Header{"Content-Type": []string{"text/html"}},
			body:        `<html><head><title>NAKIVO Backup &amp; Replication</title><script src="/ext-all.js?v=4.2.1"></script></head><body><h1>NAKIVO v10.11.3</h1></body></html>`,
			wantResult:  true,
			wantVersion: "10.11.3",
		},
		{
			name:        "version extraction ignores IP address in body",
			statusCode:  200,
			headers:     http.Header{"Content-Type": []string{"text/html"}},
			body:        `<html><head><title>NAKIVO Backup</title></head><body><p>Server: 192.168.1.100</p><h1>NAKIVO v10.11.3</h1></body></html>`,
			wantResult:  true,
			wantVersion: "10.11.3",
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

			// Mandatory: Severity must be unset (fingerprinter-only, no misconfig).
			if result.Severity != "" {
				t.Errorf("Severity = %q, want empty string", result.Severity)
			}
			if len(result.SecurityFindings) != 0 {
				t.Errorf("SecurityFindings = %v, want empty", result.SecurityFindings)
			}

			if result.Technology != "nakivo" {
				t.Errorf("Technology = %q, want %q", result.Technology, "nakivo")
			}

			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
		})
	}
}

func TestNAKIVOFingerprinter_VersionGuard(t *testing.T) {
	f := &NAKIVOFingerprinter{}
	resp := &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html"}},
	}
	body := `<html><head><title>NAKIVO Backup</title></head><body>Build 10:11.3</body></html>`
	result, err := f.Fingerprint(resp, []byte(body))
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil, expected a result")
	}
	if result.Version != "" {
		t.Errorf("Version = %q, want empty string (metacharacter guard should reject colon)", result.Version)
	}
}

func TestNAKIVOFingerprinter_CPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantCPE string
	}{
		{
			name:    "with version",
			version: "10.11.3",
			wantCPE: `cpe:2.3:a:nakivo:backup_\&_replication_director:10.11.3:*:*:*:*:*:*:*`,
		},
		{
			name:    "without version uses wildcard",
			version: "",
			wantCPE: `cpe:2.3:a:nakivo:backup_\&_replication_director:*:*:*:*:*:*:*:*`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildNAKIVOCPE(tt.version)
			if got != tt.wantCPE {
				t.Errorf("buildNAKIVOCPE(%q) = %q, want %q", tt.version, got, tt.wantCPE)
			}
			if !strings.Contains(got, `\&`) {
				t.Errorf("buildNAKIVOCPE(%q) = %q, want escaped ampersand in product name", tt.version, got)
			}
		})
	}
}
