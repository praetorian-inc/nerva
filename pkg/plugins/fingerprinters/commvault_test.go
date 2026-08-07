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

func TestCommvaultFingerprinter_Name(t *testing.T) {
	f := &CommvaultFingerprinter{}
	if got := f.Name(); got != "commvault" {
		t.Errorf("Name() = %q, want %q", got, "commvault")
	}
}

func TestCommvaultFingerprinter_Match(t *testing.T) {
	f := &CommvaultFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "accepts Server header containing Commvault",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"Commvault WebServer"}},
			want:       true,
		},
		{
			name:       "accepts Server header case-insensitive",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"commvault webserver"}},
			want:       true,
		},
		{
			name:       "rejects 500 server error",
			statusCode: 500,
			headers:    http.Header{"Server": []string{"Commvault WebServer"}},
			want:       false,
		},
		{
			name:       "rejects unrelated Server header",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"Apache/2.4.29"}},
			want:       false,
		},
		{
			name:       "rejects no headers",
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

func TestCommvaultFingerprinter_Fingerprint(t *testing.T) {
	f := &CommvaultFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		body       string
		wantResult bool
		wantFlag   string
		wantGorkha string
	}{
		{
			name:       "positive: Server header Commvault WebServer",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"Commvault WebServer"}},
			body:       ``,
			wantResult: true,
		},
		{
			name:       "positive: Server header case-insensitive",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"commvault webserver"}},
			body:       ``,
			wantResult: true,
		},
		{
			name:       "positive: Server header with version-like suffix",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"Commvault WebServer 11.28"}},
			body:       ``,
			wantResult: true,
		},
		{
			name:       "positive: with WEBSERVERCORE-FLAG and cv-gorkha headers",
			statusCode: 200,
			headers: http.Header{
				"Server":             []string{"Commvault WebServer"},
				"Webservercore-Flag": []string{"1"},
				"Cv-Gorkha":          []string{"active"},
			},
			body:       ``,
			wantResult: true,
			wantFlag:   "1",
			wantGorkha: "active",
		},
		{
			name:       "negative: unrelated Server header",
			statusCode: 200,
			headers:    http.Header{"Server": []string{"Apache/2.4.29"}},
			body:       ``,
			wantResult: false,
		},
		{
			name:       "negative: 500 status",
			statusCode: 500,
			headers:    http.Header{"Server": []string{"Commvault WebServer"}},
			body:       ``,
			wantResult: false,
		},
		{
			name:       "negative: no Server header, body contains Commvault",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>Commvault Command Center</body></html>`,
			wantResult: false,
		},
		{
			name:       "negative: empty response headers",
			statusCode: 200,
			headers:    http.Header{},
			body:       ``,
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

			if result.Severity != "" {
				t.Errorf("Severity = %q, want empty string (fingerprinter-only, no severity)", result.Severity)
			}

			if result.Technology != "commvault" {
				t.Errorf("Technology = %q, want %q", result.Technology, "commvault")
			}

			if result.Version != "" {
				t.Errorf("Version = %q, want empty string", result.Version)
			}

			if len(result.SecurityFindings) != 0 {
				t.Errorf("SecurityFindings = %v, want empty", result.SecurityFindings)
			}

			if len(result.CPEs) != 1 || result.CPEs[0] != "cpe:2.3:a:commvault:commvault:*:*:*:*:*:*:*:*" {
				t.Errorf("CPEs = %v, want [%q]", result.CPEs, "cpe:2.3:a:commvault:commvault:*:*:*:*:*:*:*:*")
			}

			if tt.wantFlag != "" {
				if got, _ := result.Metadata["webservercore_flag"].(string); got != tt.wantFlag {
					t.Errorf("Metadata[webservercore_flag] = %q, want %q", got, tt.wantFlag)
				}
			}

			if tt.wantGorkha != "" {
				if got, _ := result.Metadata["gorkha"].(string); got != tt.wantGorkha {
					t.Errorf("Metadata[gorkha] = %q, want %q", got, tt.wantGorkha)
				}
			}
		})
	}
}

// TestCommvaultFingerprinter_PassiveInterface verifies that CommvaultFingerprinter
// implements HTTPFingerprinter (passive) but NOT ActiveHTTPFingerprinter.
func TestCommvaultFingerprinter_PassiveInterface(t *testing.T) {
	var _ HTTPFingerprinter = (*CommvaultFingerprinter)(nil)

	if _, ok := any(&CommvaultFingerprinter{}).(ActiveHTTPFingerprinter); ok {
		t.Error("CommvaultFingerprinter must NOT implement ActiveHTTPFingerprinter (passive fingerprinter)")
	}
}
