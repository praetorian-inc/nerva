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

// Interface compliance assertion
var _ ActiveHTTPFingerprinter = (*SolarWindsWHDFingerprinter)(nil)

func TestSolarWindsWHDFingerprinter_Name(t *testing.T) {
	f := &SolarWindsWHDFingerprinter{}
	if got := f.Name(); got != "solarwinds-whd" {
		t.Errorf("Name() = %q, want %q", got, "solarwinds-whd")
	}
}

func TestSolarWindsWHDFingerprinter_ProbeEndpoint(t *testing.T) {
	f := &SolarWindsWHDFingerprinter{}
	if got := f.ProbeEndpoint(); got != "/helpdesk/WebObjects/Helpdesk.woa" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/helpdesk/WebObjects/Helpdesk.woa")
	}
}

func TestSolarWindsWHDFingerprinter_Match(t *testing.T) {
	f := &SolarWindsWHDFingerprinter{}

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
			name:       "accepts x-webobjects-loadaverage header",
			statusCode: 200,
			headers:    http.Header{"X-Webobjects-Loadaverage": []string{"1.5"}},
			want:       true,
		},
		{
			name:       "accepts x-webobjects-servlet header",
			statusCode: 200,
			headers:    http.Header{"X-Webobjects-Servlet": []string{"Helpdesk.woa"}},
			want:       true,
		},
		{
			name:       "accepts 404 with WebObjects header",
			statusCode: 404,
			headers:    http.Header{"X-Webobjects-Loadaverage": []string{"0.2"}},
			want:       true,
		},
		{
			name:       "rejects 500 server error",
			statusCode: 500,
			headers:    http.Header{"Content-Type": []string{"text/html"}, "X-Webobjects-Loadaverage": []string{"1.5"}},
			want:       false,
		},
		{
			name:       "rejects application/json without WebObjects header",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"application/json"}},
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

func TestSolarWindsWHDFingerprinter_Fingerprint(t *testing.T) {
	f := &SolarWindsWHDFingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		body       string
		wantResult bool
	}{
		{
			name:       "positive: x-webobjects-loadaverage header present",
			statusCode: 200,
			headers:    http.Header{"X-Webobjects-Loadaverage": []string{"1.2"}},
			body:       ``,
			wantResult: true,
		},
		{
			name:       "positive: x-webobjects-servlet header present",
			statusCode: 200,
			headers:    http.Header{"X-Webobjects-Servlet": []string{"Helpdesk.woa"}},
			body:       ``,
			wantResult: true,
		},
		{
			name:       "positive: body contains both Web Help Desk and SolarWinds",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><h1>Web Help Desk</h1><footer>SolarWinds</footer></body></html>`,
			wantResult: true,
		},
		{
			name:       "negative: body contains Web Help Desk but not SolarWinds",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><h1>Web Help Desk</h1></body></html>`,
			wantResult: false,
		},
		{
			name:       "negative: status 500",
			statusCode: 500,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>Web Help Desk SolarWinds</body></html>`,
			wantResult: false,
		},
		{
			name:       "negative: empty body, no WebObjects headers",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       ``,
			wantResult: false,
		},
		{
			name:       "positive: WebObjects header present without body markers (probe path confirms WHD)",
			statusCode: 200,
			headers:    http.Header{"X-Webobjects-Loadaverage": []string{"0.9"}},
			body:       `<html><body>OK</body></html>`,
			wantResult: true,
		},
		{
			name:       "negative: unrelated HTML, no headers, no brand terms",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><h1>Login</h1><form action="/login">Username</form></body></html>`,
			wantResult: false,
		},
		{
			name:       "positive: case-insensitive brand match",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>WEB HELP DESK by solarwinds</body></html>`,
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

			if result.Technology != "solarwinds-whd" {
				t.Errorf("Technology = %q, want %q", result.Technology, "solarwinds-whd")
			}

			if result.Version != "" {
				t.Errorf("Version = %q, want empty string", result.Version)
			}

			if len(result.SecurityFindings) != 0 {
				t.Errorf("SecurityFindings = %v, want empty", result.SecurityFindings)
			}
		})
	}
}

func TestSolarWindsWHDFingerprinter_CPE(t *testing.T) {
	result := buildSolarWindsWHDResult()
	if len(result.CPEs) != 1 {
		t.Fatalf("CPEs length = %d, want 1", len(result.CPEs))
	}
	want := "cpe:2.3:a:solarwinds:webhelpdesk:*:*:*:*:*:*:*:*"
	if result.CPEs[0] != want {
		t.Errorf("CPE = %q, want %q", result.CPEs[0], want)
	}
	if !strings.HasPrefix(result.CPEs[0], "cpe:2.3:a:solarwinds:webhelpdesk:") {
		t.Errorf("CPE[0] = %q, want prefix cpe:2.3:a:solarwinds:webhelpdesk:", result.CPEs[0])
	}
	// Mandatory severity check
	if result.Severity != "" {
		t.Errorf("Severity = %q, want empty string", result.Severity)
	}
}
