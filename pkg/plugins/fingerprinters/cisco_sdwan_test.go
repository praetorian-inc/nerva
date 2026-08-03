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

// -- Name --

func TestCiscoSDWANFingerprinter_Name(t *testing.T) {
	fp := &CiscoSDWANFingerprinter{}
	if got := fp.Name(); got != "cisco-sdwan" {
		t.Errorf("Name() = %q, want %q", got, "cisco-sdwan")
	}
}

// -- Match --

func TestCiscoSDWANFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		want       bool
	}{
		{name: "200 OK passes", statusCode: 200, want: true},
		{name: "302 redirect passes", statusCode: 302, want: true},
		{name: "404 passes", statusCode: 404, want: true},
		{name: "499 passes", statusCode: 499, want: true},
		{name: "100 rejected", statusCode: 100, want: false},
		{name: "500 rejected", statusCode: 500, want: false},
		{name: "503 rejected", statusCode: 503, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CiscoSDWANFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// -- Fingerprint: positive --

func TestCiscoSDWANFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name          string
		statusCode    int
		body          string
		wantDetection string
	}{
		{
			name:          "Title: Cisco vManage",
			statusCode:    200,
			body:          "<html><head><title>Cisco vManage</title></head><body></body></html>",
			wantDetection: "title",
		},
		{
			name:          "Title: Cisco SD-WAN",
			statusCode:    200,
			body:          "<html><head><title>Cisco SD-WAN</title></head><body></body></html>",
			wantDetection: "title",
		},
		{
			name:          "Title: Cisco Catalyst SD-WAN",
			statusCode:    200,
			body:          "<html><head><title>Cisco Catalyst SD-WAN</title></head><body></body></html>",
			wantDetection: "title",
		},
		{
			name:          "Title: Viptela vManage (legacy)",
			statusCode:    200,
			body:          "<html><head><title>Viptela vManage</title></head><body></body></html>",
			wantDetection: "title",
		},
		{
			name:          "Title case-insensitive",
			statusCode:    200,
			body:          "<html><head><TITLE>CISCO VMANAGE</TITLE></head></html>",
			wantDetection: "title",
		},
		{
			name:          "Tier-2: j_security_check + /dataservice/ together",
			statusCode:    200,
			body:          `<html><body><form action="/j_security_check"><input name="j_username"/></form><script src="/dataservice/client.js"></script></body></html>`,
			wantDetection: "login_form",
		},
		{
			name:          "Title beats Tier-2 signals (priority)",
			statusCode:    200,
			body:          `<html><head><title>Cisco vManage</title></head><body><form action="/j_security_check"></form><a href="/dataservice/"></a></body></html>`,
			wantDetection: "title",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CiscoSDWANFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want non-nil")
			}
			if result.Technology != "cisco-sdwan-manager" {
				t.Errorf("Technology = %q, want cisco-sdwan-manager", result.Technology)
			}
			if result.Version != "" {
				t.Errorf("Version = %q, want empty (no version extraction)", result.Version)
			}
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			} else if result.CPEs[0] != "cpe:2.3:a:cisco:catalyst_sd-wan_manager:*:*:*:*:*:*:*:*" {
				t.Errorf("CPE = %q, want wildcard CPE", result.CPEs[0])
			}
			if result.Metadata == nil {
				t.Fatal("Metadata is nil")
			}
			if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != tt.wantDetection {
				t.Errorf("Metadata[detection_method] = %v, want %q", result.Metadata["detection_method"], tt.wantDetection)
			}
		})
	}
}

// -- Fingerprint: negative --

func TestCiscoSDWANFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{name: "Generic page", statusCode: 200, body: "<html><title>Welcome</title></html>"},
		{name: "Cisco but not vManage", statusCode: 200, body: "<html><title>Cisco ISE</title></html>"},
		{name: "j_security_check alone (no /dataservice/)", statusCode: 200, body: `<html><body><form action="/j_security_check"></form></body></html>`},
		{name: "/dataservice/ alone (no j_security_check)", statusCode: 200, body: `<html><body><a href="/dataservice/device"></a></body></html>`},
		{name: "CPE-injection attempt", statusCode: 200, body: "<html><title>Cisco vManage</title><body>:*:malicious</body></html>"},
		{name: "Body > 2 MiB rejected", statusCode: 200, body: "<title>Cisco vManage</title>" + string(make([]byte, 2*1024*1024+1))},
		{name: "Status 500 rejected", statusCode: 500, body: "<html><title>Cisco vManage</title></html>"},
		{name: "Status 199 rejected", statusCode: 199, body: "<html><title>Cisco vManage</title></html>"},
		{name: "Empty body", statusCode: 200},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &CiscoSDWANFingerprinter{}
			resp := &http.Response{StatusCode: tt.statusCode, Header: make(http.Header)}

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

// -- Integration --

func TestCiscoSDWANFingerprinter_Integration(t *testing.T) {
	fp := &CiscoSDWANFingerprinter{}

	resp := &http.Response{StatusCode: 200, Header: make(http.Header)}
	body := []byte(`<html><head><title>Cisco vManage</title></head>
<body><form action="/j_security_check" method="POST">
<input name="j_username"/><input name="j_password"/>
</form><script src="/dataservice/client.js"></script></body></html>`)

	if !fp.Match(resp) {
		t.Fatal("Match() returned false, want true")
	}
	result, err := fp.Fingerprint(resp, body)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil")
	}
	if result.Technology != "cisco-sdwan-manager" {
		t.Errorf("Technology = %q, want cisco-sdwan-manager", result.Technology)
	}
	if v, ok := result.Metadata["vendor"].(string); !ok || v != "Cisco" {
		t.Errorf("Metadata[vendor] = %v, want Cisco", result.Metadata["vendor"])
	}
	if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != "title" {
		t.Errorf("Metadata[detection_method] = %v, want title", result.Metadata["detection_method"])
	}
}
