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

func TestMongooseFingerprinter_Name(t *testing.T) {
	fp := &MongooseFingerprinter{}
	if got := fp.Name(); got != "mongoose" {
		t.Errorf("Name() = %q, want %q", got, "mongoose")
	}
}

func TestMongooseFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		contentType string
		want        bool
	}{
		{
			name:   "Server: Mongoose/7.14 returns true",
			server: "Mongoose/7.14",
			want:   true,
		},
		{
			name:   "Server: Mongoose returns true",
			server: "Mongoose",
			want:   true,
		},
		{
			name:   "Server: mongoose/7.21 returns true (case-insensitive)",
			server: "mongoose/7.21",
			want:   true,
		},
		{
			name:        "text/html content type returns true (body detection path)",
			contentType: "text/html; charset=utf-8",
			want:        true,
		},
		{
			name:   "Server: nginx/1.18.0 returns false",
			server: "nginx/1.18.0",
			want:   false,
		},
		{
			name:   "Server: Apache/2.4.41 returns false",
			server: "Apache/2.4.41",
			want:   false,
		},
		{
			name:        "application/json content type returns false",
			contentType: "application/json",
			want:        false,
		},
		{
			name: "No headers returns false",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MongooseFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
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

func TestMongooseFingerprinter_Fingerprint_ServerHeader(t *testing.T) {
	tests := []struct {
		name        string
		server      string
		wantVersion string
	}{
		{
			name:        "Mongoose/7.14",
			server:      "Mongoose/7.14",
			wantVersion: "7.14",
		},
		{
			name:        "Mongoose/7.21",
			server:      "Mongoose/7.21",
			wantVersion: "7.21",
		},
		{
			name:        "mongoose/7.0 (case-insensitive)",
			server:      "mongoose/7.0",
			wantVersion: "7.0",
		},
		{
			name:        "Mongoose/7.14.1 (three-part version)",
			server:      "Mongoose/7.14.1",
			wantVersion: "7.14.1",
		},
		{
			name:        "Mongoose (no version)",
			server:      "Mongoose",
			wantVersion: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MongooseFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Server", tt.server)

			result, err := fp.Fingerprint(resp, nil)
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "mongoose" {
				t.Errorf("Technology = %q, want %q", result.Technology, "mongoose")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := buildMongooseCPE(tt.wantVersion)
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}

			// Check metadata
			if vendor, ok := result.Metadata["vendor"].(string); !ok || vendor != "Cesanta" {
				t.Errorf("Metadata[vendor] = %v, want %q", result.Metadata["vendor"], "Cesanta")
			}
			if product, ok := result.Metadata["product"].(string); !ok || product != "Mongoose" {
				t.Errorf("Metadata[product] = %v, want %q", result.Metadata["product"], "Mongoose")
			}
		})
	}
}

func TestMongooseFingerprinter_Fingerprint_DirectoryListing(t *testing.T) {
	tests := []struct {
		name             string
		body             string
		wantVersion      string
		wantDirListing   bool
	}{
		{
			name: "Directory listing with version 7.21",
			body: `<html><head><title>Index of /</title></head>
<body><h1>Index of /</h1>
<table cellpadding="0"><thead><tr>
<th><a href="#" onclick="sort(0)">Name</a></th>
<th><a href="#" onclick="sort(1)">Modified</a></th>
<th><a href="#" onclick="sort(2)">Size</a></th>
</tr></thead><tbody>
<tr><td><a href="file.txt">file.txt</a></td><td>2024-01-01</td><td>1234</td></tr>
</tbody></table>
<address>Mongoose v.7.21</address>
</body></html>`,
			wantVersion:    "7.21",
			wantDirListing: true,
		},
		{
			name: "Directory listing with version 7.14",
			body: `<html><body>
<table cellpadding="0"><tr><td>test</td></tr></table>
<address>Mongoose v.7.14</address>
</body></html>`,
			wantVersion:    "7.14",
			wantDirListing: true,
		},
		{
			name:           "Footer only, no table",
			body:           `<html><body><address>Mongoose v.7.10</address></body></html>`,
			wantVersion:    "7.10",
			wantDirListing: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MongooseFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Content-Type", "text/html; charset=utf-8")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "mongoose" {
				t.Errorf("Technology = %q, want %q", result.Technology, "mongoose")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			expectedCPE := buildMongooseCPE(tt.wantVersion)
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}

			if tt.wantDirListing {
				if dirListing, ok := result.Metadata["directory_listing"].(bool); !ok || !dirListing {
					t.Error("expected Metadata[directory_listing] to be true")
				}
			} else {
				if _, ok := result.Metadata["directory_listing"]; ok {
					t.Error("expected Metadata[directory_listing] to not be set")
				}
			}
		})
	}
}

func TestMongooseFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name   string
		server string
		body   string
	}{
		{
			name:   "Server: nginx/1.18.0",
			server: "nginx/1.18.0",
		},
		{
			name:   "Server: Apache/2.4.41",
			server: "Apache/2.4.41",
		},
		{
			name:   "Server: Mongoose/7.14:*:*:*:*:*:*:* (CPE injection attempt)",
			server: "Mongoose/7.14:*:*:*:*:*:*:*",
		},
		{
			name:   "No Server header, no body",
			server: "",
		},
		{
			name: "HTML body without Mongoose signature",
			body: `<html><body><h1>Hello World</h1></body></html>`,
		},
		{
			name: "Body with generic address tag",
			body: `<html><body><address>Apache/2.4.41</address></body></html>`,
		},
		{
			name: "Body with partial Mongoose string (no version pattern)",
			body: `<html><body><p>Powered by Mongoose</p></body></html>`,
		},
		{
			name:   "Server: Mongoose/ (trailing slash, no version)",
			server: "Mongoose/",
		},
		{
			name: "Body with CPE injection in address tag",
			body: `<html><body><address>Mongoose v.7.14:*:*:*</address></body></html>`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &MongooseFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.body != "" {
				resp.Header.Set("Content-Type", "text/html")
			}

			var body []byte
			if tt.body != "" {
				body = []byte(tt.body)
			}

			result, err := fp.Fingerprint(resp, body)
			if err != nil {
				t.Fatalf("Fingerprint() unexpected error = %v", err)
			}
			if result != nil {
				t.Errorf("Fingerprint() = %+v, want nil", result)
			}
		})
	}
}

func TestBuildMongooseCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With two-part version",
			version: "7.14",
			want:    "cpe:2.3:a:cesanta:mongoose:7.14:*:*:*:*:*:*:*",
		},
		{
			name:    "With three-part version",
			version: "7.14.1",
			want:    "cpe:2.3:a:cesanta:mongoose:7.14.1:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:cesanta:mongoose:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildMongooseCPE(tt.version); got != tt.want {
				t.Errorf("buildMongooseCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestMongooseFingerprinter_ServerHeaderPriority(t *testing.T) {
	// When both Server header and body contain version info,
	// Server header version should be used
	fp := &MongooseFingerprinter{}
	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Server", "Mongoose/7.21")
	resp.Header.Set("Content-Type", "text/html")

	body := []byte(`<html><body><address>Mongoose v.7.14</address></body></html>`)

	result, err := fp.Fingerprint(resp, body)
	if err != nil {
		t.Fatalf("Fingerprint() error = %v", err)
	}
	if result == nil {
		t.Fatal("Fingerprint() returned nil result")
	}

	// Should use Server header version (7.21), not body version (7.14)
	if result.Version != "7.21" {
		t.Errorf("Version = %q, want %q (Server header should take priority)", result.Version, "7.21")
	}
}

func TestMongooseFingerprinter_Integration(t *testing.T) {
	originalCount := len(GetFingerprinters())
	t.Cleanup(func() {
		httpFingerprinters = httpFingerprinters[:originalCount]
	})

	fp := &MongooseFingerprinter{}
	Register(fp)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Server", "Mongoose/7.14")

	results := RunFingerprinters(resp, nil)

	found := false
	for _, result := range results {
		if result.Technology == "mongoose" {
			found = true
			if result.Version != "7.14" {
				t.Errorf("Version = %q, want %q", result.Version, "7.14")
			}
			expectedCPE := "cpe:2.3:a:cesanta:mongoose:7.14:*:*:*:*:*:*:*"
			if len(result.CPEs) == 0 || result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %v, want %q", result.CPEs, expectedCPE)
			}
		}
	}

	if !found {
		t.Error("MongooseFingerprinter not found in results")
	}
}
