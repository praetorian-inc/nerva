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

// ---- GotenbergHealthFingerprinter tests ----

func TestGotenbergFingerprinter_Name(t *testing.T) {
	fp := &GotenbergFingerprinter{}
	if got := fp.Name(); got != "gotenberg" {
		t.Errorf("Name() = %q, want %q", got, "gotenberg")
	}
}

func TestGotenbergFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &GotenbergFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/version" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/version")
	}
}

func TestGotenbergFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		traceValue string
		setHeader  bool
		want       bool
	}{
		{
			name:       "Gotenberg-Trace header present with value",
			traceValue: "some-trace-value",
			setHeader:  true,
			want:       true,
		},
		{
			name:       "Gotenberg-Trace header present with UUID",
			traceValue: "dc34af5f-4e94-43b3-b8d6-5e2d99f42dc5",
			setHeader:  true,
			want:       true,
		},
		{
			name:      "No Gotenberg-Trace header",
			setHeader: false,
			want:      false,
		},
		{
			name:       "Empty Gotenberg-Trace header value",
			traceValue: "",
			setHeader:  true,
			want:       false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GotenbergFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.setHeader {
				resp.Header.Set("Gotenberg-Trace", tt.traceValue)
			}

			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestGotenbergFingerprinter_Fingerprint_Valid(t *testing.T) {
	const traceID = "dc34af5f-4e94-43b3-b8d6-5e2d99f42dc5"

	tests := []struct {
		name        string
		body        string
		wantVersion string
	}{
		{
			name:        "Version 8.9.1",
			body:        "8.9.1",
			wantVersion: "8.9.1",
		},
		{
			name:        "Older version 7.0.0",
			body:        "7.0.0",
			wantVersion: "7.0.0",
		},
		{
			name:        "Major boundary version 8.0.0",
			body:        "8.0.0",
			wantVersion: "8.0.0",
		},
		{
			name:        "Version with trailing newline trimmed",
			body:        "8.9.1\n",
			wantVersion: "8.9.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GotenbergFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Gotenberg-Trace", traceID)

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil result")
			}

			if result.Technology != "gotenberg" {
				t.Errorf("Technology = %q, want %q", result.Technology, "gotenberg")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			// Verify traceId in metadata
			if traceVal, ok := result.Metadata["traceId"].(string); !ok || traceVal != traceID {
				t.Errorf("Metadata[traceId] = %v, want %q", result.Metadata["traceId"], traceID)
			}

			// Verify exact CPE string
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			}
			expectedCPE := "cpe:2.3:a:gotenberg:gotenberg:" + tt.wantVersion + ":*:*:*:*:*:*:*"
			if result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], expectedCPE)
			}
		})
	}
}

func TestGotenbergFingerprinter_Fingerprint_Invalid(t *testing.T) {
	const traceID = "dc34af5f-4e94-43b3-b8d6-5e2d99f42dc5"

	tests := []struct {
		name      string
		body      string
		setTrace  bool
		traceVal  string
	}{
		{
			name:     "No Gotenberg-Trace header",
			body:     "8.9.1",
			setTrace: false,
		},
		{
			name:     "Non-semver body",
			body:     "Not Found",
			setTrace: true,
			traceVal: traceID,
		},
		{
			name:     "Empty body",
			body:     "",
			setTrace: true,
			traceVal: traceID,
		},
		{
			name:     "CPE injection attempt in version",
			body:     "8.9.1:*:*:*:*:*:*:*",
			setTrace: true,
			traceVal: traceID,
		},
		{
			name:     "Pre-release suffix rejected",
			body:     "8.9.1-beta",
			setTrace: true,
			traceVal: traceID,
		},
		{
			name:     "HTML body",
			body:     "<html><body>404 Not Found</body></html>",
			setTrace: true,
			traceVal: traceID,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GotenbergFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.setTrace {
				resp.Header.Set("Gotenberg-Trace", tt.traceVal)
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

func TestBuildGotenbergCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "With version",
			version: "8.9.1",
			want:    "cpe:2.3:a:gotenberg:gotenberg:8.9.1:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version",
			version: "",
			want:    "cpe:2.3:a:gotenberg:gotenberg:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildGotenbergCPE(tt.version); got != tt.want {
				t.Errorf("buildGotenbergCPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestGotenbergFingerprinter_Integration(t *testing.T) {
	// Register the fingerprinter (also happens in init(), but test explicitly)
	fp := &GotenbergFingerprinter{}
	Register(fp)

	body := []byte("8.9.1")

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Gotenberg-Trace", "dc34af5f-4e94-43b3-b8d6-5e2d99f42dc5")
	resp.Header.Set("Content-Type", "text/plain; charset=UTF-8")

	results := RunFingerprinters(resp, body)

	found := false
	for _, result := range results {
		if result.Technology == "gotenberg" {
			found = true
			if result.Version != "8.9.1" {
				t.Errorf("Version = %q, want %q", result.Version, "8.9.1")
			}
			expectedCPE := "cpe:2.3:a:gotenberg:gotenberg:8.9.1:*:*:*:*:*:*:*"
			if len(result.CPEs) == 0 || result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %v, want %q", result.CPEs, expectedCPE)
			}
		}
	}

	if !found {
		t.Error("GotenbergFingerprinter not found in results")
	}
}

func TestGotenbergHealthFingerprinter_Name(t *testing.T) {
	fp := &GotenbergHealthFingerprinter{}
	if got := fp.Name(); got != "gotenberg-health" {
		t.Errorf("Name() = %q, want %q", got, "gotenberg-health")
	}
}

func TestGotenbergHealthFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &GotenbergHealthFingerprinter{}
	if got := fp.ProbeEndpoint(); got != "/health" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/health")
	}
}

func TestGotenbergHealthFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		traceValue  string
		setTrace    bool
		contentType string
		want        bool
	}{
		{
			name:        "Gotenberg-Trace plus application/json",
			traceValue:  "dc34af5f-4e94-43b3-b8d6-5e2d99f42dc5",
			setTrace:    true,
			contentType: "application/json",
			want:        true,
		},
		{
			name:        "Gotenberg-Trace plus application/json with charset",
			traceValue:  "dc34af5f-4e94-43b3-b8d6-5e2d99f42dc5",
			setTrace:    true,
			contentType: "application/json; charset=utf-8",
			want:        true,
		},
		{
			name:        "Gotenberg-Trace plus text/plain — health should be JSON",
			traceValue:  "dc34af5f-4e94-43b3-b8d6-5e2d99f42dc5",
			setTrace:    true,
			contentType: "text/plain",
			want:        false,
		},
		{
			name:        "No Gotenberg-Trace plus application/json",
			setTrace:    false,
			contentType: "application/json",
			want:        false,
		},
		{
			name:     "No Gotenberg-Trace and no Content-Type",
			setTrace: false,
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GotenbergHealthFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.setTrace {
				resp.Header.Set("Gotenberg-Trace", tt.traceValue)
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

func TestGotenbergHealthFingerprinter_Fingerprint_Valid(t *testing.T) {
	const traceID = "dc34af5f-4e94-43b3-b8d6-5e2d99f42dc5"
	const expectedCPE = "cpe:2.3:a:gotenberg:gotenberg:*:*:*:*:*:*:*:*"

	tests := []struct {
		name               string
		body               string
		wantComponentCount int
	}{
		{
			name:               "Full health response with chromium and libreoffice",
			body:               `{"status":"up","details":{"chromium":{"status":"up","timestamp":"2026-03-06T16:07:01.898483128Z"},"libreoffice":{"status":"up","timestamp":"2026-03-06T16:07:01.898473294Z"}}}`,
			wantComponentCount: 2,
		},
		{
			name:               "Health response with only chromium",
			body:               `{"status":"up","details":{"chromium":{"status":"up","timestamp":"2026-03-06T16:07:01.898483128Z"}}}`,
			wantComponentCount: 1,
		},
		{
			name:               "Health response with only libreoffice",
			body:               `{"status":"up","details":{"libreoffice":{"status":"up","timestamp":"2026-03-06T16:07:01.898473294Z"}}}`,
			wantComponentCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GotenbergHealthFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			resp.Header.Set("Gotenberg-Trace", traceID)
			resp.Header.Set("Content-Type", "application/json")

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}
			if result == nil {
				t.Fatal("Fingerprint() returned nil, want non-nil result")
			}

			if result.Technology != "gotenberg" {
				t.Errorf("Technology = %q, want %q", result.Technology, "gotenberg")
			}
			if result.Version != "" {
				t.Errorf("Version = %q, want empty string", result.Version)
			}
			if len(result.CPEs) == 0 || result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %v, want %q", result.CPEs, expectedCPE)
			}

			if traceVal, ok := result.Metadata["traceId"].(string); !ok || traceVal != traceID {
				t.Errorf("Metadata[traceId] = %v, want %q", result.Metadata["traceId"], traceID)
			}
			components, ok := result.Metadata["components"].([]string)
			if !ok {
				t.Fatalf("Metadata[components] is not []string: %T", result.Metadata["components"])
			}
			if len(components) != tt.wantComponentCount {
				t.Errorf("len(components) = %d, want %d (components = %v)", len(components), tt.wantComponentCount, components)
			}
		})
	}
}

func TestGotenbergHealthFingerprinter_Fingerprint_Invalid(t *testing.T) {
	const traceID = "dc34af5f-4e94-43b3-b8d6-5e2d99f42dc5"

	tests := []struct {
		name        string
		body        string
		setTrace    bool
		contentType string
	}{
		{
			name:        "No Gotenberg-Trace header",
			body:        `{"status":"up","details":{"chromium":{"status":"up"}}}`,
			setTrace:    false,
			contentType: "application/json",
		},
		{
			name:        "Non-JSON body",
			body:        "not json at all",
			setTrace:    true,
			contentType: "application/json",
		},
		{
			name:        "JSON without details field",
			body:        `{"status":"up"}`,
			setTrace:    true,
			contentType: "application/json",
		},
		{
			name:        "JSON with empty details",
			body:        `{"status":"up","details":{}}`,
			setTrace:    true,
			contentType: "application/json",
		},
		{
			name:        "JSON with unknown component names only",
			body:        `{"status":"up","details":{"unknown":{"status":"up","timestamp":"2026-03-06T16:07:01Z"}}}`,
			setTrace:    true,
			contentType: "application/json",
		},
		{
			name:        "Empty JSON object",
			body:        `{}`,
			setTrace:    true,
			contentType: "application/json",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &GotenbergHealthFingerprinter{}
			resp := &http.Response{
				Header: make(http.Header),
			}
			if tt.setTrace {
				resp.Header.Set("Gotenberg-Trace", traceID)
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
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

func TestGotenbergHealthFingerprinter_Integration(t *testing.T) {
	const traceID = "dc34af5f-4e94-43b3-b8d6-5e2d99f42dc5"
	const expectedCPE = "cpe:2.3:a:gotenberg:gotenberg:*:*:*:*:*:*:*:*"

	fp := &GotenbergHealthFingerprinter{}
	Register(fp)

	body := []byte(`{"status":"up","details":{"chromium":{"status":"up","timestamp":"2026-03-06T16:07:01.898483128Z"},"libreoffice":{"status":"up","timestamp":"2026-03-06T16:07:01.898473294Z"}}}`)

	resp := &http.Response{
		Header: make(http.Header),
	}
	resp.Header.Set("Gotenberg-Trace", traceID)
	resp.Header.Set("Content-Type", "application/json")

	results := RunFingerprinters(resp, body)

	found := false
	for _, result := range results {
		if result.Technology == "gotenberg" && result.Version == "" {
			found = true
			if len(result.CPEs) == 0 || result.CPEs[0] != expectedCPE {
				t.Errorf("CPE = %v, want %q", result.CPEs, expectedCPE)
			}
		}
	}

	if !found {
		t.Error("GotenbergHealthFingerprinter not found in results (no gotenberg result with empty version)")
	}
}
