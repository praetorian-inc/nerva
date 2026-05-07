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
	"net/url"
	"testing"
)

// ── Name / ProbeEndpoint ───────────────────────────────────────────────────────

func TestScreenConnectFingerprinter_Name(t *testing.T) {
	fp := &ScreenConnectFingerprinter{}
	if got := fp.Name(); got != "screenconnect" {
		t.Errorf("Name() = %q, want %q", got, "screenconnect")
	}
}

func TestScreenConnectFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &ScreenConnectFingerprinter{}
	// Exact string check — no trailing slash, no trailing segment, no query string.
	// Deviations could approach the CVE-2024-1709 exploit surface.
	if got := fp.ProbeEndpoint(); got != "/SetupWizard.aspx" {
		t.Errorf("ProbeEndpoint() = %q, want %q", got, "/SetupWizard.aspx")
	}
}

// ── Match ──────────────────────────────────────────────────────────────────────

func TestScreenConnectFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		server     string
		want       bool
	}{
		{
			name:       "200 OK passes",
			statusCode: 200,
			want:       true,
		},
		{
			name:       "302 redirect passes (configured SetupWizard redirect)",
			statusCode: 302,
			want:       true,
		},
		{
			name:       "404 Not Found passes (still in 200-499 range)",
			statusCode: 404,
			want:       true,
		},
		{
			name:       "499 passes (upper boundary of accepted range)",
			statusCode: 499,
			want:       true,
		},
		{
			name:       "100 Informational rejected",
			statusCode: 100,
			want:       false,
		},
		{
			name:       "500 Internal Server Error rejected",
			statusCode: 500,
			want:       false,
		},
		{
			name:       "503 Service Unavailable rejected",
			statusCode: 503,
			want:       false,
		},
		// Header-based hit: Server: ScreenConnect should match regardless of body.
		{
			name:       "Server: ScreenConnect header match",
			statusCode: 200,
			server:     "ScreenConnect",
			want:       true,
		},
		{
			name:       "Server header with ScreenConnect embedded in string",
			statusCode: 200,
			server:     "ScreenConnect/24.2.5",
			want:       true,
		},
		{
			name:       "Server: Microsoft-IIS/10.0 does NOT trigger header match but status still passes",
			statusCode: 200,
			server:     "Microsoft-IIS/10.0",
			want:       true, // passes on status (200); body check is in Fingerprint
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ScreenConnectFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if got := fp.Match(resp); got != tt.want {
				t.Errorf("Match() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ── Fingerprint: positive (valid) ─────────────────────────────────────────────

func TestScreenConnectFingerprinter_Fingerprint_Valid(t *testing.T) {
	tests := []struct {
		name           string
		statusCode     int
		body           string
		server         string
		wantNil        bool
		wantVersion    string
		wantCPE        string
		wantInstanceID string
		wantDetection  string
		wantProbePath  bool
		probePath      string // if set, inject into resp.Request.URL.Path
	}{
		{
			name:       "ScreenConnect login title + Script.ashx version",
			statusCode: 200,
			body: `<html><head><title>ScreenConnect</title>
<script src="/Script.ashx?sv=24.2.5"></script>
</head><body><p>Please login to continue</p></body></html>`,
			wantVersion:   "24.2.5",
			wantCPE:       "cpe:2.3:a:connectwise:screenconnect:24.2.5:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "ConnectWise Control login title, version empty (no version token)",
			statusCode: 200,
			body: `<html><head><title>ConnectWise Control</title>
</head><body><p>Please login to continue</p></body></html>`,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "JS block with Version and InstanceID both extracted",
			statusCode: 200,
			body: `<html><head><title>ScreenConnect</title></head><body>
<script>window.ScreenConnect = {Version: "25.2.4", InstanceID: "abcd1234ef567890"};</script>
</body></html>`,
			wantVersion:    "25.2.4",
			wantCPE:        "cpe:2.3:a:connectwise:screenconnect:25.2.4:*:*:*:*:*:*:*",
			wantInstanceID: "abcd1234ef567890",
			wantDetection:  "body",
		},
		{
			name:       "Meta tag version extracted when no Script.ashx present",
			statusCode: 200,
			body: `<html><head>
<title>ScreenConnect</title>
<meta name="screenconnect-version" content="23.9.8">
</head><body></body></html>`,
			wantVersion:   "23.9.8",
			wantCPE:       "cpe:2.3:a:connectwise:screenconnect:23.9.8:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "Script.ashx version takes priority over JS block version",
			statusCode: 200,
			body: `<html><head><title>ScreenConnect</title>
<script src="/Script.ashx?sv=24.2.5"></script>
</head><body>
<script>window.ScreenConnect = {Version: "25.0.0", InstanceID: "aabbccdd11223344"};</script>
</body></html>`,
			// Script.ashx (priority 1) wins over JS block (priority 2).
			wantVersion:    "24.2.5",
			wantCPE:        "cpe:2.3:a:connectwise:screenconnect:24.2.5:*:*:*:*:*:*:*",
			wantInstanceID: "aabbccdd11223344", // still extracted from JS block
			wantDetection:  "body",
		},
		{
			name:          "Server: ScreenConnect header-only match, empty body",
			statusCode:    200,
			server:        "ScreenConnect/24.2.5",
			body:          "",
			wantNil:       false,
			wantVersion:   "",
			wantCPE:       "cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*",
			wantDetection: "server_header",
		},
		{
			name:       "Server: ScreenConnect header + body tokens — body takes priority for version",
			statusCode: 200,
			server:     "ScreenConnect",
			body: `<html><head><title>ScreenConnect</title>
<script src="/Script.ashx?sv=24.1.0"></script>
</head></html>`,
			wantVersion:   "24.1.0",
			wantCPE:       "cpe:2.3:a:connectwise:screenconnect:24.1.0:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
		{
			name:       "Active probe response: SetupWizard.aspx 200 with ScreenConnect form",
			statusCode: 200,
			body: `<html><head><title>ScreenConnect Setup</title>
<script src="/Script.ashx?sv=24.2.5"></script>
</head><body><form>Setup wizard</form></body></html>`,
			probePath:     "/SetupWizard.aspx",
			wantVersion:   "24.2.5",
			wantCPE:       "cpe:2.3:a:connectwise:screenconnect:24.2.5:*:*:*:*:*:*:*",
			wantDetection: "active_probe",
			wantProbePath: true,
		},
		{
			name:       "ConnectWise ScreenConnect transitional branding detected",
			statusCode: 200,
			body: `<html><head><title>ConnectWise ScreenConnect</title>
<script src="/Script.ashx?sv=23.9.8"></script>
</head><body></body></html>`,
			// "ConnectWise ScreenConnect" contains "screenconnect" — brand token matches.
			wantVersion:   "23.9.8",
			wantCPE:       "cpe:2.3:a:connectwise:screenconnect:23.9.8:*:*:*:*:*:*:*",
			wantDetection: "body",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ScreenConnectFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
			}
			if tt.probePath != "" {
				resp.Request = &http.Request{URL: &url.URL{Path: tt.probePath}}
			}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			if err != nil {
				t.Fatalf("Fingerprint() error = %v", err)
			}

			if tt.wantNil {
				if result != nil {
					t.Errorf("Fingerprint() = %+v, want nil", result)
				}
				return
			}

			if result == nil {
				t.Fatal("Fingerprint() returned nil, want non-nil result")
			}

			if result.Technology != "screenconnect" {
				t.Errorf("Technology = %q, want %q", result.Technology, "screenconnect")
			}
			if result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			} else if result.CPEs[0] != tt.wantCPE {
				t.Errorf("CPE = %q, want %q", result.CPEs[0], tt.wantCPE)
			}
			if result.Metadata == nil {
				t.Fatal("Metadata is nil")
			}

			if tt.wantInstanceID != "" {
				if id, ok := result.Metadata["instance_id"].(string); !ok || id != tt.wantInstanceID {
					t.Errorf("Metadata[instance_id] = %v, want %q", result.Metadata["instance_id"], tt.wantInstanceID)
				}
			} else {
				if _, ok := result.Metadata["instance_id"]; ok {
					t.Errorf("Metadata[instance_id] should be absent when not in body, got %v", result.Metadata["instance_id"])
				}
			}

			if tt.wantDetection != "" {
				if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != tt.wantDetection {
					t.Errorf("Metadata[detection_method] = %v, want %q", result.Metadata["detection_method"], tt.wantDetection)
				}
			}

			if tt.wantProbePath {
				if pp, ok := result.Metadata["probe_path"].(string); !ok || pp != "/SetupWizard.aspx" {
					t.Errorf("Metadata[probe_path] = %v, want %q", result.Metadata["probe_path"], "/SetupWizard.aspx")
				}
			} else {
				if _, ok := result.Metadata["probe_path"]; ok {
					t.Errorf("Metadata[probe_path] should be absent for non-active-probe responses, got %v", result.Metadata["probe_path"])
				}
			}
		})
	}
}

// ── Fingerprint: negative (invalid — must return nil) ─────────────────────────

func TestScreenConnectFingerprinter_Fingerprint_Invalid(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
		server     string
	}{
		{
			name:       "Okta login page",
			statusCode: 200,
			body:       `<html><head><title>Okta Sign-In</title></head><body></body></html>`,
		},
		{
			name:       "TeamViewer Management Console",
			statusCode: 200,
			body:       `<html><head><title>TeamViewer Management Console</title></head><body></body></html>`,
		},
		{
			name:       "AnyDesk Web",
			statusCode: 200,
			body:       `<html><head><title>AnyDesk Web</title></head><body></body></html>`,
		},
		{
			name:       "Microsoft IIS default page",
			statusCode: 200,
			body:       `<html><head><title>IIS Windows Server</title></head><body><p>Welcome to Microsoft IIS</p></body></html>`,
		},
		{
			name:       "Empty body and Server: Microsoft-IIS/10.0 (no screenconnect in server)",
			statusCode: 200,
			server:     "Microsoft-IIS/10.0",
			body:       "",
		},
		{
			name:       "Body with 'control' alone — not sufficient brand token",
			statusCode: 200,
			body:       `<html><head><title>Control Panel</title></head><body><p>Remote control system</p></body></html>`,
		},
		{
			name:       "Body with 'connect' alone — not sufficient brand token",
			statusCode: 200,
			body:       `<html><head><title>Connect Portal</title></head><body><p>Please connect to continue</p></body></html>`,
		},
		{
			name:       "LogMeIn Control — not a brand token match",
			statusCode: 200,
			body:       `<html><head><title>LogMeIn</title></head><body><p>LogMeIn Control Panel</p></body></html>`,
		},
		{
			name:       "HP Connect — not a brand token match",
			statusCode: 200,
			body:       `<html><head><title>HP Connect</title></head><body><p>HP Connect login</p></body></html>`,
		},
		{
			name:       "CPE-injection attempt in body (contains :*:)",
			statusCode: 200,
			body:       `<html><head><title>ScreenConnect</title><script src="/Script.ashx?sv=24.2.5:*:malicious"></script></head></html>`,
		},
		{
			name:       "Body length > 2 MiB is rejected",
			statusCode: 200,
			body:       "screenconnect" + string(make([]byte, 2*1024*1024+1)),
		},
		{
			name:       "Status 302 with empty body and no server header",
			statusCode: 302,
			body:       "",
		},
		{
			name:       "Status 500 rejected",
			statusCode: 500,
			body:       `<html><head><title>ScreenConnect</title></head><body></body></html>`,
		},
		{
			name:       "Status 503 rejected",
			statusCode: 503,
			body:       `<html><head><title>ScreenConnect</title></head><body></body></html>`,
		},
		{
			name:       "Server header ScreenConnect-Plus (not our product)",
			statusCode: 200,
			server:     "ScreenConnect-Plus",
			body:       "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &ScreenConnectFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     make(http.Header),
			}
			if tt.server != "" {
				resp.Header.Set("Server", tt.server)
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

// ── Header-only matching (Directive A) ────────────────────────────────────────

func TestScreenConnectFingerprinter_HeaderOnlyMatch(t *testing.T) {
	fp := &ScreenConnectFingerprinter{}

	// Positive: Server: ScreenConnect header with empty body should produce a result.
	t.Run("Server: ScreenConnect header produces result with empty body", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Server", "ScreenConnect")

		result, err := fp.Fingerprint(resp, []byte(""))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want non-nil result for Server: ScreenConnect")
		}
		if result.Technology != "screenconnect" {
			t.Errorf("Technology = %q, want %q", result.Technology, "screenconnect")
		}
		if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != "server_header" {
			t.Errorf("Metadata[detection_method] = %v, want %q", result.Metadata["detection_method"], "server_header")
		}
	})

	// Positive: Server header case-insensitive check.
	t.Run("Server: screenconnect lowercase header", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Server", "screenconnect/25.0.0")

		result, err := fp.Fingerprint(resp, []byte(""))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want non-nil for lowercase server header")
		}
		if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != "server_header" {
			t.Errorf("Metadata[detection_method] = %v, want server_header", result.Metadata["detection_method"])
		}
	})

	// Negative: Server: Microsoft-IIS/10.0 must NOT match.
	t.Run("Server: Microsoft-IIS/10.0 does not match header-only", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Server", "Microsoft-IIS/10.0")

		result, err := fp.Fingerprint(resp, []byte(""))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result != nil {
			t.Errorf("Fingerprint() = %+v, want nil for Microsoft-IIS with empty body", result)
		}
	})

	// Negative: Server: nginx with empty body must NOT match.
	t.Run("Server: nginx does not match header-only", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		resp.Header.Set("Server", "nginx/1.24.0")

		result, err := fp.Fingerprint(resp, []byte(""))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result != nil {
			t.Errorf("Fingerprint() = %+v, want nil for nginx with empty body", result)
		}
	})
}

// ── Active probe response ──────────────────────────────────────────────────────

func TestScreenConnectFingerprinter_ActiveProbeResponse(t *testing.T) {
	fp := &ScreenConnectFingerprinter{}

	t.Run("SetupWizard.aspx response sets probe_path metadata", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request: &http.Request{
				URL: &url.URL{Path: "/SetupWizard.aspx"},
			},
		}
		body := `<html><head><title>ScreenConnect</title>
<script src="/Script.ashx?sv=24.2.5"></script>
</head><body><form>Setup</form></body></html>`

		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want non-nil")
		}
		if pp, ok := result.Metadata["probe_path"].(string); !ok || pp != "/SetupWizard.aspx" {
			t.Errorf("Metadata[probe_path] = %v, want %q", result.Metadata["probe_path"], "/SetupWizard.aspx")
		}
		if dm, ok := result.Metadata["detection_method"].(string); !ok || dm != "active_probe" {
			t.Errorf("Metadata[detection_method] = %v, want %q", result.Metadata["detection_method"], "active_probe")
		}
	})

	t.Run("Root response does NOT set probe_path metadata", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := `<html><head><title>ScreenConnect</title></head><body></body></html>`

		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want non-nil")
		}
		if _, ok := result.Metadata["probe_path"]; ok {
			t.Errorf("Metadata[probe_path] should be absent for root response, got %v", result.Metadata["probe_path"])
		}
	})

	t.Run("nil Request does not panic and does not set probe_path", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
			Request:    nil,
		}
		body := `<html><head><title>ScreenConnect</title></head><body></body></html>`

		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil, want non-nil")
		}
		if _, ok := result.Metadata["probe_path"]; ok {
			t.Errorf("Metadata[probe_path] should be absent when Request is nil, got %v", result.Metadata["probe_path"])
		}
	})
}

// ── Instance ID extraction (Directive B) ──────────────────────────────────────

func TestScreenConnectFingerprinter_InstanceID(t *testing.T) {
	fp := &ScreenConnectFingerprinter{}

	t.Run("InstanceID present in JS block is extracted", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := `<html><head><title>ScreenConnect</title></head><body>
<script>window.ScreenConnect = {Version: "25.2.4", InstanceID: "abcd1234ef567890"};</script>
</body></html>`

		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil")
		}
		if id, ok := result.Metadata["instance_id"].(string); !ok || id != "abcd1234ef567890" {
			t.Errorf("Metadata[instance_id] = %v, want %q", result.Metadata["instance_id"], "abcd1234ef567890")
		}
	})

	t.Run("InstanceID absent from JS block — key omitted from Metadata", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := `<html><head><title>ScreenConnect</title></head><body>
<script>window.ScreenConnect = {Version: "25.2.4"};</script>
</body></html>`

		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil")
		}
		if _, ok := result.Metadata["instance_id"]; ok {
			t.Errorf("Metadata[instance_id] should be absent when InstanceID not in body, got %v", result.Metadata["instance_id"])
		}
	})

	t.Run("InstanceID with 32 hex chars is accepted", func(t *testing.T) {
		resp := &http.Response{
			StatusCode: 200,
			Header:     make(http.Header),
		}
		body := `<html><head><title>ScreenConnect</title></head><body>
<script>window.ScreenConnect = {Version: "25.0.0", InstanceID: "aabbccddeeff00112233445566778899"};</script>
</body></html>`

		result, err := fp.Fingerprint(resp, []byte(body))
		if err != nil {
			t.Fatalf("Fingerprint() error = %v", err)
		}
		if result == nil {
			t.Fatal("Fingerprint() returned nil")
		}
		if id, ok := result.Metadata["instance_id"].(string); !ok || id != "aabbccddeeff00112233445566778899" {
			t.Errorf("Metadata[instance_id] = %v, want 32-char hex", result.Metadata["instance_id"])
		}
	})
}

// ── TestExtractVersion ─────────────────────────────────────────────────────────

func TestExtractVersion(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "Script.ashx extraction",
			body: `<script src="/Script.ashx?sv=24.2.5"></script>`,
			want: "24.2.5",
		},
		{
			name: "JS block version extraction",
			body: `<script>window.ScreenConnect = {Version: "25.2.4"};</script>`,
			want: "25.2.4",
		},
		{
			name: "Meta tag version extraction",
			body: `<meta name="screenconnect-version" content="23.9.8">`,
			want: "23.9.8",
		},
		{
			name: "Script.ashx takes priority over JS block",
			body: `<script src="/Script.ashx?sv=24.2.5"></script><script>window.ScreenConnect = {Version: "99.0.0"};</script>`,
			want: "24.2.5",
		},
		{
			name: "JS block takes priority over meta tag",
			body: `<script>window.ScreenConnect = {Version: "25.2.4"};</script><meta name="screenconnect-version" content="23.9.8">`,
			want: "25.2.4",
		},
		{
			name: "Alpha-suffix version: Script.ashx regex stops at digit boundary (captures 24.2.5)",
			// The Script.ashx regex matches [0-9]+(?:\.[0-9]+){1,3} which stops before '-'.
			// So "24.2.5-beta" yields capture group "24.2.5" which passes validation.
			// To test rejection, use a version that fails two-stage validation, e.g. ".5.beta"
			// which doesn't match the extraction regex at all.
			body: `<script src="/Script.ashx?sv=.5.beta"></script>`,
			want: "",
		},
		{
			name: "No version in body",
			body: `<html><head><title>ScreenConnect</title></head></html>`,
			want: "",
		},
		{
			name: "Four-component version is valid",
			body: `<script src="/Script.ashx?sv=25.0.0.1234"></script>`,
			want: "25.0.0.1234",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractScreenConnectVersion([]byte(tt.body)); got != tt.want {
				t.Errorf("extractScreenConnectVersion() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ── TestExtractInstanceID ──────────────────────────────────────────────────────

func TestExtractInstanceID(t *testing.T) {
	tests := []struct {
		name string
		body string
		want string
	}{
		{
			name: "Valid 16-char hex instance ID",
			body: `InstanceID: "abcd1234ef567890"`,
			want: "abcd1234ef567890",
		},
		{
			name: "Valid 32-char hex instance ID",
			body: `InstanceID: "aabbccddeeff00112233445566778899"`,
			want: "aabbccddeeff00112233445566778899",
		},
		{
			name: "No InstanceID in body",
			body: `window.ScreenConnect = {Version: "25.2.4"}`,
			want: "",
		},
		{
			name: "Uppercase hex rejected (regex anchored to [a-f0-9])",
			body: `InstanceID: "ABCD1234EF567890"`,
			want: "",
		},
		{
			name: "Too short (7 chars) rejected",
			body: `InstanceID: "abcdef1"`,
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractScreenConnectInstanceID([]byte(tt.body)); got != tt.want {
				t.Errorf("extractScreenConnectInstanceID() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ── TestBuildScreenConnectCPE ──────────────────────────────────────────────────

func TestBuildScreenConnectCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{
			name:    "Version 24.2.5",
			version: "24.2.5",
			want:    "cpe:2.3:a:connectwise:screenconnect:24.2.5:*:*:*:*:*:*:*",
		},
		{
			name:    "Version 25.2.4",
			version: "25.2.4",
			want:    "cpe:2.3:a:connectwise:screenconnect:25.2.4:*:*:*:*:*:*:*",
		},
		{
			name:    "Four-component version 25.0.0.1234",
			version: "25.0.0.1234",
			want:    "cpe:2.3:a:connectwise:screenconnect:25.0.0.1234:*:*:*:*:*:*:*",
		},
		{
			name:    "Empty version uses wildcard",
			version: "",
			want:    "cpe:2.3:a:connectwise:screenconnect:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := buildScreenConnectCPE(tt.version); got != tt.want {
				t.Errorf("buildScreenConnectCPE(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

// ── TestScreenConnectVersionValidation ────────────────────────────────────────

func TestScreenConnectVersionValidation(t *testing.T) {
	tests := []struct {
		version string
		valid   bool
	}{
		{"24.2.5", true},
		{"25.2.4", true},
		{"23.9.8", true},
		{"25.0.0.1234", true},
		{"1.0", true},
		{"24.2.5-beta", false},
		{"24.2.5:*:", false},
		{"abc", false},
		{"", false},
		{"24.2.5.6.7", false}, // 5 components — exceeds {1,3} suffix groups
		{".1", false},
		{"..", false},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := screenConnectVersionValidateRegex.MatchString(tt.version)
			if got != tt.valid {
				t.Errorf("screenConnectVersionValidateRegex.MatchString(%q) = %v, want %v", tt.version, got, tt.valid)
			}
		})
	}
}

// ── Integration test ──────────────────────────────────────────────────────────

func TestScreenConnectFingerprinter_Integration(t *testing.T) {
	// Save and restore global state to prevent test pollution (mirrors gradio_test.go:355-357).
	saved := httpFingerprinters
	t.Cleanup(func() { httpFingerprinters = saved })
	httpFingerprinters = nil

	fp := &ScreenConnectFingerprinter{}
	Register(fp)

	resp := &http.Response{
		StatusCode: 200,
		Header:     make(http.Header),
	}

	body := []byte(`<html><head>
<title>ScreenConnect</title>
<script src="/Script.ashx?sv=24.2.5"></script>
</head><body><p>Please login to continue</p></body></html>`)

	results := RunFingerprinters(resp, body)

	found := false
	for _, result := range results {
		if result.Technology == "screenconnect" {
			found = true
			if result.Version != "24.2.5" {
				t.Errorf("Version = %q, want %q", result.Version, "24.2.5")
			}
			if len(result.CPEs) == 0 {
				t.Error("Expected at least one CPE")
			} else if result.CPEs[0] != "cpe:2.3:a:connectwise:screenconnect:24.2.5:*:*:*:*:*:*:*" {
				t.Errorf("CPE = %q, want canonical CPE", result.CPEs[0])
			}
			if v, ok := result.Metadata["vendor"].(string); !ok || v != "ConnectWise" {
				t.Errorf("Metadata[vendor] = %v, want ConnectWise", result.Metadata["vendor"])
			}
		}
	}

	if !found {
		t.Error("ScreenConnectFingerprinter not found in RunFingerprinters results")
	}
}
