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

func TestDynamics365Fingerprinter_Name(t *testing.T) {
	f := &Dynamics365Fingerprinter{}
	if name := f.Name(); name != "dynamics365" {
		t.Errorf("Name() = %q, expected %q", name, "dynamics365")
	}
}

func TestDynamics365Fingerprinter_ProbeEndpoint(t *testing.T) {
	f := &Dynamics365Fingerprinter{}
	if ep := f.ProbeEndpoint(); ep != "/_services/about" {
		t.Errorf("ProbeEndpoint() = %q, expected %q", ep, "/_services/about")
	}
}

func TestDynamics365Fingerprinter_Match(t *testing.T) {
	f := &Dynamics365Fingerprinter{}

	tests := []struct {
		name       string
		statusCode int
		headers    http.Header
		want       bool
	}{
		{
			name:       "matches x-ms-request-id header",
			statusCode: 200,
			headers:    http.Header{"X-Ms-Request-Id": []string{"abc-123"}},
			want:       true,
		},
		{
			name:       "matches REQ_ID header",
			statusCode: 200,
			headers:    http.Header{"Req_id": []string{"req-456"}},
			want:       true,
		},
		{
			name:       "matches ms-dyn-aid header",
			statusCode: 200,
			headers:    http.Header{"Ms-Dyn-Aid": []string{"dyn-789"}},
			want:       true,
		},
		{
			name:       "matches OData-Version header",
			statusCode: 200,
			headers:    http.Header{"Odata-Version": []string{"4.0"}},
			want:       true,
		},
		{
			name:       "matches Dynamics365PortalAnalytics cookie",
			statusCode: 200,
			headers:    http.Header{"Set-Cookie": []string{"Dynamics365PortalAnalytics=abc123; Path=/"}},
			want:       true,
		},
		{
			name:       "matches CrmOwinAuth cookie",
			statusCode: 200,
			headers:    http.Header{"Set-Cookie": []string{"CrmOwinAuth=token; Path=/"}},
			want:       true,
		},
		{
			name:       "matches text/html content type",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
			want:       true,
		},
		{
			name:       "matches application/json content type",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"application/json"}},
			want:       true,
		},
		{
			name:       "rejects 500 status",
			statusCode: 500,
			headers:    http.Header{"X-Ms-Request-Id": []string{"abc"}},
			want:       false,
		},
		{
			name:       "rejects status below 200",
			statusCode: 199,
			headers:    http.Header{"X-Ms-Request-Id": []string{"abc"}},
			want:       false,
		},
		{
			name:       "rejects no signals",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"application/octet-stream"}},
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

func TestDynamics365Fingerprinter_Fingerprint(t *testing.T) {
	f := &Dynamics365Fingerprinter{}

	tests := []struct {
		name           string
		statusCode     int
		headers        http.Header
		body           string
		wantResult     bool
		wantTech       string
		wantVersion    string
		wantCPEPrefix  string
		wantComponent  string
		wantDeployment string
		wantOData      bool
	}{
		// --- Header signal tests ---
		{
			name:       "detects via x-ms-request-id header",
			statusCode: 200,
			headers:    http.Header{"X-Ms-Request-Id": []string{"abc-123"}},
			body:       "",
			wantResult: true,
			wantTech:   "dynamics365",
		},
		{
			name:       "detects via REQ_ID header",
			statusCode: 200,
			headers:    http.Header{"Req_id": []string{"req-456"}},
			body:       "",
			wantResult: true,
			wantTech:   "dynamics365",
		},
		{
			name:          "detects Finance & Operations via ms-dyn-aid header",
			statusCode:    200,
			headers:       http.Header{"Ms-Dyn-Aid": []string{"dyn-789"}},
			body:          "",
			wantResult:    true,
			wantTech:      "dynamics365",
			wantComponent: "Finance & Operations",
		},
		{
			name:       "detects OData API via OData-Version header",
			statusCode: 200,
			headers:    http.Header{"Odata-Version": []string{"4.0"}},
			body:       "",
			wantResult: true,
			wantTech:   "dynamics365",
			wantOData:  true,
		},

		// --- Cookie signal tests ---
		{
			name:          "detects Power Apps Portal via Dynamics365PortalAnalytics cookie",
			statusCode:    200,
			headers:       http.Header{"Set-Cookie": []string{"Dynamics365PortalAnalytics=abc; Path=/"}},
			body:          "",
			wantResult:    true,
			wantTech:      "dynamics365",
			wantComponent: "Power Apps Portal",
		},
		{
			name:          "detects CRM via CrmOwinAuth cookie",
			statusCode:    200,
			headers:       http.Header{"Set-Cookie": []string{"CrmOwinAuth=token; Path=/"}},
			body:          "",
			wantResult:    true,
			wantTech:      "dynamics365",
			wantComponent: "CRM",
		},

		// --- Body signal tests: adx_ prefixes (Power Apps Portal) ---
		{
			name:       "detects Power Apps Portal via adx_entityform body signal",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<div class="adx_entityform">Form Content</div>`,
			wantResult:    true,
			wantTech:      "dynamics365",
			wantComponent: "Power Apps Portal",
		},
		{
			name:       "detects Power Apps Portal via adx_entitylist body signal",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<div class="adx_entitylist">List Content</div>`,
			wantResult:    true,
			wantTech:      "dynamics365",
			wantComponent: "Power Apps Portal",
		},

		// --- Body signal tests: Liquid tags ---
		{
			name:       "detects Power Apps Portal via entityform Liquid tag",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `{% entityform id:"form-id" %}`,
			wantResult:    true,
			wantTech:      "dynamics365",
			wantComponent: "Power Apps Portal",
		},

		// --- Body signal tests: CRM client-side ---
		{
			name:       "detects CRM via Xrm.Page body signal",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<script>var ctx = Xrm.Page.context;</script>`,
			wantResult:    true,
			wantTech:      "dynamics365",
			wantComponent: "CRM",
		},
		{
			name:       "detects CRM via ClientGlobalContext.js.aspx body signal",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<script src="/webresources/ClientGlobalContext.js.aspx"></script>`,
			wantResult:    true,
			wantTech:      "dynamics365",
			wantComponent: "CRM",
		},
		{
			name:       "detects CRM via Microsoft.Dynamics body signal",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<script>Microsoft.Dynamics.CRM.Initialize();</script>`,
			wantResult:    true,
			wantTech:      "dynamics365",
			wantComponent: "CRM",
		},

		// --- Body signal tests: domain references ---
		{
			name:           "detects online deployment via .dynamics.com domain",
			statusCode:     200,
			headers:        http.Header{"Content-Type": []string{"text/html"}},
			body:           `<a href="https://contoso.crm.dynamics.com/api/data/v9.2">API</a>`,
			wantResult:     true,
			wantTech:       "dynamics365",
			wantDeployment: "online",
		},
		{
			name:       "detects via powerappsportals.com domain",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<link rel="canonical" href="https://contoso.powerappsportals.com"/>`,
			wantResult: true,
			wantTech:   "dynamics365",
		},

		// --- Body signal tests: msdyn_ prefix ---
		{
			name:       "detects via msdyn_ managed solution prefix",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<div data-entity="msdyn_workorder">Work Order</div>`,
			wantResult: true,
			wantTech:   "dynamics365",
		},

		// --- Body signal tests: crmEntityFormView ---
		{
			name:          "detects CRM via crmEntityFormView body signal",
			statusCode:    200,
			headers:       http.Header{"Content-Type": []string{"text/html"}},
			body:          `<div class="crmEntityFormView">Form</div>`,
			wantResult:    true,
			wantTech:      "dynamics365",
			wantComponent: "CRM",
		},

		// --- Deployment detection ---
		{
			name:       "detects on-premises deployment via IIS Server header",
			statusCode: 200,
			headers: http.Header{
				"X-Ms-Request-Id": []string{"abc"},
				"Server":          []string{"Microsoft-IIS/10.0"},
			},
			body:           "",
			wantResult:     true,
			wantTech:       "dynamics365",
			wantDeployment: "on-premises",
		},

		// --- Version extraction from /_services/about ---
		{
			name:       "extracts version from portal about page",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>Portal version: 9.4.8.13</body></html>`,
			wantResult:    true,
			wantTech:      "dynamics365",
			wantVersion:   "9.4.8.13",
			wantCPEPrefix: "cpe:2.3:a:microsoft:dynamics_365:9.4.8.13",
			wantComponent: "Power Apps Portal",
		},
		{
			name:       "extracts version from Version prefix with header signal",
			statusCode: 200,
			headers: http.Header{
				"X-Ms-Request-Id": []string{"abc"},
				"Content-Type":    []string{"text/html"},
			},
			body:          `<html><body>Portal Version: 8.2.1.3</body></html>`,
			wantResult:    true,
			wantTech:      "dynamics365",
			wantVersion:   "8.2.1.3",
			wantCPEPrefix: "cpe:2.3:a:microsoft:dynamics_365:8.2.1.3",
		},
		{
			name:       "extracts two-part version",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body>Portal version: 9.4</body></html>`,
			wantResult:    true,
			wantTech:      "dynamics365",
			wantVersion:   "9.4",
			wantComponent: "Power Apps Portal",
		},

		// --- CPE construction ---
		{
			name:          "CPE uses wildcard when no version available",
			statusCode:    200,
			headers:       http.Header{"X-Ms-Request-Id": []string{"abc"}},
			body:          "",
			wantResult:    true,
			wantTech:      "dynamics365",
			wantCPEPrefix: "cpe:2.3:a:microsoft:dynamics_365:*",
		},

		// --- Negative cases ---
		{
			name:       "returns nil for 500 status",
			statusCode: 500,
			headers:    http.Header{"X-Ms-Request-Id": []string{"abc"}},
			body:       `Xrm.Page`,
			wantResult: false,
		},
		{
			name:       "returns nil with no signals",
			statusCode: 200,
			headers:    http.Header{"Content-Type": []string{"text/html"}},
			body:       `<html><body><h1>Welcome</h1></body></html>`,
			wantResult: false,
		},

		// --- Combined signals ---
		{
			name:       "full Power Apps Portal with all signals",
			statusCode: 200,
			headers: http.Header{
				"X-Ms-Request-Id": []string{"abc-123"},
				"Set-Cookie":      []string{"Dynamics365PortalAnalytics=xyz; Path=/"},
				"Content-Type":    []string{"text/html"},
			},
			body: `<html><body>
<div class="adx_entityform">Form</div>
{% entityform id:"form" %}
Portal version: 9.4.8.13
<a href="https://contoso.powerappsportals.com">Portal</a>
</body></html>`,
			wantResult:     true,
			wantTech:       "dynamics365",
			wantVersion:    "9.4.8.13",
			wantComponent:  "Power Apps Portal",
			wantDeployment: "online",
		},
		{
			name:       "full CRM on-premises with all signals",
			statusCode: 200,
			headers: http.Header{
				"X-Ms-Request-Id": []string{"abc"},
				"Odata-Version":   []string{"4.0"},
				"Server":          []string{"Microsoft-IIS/10.0"},
				"Set-Cookie":      []string{"CrmOwinAuth=token; Path=/"},
				"Content-Type":    []string{"text/html"},
			},
			body: `<html><body>
<script>Xrm.Page.context.getClientUrl();</script>
<script src="ClientGlobalContext.js.aspx"></script>
<div class="crmEntityFormView">Form</div>
</body></html>`,
			wantResult:     true,
			wantTech:       "dynamics365",
			wantComponent:  "CRM",
			wantDeployment: "on-premises",
			wantOData:      true,
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
				t.Error("Fingerprint() returned nil, expected result")
				return
			}

			if !tt.wantResult && result != nil {
				t.Errorf("Fingerprint() returned result, expected nil")
				return
			}

			if result == nil {
				return
			}

			if result.Technology != tt.wantTech {
				t.Errorf("Technology = %q, want %q", result.Technology, tt.wantTech)
			}

			if tt.wantVersion != "" && result.Version != tt.wantVersion {
				t.Errorf("Version = %q, want %q", result.Version, tt.wantVersion)
			}

			if tt.wantVersion == "" && result.Version != "" {
				t.Errorf("Version = %q, expected empty", result.Version)
			}

			if tt.wantCPEPrefix != "" && len(result.CPEs) > 0 {
				cpe := result.CPEs[0]
				if len(cpe) < len(tt.wantCPEPrefix) || cpe[:len(tt.wantCPEPrefix)] != tt.wantCPEPrefix {
					t.Errorf("CPE = %q, want prefix %q", cpe, tt.wantCPEPrefix)
				}
			}

			if tt.wantComponent != "" {
				component, _ := result.Metadata["component"]
				if component != tt.wantComponent {
					t.Errorf("component = %q, want %q", component, tt.wantComponent)
				}
			}

			if tt.wantDeployment != "" {
				deployment, _ := result.Metadata["deployment"]
				if deployment != tt.wantDeployment {
					t.Errorf("deployment = %q, want %q", deployment, tt.wantDeployment)
				}
			}

			if tt.wantOData {
				odataAPI, _ := result.Metadata["odata_api"]
				if odataAPI != true {
					t.Errorf("odata_api = %v, want true", odataAPI)
				}
			}
		})
	}
}

func TestBuildDynamics365CPE(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{
			version: "9.4.8.13",
			want:    "cpe:2.3:a:microsoft:dynamics_365:9.4.8.13:*:*:*:*:*:*:*",
		},
		{
			version: "8.2",
			want:    "cpe:2.3:a:microsoft:dynamics_365:8.2:*:*:*:*:*:*:*",
		},
		{
			version: "",
			want:    "cpe:2.3:a:microsoft:dynamics_365:*:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run("version_"+tt.version, func(t *testing.T) {
			if got := buildDynamics365CPE(tt.version); got != tt.want {
				t.Errorf("buildDynamics365CPE() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPortalVersionRegex(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantVer string
	}{
		{
			name:    "Portal version: 9.4.8.13",
			input:   "Portal version: 9.4.8.13",
			wantVer: "9.4.8.13",
		},
		{
			name:    "Version: 8.2.1.3",
			input:   "Version: 8.2.1.3",
			wantVer: "8.2.1.3",
		},
		{
			name:    "two-part version",
			input:   "Portal version: 9.4",
			wantVer: "9.4",
		},
		{
			name:    "three-part version",
			input:   "version: 9.4.8",
			wantVer: "9.4.8",
		},
		{
			name:    "no match",
			input:   "Some other text without version info",
			wantVer: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := portalVersionRegex.FindStringSubmatch(tt.input)
			got := ""
			if matches != nil {
				got = matches[1]
			}
			if got != tt.wantVer {
				t.Errorf("portalVersionRegex match = %q, want %q", got, tt.wantVer)
			}
		})
	}
}

func TestPortalVersionSafeRegex(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"9.4.8.13", true},
		{"8.2", true},
		{"9", true},
		{"abc", false},
		{"9.4;DROP TABLE", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := portalVersionSafeRegex.MatchString(tt.input); got != tt.want {
				t.Errorf("portalVersionSafeRegex.MatchString(%q) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}
