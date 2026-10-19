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

/*
Package fingerprinters provides HTTP fingerprinting for Azure App Service Kudu (SCM).

# Detection Strategy

Kudu is the Site Control Manager for Azure App Service. It is the control
plane used for zip deploy, WebDeploy, the debug console, process listing,
and Visual Studio remote debugging. It typically listens on
*.scm.azurewebsites.net (or a custom SCM hostname) rather than the public
app hostname.

Detection probes GET /DebugConsole (the Kudu debug console) and matches:

  - HTTP 401 with WWW-Authenticate: Basic realm="site" (publishing credentials)
  - HTTP 302/401 Location to App Service AAD SSO (client abfa0a7c-… / appservice.azure.com)
  - HTTP 200 HTML that is actually the Kudu console (not an AAD login page)

# Remote debugging

Azure App Service remoteDebuggingEnabled starts vsdbg/msvsmon behind Kudu.
Multi-tenant App Service does not publish TCP 4022/4024 on the public VIP;
the attach path is SCM. An unauthenticated Kudu console is command execution
on the worker. Authenticated Kudu is still the service being exposed.

# What We Do NOT Detect

  - The ARM flag remoteDebuggingEnabled (cloud config, not a network service)
  - The public app hostname (ARRAffinity + IIS is every App Service site)
  - Raw msvsmon on 4022/4024 (not reachable on multi-tenant App Service)

# CPE

cpe:2.3:a:microsoft:azure_app_service:*:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// Well-known Azure Portal / Kudu AAD application ID.
const azureKuduAADClientID = "abfa0a7c-a6b6-4736-8310-5855508787cd"

// AzureKuduFingerprinter detects Azure App Service Kudu/SCM.
type AzureKuduFingerprinter struct{}

func init() {
	Register(&AzureKuduFingerprinter{})
}

func (f *AzureKuduFingerprinter) Name() string {
	return "azure-app-service-kudu"
}

func (f *AzureKuduFingerprinter) ProbeEndpoint() string {
	return "/DebugConsole"
}

func (f *AzureKuduFingerprinter) ProbeAccept() string {
	return "text/html"
}

func (f *AzureKuduFingerprinter) Match(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	if kuduBasicRealm(resp.Header.Get("WWW-Authenticate")) {
		return true
	}
	if kuduSSORedirect(resp.Header.Get("Location")) {
		return true
	}
	// 200 HTML: Fingerprint() validates the Kudu console body.
	if resp.StatusCode == http.StatusOK && strings.Contains(strings.ToLower(resp.Header.Get("Content-Type")), "text/html") {
		return true
	}
	return false
}

func (f *AzureKuduFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil {
		return nil, nil
	}

	www := resp.Header.Get("WWW-Authenticate")
	loc := resp.Header.Get("Location")
	lower := strings.ToLower(string(body))

	auth := ""
	unauthConsole := false

	// Check the unauthenticated console body first: a real Kudu console page
	// embeds its own *.scm.azurewebsites.net hostname, so a body-based SSO check
	// would mask the Critical finding. The SSO signal is read only from the
	// Location header (the HTTP plugin preserves 3xx redirects without following).
	switch {
	case kuduConsoleBody(lower):
		auth = "none"
		unauthConsole = true
	case kuduBasicRealm(www):
		auth = "basic"
	case kuduSSORedirect(loc):
		auth = "aad"
	default:
		return nil, nil
	}

	result := &FingerprintResult{
		Technology: "azure-app-service-kudu",
		CPEs:       []string{"cpe:2.3:a:microsoft:azure_app_service:*:*:*:*:*:*:*:*"},
		Metadata: map[string]any{
			"vendor":    "Microsoft",
			"product":   "Azure App Service Kudu",
			"auth_mode": auth,
		},
	}
	if unauthConsole {
		result.Severity = plugins.SeverityCritical
		result.SecurityFindings = []plugins.SecurityFinding{{
			ID:          "kudu-unauthenticated-console",
			Severity:    plugins.SeverityCritical,
			Description: "Azure App Service Kudu debug console is accessible without authentication",
			Evidence:    "GET /DebugConsole returned 200 with Kudu debug console markup",
		}}
	}
	return result, nil
}

// CheckMisconfigs probes Kudu process APIs used to attach a debugger.
func (f *AzureKuduFingerprinter) CheckMisconfigs(client *http.Client, baseURL, host string) []plugins.SecurityFinding {
	if client == nil || baseURL == "" {
		return nil
	}
	req, err := http.NewRequest(http.MethodGet, strings.TrimRight(baseURL, "/")+"/api/processes", nil)
	if err != nil {
		return nil
	}
	req.Header.Set("Accept", "application/json")
	if host != "" {
		req.Host = host
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return nil
	}
	if !kuduProcessListBody(body) {
		return nil
	}
	return []plugins.SecurityFinding{{
		ID:          "kudu-unauthenticated-api",
		Severity:    plugins.SeverityHigh,
		Description: "Azure App Service Kudu process API is accessible without authentication",
		Evidence:    "GET /api/processes returned 200 JSON listing worker processes",
	}}
}

func kuduBasicRealm(wwwAuth string) bool {
	l := strings.ToLower(wwwAuth)
	return strings.Contains(l, "basic") && strings.Contains(l, `realm="site"`)
}

func kuduSSORedirect(s string) bool {
	l := strings.ToLower(s)
	if l == "" {
		return false
	}
	if strings.Contains(l, azureKuduAADClientID) {
		return true
	}
	if strings.Contains(l, "scm.azurewebsites.net") {
		return true
	}
	if strings.Contains(l, "sso.azurewebsites.windows.net") {
		return true
	}
	if strings.Contains(l, "appservice.azure.com") {
		return true
	}
	return false
}

func kuduConsoleBody(lower string) bool {
	if strings.Contains(lower, "sign in to your") {
		return false
	}
	hasKudu := strings.Contains(lower, "kudu")
	hasConsole := strings.Contains(lower, "debug console") ||
		strings.Contains(lower, "debugconsole") ||
		strings.Contains(lower, "kudu.js")
	return hasKudu && hasConsole
}

// kuduProcessListBody reports whether body is a Kudu /api/processes JSON array:
// a non-empty array of process objects, at least one of which has an "id" plus a
// Kudu-specific marker (the self-referential /api/processes href, the SCM or
// webjob flags, or a w3wp worker name). Every record is examined, since Kudu may
// omit the false-valued flags and the first process need not be the SCM worker.
// Parsing the JSON (rather than substring matching) avoids flagging arbitrary
// JSON arrays or HTML pages that merely contain these tokens.
func kuduProcessListBody(body []byte) bool {
	var procs []map[string]any
	if err := json.Unmarshal(body, &procs); err != nil || len(procs) == 0 {
		return false
	}
	for _, p := range procs {
		if _, ok := p["id"]; !ok {
			continue
		}
		if href, ok := p["href"].(string); ok && strings.Contains(strings.ToLower(href), "/api/processes") {
			return true
		}
		if _, ok := p["is_scm_site"]; ok {
			return true
		}
		if _, ok := p["is_webjob"]; ok {
			return true
		}
		if name, ok := p["name"].(string); ok && strings.Contains(strings.ToLower(name), "w3wp") {
			return true
		}
	}
	return false
}
