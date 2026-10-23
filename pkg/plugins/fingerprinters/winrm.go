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
Package fingerprinters provides HTTP fingerprinting for WinRM.

# Detection Strategy

WinRM (Windows Remote Management) is a Microsoft implementation of WS-Management
protocol for remote Windows system management. Detection identifies:
  - Microsoft-HTTPAPI Server header (HTTP.sys), which is necessary but not
    sufficient: many non-WinRM services (WCF, Azure gateways) use the same header
  - Probe /wsman (standard WS-Management path)
  - 401 Unauthorized with a WinRM/WS-Man WWW-Authenticate challenge
    (Negotiate, Kerberos or CredSSP) indicates an auth-required WinRM instance
  - HTTP 2xx is treated as unauthenticated WinRM only when the response body
    carries actual WS-Man SOAP evidence (an IdentifyResponse, the WS-Man
    namespace or a WSManFault). A SOAP Content-Type or a Windows-auth header
    alone is shared by non-WinRM HTTP.sys listeners, and a generic HTTP.sys
    "Endpoint not found" HTML page is not WinRM.

Port Configuration:
  - 5985: HTTP (unencrypted WinRM)
  - 5986: HTTPS (encrypted WinRM)

# Example Usage

	fp := &WinRMFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s\n", result.Technology)
		}
	}
*/
package fingerprinters

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// WinRMFingerprinter detects WinRM instances via Microsoft-HTTPAPI header on /wsman endpoint
type WinRMFingerprinter struct{}

func init() {
	Register(&WinRMFingerprinter{})
}

func (f *WinRMFingerprinter) Name() string {
	return "winrm"
}

func (f *WinRMFingerprinter) ProbeEndpoint() string {
	return "/wsman"
}

func (f *WinRMFingerprinter) Match(resp *http.Response) bool {
	// Microsoft-HTTPAPI/2.0 is the Server header used by Windows HTTP.sys
	// which powers WinRM. This is present on all WinRM responses, but also
	// on unrelated HTTP.sys listeners. Fingerprint() requires WS-Man evidence.
	return isHTTPAPI(resp)
}

func (f *WinRMFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if !isHTTPAPI(resp) {
		return nil, nil
	}
	// HTTP.sys WCF/Azure-gateway "Service / Endpoint not found" pages are not WinRM.
	if isHTTPAPIGenericServicePage(body) {
		return nil, nil
	}

	ok, authRequired := classifyWinRM(resp, body)
	if !ok {
		return nil, nil
	}

	metadata := map[string]any{
		"auth_required": authRequired,
	}
	if server := resp.Header.Get("Server"); server != "" {
		metadata["server"] = server
	}

	result := &FingerprintResult{
		Technology: "winrm",
		CPEs:       []string{buildWinRMCPE()},
		Metadata:   metadata,
	}

	if !authRequired && resp.StatusCode/100 == 2 {
		result.Severity = plugins.SeverityCritical
		result.SecurityFindings = []plugins.SecurityFinding{
			{
				ID:          "winrm-no-auth",
				Severity:    plugins.SeverityCritical,
				Description: "WinRM endpoint accessible without authentication — enables remote command execution",
				Evidence:    fmt.Sprintf("WinRM /wsman endpoint returned HTTP %d WS-Man response without requiring credentials", resp.StatusCode),
			},
		}
		if resp.TLS == nil {
			result.SecurityFindings = append(result.SecurityFindings, plugins.SecurityFinding{
				ID:          "winrm-cleartext",
				Severity:    plugins.SeverityMedium,
				Description: "WinRM running over HTTP instead of HTTPS — credentials and commands transmitted in cleartext",
				Evidence:    "WinRM detected on unencrypted HTTP connection",
			})
		}
	}

	return result, nil
}

func buildWinRMCPE() string {
	return "cpe:2.3:a:microsoft:windows_remote_management:*:*:*:*:*:*:*:*"
}

func isHTTPAPI(resp *http.Response) bool {
	if resp == nil {
		return false
	}
	return strings.Contains(resp.Header.Get("Server"), "Microsoft-HTTPAPI")
}

// isHTTPAPIGenericServicePage reports HTTP.sys default WCF HTML (not WS-Man).
func isHTTPAPIGenericServicePage(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := bytes.ToLower(body)
	if !bytes.Contains(lower, []byte("endpoint not found")) {
		return false
	}
	return bytes.Contains(lower, []byte("heading1")) ||
		bytes.Contains(lower, []byte("<title>service</title>")) ||
		bytes.Contains(lower, []byte("xhtml1-transitional"))
}

// classifyWinRM returns whether the response is WinRM and whether auth is required.
//
// A 401 is auth-required WinRM only when it carries a WinRM/WS-Man
// WWW-Authenticate challenge (Negotiate, Kerberos or CredSSP). A 2xx is
// unauthenticated WinRM only when the body carries actual WS-Man SOAP evidence
// (an IdentifyResponse, the WS-Man namespace or a WSManFault); a SOAP
// Content-Type or a Windows-auth header alone is shared by non-WinRM HTTP.sys
// listeners and is not sufficient.
func classifyWinRM(resp *http.Response, body []byte) (ok bool, authRequired bool) {
	if resp.StatusCode == http.StatusUnauthorized {
		if wsManAuthChallenge(resp) {
			return true, true
		}
		return false, false
	}
	if resp.StatusCode/100 != 2 {
		return false, false
	}
	if wsManBody(body) {
		return true, false
	}
	return false, false
}

// wsManAuthChallenge reports a WinRM/WS-Man WWW-Authenticate challenge.
func wsManAuthChallenge(resp *http.Response) bool {
	www := strings.ToLower(resp.Header.Get("WWW-Authenticate"))
	return strings.Contains(www, "negotiate") ||
		strings.Contains(www, "kerberos") ||
		strings.Contains(www, "credssp")
}

// wsManBody reports an actual WS-Man SOAP body: an Identify response, the
// WS-Man namespace, or a WSManFault. A SOAP Content-Type alone is not enough,
// because WCF and other HTTP.sys services share the same media type.
func wsManBody(body []byte) bool {
	if len(body) == 0 {
		return false
	}
	lower := bytes.ToLower(body)
	markers := [][]byte{
		[]byte("schemas.dmtf.org/wbem/wsman"),
		[]byte("identifyresponse"),
		[]byte("wsmanfault"),
		[]byte("microsoft.wsman"),
		[]byte("www.dmtf.org/standards/wbem"),
	}
	for _, m := range markers {
		if bytes.Contains(lower, m) {
			return true
		}
	}
	return false
}
