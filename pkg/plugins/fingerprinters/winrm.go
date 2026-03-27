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
  - WinRM endpoints via Microsoft-HTTPAPI/2.0 server header
  - Probe /wsman endpoint (standard WS-Management path)
  - 401 Unauthorized indicates auth-required WinRM instance

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
	"net/http"
	"strings"
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
	// which powers WinRM. This is present on all WinRM responses.
	return strings.Contains(resp.Header.Get("Server"), "Microsoft-HTTPAPI")
}

func (f *WinRMFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Validate Server header contains Microsoft-HTTPAPI
	server := resp.Header.Get("Server")
	if !strings.Contains(server, "Microsoft-HTTPAPI") {
		return nil, nil
	}

	metadata := map[string]any{
		"auth_required": resp.StatusCode == 401,
	}
	if server != "" {
		metadata["server"] = server
	}

	return &FingerprintResult{
		Technology: "winrm",
		CPEs:       []string{buildWinRMCPE()},
		Metadata:   metadata,
	}, nil
}

func buildWinRMCPE() string {
	return "cpe:2.3:a:microsoft:windows_remote_management:*:*:*:*:*:*:*:*"
}
