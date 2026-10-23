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

// Citrix ADC / NetScaler management plane, distinct from Gateway / AAA.
//
// Detection Strategy:
// The ADC configuration GUI and NITRO API are a different attack surface from
// the Citrix Gateway / AAA user portal (LogonPoint, /vpn/). Management-plane
// CVEs are routinely exploited against internet-facing ADCs; this fingerprinter
// identifies that plane so it can be reported separately from the site/VPN.
//
// Two active probes:
//
//  1. GET /menu/neo — modern configuration GUI (CitrixADCAdminFingerprinter)
//  2. GET /nitro/v1/config — NITRO REST API (CitrixADCNitroFingerprinter)
//
// Negative match: Gateway/AAA markers (LogonPoint, /vpn/login.js,
// _ctxstxt_NetscalerGateway) return nil so this never collides with
// CitrixNetScalerFingerprinter.
//
// CPE is the same ADC CPE as the Gateway fingerprinter; Technology
// "citrix-adc-admin" distinguishes the interface.
package fingerprinters

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const citrixADCAdminFindingID = "citrix-adc-admin-panel-exposed"

var (
	citrixADCAdminTitlePattern = regexp.MustCompile(
		`(?i)<title[^>]{0,200}>\s*(Citrix ADC|NetScaler ADC|Citrix Application Delivery Management)\s*</title>`,
	)
)

var (
	citrixMenuNeoAsset   = []byte("/menu/neo/")
	citrixNsGUIAsset     = []byte("/ns_gui/")
	citrixNitroAPIAsset  = []byte("/nitro/v1/")
	citrixADCAdminCookie = []byte("NITRO_WEB_APPLICATION")
)

// Gateway/AAA markers — any hit means this is the user portal, not management.
var citrixGatewayNegativeMarkers = [][]byte{
	[]byte("/vpn/login.js"),
	[]byte("/vpn/js/rdx.js"),
	[]byte("/logon/LogonPoint/"),
	[]byte("_ctxstxt_NetscalerGateway"),
	[]byte("_ctxstxt_NetscalerAAA"),
	[]byte("Citrix Gateway"),
	[]byte("NetScaler Gateway"),
	[]byte("NetScaler AAA"),
}

func init() {
	Register(&CitrixADCAdminFingerprinter{})
	Register(&CitrixADCNitroFingerprinter{})
}

// CitrixADCAdminFingerprinter detects the ADC configuration GUI at /menu/neo.
type CitrixADCAdminFingerprinter struct{}

func (f *CitrixADCAdminFingerprinter) Name() string { return "citrix-adc-admin" }

func (f *CitrixADCAdminFingerprinter) ProbeEndpoint() string { return "/menu/neo" }

func (f *CitrixADCAdminFingerprinter) ProbeAccept() string { return "text/html" }

func (f *CitrixADCAdminFingerprinter) Match(resp *http.Response) bool {
	// 4xx error pages frequently echo the probed path (e.g. a 404 body that
	// prints "/menu/neo"), so they are not a reliable signal for the GUI.
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 400 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if ct == "" || strings.Contains(ct, "text/html") || strings.Contains(ct, "application/xhtml+xml") {
		return true
	}
	return citrixAdminLocationPath(resp)
}

func (f *CitrixADCAdminFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil || hasCitrixGatewayMarkers(body) {
		return nil, nil
	}
	if !isCitrixADCAdminGUI(resp, body) {
		return nil, nil
	}
	return citrixADCAdminResult("gui", "GET /menu/neo returned Citrix ADC configuration GUI markup"), nil
}

// CitrixADCNitroFingerprinter detects the NITRO management API.
type CitrixADCNitroFingerprinter struct{}

func (f *CitrixADCNitroFingerprinter) Name() string { return "citrix-adc-nitro" }

func (f *CitrixADCNitroFingerprinter) ProbeEndpoint() string { return "/nitro/v1/config" }

func (f *CitrixADCNitroFingerprinter) ProbeAccept() string { return "application/json" }

func (f *CitrixADCNitroFingerprinter) Match(resp *http.Response) bool {
	if resp == nil || resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return ct == "" || strings.Contains(ct, "json") || strings.Contains(ct, "text/html")
}

func (f *CitrixADCNitroFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if resp == nil || hasCitrixGatewayMarkers(body) {
		return nil, nil
	}
	if !isCitrixNITRO(body) {
		return nil, nil
	}
	return citrixADCAdminResult("nitro", "GET /nitro/v1/config returned a NITRO API envelope"), nil
}

type nitroEnvelope struct {
	Errorcode int    `json:"errorcode"`
	Message   string `json:"message"`
}

func isCitrixNITRO(body []byte) bool {
	var env nitroEnvelope
	if err := json.Unmarshal(body, &env); err != nil {
		return false
	}
	msg := strings.ToLower(env.Message)
	switch {
	case env.Errorcode == 354:
		return true
	case env.Errorcode == 444:
		return true
	case strings.Contains(msg, "not authorized to execute this command"):
		return true
	case env.Errorcode == 0 && msg == "done":
		return true
	default:
		return false
	}
}

func isCitrixADCAdminGUI(resp *http.Response, body []byte) bool {
	if hasCitrixGatewayMarkers(body) {
		return false
	}
	if citrixAdminLocationPath(resp) {
		return true
	}
	if citrixADCAdminTitlePattern.Match(body) {
		return true
	}
	return bytes.Contains(body, citrixMenuNeoAsset) ||
		bytes.Contains(body, citrixNsGUIAsset) ||
		bytes.Contains(body, citrixNitroAPIAsset) ||
		bytes.Contains(body, citrixADCAdminCookie)
}

// citrixAdminLocationPath reports whether the Location header redirects into the
// ADC management GUI, matched on the URL path prefix (not a bare substring, so a
// login redirect carrying ?next=/menu/neo is not mistaken for the GUI).
func citrixAdminLocationPath(resp *http.Response) bool {
	loc := resp.Header.Get("Location")
	if loc == "" {
		return false
	}
	u, err := url.Parse(loc)
	if err != nil {
		return false
	}
	// A redirect to a different host is not evidence that this service is the
	// ADC GUI; only honor relative or same-host redirects.
	if u.Host != "" {
		if resp.Request == nil || resp.Request.URL == nil || !strings.EqualFold(u.Host, resp.Request.URL.Host) {
			return false
		}
	}
	// Match /menu/neo only as a complete path segment (exact, or followed by a
	// slash) so that e.g. /menu/neofoo does not match. /ns_gui/ already ends in a slash.
	p := strings.ToLower(u.Path)
	return p == "/menu/neo" || strings.HasPrefix(p, "/menu/neo/") || strings.HasPrefix(p, "/ns_gui/")
}

func hasCitrixGatewayMarkers(body []byte) bool {
	for _, m := range citrixGatewayNegativeMarkers {
		if bytes.Contains(body, m) {
			return true
		}
	}
	return false
}

func citrixADCAdminResult(detection, evidence string) *FingerprintResult {
	return &FingerprintResult{
		Technology: "citrix-adc-admin",
		CPEs:       []string{buildCitrixNetScalerCPE("")},
		Metadata: map[string]any{
			"vendor":           "Citrix",
			"product":          "ADC Management Interface",
			"interface_type":   "management",
			"detection_method": detection,
		},
		Severity: plugins.SeverityMedium,
		SecurityFindings: []plugins.SecurityFinding{{
			ID:          citrixADCAdminFindingID,
			Severity:    plugins.SeverityMedium,
			Description: "Citrix ADC / NetScaler management plane (configuration GUI or NITRO API) is reachable on this service, distinct from the Gateway or AAA user portal.",
			Evidence:    evidence,
		}},
	}
}
