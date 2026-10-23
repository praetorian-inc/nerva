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
Package fingerprinters provides HTTP fingerprinting for internet-exposed
Verifone and Ingenico POS/POI management interfaces (ENG-9060).

# What We Detect

Management-plane HTML that has been captured on public login pages:

  - Verifone VHQ: live <title>VHQ</title> on
    /VHQ.Authentication.VHQFederationV1/Account/Login
    (vhq.connect.verifone.com), plus Verifone copyright and a login form.
  - Ingenico Estate Manager: live <title>Ingenico Estate Management</title>
    on /emgui/resetPassword.jsp (mcmemuat.roamdata.com).
  - Ingenico TMS: live <title>TMS Web Access- Login</title> on
    /extranet/login.sm (tmsweb.services.ingenico.co.uk).

Nerva does not follow redirects and does not re-queue Location targets.
These fingerprinters actively GET the captured management paths (same
host:port). A 302 on GET / is not itself a detection.

# What We Do NOT Detect

  - Generic HTTP servers (Apache, nginx, empty bodies).
  - Pages that merely mention the vendor in prose (news, marketing).
  - Catch-all redirects: Location is never a detection signal.
  - Unverified on-box titles (VeriFone Commander, Configuration Client,
    Ingenico Telium) and unverified product Server tokens.
  - In-browser POS payloads (ENG-5284).
  - Oracle Hospitality Simphony / MICROS EGateway (oracle_simphony.go).

# Finding

Both vendors emit the same stable finding ID, pos-poi-management-exposed,
catalogued in pkg/plugins/finding_catalog.go.
*/
package fingerprinters

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const (
	posPOIMaxBodySize         = 1 << 20
	posPOIManagementFindingID = "pos-poi-management-exposed"
	verifoneCPE               = "cpe:2.3:a:verifone:vhq:*:*:*:*:*:*:*:*"
	// NVD CVE-2024-6059 uses ingenico:estate_management; CISA-ADP also lists estate_manager.
	ingenicoEstateCPE      = "cpe:2.3:a:ingenico:estate_management:*:*:*:*:*:*:*:*"
	ingenicoEstateCPEAlias = "cpe:2.3:a:ingenico:estate_manager:*:*:*:*:*:*:*:*"
	ingenicoTMSCPE         = "cpe:2.3:a:ingenico:tms:*:*:*:*:*:*:*:*"
	verifoneProbePath      = "/VHQ.Authentication.VHQFederationV1/Account/Login"
	ingenicoProbePath      = "/emgui/resetPassword.jsp"
	ingenicoTMSProbePath   = "/extranet/login.sm"
)

var (
	// Live vhq.connect.verifone.com login HTML.
	vhqTitle           = regexp.MustCompile(`(?i)<title>\s*VHQ\s*</title>`)
	verifoneCopyright  = regexp.MustCompile(`(?i)Verifone Systems, Inc`)
	vhqAuthPath        = regexp.MustCompile(`(?i)/VHQ\.Authentication\.`)
	managementUIMarker = regexp.MustCompile(`(?i)(<form\b|type=["']password["']|name=["']password["']|log\s*on|login|forgot\s+password)`)

	// Live mcmemuat.roamdata.com/emgui/resetPassword.jsp
	ingenicoEstateTitle = regexp.MustCompile(`(?i)<title>\s*Ingenico\s+Estate\s+Management\s*</title>`)
	ingenicoBody        = regexp.MustCompile(`(?i)Ingenico`)

	// Live tmsweb.services.ingenico.co.uk/extranet/login.sm
	ingenicoTMSTitle = regexp.MustCompile(`(?i)<title>\s*TMS Web Access-\s*Login\s*</title>`)
)

// VerifoneFingerprinter detects Verifone VHQ management HTTP UIs.
type VerifoneFingerprinter struct{}

// IngenicoFingerprinter detects Ingenico Estate Manager management HTTP UIs.
type IngenicoFingerprinter struct{}

// IngenicoTMSFingerprinter detects Ingenico TMS Web Access management HTTP UIs.
type IngenicoTMSFingerprinter struct{}

var (
	_ HTTPFingerprinter       = (*VerifoneFingerprinter)(nil)
	_ ActiveHTTPFingerprinter = (*VerifoneFingerprinter)(nil)
	_ AcceptHeaderProvider    = (*VerifoneFingerprinter)(nil)
	_ HTTPFingerprinter       = (*IngenicoFingerprinter)(nil)
	_ ActiveHTTPFingerprinter = (*IngenicoFingerprinter)(nil)
	_ AcceptHeaderProvider    = (*IngenicoFingerprinter)(nil)
	_ HTTPFingerprinter       = (*IngenicoTMSFingerprinter)(nil)
	_ ActiveHTTPFingerprinter = (*IngenicoTMSFingerprinter)(nil)
	_ AcceptHeaderProvider    = (*IngenicoTMSFingerprinter)(nil)
)

func init() {
	Register(&VerifoneFingerprinter{})
	Register(&IngenicoFingerprinter{})
	Register(&IngenicoTMSFingerprinter{})
}

func (f *VerifoneFingerprinter) Name() string    { return "verifone" }
func (f *IngenicoFingerprinter) Name() string    { return "ingenico" }
func (f *IngenicoTMSFingerprinter) Name() string { return "ingenico-tms" }

func (f *VerifoneFingerprinter) ProbeEndpoint() string    { return verifoneProbePath }
func (f *IngenicoFingerprinter) ProbeEndpoint() string    { return ingenicoProbePath }
func (f *IngenicoTMSFingerprinter) ProbeEndpoint() string { return ingenicoTMSProbePath }

func (f *VerifoneFingerprinter) ProbeAccept() string    { return "text/html" }
func (f *IngenicoFingerprinter) ProbeAccept() string    { return "text/html" }
func (f *IngenicoTMSFingerprinter) ProbeAccept() string { return "text/html" }

func posPOIStatusOK(resp *http.Response) bool {
	return resp != nil && resp.StatusCode >= 200 && resp.StatusCode < 400
}

func posPOIHTML(resp *http.Response) bool {
	if !posPOIStatusOK(resp) {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

func (f *VerifoneFingerprinter) Match(resp *http.Response) bool    { return posPOIHTML(resp) }
func (f *IngenicoFingerprinter) Match(resp *http.Response) bool    { return posPOIHTML(resp) }
func (f *IngenicoTMSFingerprinter) Match(resp *http.Response) bool { return posPOIHTML(resp) }

func capBody(body []byte) string {
	if len(body) > posPOIMaxBodySize {
		body = body[:posPOIMaxBodySize]
	}
	return string(body)
}

func posPOIFinding(evidence string) plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          posPOIManagementFindingID,
		Severity:    plugins.SeverityMedium,
		Description: "Internet-exposed POS/POI payment-terminal management interface",
		Evidence:    evidence,
	}
}

func verifoneIdentity(bodyStr string) (evidence string, ok bool) {
	if !vhqTitle.MatchString(bodyStr) || !managementUIMarker.MatchString(bodyStr) {
		return "", false
	}
	if !verifoneCopyright.MatchString(bodyStr) && !vhqAuthPath.MatchString(bodyStr) {
		return "", false
	}
	return "Verifone VHQ management HTML identity", true
}

func ingenicoEstateIdentity(bodyStr string) (evidence string, ok bool) {
	if ingenicoEstateTitle.MatchString(bodyStr) && ingenicoBody.MatchString(bodyStr) && managementUIMarker.MatchString(bodyStr) {
		return "Ingenico Estate Management HTML identity", true
	}
	return "", false
}

func ingenicoTMSIdentity(bodyStr string) (evidence string, ok bool) {
	if ingenicoTMSTitle.MatchString(bodyStr) && ingenicoBody.MatchString(bodyStr) && managementUIMarker.MatchString(bodyStr) {
		return "Ingenico TMS Web Access HTML identity", true
	}
	return "", false
}

func (f *VerifoneFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if !f.Match(resp) {
		return nil, nil
	}
	evidence, ok := verifoneIdentity(capBody(body))
	if !ok {
		return nil, nil
	}
	return &FingerprintResult{
		Technology: "verifone",
		Version:    "",
		CPEs:       []string{verifoneCPE},
		Metadata: map[string]any{
			"vendor":  "Verifone",
			"product": "VHQ",
		},
		SecurityFindings: []plugins.SecurityFinding{posPOIFinding(evidence)},
	}, nil
}

func (f *IngenicoFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if !f.Match(resp) {
		return nil, nil
	}
	evidence, ok := ingenicoEstateIdentity(capBody(body))
	if !ok {
		return nil, nil
	}
	return &FingerprintResult{
		Technology: "ingenico",
		Version:    "",
		CPEs:       []string{ingenicoEstateCPE, ingenicoEstateCPEAlias},
		Metadata: map[string]any{
			"vendor":  "Ingenico",
			"product": "Estate Manager",
		},
		SecurityFindings: []plugins.SecurityFinding{posPOIFinding(evidence)},
	}, nil
}

func (f *IngenicoTMSFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if !f.Match(resp) {
		return nil, nil
	}
	evidence, ok := ingenicoTMSIdentity(capBody(body))
	if !ok {
		return nil, nil
	}
	// Distinct Technology avoids fingerprintMetadata overwrite with Estate
	// (http.go keys metadata by Technology; veeam.go uses the same split).
	return &FingerprintResult{
		Technology: "ingenico-tms",
		Version:    "",
		CPEs:       []string{ingenicoTMSCPE},
		Metadata: map[string]any{
			"vendor":  "Ingenico",
			"product": "TMS",
		},
		SecurityFindings: []plugins.SecurityFinding{posPOIFinding(evidence)},
	}, nil
}
