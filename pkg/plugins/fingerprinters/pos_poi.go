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

Payment-terminal / site-controller management planes that identify themselves
over HTTP/TLS:

  - Verifone Commander (site controller) login/title pages, including the
    "VeriFone Commander" title and "VeriFone Systems, Inc." copyright used on
    Commander management UIs.
  - Ingenico Telium terminal-management pages (title "Ingenico Telium" plus
    Telium / iCT model markers).

Detection is banner/HTML identity of the management plane. Hardware-in-the-loop
is out of scope.

# What We Do NOT Detect

  - Generic HTTP servers (Apache, nginx, empty bodies).
  - Pages that merely mention the vendor in prose (news, marketing).
  - In-browser POS payloads (ENG-5284).
  - Oracle Hospitality Simphony / MICROS EGateway (oracle_simphony.go).

# Finding

Both products emit the same stable finding ID, pos-poi-management-exposed,
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
	verifoneCPE               = "cpe:2.3:a:verifone:commander:*:*:*:*:*:*:*:*"
	ingenicoCPE               = "cpe:2.3:o:ingenico:telium_2_firmware:*:*:*:*:*:*:*:*"
)

var (
	verifoneCommanderTitle = regexp.MustCompile(`(?i)<title>[^<]*VeriFone\s+Commander`)
	ingenicoTeliumTitle    = regexp.MustCompile(`(?i)<title>\s*Ingenico\s+Telium\s*</title>`)
	managementUIMarker     = regexp.MustCompile(`(?i)(<form\b|type=["']password["']|name=["']password["']|log\s*on|login)`)
)

// VerifoneFingerprinter detects Verifone Commander / POS management HTTP UIs.
type VerifoneFingerprinter struct{}

// IngenicoFingerprinter detects Ingenico Telium POS/POI management HTTP UIs.
type IngenicoFingerprinter struct{}

func init() {
	Register(&VerifoneFingerprinter{})
	Register(&IngenicoFingerprinter{})
}

func (f *VerifoneFingerprinter) Name() string { return "verifone" }
func (f *IngenicoFingerprinter) Name() string { return "ingenico" }

func posPOIMatch(resp *http.Response) bool {
	if resp == nil || resp.StatusCode != 200 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/html")
}

func (f *VerifoneFingerprinter) Match(resp *http.Response) bool { return posPOIMatch(resp) }
func (f *IngenicoFingerprinter) Match(resp *http.Response) bool { return posPOIMatch(resp) }

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

func (f *VerifoneFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if !posPOIMatch(resp) {
		return nil, nil
	}
	bodyStr := capBody(body)
	if !verifoneCommanderTitle.MatchString(bodyStr) {
		return nil, nil
	}
	return &FingerprintResult{
		Technology: "verifone",
		Version:    "",
		CPEs:       []string{verifoneCPE},
		Metadata: map[string]any{
			"vendor":  "Verifone",
			"product": "Commander",
		},
		SecurityFindings: []plugins.SecurityFinding{posPOIFinding("Verifone Commander management HTML identity")},
	}, nil
}

func (f *IngenicoFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if !posPOIMatch(resp) {
		return nil, nil
	}
	bodyStr := capBody(body)
	if !ingenicoTeliumTitle.MatchString(bodyStr) || !managementUIMarker.MatchString(bodyStr) {
		return nil, nil
	}
	return &FingerprintResult{
		Technology: "ingenico",
		Version:    "",
		CPEs:       []string{ingenicoCPE},
		Metadata: map[string]any{
			"vendor":  "Ingenico",
			"product": "Telium",
		},
		SecurityFindings: []plugins.SecurityFinding{posPOIFinding("Ingenico Telium management HTML identity")},
	}, nil
}
