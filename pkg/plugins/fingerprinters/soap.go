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
Package fingerprinters provides HTTP fingerprinting for SOAP APIs.

# Detection Strategy

SOAP (Simple Object Access Protocol) is an XML-based messaging protocol used
for web service communication. Exposed SOAP endpoints represent a security
concern due to:
  - Potential information disclosure via WSDL service descriptions
  - XML-based attack surface (XXE, SSRF, XML injection)
  - Often exposed without authentication
  - Legacy systems with known vulnerabilities

Detection uses two approaches:
 1. Passive: Check Content-Type headers and response body for SOAP envelope
    namespaces and WSDL definitions
 2. Active: Query ?wsdl endpoint to discover WSDL service descriptions

# Detection Markers

SOAP 1.1 responses contain the namespace:

	http://schemas.xmlsoap.org/soap/envelope/

SOAP 1.2 responses contain the namespace:

	http://www.w3.org/2003/05/soap-envelope

WSDL responses contain the namespace:

	http://schemas.xmlsoap.org/wsdl/

SOAP 1.2 also uses the definitive Content-Type:

	application/soap+xml

# Port Configuration

SOAP services typically run on standard HTTP/HTTPS ports:
  - 80:   HTTP
  - 443:  HTTPS
  - 8080: Alternative HTTP
  - 8443: Alternative HTTPS

# Example Usage

	fp := &SOAPFingerprinter{}
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s (version: %s)\n", result.Technology, result.Metadata["soapVersion"])
		}
	}
*/
package fingerprinters

import (
	"bytes"
	"net/http"
	"strings"
)

// SOAPFingerprinter detects SOAP API services via envelope namespaces and WSDL
type SOAPFingerprinter struct{}

// SOAP namespace URIs used for detection
const (
	soap11EnvelopeNS = "http://schemas.xmlsoap.org/soap/envelope/"
	soap12EnvelopeNS = "http://www.w3.org/2003/05/soap-envelope"
	wsdl11NS         = "http://schemas.xmlsoap.org/wsdl/"
	wsdl20NS         = "http://www.w3.org/ns/wsdl"
)

func init() {
	Register(&SOAPFingerprinter{})
}

func (f *SOAPFingerprinter) Name() string {
	return "soap"
}

func (f *SOAPFingerprinter) ProbeEndpoint() string {
	return "?wsdl"
}

func (f *SOAPFingerprinter) Match(resp *http.Response) bool {
	ct := resp.Header.Get("Content-Type")

	// application/soap+xml is definitive SOAP 1.2
	if strings.Contains(ct, "application/soap+xml") {
		return true
	}

	// text/xml and application/xml may contain SOAP envelopes or WSDL
	if strings.Contains(ct, "text/xml") || strings.Contains(ct, "application/xml") {
		return true
	}

	return false
}

func (f *SOAPFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	ct := resp.Header.Get("Content-Type")
	metadata := make(map[string]any)

	detected := false
	soapVersion := ""

	// Check Content-Type for definitive SOAP 1.2 indicator
	if strings.Contains(ct, "application/soap+xml") {
		detected = true
		soapVersion = "1.2"
	}

	// Check body for SOAP envelope namespaces
	if bytes.Contains(body, []byte(soap12EnvelopeNS)) {
		detected = true
		if soapVersion == "" {
			soapVersion = "1.2"
		}
	}

	if bytes.Contains(body, []byte(soap11EnvelopeNS)) {
		detected = true
		if soapVersion == "" {
			soapVersion = "1.1"
		}
	}

	// Check body for WSDL namespaces
	wsdlDetected := false
	if bytes.Contains(body, []byte(wsdl11NS)) {
		detected = true
		wsdlDetected = true
		metadata["wsdl_version"] = "1.1"
	}
	if bytes.Contains(body, []byte(wsdl20NS)) {
		detected = true
		wsdlDetected = true
		metadata["wsdl_version"] = "2.0"
	}
	metadata["wsdl_available"] = wsdlDetected

	if !detected {
		return nil, nil
	}

	if soapVersion != "" {
		metadata["soap_version"] = soapVersion
	}

	// Extract WSDL target namespace if present
	if wsdlDetected {
		if ns := extractTargetNamespace(body); ns != "" {
			metadata["target_namespace"] = ns
		}
	}

	// Detect SOAP fault presence
	if bytes.Contains(body, []byte(":Fault")) || bytes.Contains(body, []byte("<Fault")) {
		metadata["has_fault"] = true
	}

	return &FingerprintResult{
		Technology: "soap",
		Version:    soapVersion,
		CPEs:       []string{},
		Metadata:   metadata,
	}, nil
}

// extractTargetNamespace extracts the targetNamespace attribute from a WSDL
// definitions element. Returns empty string if not found.
func extractTargetNamespace(body []byte) string {
	// Look for targetNamespace="..." in the body
	marker := []byte(`targetNamespace="`)
	idx := bytes.Index(body, marker)
	if idx < 0 {
		return ""
	}

	start := idx + len(marker)
	if start >= len(body) {
		return ""
	}

	end := bytes.IndexByte(body[start:], '"')
	if end < 0 || end > 2048 {
		return ""
	}

	return string(body[start : start+end])
}
