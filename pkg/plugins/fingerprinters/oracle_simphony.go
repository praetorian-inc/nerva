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
Package fingerprinters provides HTTP fingerprinting for Oracle Hospitality Simphony
(formerly MICROS EGateway).

# What We Detect

Oracle Hospitality Simphony is an enterprise point-of-sale (POS) platform used
in hotels, restaurants, and hospitality venues. It was formerly sold under the
MICROS brand before Oracle acquired MICROS Systems in 2014. The platform exposes
a SOAP/ASMX web service called the EGateway at a well-known path:

	/EGateway/EGateway.asmx

This service is historically exposed at scale and is associated with
CVE-2018-2636, a path-traversal vulnerability allowing unauthenticated file read.
This fingerprinter performs non-intrusive service detection only and does NOT
exploit CVE-2018-2636.

# Detection Strategy

The fingerprinter probes /EGateway/EGateway.asmx. An unauthenticated GET returns
either an HTML service listing (ASP.NET ASMX description page) or WSDL XML. Four
product-unique markers are checked:

 1. micros_namespace  — body contains "micros-hosting.com/egateway" (MICROS hosting
    company domain used as the SOAPAction XML namespace; case-insensitive)
 2. egateway_soap_port — body contains "EGatewaySoap" (WSDL port type name
    unique to MICROS EGateway)
 3. process_dime_operation — body contains "ProcessDimeRequest" (WSDL/HTML
    operation name unique to MICROS EGateway's DIME processing)
 4. server_header — Server response header equals "mCommerceMobileWebServer"
    (case-insensitive; product-specific HTTP server name)

All four markers are reflection-safe: none appear in the probe path
/EGateway/EGateway.asmx itself, so matches cannot be triggered by the URL
echoing back in an error page.

# Version

Version is not cleanly exposed unauthenticated. The fingerprinter is
presence-only and always returns an empty version string.

# CPE

	cpe:2.3:a:oracle:hospitality_simphony:*:*:*:*:*:*:*:*
*/
package fingerprinters

import (
	"fmt"
	"net/http"
	"strings"
)

// OracleSimphonyFingerprinter detects Oracle Hospitality Simphony (MICROS EGateway)
// via the ASMX service description endpoint.
type OracleSimphonyFingerprinter struct{}

func init() {
	Register(&OracleSimphonyFingerprinter{})
}

func (f *OracleSimphonyFingerprinter) Name() string {
	return "oracle_simphony"
}

// ProbeEndpoint returns the MICROS EGateway ASMX service description path.
// An unauthenticated GET returns either an HTML service listing or WSDL XML.
func (f *OracleSimphonyFingerprinter) ProbeEndpoint() string {
	return "/EGateway/EGateway.asmx"
}

// ProbeAccept requests XML or HTML, matching what ASMX endpoints return for
// service descriptions and WSDL documents.
func (f *OracleSimphonyFingerprinter) ProbeAccept() string {
	return "text/xml, text/html"
}

// Match returns true for 2xx–4xx responses with XML or HTML content.
// ASMX endpoints may return text/xml, application/xml, application/soap+xml
// (WSDL / SOAP), or text/html (service description page).
func (f *OracleSimphonyFingerprinter) Match(resp *http.Response) bool {
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	return strings.Contains(ct, "text/xml") ||
		strings.Contains(ct, "text/html") ||
		strings.Contains(ct, "application/xml") ||
		strings.Contains(ct, "application/soap+xml")
}

// Fingerprint detects Oracle Hospitality Simphony from the EGateway ASMX response.
// Any one of the four product-unique markers triggers a positive detection.
func (f *OracleSimphonyFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Defense-in-depth: cap body to 2 MiB to prevent runaway allocation.
	const maxBody = 2 * 1024 * 1024
	if len(body) > maxBody {
		body = body[:maxBody]
	}

	bodyStr := string(body)

	// Signal 1: MICROS hosting company namespace (most specific; case-insensitive).
	hasMicrosNS := strings.Contains(strings.ToLower(bodyStr), "micros-hosting.com/egateway")

	// Signal 2: WSDL port type name (product-unique structural marker).
	hasEGatewaySoap := strings.Contains(bodyStr, "EGatewaySoap")

	// Signal 3: WSDL/HTML operation name unique to MICROS EGateway DIME processing.
	hasProcessDime := strings.Contains(bodyStr, "ProcessDimeRequest")

	// Signal 4: Product-specific HTTP server name (case-insensitive header match).
	hasMicrosServer := strings.Contains(strings.ToLower(resp.Header.Get("Server")), "mcommercemobilewebserver")

	detected := hasMicrosNS || hasEGatewaySoap || hasProcessDime || hasMicrosServer
	if !detected {
		return nil, nil
	}

	metadata := map[string]any{
		"vendor":           "Oracle",
		"product":          "Oracle Hospitality Simphony",
		"aka":              "MICROS EGateway",
		"detection_method": simphonyDetectionMethod(hasMicrosNS, hasEGatewaySoap, hasProcessDime, hasMicrosServer),
		"service_path":     "/EGateway/EGateway.asmx",
	}

	if hasMicrosServer {
		metadata["server_header"] = resp.Header.Get("Server")
	}

	return &FingerprintResult{
		Technology: "oracle_simphony",
		Version:    "",
		CPEs:       []string{buildOracleSimphonyCPE("")},
		Metadata:   metadata,
	}, nil
}

// simphonyDetectionMethod returns the highest-priority signal that triggered detection.
// Priority: micros_namespace > egateway_soap_port > process_dime_operation > server_header.
func simphonyDetectionMethod(hasMicrosNS, hasEGatewaySoap, hasProcessDime, hasMicrosServer bool) string {
	switch {
	case hasMicrosNS:
		return "micros_namespace"
	case hasEGatewaySoap:
		return "egateway_soap_port"
	case hasProcessDime:
		return "process_dime_operation"
	case hasMicrosServer:
		return "server_header"
	default:
		return ""
	}
}

// buildOracleSimphonyCPE constructs a CPE 2.3 URI for Oracle Hospitality Simphony.
// An empty or metachar-containing version is replaced with the wildcard "*".
func buildOracleSimphonyCPE(version string) string {
	if version == "" || strings.ContainsAny(version, ":*?") {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:oracle:hospitality_simphony:%s:*:*:*:*:*:*:*", version)
}
