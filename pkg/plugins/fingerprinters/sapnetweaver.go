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
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"unicode"
)

// SAPNetWeaverFingerprinter detects SAP NetWeaver application servers
type SAPNetWeaverFingerprinter struct{}

func init() {
	Register(&SAPNetWeaverFingerprinter{})
}

// maxXMLFieldLen is the maximum number of bytes accepted from an extracted XML field.
// Values exceeding this length are rejected to prevent multi-megabyte string injection.
const maxXMLFieldLen = 256

// validVersionPattern matches only dotted-decimal version strings safe for CPE insertion.
var validVersionPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)*$`)

// SAP server header version extraction patterns
var (
	// Matches "SAP NetWeaver Application Server 7.45" -> "7.45"
	// Matches "SAP NetWeaver Application Server / ABAP 753" -> "753"
	sapServerVersionPattern = regexp.MustCompile(`(?i)SAP\s+(?:NetWeaver\s+)?(?:Application\s+Server\s*(?:/\s*\w+\s*)?|J2EE\s+Engine/)([0-9]+(?:\.[0-9]+)*)`)

	// SAP release normalizer: "750" -> "7.50"
	sapReleaseThreeDigit = regexp.MustCompile(`^([0-9])([0-9]{2})$`)
)

func (f *SAPNetWeaverFingerprinter) Name() string {
	return "sap-netweaver"
}

func (f *SAPNetWeaverFingerprinter) ProbeEndpoint() string {
	return "/sap/public/info"
}

func (f *SAPNetWeaverFingerprinter) Match(resp *http.Response) bool {
	// Accept 2xx-4xx responses; reject 1xx and 5xx
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return false
	}

	return hasSAPIndicator(resp)
}

func (f *SAPNetWeaverFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Accept 2xx-4xx responses; reject 1xx and 5xx
	if resp.StatusCode < 200 || resp.StatusCode >= 500 {
		return nil, nil
	}

	headerMatch := hasSAPIndicator(resp)

	// Attempt XML body parsing from /sap/public/info
	rfcsysid := extractXMLField(string(body), "RFCSYSID")
	rfcsaprl := extractXMLField(string(body), "RFCSAPRL")
	rfckernrl := extractXMLField(string(body), "RFCKERNRL")
	rfcopsys := extractXMLField(string(body), "RFCOPSYS")
	rfcdbsys := extractXMLField(string(body), "RFCDBSYS")

	bodyMatch := rfcsysid != ""

	if !headerMatch && !bodyMatch {
		return nil, nil
	}

	// Version extraction: Server header first, then RFCSAPRL, then RFCKERNRL
	version := ""
	serverHeader := resp.Header.Get("Server")
	if v := extractSAPVersionFromServer(serverHeader); v != "" {
		version = v
	} else if rfcsaprl != "" {
		version = normalizeSAPRelease(rfcsaprl)
	} else if rfckernrl != "" {
		version = normalizeSAPRelease(rfckernrl)
	}

	// Stack type detection
	stackType := ""
	serverLower := strings.ToLower(serverHeader)
	if strings.Contains(serverLower, "j2ee engine") || strings.Contains(serverLower, "java") {
		stackType = "java"
	} else if strings.Contains(serverLower, "abap") || resp.Header.Get("disp+work") != "" {
		stackType = "abap"
	}

	metadata := map[string]any{
		"vendor":      "SAP",
		"product":     "NetWeaver",
		"stack_type":   stackType,
	}

	if rfcsysid != "" {
		metadata["sid"] = sanitizeXMLValue(rfcsysid)
	}
	if rfckernrl != "" {
		metadata["kernel_version"] = normalizeSAPRelease(rfckernrl)
	}
	if rfcopsys != "" {
		metadata["os"] = sanitizeXMLValue(rfcopsys)
	}
	if rfcdbsys != "" {
		metadata["database"] = sanitizeXMLValue(rfcdbsys)
	}

	return &FingerprintResult{
		Technology: "sap-netweaver",
		Version:    version,
		CPEs:       []string{buildSAPNetWeaverCPE(version)},
		Metadata:   metadata,
	}, nil
}

// hasSAPIndicator checks Server header and SAP-specific headers for SAP indicators.
func hasSAPIndicator(resp *http.Response) bool {
	serverLower := strings.ToLower(resp.Header.Get("Server"))
	if strings.Contains(serverLower, "sap netweaver") ||
		strings.Contains(serverLower, "sap j2ee engine") ||
		strings.Contains(serverLower, "sap web dispatcher") {
		return true
	}

	if resp.Header.Get("sap-server") != "" {
		return true
	}
	if resp.Header.Get("sap-system") != "" {
		return true
	}
	if resp.Header.Get("disp+work") != "" {
		return true
	}

	return false
}

// extractXMLField extracts the text content of a simple XML element by name.
// It handles elements of the form <FIELDNAME>value</FIELDNAME>.
func extractXMLField(body, fieldName string) string {
	open := "<" + fieldName + ">"
	close := "</" + fieldName + ">"

	start := strings.Index(body, open)
	if start == -1 {
		return ""
	}
	start += len(open)

	end := strings.Index(body[start:], close)
	if end == -1 {
		return ""
	}

	value := strings.TrimSpace(body[start : start+end])
	if len(value) > maxXMLFieldLen {
		return ""
	}
	return value
}

// extractSAPVersionFromServer parses the Server header for a SAP version string.
// Examples:
//   - "SAP NetWeaver Application Server 7.45" -> "7.45"
//   - "SAP NetWeaver Application Server / ABAP 753" -> "7.53"
//   - "SAP J2EE Engine/7.00" -> "7.00"
func extractSAPVersionFromServer(serverHeader string) string {
	matches := sapServerVersionPattern.FindStringSubmatch(serverHeader)
	if len(matches) < 2 {
		return ""
	}
	return normalizeSAPRelease(matches[1])
}

// normalizeSAPRelease converts a 3-digit SAP release to dotted notation.
// Examples: "750" -> "7.50", "753" -> "7.53", "7.45" -> "7.45" (unchanged)
func normalizeSAPRelease(release string) string {
	if matches := sapReleaseThreeDigit.FindStringSubmatch(release); len(matches) == 3 {
		return fmt.Sprintf("%s.%s", matches[1], matches[2])
	}
	return release
}

// isValidVersion reports whether s is a safe dotted-decimal version string
// suitable for insertion into a CPE identifier.
func isValidVersion(s string) bool {
	return validVersionPattern.MatchString(s)
}

// buildSAPNetWeaverCPE constructs a CPE 2.3 identifier for SAP NetWeaver.
// If version is empty or does not match the expected dotted-decimal format,
// the wildcard "*" is used to prevent CPE injection.
func buildSAPNetWeaverCPE(version string) string {
	if version == "" || !isValidVersion(version) {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:sap:netweaver:%s:*:*:*:*:*:*:*", version)
}

// sanitizeXMLValue strips non-printable characters (keeping ASCII 32-126) from s
// and truncates the result to maxXMLFieldLen bytes. This prevents metadata map
// pollution from crafted XML responses.
func sanitizeXMLValue(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r >= 32 && r <= 126 && unicode.IsPrint(r) {
			b.WriteRune(r)
		}
	}
	result := b.String()
	if len(result) > maxXMLFieldLen {
		return result[:maxXMLFieldLen]
	}
	return result
}
