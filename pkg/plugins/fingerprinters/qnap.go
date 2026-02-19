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
Package fingerprinters provides HTTP fingerprinting for QNAP NAS devices.

# Detection Strategy

QNAP NAS devices run QTS (QNAP Turbo Station) operating system, which is commonly
found on customer attack surfaces. Detection of exposed NAS devices is critical because:
  - Often contain sensitive business data and backups
  - Frequently exposed to the internet for remote access
  - Target for ransomware and data exfiltration
  - May have admin interfaces exposed without authentication
  - Historical vulnerabilities in QTS firmware

Detection uses active probing of the authLogin.cgi endpoint which returns identifying
XML without requiring authentication. This endpoint is unique to QNAP devices.

# Response Format

The /cgi-bin/authLogin.cgi endpoint returns XML with device information:

	<?xml version="1.0" encoding="UTF-8" ?>
	<QDocRoot version="1.0">
	<firmware>
	  <version><![CDATA[4.4.1]]></version>
	  <number><![CDATA[1216]]></number>
	  <build><![CDATA[20200214]]></build>
	</firmware>
	<hostname><![CDATA[NAS-NAME]]></hostname>
	<model>
	  <displayModelName><![CDATA[TS-873U-RP]]></displayModelName>
	</model>
	</QDocRoot>

Response breakdown:
  - <QDocRoot> - Root element unique to QNAP devices (primary detection)
  - <firmware><version> - QTS version string (e.g., "4.4.1", "5.1.0")
  - <firmware><number> - Build number (e.g., "1216")
  - <firmware><build> - Build date in YYYYMMDD format
  - <model><displayModelName> - Hardware model (e.g., "TS-873U-RP")
  - <hostname> - Device hostname

# Port Configuration

QNAP NAS devices typically expose web interfaces on:
  - 8080: HTTP (default)
  - 443:  HTTPS (default)
  - 8081: Alternative HTTP port

# Security Relevance

QNAP devices are frequently targeted in attacks:
  - CVE-2024-27130: SQL injection in Music Station
  - CVE-2023-23368: Authentication bypass in QTS
  - CVE-2021-28799: Hardcoded credentials
  - Regular targets for Qlocker, eCh0raix ransomware

Detection helps identify exposed devices for vulnerability assessment and remediation.

# Example Usage

	fp := &QNAPFingerprinter{}
	// Probe /cgi-bin/authLogin.cgi endpoint
	if fp.Match(resp) {
		result, err := fp.Fingerprint(resp, body)
		if err == nil && result != nil {
			fmt.Printf("Detected: %s version %s\n", result.Technology, result.Version)
		}
	}
*/
package fingerprinters

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// QNAPFingerprinter detects QNAP NAS devices via authLogin.cgi endpoint
type QNAPFingerprinter struct{}

func init() {
	Register(&QNAPFingerprinter{})
}

func (f *QNAPFingerprinter) Name() string {
	return "qnap-qts"
}

func (f *QNAPFingerprinter) ProbeEndpoint() string {
	return "/cgi-bin/authLogin.cgi"
}

func (f *QNAPFingerprinter) Match(resp *http.Response) bool {
	// Check Content-Type contains xml
	contentType := resp.Header.Get("Content-Type")
	return strings.Contains(contentType, "text/xml") || strings.Contains(contentType, "application/xml")
}

func (f *QNAPFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	// Primary detection: body contains <QDocRoot (unique to QNAP)
	if !bytes.Contains(body, []byte("<QDocRoot")) {
		return nil, nil
	}

	// Secondary confirmation: body contains <firmware>
	if !bytes.Contains(body, []byte("<firmware>")) {
		return nil, nil
	}

	metadata := make(map[string]any)

	// Extract version from <version><![CDATA[...]]></version>
	version := extractCDATAContent(body, "version")

	// Extract additional metadata
	if buildNumber := extractCDATAContent(body, "number"); buildNumber != "" {
		metadata["buildNumber"] = buildNumber
	}
	if buildDate := extractCDATAContent(body, "build"); buildDate != "" {
		metadata["buildDate"] = buildDate
	}
	if model := extractCDATAContent(body, "displayModelName"); model != "" {
		metadata["model"] = model
	}
	if hostname := extractCDATAContent(body, "hostname"); hostname != "" {
		metadata["hostname"] = hostname
	}

	return &FingerprintResult{
		Technology: "qnap-qts",
		Version:    version,
		CPEs:       []string{buildQNAPCPE(version)},
		Metadata:   metadata,
	}, nil
}

// extractCDATAContent extracts content from <tag><![CDATA[content]]></tag> pattern
func extractCDATAContent(body []byte, tag string) string {
	// Pattern: <tag><![CDATA[content]]></tag>
	pattern := fmt.Sprintf(`<%s><!\[CDATA\[([^\]]*)\]\]></%s>`, tag, tag)
	re := regexp.MustCompile(pattern)
	matches := re.FindSubmatch(body)
	if len(matches) > 1 {
		return string(matches[1])
	}
	return ""
}

func buildQNAPCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:o:qnap:qts:%s:*:*:*:*:*:*:*", version)
}
