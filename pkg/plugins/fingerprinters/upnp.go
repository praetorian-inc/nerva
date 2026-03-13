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
Package fingerprinters provides HTTP fingerprinting for UPnP services.

# Detection Strategy

UPnP (Universal Plug and Play) devices expose HTTP endpoints that serve XML
device descriptions containing UPnP-specific schemas. Detection targets these
HTTP responses.

Security relevance:
  - UPnP devices may expose internal network topology
  - SOAP control endpoints can allow device manipulation
  - Often found on IoT devices with weak security
  - Can be abused for SSRF or port mapping attacks

Detection uses passive approach on root HTTP response:
  - Check for SERVER header containing "UPnP" (case-insensitive substring)
  - Check response body for UPnP XML namespace (urn:schemas-upnp-org)
  - Extract server string and UPnP version information

# Response Headers

UPnP devices typically include identifying headers:

	SERVER: Linux/3.0 UPnP/1.0 IpBridge/1.16.0
	Content-Type: text/xml; charset="utf-8"

# Response Body

UPnP device descriptions contain XML with UPnP namespace:

	<root xmlns="urn:schemas-upnp-org:device-1-0">
	  <specVersion><major>1</major><minor>0</minor></specVersion>
	  <device>
	    <deviceType>urn:schemas-upnp-org:device:Basic:1</deviceType>
	    <friendlyName>Philips hue</friendlyName>
	  </device>
	</root>

# Port Configuration

UPnP HTTP endpoints typically run on:
  - 2869: Windows UPnP Device Host
  - 5000: Synology DSM, various UPnP devices
  - 8080: Common alternative HTTP port
  - 49152-65535: Dynamic ports advertised via SSDP

# Example Usage

	fp := &UPnPFingerprinter{}
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

// UPnPFingerprinter detects UPnP services via HTTP response headers and body content
type UPnPFingerprinter struct{}

func init() {
	Register(&UPnPFingerprinter{})
}

// upnpNamespacePattern matches UPnP XML namespace in response body
var upnpNamespacePattern = regexp.MustCompile(`(?i)urn:schemas-upnp-org`)

// upnpVersionPattern extracts UPnP version from SERVER header (e.g., "UPnP/1.0")
var upnpVersionPattern = regexp.MustCompile(`(?i)UPnP/(\d+\.\d+)`)

func (f *UPnPFingerprinter) Name() string {
	return "upnp"
}

func (f *UPnPFingerprinter) Match(resp *http.Response) bool {
	// Check SERVER header for UPnP indicator
	server := resp.Header.Get("Server")
	return strings.Contains(strings.ToLower(server), "upnp")
}

func (f *UPnPFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	metadata := make(map[string]any)

	server := resp.Header.Get("Server")
	hasServerMatch := strings.Contains(strings.ToLower(server), "upnp")
	hasBodyMatch := upnpNamespacePattern.Match(body)

	if !hasServerMatch && !hasBodyMatch {
		return nil, nil
	}

	// Extract UPnP version from SERVER header
	var version string
	if matches := upnpVersionPattern.FindStringSubmatch(server); len(matches) > 1 {
		version = matches[1]
	}

	// Store full server string in metadata
	if server != "" {
		metadata["server"] = server
	}

	// Check for UPnP XML namespace in body for additional confirmation
	if hasBodyMatch {
		metadata["upnp_namespace"] = true
	}

	// Extract device type from body if present
	if idx := bytes.Index(bytes.ToLower(body), []byte("<devicetype>")); idx >= 0 {
		endIdx := bytes.Index(bytes.ToLower(body[idx:]), []byte("</devicetype>"))
		if endIdx > 0 {
			deviceType := string(body[idx+len("<deviceType>") : idx+endIdx])
			metadata["device_type"] = strings.TrimSpace(deviceType)
		}
	}

	// Extract friendly name from body if present
	if idx := bytes.Index(bytes.ToLower(body), []byte("<friendlyname>")); idx >= 0 {
		endIdx := bytes.Index(bytes.ToLower(body[idx:]), []byte("</friendlyname>"))
		if endIdx > 0 {
			friendlyName := string(body[idx+len("<friendlyName>") : idx+endIdx])
			metadata["friendly_name"] = strings.TrimSpace(friendlyName)
		}
	}

	return &FingerprintResult{
		Technology: "upnp",
		Version:    version,
		CPEs:       []string{buildUPnPCPE(version)},
		Metadata:   metadata,
	}, nil
}

func buildUPnPCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:upnp:upnp:%s:*:*:*:*:*:*:*", version)
}
