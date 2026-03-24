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
Package fingerprinters provides HTTP fingerprinting for Ubiquiti UniFi and EdgeOS.

# Detection Strategy

Two fingerprinters are registered:

  - UniFiStatusFingerprinter (Active): probes /status for the UniFi Controller
    JSON API, extracts the server version from meta.server_version.

  - UniFiTitleFingerprinter (Passive): checks the HTML title of the root page
    for "UniFi Network", "UniFi OS", or "EdgeOS". Refines product type using
    X-CSRF-Token (unifi-os) and Server: lighttpd (edgeos) headers.

Results are appended as technologies to the HTTPS service payload, matching
the pattern used by Kubernetes, Jenkins, and Elasticsearch fingerprinters.

# Response Structures

/status (UniFi Controller):

	{"data":[],"meta":{"rc":"ok","server_version":"7.5.187","up":true,"uuid":"..."}}

/ (HTML root for UniFi OS / EdgeOS):

	<html><head><title>UniFi OS</title>...</html>

# CPE Format

  - UniFi: cpe:2.3:a:ui:unifi_network_application:{version}:*:*:*:*:*:*:*
  - EdgeOS: cpe:2.3:o:ui:edgeos:*:*:*:*:*:*:*:* (version requires auth)
*/
package fingerprinters

import (
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"strings"
)

// unifiStatusResponse represents the JSON structure returned by GET /status
type unifiStatusResponse struct {
	Meta unifiStatusMeta `json:"meta"`
}

type unifiStatusMeta struct {
	RC            string `json:"rc"`
	ServerVersion string `json:"server_version"`
}

// unifiSystemResponse represents the JSON structure returned by GET /api/system (UniFi OS)
type unifiSystemResponse struct {
	Hardware struct {
		Shortname string `json:"shortname"`
	} `json:"hardware"`
	Name           string `json:"name"`
	DeviceState    string `json:"deviceState"`
	CloudConnected bool   `json:"cloudConnected"`
}

var (
	// titlePattern extracts the content of the HTML <title> tag
	unifiTitlePattern = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

	// unifiVersionPattern validates version strings before CPE interpolation
	unifiVersionPattern = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
)

// sanitizeUniFiVersion validates a version string before CPE interpolation.
// Returns the version unchanged if it matches the allowed pattern, or empty
// string if it contains characters that could corrupt the CPE format.
func sanitizeUniFiVersion(version string) string {
	if unifiVersionPattern.MatchString(version) {
		return version
	}
	return ""
}

// buildUniFiCPE generates a CPE string for the detected Ubiquiti product.
func buildUniFiCPE(version, productType string) string {
	v := version
	if v == "" {
		v = "*"
	}
	if productType == "edgeos" {
		// EdgeOS version requires authentication; always use wildcard
		return "cpe:2.3:o:ui:edgeos:*:*:*:*:*:*:*:*"
	}
	// UniFi Controller and UniFi OS use application CPE
	return fmt.Sprintf("cpe:2.3:a:ui:unifi_network_application:%s:*:*:*:*:*:*:*", v)
}

// extractHTMLTitle extracts the content of the <title> tag from HTML body.
func extractHTMLTitle(body []byte) string {
	matches := unifiTitlePattern.FindSubmatch(body)
	if len(matches) < 2 {
		return ""
	}
	return strings.TrimSpace(string(matches[1]))
}

// UniFiStatusFingerprinter detects UniFi Network Controller via the /status endpoint
type UniFiStatusFingerprinter struct{}

// UniFiTitleFingerprinter detects UniFi OS and EdgeOS via HTML title tag on root page
type UniFiTitleFingerprinter struct{}

// UniFiSystemFingerprinter probes /api/system on UniFi OS devices for hardware model
type UniFiSystemFingerprinter struct{}

func init() {
	Register(&UniFiStatusFingerprinter{})
	Register(&UniFiTitleFingerprinter{})
	Register(&UniFiSystemFingerprinter{})
}

// --- UniFiStatusFingerprinter ---

func (f *UniFiStatusFingerprinter) Name() string { return "unifi-status" }

func (f *UniFiStatusFingerprinter) ProbeEndpoint() string { return "/status" }

func (f *UniFiStatusFingerprinter) Match(resp *http.Response) bool {
	// UniFi /status always returns JSON
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *UniFiStatusFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var statusResp unifiStatusResponse
	if err := json.Unmarshal(body, &statusResp); err != nil {
		return nil, nil // Not UniFi JSON format
	}

	// Validate: meta.rc must be "ok" AND meta.server_version must be present
	if statusResp.Meta.RC != "ok" {
		return nil, nil
	}
	if statusResp.Meta.ServerVersion == "" {
		return nil, nil
	}

	version := sanitizeUniFiVersion(statusResp.Meta.ServerVersion)
	cpe := buildUniFiCPE(version, "unifi-controller")

	return &FingerprintResult{
		Technology: "unifi-controller",
		Version:    version,
		CPEs:       []string{cpe},
	}, nil
}

// --- UniFiTitleFingerprinter ---

func (f *UniFiTitleFingerprinter) Name() string { return "unifi-title" }

func (f *UniFiTitleFingerprinter) Match(resp *http.Response) bool {
	// Match HTML responses (or empty Content-Type which may be HTML)
	ct := resp.Header.Get("Content-Type")
	return strings.Contains(ct, "text/html") || ct == ""
}

func (f *UniFiTitleFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	title := extractHTMLTitle(body)
	if title == "" {
		return nil, nil
	}

	var productType string
	switch {
	case strings.Contains(title, "UniFi Network"):
		productType = "unifi-controller"
	case strings.Contains(title, "UniFi OS"):
		productType = "unifi-os"
	case strings.Contains(title, "EdgeOS"):
		productType = "edgeos"
	default:
		return nil, nil // Not a Ubiquiti product
	}

	// Phase 3: Header enrichment (best-effort)
	if resp.Header.Get("X-CSRF-Token") != "" {
		productType = "unifi-os"
	}
	if strings.Contains(strings.ToLower(resp.Header.Get("Server")), "lighttpd") {
		productType = "edgeos"
	}

	cpe := buildUniFiCPE("", productType)

	return &FingerprintResult{
		Technology: productType,
		CPEs:       []string{cpe},
	}, nil
}

// --- UniFiSystemFingerprinter ---

func (f *UniFiSystemFingerprinter) Name() string { return "unifi-system" }

func (f *UniFiSystemFingerprinter) ProbeEndpoint() string { return "/api/system" }

func (f *UniFiSystemFingerprinter) Match(resp *http.Response) bool {
	return strings.Contains(resp.Header.Get("Content-Type"), "application/json")
}

func (f *UniFiSystemFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	var sysResp unifiSystemResponse
	if err := json.Unmarshal(body, &sysResp); err != nil {
		return nil, nil
	}

	// Validate this is a UniFi OS system response
	if sysResp.Hardware.Shortname == "" {
		return nil, nil
	}

	return &FingerprintResult{
		Technology: "unifi-os",
		CPEs:       []string{buildUniFiCPE("", "unifi-os")},
		Metadata: map[string]any{
			"hardwareModel":  sysResp.Hardware.Shortname,
			"deviceName":     sysResp.Name,
			"deviceState":    sysResp.DeviceState,
			"cloudConnected": sysResp.CloudConnected,
		},
	}, nil
}
