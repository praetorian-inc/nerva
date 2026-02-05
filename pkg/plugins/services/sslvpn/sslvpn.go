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
SSL VPN Fingerprinting (Cisco AnyConnect / Palo Alto GlobalProtect)

This plugin implements fingerprinting for enterprise SSL VPN solutions:
- Cisco AnyConnect (ASA VPN)
- Palo Alto GlobalProtect

Detection Strategy:

  PHASE 1 - DETECTION (determines if the service is an SSL VPN):

    CISCO ANYCONNECT:
      Primary paths:
        - /+CSCOE+/logon.html (main login page)
        - /+CSCOT+/translation-table (tunnel configuration)
      Additional paths:
        - /+CSCOU+/portal.html (user portal)
        - /+webvpn+/index.html (WebVPN resources)
        - /+CSCOE+/win.js (JavaScript with version info)
        - /CACHE/sdesktop/install.html (Secure Desktop installer)
      Detection markers:
        - Body: webvpn, CSCOE, CSCOT, CSCOU, anyconnect, cisco vpn, asa, firepower
        - Headers: X-ASA-Version, X-Transcend-Version, Server: Cisco
        - Cookies: webvpn, webvpnlogin, webvpncontext, webvpnLang

    PALO ALTO GLOBALPROTECT:
      Primary paths:
        - /global-protect/prelogin.esp (returns XML with version - most reliable)
        - /global-protect/login.esp (login page)
        - /ssl-vpn/login.esp (alternative login)
      Additional paths:
        - /global-protect/getconfig.esp (configuration endpoint)
        - /global-protect/portal/portal.esp (portal page)
        - /global-protect/getsoftwarepage.esp (software download)
        - /ssl-vpn/hipreport.esp (HIP report endpoint)
        - /ssl-vpn/hipreportcheck.esp (HIP check)
      Detection markers:
        - Body: global-protect, PAN_FORM, palo alto, pan-os, saml-auth-status
        - Headers: X-Private-Pan-Sslvpn, Server containing PAN-OS
        - XML: <prelogin-response>, <saml-auth-method>

  PHASE 2 - ENRICHMENT (attempts to retrieve version information):
    After VPN type is detected, extract version from:
      - HTTP response headers (X-ASA-Version, X-Transcend-Version, Server)
      - HTML/XML response body (version strings, XML tags)
      - prelogin.esp XML response: <sw-version> tag

Port Information:
  - Port 443: Standard HTTPS port for SSL VPN

Security Note:
  These VPN appliances have had critical vulnerabilities:
  - CVE-2020-3452: Cisco ASA/FTD arbitrary file read
  - CVE-2024-3400: Palo Alto PAN-OS command injection
  - CVE-2021-1445: Cisco ASA web services buffer overflow
  - CVE-2020-2021: Palo Alto SAML authentication bypass
  Version detection enables vulnerability correlation.

CPE Format:
  - Cisco: cpe:2.3:a:cisco:adaptive_security_appliance_software:{version}:*:*:*:*:*:*:*
  - Palo Alto: cpe:2.3:o:paloaltonetworks:pan-os:{version}:*:*:*:*:*:*:*
*/

package sslvpn

import (
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const SSLVPN = "sslvpn"

// VPN vendor constants
const (
	VendorCiscoAnyConnect       = "Cisco"
	VendorPaloAltoGlobalProtect = "Palo Alto"
	ProductAnyConnect           = "AnyConnect"
	ProductGlobalProtect        = "GlobalProtect"
)

// User agent for HTTP requests
const userAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36"

type SSLVPNPlugin struct{}

func init() {
	plugins.RegisterPlugin(&SSLVPNPlugin{})
}

// AnyConnect detection paths (ordered by reliability/speed)
var anyConnectPaths = []string{
	"/+CSCOE+/logon.html",
	"/+CSCOT+/translation-table?type=mst&textdomain=AnyConnect&maxsandboxversion=0&sasession=0",
	"/+CSCOU+/portal.html",
	"/+webvpn+/index.html",
	"/+CSCOE+/win.js",
	"/CACHE/sdesktop/install.html",
	"/+CSCOE+/session_password.html",
}

// GlobalProtect detection paths (ordered by reliability/speed)
// prelogin.esp is first as it returns XML with version information
var globalProtectPaths = []string{
	"/global-protect/prelogin.esp",
	"/global-protect/login.esp",
	"/ssl-vpn/login.esp",
	"/global-protect/portal/portal.esp",
	"/global-protect/getconfig.esp",
	"/global-protect/getsoftwarepage.esp",
	"/ssl-vpn/hipreport.esp",
	"/ssl-vpn/hipreportcheck.esp",
	"/global-protect/portal/css/login.css",
}

// AnyConnect detection patterns in response body
var anyConnectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)webvpn`),
	regexp.MustCompile(`(?i)CSCOE`),
	regexp.MustCompile(`(?i)CSCOT`),
	regexp.MustCompile(`(?i)CSCOU`),
	regexp.MustCompile(`(?i)anyconnect`),
	regexp.MustCompile(`(?i)cisco.*vpn`),
	regexp.MustCompile(`(?i)\basa\b`),
	regexp.MustCompile(`(?i)firepower`),
	regexp.MustCompile(`(?i)adaptivesecurityappliance`),
	regexp.MustCompile(`(?i)sdesktop`),
}

// AnyConnect cookie names that indicate Cisco ASA
var anyConnectCookies = []string{
	"webvpn",
	"webvpnlogin",
	"webvpncontext",
	"webvpnLang",
	"webvpnSharePoint",
}

// GlobalProtect detection patterns in response body
var globalProtectPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)global-?protect`),
	regexp.MustCompile(`(?i)PAN_FORM`),
	regexp.MustCompile(`(?i)palo\s*alto`),
	regexp.MustCompile(`(?i)pan-os`),
	regexp.MustCompile(`(?i)/global-protect/`),
	regexp.MustCompile(`(?i)<prelogin-response>`),
	regexp.MustCompile(`(?i)<saml-auth-method>`),
	regexp.MustCompile(`(?i)saml-auth-status`),
	regexp.MustCompile(`(?i)<portal>`),
	regexp.MustCompile(`(?i)portal-prelogin`),
}

// Version extraction patterns
var (
	// Cisco ASA version patterns
	asaVersionBodyPattern = regexp.MustCompile(`(?i)(?:version|asa)[:\s]+([0-9]+(?:\.[0-9]+)+(?:\([0-9]+\))?)`)

	// Palo Alto PAN-OS version patterns
	panOSVersionPattern = regexp.MustCompile(`(?i)(?:pan-os|panos)[:\s]+([0-9]+(?:\.[0-9]+)+)`)
	panOSServerPattern  = regexp.MustCompile(`(?i)PAN-OS\s+([0-9]+(?:\.[0-9]+)+)`)
	// prelogin.esp XML: <sw-version>10.2.3</sw-version>
	panOSPreloginVersionPattern = regexp.MustCompile(`(?i)<sw-version>([0-9]+(?:\.[0-9]+)+(?:-h[0-9]+)?)</sw-version>`)
	// Alternative XML patterns
	panOSAppVersionPattern = regexp.MustCompile(`(?i)<app-version>([0-9]+(?:\.[0-9]+)+)</app-version>`)
)

// detectAnyConnect checks if the response indicates a Cisco AnyConnect VPN
func detectAnyConnect(body []byte, headers http.Header) bool {
	// Check response body for AnyConnect markers
	bodyStr := string(body)
	for _, pattern := range anyConnectPatterns {
		if pattern.MatchString(bodyStr) {
			return true
		}
	}

	// Check Server header
	serverHeader := strings.ToLower(headers.Get("Server"))
	if strings.Contains(serverHeader, "cisco") {
		return true
	}

	// Check for X-ASA-Version header (definitive indicator)
	if headers.Get("X-ASA-Version") != "" {
		return true
	}

	// Check for X-Transcend-Version header (another ASA indicator)
	if headers.Get("X-Transcend-Version") != "" {
		return true
	}

	// Check cookies for AnyConnect indicators
	if detectAnyConnectCookies(headers) {
		return true
	}

	return false
}

// detectAnyConnectCookies checks Set-Cookie headers for AnyConnect indicators
func detectAnyConnectCookies(headers http.Header) bool {
	cookies := headers.Values("Set-Cookie")
	for _, cookie := range cookies {
		cookieLower := strings.ToLower(cookie)
		for _, vpnCookie := range anyConnectCookies {
			if strings.Contains(cookieLower, strings.ToLower(vpnCookie)) {
				return true
			}
		}
	}
	return false
}

// detectGlobalProtect checks if the response indicates a Palo Alto GlobalProtect VPN
func detectGlobalProtect(body []byte, headers http.Header) bool {
	// Check response body for GlobalProtect markers
	bodyStr := string(body)
	for _, pattern := range globalProtectPatterns {
		if pattern.MatchString(bodyStr) {
			return true
		}
	}

	// Check Server header
	serverHeader := strings.ToLower(headers.Get("Server"))
	if strings.Contains(serverHeader, "palo alto") ||
		strings.Contains(serverHeader, "pan-os") {
		return true
	}

	// Check for X-Private-Pan-Sslvpn header (PAN-specific)
	if headers.Get("X-Private-Pan-Sslvpn") != "" {
		return true
	}

	return false
}

// extractAnyConnectVersion attempts to extract version from Cisco AnyConnect response
func extractAnyConnectVersion(body []byte, headers http.Header) string {
	// First check X-ASA-Version header (most reliable)
	if version := headers.Get("X-ASA-Version"); version != "" {
		return version
	}

	// Check X-Transcend-Version header
	if version := headers.Get("X-Transcend-Version"); version != "" {
		return version
	}

	// Check Server header for version
	serverHeader := headers.Get("Server")
	if matches := asaVersionBodyPattern.FindStringSubmatch(serverHeader); len(matches) > 1 {
		return matches[1]
	}

	// Check body for version strings
	if matches := asaVersionBodyPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	return ""
}

// extractGlobalProtectVersion attempts to extract version from GlobalProtect response
func extractGlobalProtectVersion(body []byte, headers http.Header) string {
	// Check Server header first
	serverHeader := headers.Get("Server")
	if matches := panOSServerPattern.FindStringSubmatch(serverHeader); len(matches) > 1 {
		return matches[1]
	}

	// Check for prelogin.esp XML response (most reliable for version)
	// Format: <sw-version>10.2.3</sw-version> or <sw-version>10.2.3-h1</sw-version>
	if matches := panOSPreloginVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	// Check for app-version in XML
	if matches := panOSAppVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	// Check body for general version patterns
	if matches := panOSVersionPattern.FindSubmatch(body); len(matches) > 1 {
		return string(matches[1])
	}

	return ""
}

// buildAnyConnectCPE constructs a CPE string for Cisco ASA/AnyConnect
func buildAnyConnectCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:a:cisco:adaptive_security_appliance_software:%s:*:*:*:*:*:*:*", version)
}

// buildGlobalProtectCPE constructs a CPE string for Palo Alto PAN-OS
func buildGlobalProtectCPE(version string) string {
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf("cpe:2.3:o:paloaltonetworks:pan-os:%s:*:*:*:*:*:*:*", version)
}

// tlsConfig for SSL VPN connections - needs legacy renegotiation support
var tlsConfig = &tls.Config{
	InsecureSkipVerify: true, //nolint:gosec
	MinVersion:         tls.VersionTLS10,
	Renegotiation:      tls.RenegotiateFreelyAsClient,
}

// makeHTTPRequest performs an HTTPS request to the specified path
// It dials a fresh TLS connection for each request to avoid connection state issues
func makeHTTPRequest(addr string, path string, host string, timeout time.Duration) (*http.Response, []byte, error) {
	url := fmt.Sprintf("https://%s%s", host, path)

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, nil, err
	}

	if host != "" {
		req.Host = host
	}
	req.Header.Set("User-Agent", userAgent)

	// Create a custom transport that dials fresh TLS connections
	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
		// Disable connection pooling to ensure fresh connections
		DisableKeepAlives: true,
	}

	client := http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp, nil, err
	}

	return resp, body, nil
}

func (p *SSLVPNPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Close the passed connection - we'll dial our own for HTTP requests
	conn.Close()

	// Determine the target address for HTTP requests
	addr := target.Address.String()
	host := addr
	if target.Host != "" {
		host = fmt.Sprintf("%s:%d", target.Host, target.Address.Port())
	}

	// Try AnyConnect detection paths first
	for _, path := range anyConnectPaths {
		resp, body, err := makeHTTPRequest(addr, path, host, timeout)
		if err != nil {
			continue
		}

		// Only accept 2xx responses - error/redirect pages may reflect the request path
		// which can cause false positives (e.g., Google's 404, Apple's 301 contain "CSCOE")
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}

		if detectAnyConnect(body, resp.Header) {
			version := extractAnyConnectVersion(body, resp.Header)
			cpe := buildAnyConnectCPE(version)

			payload := plugins.ServiceSSLVPN{
				Vendor:  VendorCiscoAnyConnect,
				Product: ProductAnyConnect,
				CPEs:    []string{cpe},
			}

			return plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS), nil
		}
	}

	// Try GlobalProtect detection paths
	for _, path := range globalProtectPaths {
		resp, body, err := makeHTTPRequest(addr, path, host, timeout)
		if err != nil {
			continue
		}

		// Only accept 2xx responses - error/redirect pages may reflect the request path
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			continue
		}

		if detectGlobalProtect(body, resp.Header) {
			version := extractGlobalProtectVersion(body, resp.Header)
			cpe := buildGlobalProtectCPE(version)

			payload := plugins.ServiceSSLVPN{
				Vendor:  VendorPaloAltoGlobalProtect,
				Product: ProductGlobalProtect,
				CPEs:    []string{cpe},
			}

			return plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS), nil
		}
	}

	return nil, nil
}

func (p *SSLVPNPlugin) PortPriority(port uint16) bool {
	return port == 443
}

func (p *SSLVPNPlugin) Name() string {
	return SSLVPN
}

func (p *SSLVPNPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

// Priority returns a lower value than generic HTTPS (1) to detect VPN first
// Lower priority values run earlier in the plugin chain
func (p *SSLVPNPlugin) Priority() int {
	return 0
}
