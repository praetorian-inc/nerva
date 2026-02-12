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

package sip

import (
	"bytes"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	SIP             = "sip"
	SIPS            = "sips"
	DefaultSIPPort  = 5060
	DefaultSIPSPort = 5061
)

type SIPData struct {
	Banner         string
	Server         string
	AllowedMethods []string
	StatusCode     int
}

// Version extraction patterns for SIP servers
var versionPatterns = []struct {
	product string
	pattern *regexp.Regexp
}{
	{"Asterisk", regexp.MustCompile(`Asterisk\s+PBX\s+(\d+\.\d+\.\d+)`)},
	{"Audiocodes", regexp.MustCompile(`Audiocodes[^\d]*Mediant\s*(\d+)`)},
	{"Kamailio", regexp.MustCompile(`Kamailio/(\d+\.\d+\.\d+)`)},
	{"Kamailio", regexp.MustCompile(`(?i)kamailio\s*\((\d+\.\d+\.\d+)`)},
	{"OpenSIPS", regexp.MustCompile(`OpenSIPS/(\d+\.\d+\.\d+)`)},
	{"FreeSWITCH", regexp.MustCompile(`(?i)FreeSWITCH[^\d]*(\d+\.\d+(?:\.\d+)?)`)},
	{"FreePBX", regexp.MustCompile(`FPBX[^\d]*(\d+\.\d+\.\d+)`)},
	{"Cisco", regexp.MustCompile(`Cisco[^\d]*(\d+\.\d+)`)},
	{"3CX", regexp.MustCompile(`3CXPhoneSystem\s+(\d+\.\d+)`)},
	{"TANDBERG", regexp.MustCompile(`TANDBERG/\d+\s+\(([\w.]+)\)`)},
}

// Server identification patterns (no version required, used as fallback)
var serverPatterns = []struct {
	product string
	pattern *regexp.Regexp
}{
	{"Asterisk", regexp.MustCompile(`(?i)Asterisk`)},
	{"Audiocodes", regexp.MustCompile(`(?i)Audiocodes`)},
	{"Kamailio", regexp.MustCompile(`(?i)kamailio`)},
	{"OpenSIPS", regexp.MustCompile(`(?i)OpenSIPS`)},
	{"FreeSWITCH", regexp.MustCompile(`(?i)FreeSWITCH`)},
	{"FreePBX", regexp.MustCompile(`(?i)FreePBX|FPBX`)},
	{"Cisco", regexp.MustCompile(`(?i)Cisco`)},
	{"3CX", regexp.MustCompile(`(?i)3CX`)},
	{"TANDBERG", regexp.MustCompile(`(?i)TANDBERG`)},
}

// CPE vendor mappings for known SIP servers (CPE 2.3 format)
var cpeVendors = map[string]string{
	"Asterisk":   "cpe:2.3:a:digium:asterisk:%s:*:*:*:*:*:*:*",
	"Audiocodes": "cpe:2.3:h:audiocodes:mediant_%s:*:*:*:*:*:*:*:*",
	"Kamailio":   "cpe:2.3:a:kamailio:kamailio:%s:*:*:*:*:*:*:*",
	"OpenSIPS":   "cpe:2.3:a:opensips:opensips:%s:*:*:*:*:*:*:*",
	"FreeSWITCH": "cpe:2.3:a:freeswitch:freeswitch:%s:*:*:*:*:*:*:*",
	"FreePBX":    "cpe:2.3:a:freepbx:freepbx:%s:*:*:*:*:*:*:*",
	"Cisco":      "cpe:2.3:a:cisco:unified_communications_manager:%s:*:*:*:*:*:*:*",
	"3CX":        "cpe:2.3:a:3cx:phone_system:%s:*:*:*:*:*:*:*",
	"TANDBERG":   "cpe:2.3:h:cisco:telepresence_codec:%s:*:*:*:*:*:*:*",
}

type UDPPlugin struct{}
type TCPPlugin struct{}
type TLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&UDPPlugin{})
	plugins.RegisterPlugin(&TCPPlugin{})
	plugins.RegisterPlugin(&TLSPlugin{})
}

// extractSIPVersion extracts product name and version from Server header
func extractSIPVersion(serverHeader string) (product, version string) {
	if serverHeader == "" {
		return "", ""
	}

	// Phase 1: Try to extract product with version
	for _, vp := range versionPatterns {
		matches := vp.pattern.FindStringSubmatch(serverHeader)
		if len(matches) >= 2 {
			return vp.product, matches[1]
		}
	}

	// Phase 2: Fallback - identify product without version
	for _, sp := range serverPatterns {
		if sp.pattern.MatchString(serverHeader) {
			return sp.product, ""
		}
	}

	return "", ""
}

// buildSIPCPE generates CPE string for detected SIP product
func buildSIPCPE(product, version string) string {
	if product == "" {
		return ""
	}

	cpeTemplate, exists := cpeVendors[product]
	if !exists {
		return ""
	}

	// Use version if available, otherwise use wildcard
	if version == "" {
		version = "*"
	}

	return fmt.Sprintf(cpeTemplate, version)
}

// buildOPTIONSRequest creates an RFC 3261 compliant SIP OPTIONS request
func buildOPTIONSRequest(transport string) []byte {
	request := fmt.Sprintf(
		"OPTIONS sip:100@127.0.0.1 SIP/2.0\r\n"+
			"Via: SIP/2.0/%s 127.0.0.1:5060;branch=z9hG4bK776asdhds\r\n"+
			"Max-Forwards: 70\r\n"+
			"To: <sip:100@127.0.0.1>\r\n"+
			"From: <sip:scanner@127.0.0.1>;tag=1928301774\r\n"+
			"Call-ID: a84b4c76e66710@127.0.0.1\r\n"+
			"CSeq: 63104 OPTIONS\r\n"+
			"Contact: <sip:scanner@127.0.0.1>\r\n"+
			"Accept: application/sdp\r\n"+
			"Content-Length: 0\r\n\r\n",
		strings.ToUpper(transport))
	return []byte(request)
}

// validateSIPResponse checks if response is a valid SIP response
func validateSIPResponse(response []byte) bool {
	if len(response) < 12 {
		return false
	}

	// Check for "SIP/2.0 " prefix
	if !bytes.HasPrefix(response, []byte("SIP/2.0 ")) {
		return false
	}

	// Extract status code (3 digits after "SIP/2.0 ")
	if len(response) < 12 {
		return false
	}
	statusCode := response[8:11]

	// Verify it's a 3-digit number in valid range (100-699)
	for i := 0; i < 3; i++ {
		if statusCode[i] < '0' || statusCode[i] > '9' {
			return false
		}
	}

	// Check status code range
	code := (int(statusCode[0])-'0')*100 + (int(statusCode[1])-'0')*10 + (int(statusCode[2]) - '0')
	return code >= 100 && code < 700
}

// extractHeader extracts a header value from SIP response (case-insensitive)
func extractHeader(response []byte, headerName string) string {
	lines := bytes.Split(response, []byte("\r\n"))
	headerNameLower := strings.ToLower(headerName)

	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		// Check for header name (case-insensitive)
		colonIdx := bytes.IndexByte(line, ':')
		if colonIdx == -1 {
			continue
		}

		lineHeader := strings.ToLower(string(line[:colonIdx]))
		if strings.TrimSpace(lineHeader) == headerNameLower {
			value := string(line[colonIdx+1:])
			return strings.TrimSpace(value)
		}
	}

	return ""
}

// parseAllowHeader parses the Allow header into method list
func parseAllowHeader(response []byte) []string {
	allowHeader := extractHeader(response, "Allow")
	if allowHeader == "" {
		return nil
	}

	methods := strings.Split(allowHeader, ",")
	result := make([]string, 0, len(methods))
	for _, method := range methods {
		method = strings.TrimSpace(method)
		if method != "" {
			result = append(result, method)
		}
	}

	return result
}

// DetectSIP performs SIP detection using OPTIONS request
func DetectSIP(conn net.Conn, transport string, timeout time.Duration) (*SIPData, error) {
	request := buildOPTIONSRequest(transport)

	response, err := utils.SendRecv(conn, request, timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, nil
	}

	// Validate SIP response
	if !validateSIPResponse(response) {
		return nil, nil
	}

	// Extract status code
	statusCode := (int(response[8])-'0')*100 + (int(response[9])-'0')*10 + (int(response[10]) - '0')

	// Extract headers
	server := extractHeader(response, "Server")
	allowedMethods := parseAllowHeader(response)

	return &SIPData{
		Banner:         string(response),
		Server:         server,
		AllowedMethods: allowedMethods,
		StatusCode:     statusCode,
	}, nil
}

func (p *UDPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	data, err := DetectSIP(conn, "UDP", timeout)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, nil
	}

	// Extract version information
	product, version := extractSIPVersion(data.Server)
	cpe := buildSIPCPE(product, version)

	var cpes []string
	if cpe != "" {
		cpes = []string{cpe}
	}

	payload := plugins.ServiceSIP{
		Banner:         data.Banner,
		Server:         data.Server,
		AllowedMethods: data.AllowedMethods,
		CPEs:           cpes,
	}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.UDP), nil
}

func (p *UDPPlugin) PortPriority(port uint16) bool {
	return port == DefaultSIPPort
}

func (p *UDPPlugin) Name() string {
	return SIP
}

func (p *UDPPlugin) Type() plugins.Protocol {
	return plugins.UDP
}

func (p *UDPPlugin) Priority() int {
	return 50
}

func (p *TCPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	data, err := DetectSIP(conn, "TCP", timeout)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, nil
	}

	// Extract version information
	product, version := extractSIPVersion(data.Server)
	cpe := buildSIPCPE(product, version)

	var cpes []string
	if cpe != "" {
		cpes = []string{cpe}
	}

	payload := plugins.ServiceSIP{
		Banner:         data.Banner,
		Server:         data.Server,
		AllowedMethods: data.AllowedMethods,
		CPEs:           cpes,
	}

	return plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP), nil
}

func (p *TCPPlugin) PortPriority(port uint16) bool {
	return port == DefaultSIPPort
}

func (p *TCPPlugin) Name() string {
	return SIP
}

func (p *TCPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *TCPPlugin) Priority() int {
	return 50
}

func (p *TLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	data, err := DetectSIP(conn, "TLS", timeout)
	if err != nil {
		return nil, err
	}

	if data == nil {
		return nil, nil
	}

	// Extract version information
	product, version := extractSIPVersion(data.Server)
	cpe := buildSIPCPE(product, version)

	var cpes []string
	if cpe != "" {
		cpes = []string{cpe}
	}

	payload := plugins.ServiceSIPS{
		Banner:         data.Banner,
		Server:         data.Server,
		AllowedMethods: data.AllowedMethods,
		CPEs:           cpes,
	}

	return plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS), nil
}

func (p *TLSPlugin) PortPriority(port uint16) bool {
	return port == DefaultSIPSPort
}

func (p *TLSPlugin) Name() string {
	return SIPS
}

func (p *TLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *TLSPlugin) Priority() int {
	return 51
}
