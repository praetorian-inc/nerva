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
IPP (Internet Printing Protocol) Fingerprinting

This plugin implements IPP fingerprinting using the binary IPP protocol
over HTTP POST. IPP is used by printers, print servers, and multi-function
devices (MFDs) to expose printing capabilities.

Default Port: 631 (both plain TCP and TCPTLS)

Security Note:
  Exposed IPP services can reveal detailed printer information including make,
  model, firmware version, and URI. Unauthenticated access to IPP can allow
  job submission and configuration changes on vulnerable printers.

Detection Strategy:
  PHASE 1 - IPP Get-Printer-Attributes Detection:
    - Build binary IPP Get-Printer-Attributes request (operation-id 0x000B)
    - Wrap in HTTP POST to /ipp/print with Content-Type: application/ipp
    - Validate response has Content-Type: application/ipp header
    - Parse binary IPP response: version (2 bytes), status-code (2 bytes),
      request-id (4 bytes), then attribute groups
    - Status codes 0x0000-0x00FF are considered successful
    - Extract printer attributes: make-and-model, firmware version, state,
      IPP versions supported, printer name, URI

IPP Binary Wire Format:

  IPP Request Header:
    [0-1]  version-number: 0x0200 (IPP/2.0)
    [2-3]  operation-id:   0x000B (Get-Printer-Attributes)
    [4-7]  request-id:     0x00000001

  Attribute Group Format:
    [0]    begin-attribute-group-tag (e.g., 0x01=operation-attributes)
    then attributes follow:
      [0]    value-tag (e.g., 0x47=charset, 0x48=naturalLanguage, 0x45=uri, 0x44=keyword)
      [1-2]  name-length (big-endian uint16)
      [N]    name bytes (UTF-8)
      [N+2]  value-length (big-endian uint16)
      [M]    value bytes
    name-length=0 means additional value for previous attribute

  End of Attributes:
    [0]    0x03 (end-of-attributes-tag)

  IPP Response Header:
    [0-1]  version-number
    [2-3]  status-code (0x0000=successful-ok, 0x0001=successful-ok-ignored)
    [4-7]  request-id

Group Delimiter Tags:
  0x01 = operation-attributes-tag
  0x04 = printer-attributes-tag
  0x03 = end-of-attributes-tag

Value Tags:
  0x41 = textWithoutLanguage
  0x44 = keyword
  0x45 = uri
  0x47 = charset
  0x48 = naturalLanguage
  0x23 = enum

References:
  - RFC 8010: Internet Printing Protocol/1.1: Encoding and Transport
  - RFC 8011: Internet Printing Protocol/1.1: Model and Semantics
  - https://www.pwg.org/ipp/
*/

package ipp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	IPPName    = "ipp"
	IPPPort    = 631
	IPPTLSPort = 631

	// IPP protocol version 2.0
	ippVersionMajor = 0x02
	ippVersionMinor = 0x00

	// IPP operation IDs
	ippOpGetPrinterAttributes = 0x000B

	// IPP attribute group tags
	ippTagOperationAttributes = 0x01
	ippTagPrinterAttributes   = 0x04
	ippTagEndOfAttributes     = 0x03

	// IPP value tags
	ippTagTextWithoutLanguage = 0x41
	ippTagKeyword             = 0x44
	ippTagURI                 = 0x45
	ippTagCharset             = 0x47
	ippTagNaturalLanguage     = 0x48

	// IPP status code upper bound for "successful" range
	ippStatusSuccessMax = 0x00FF
)

// ippDetectionResult holds the parsed IPP response data
type ippDetectionResult struct {
	detected            bool
	printerMakeAndModel string
	firmwareVersion     string
	printerState        string
	ippVersions         []string
	printerName         string
	printerURI          string
}

// IPPPlugin detects IPP on plain TCP port 631
type IPPPlugin struct{}

// IPPTLSPlugin detects IPP over TLS on port 631
type IPPTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&IPPPlugin{})
	plugins.RegisterPlugin(&IPPTLSPlugin{})
}

// buildIPPRequest constructs the binary IPP Get-Printer-Attributes request body.
//
// The request asks for key printer attributes including make-and-model,
// firmware version, state, IPP versions, name, and URI.
func buildIPPRequest(host string, port int) []byte {
	uri := fmt.Sprintf("ipp://%s:%d/ipp/print", host, port)

	var buf []byte

	// IPP header
	buf = append(buf, ippVersionMajor, ippVersionMinor) // version 2.0
	buf = append(buf, 0x00, 0x0B)                       // operation-id: Get-Printer-Attributes
	buf = append(buf, 0x00, 0x00, 0x00, 0x01)           // request-id: 1

	// begin operation-attributes-tag
	buf = append(buf, ippTagOperationAttributes)

	// attributes-charset = "utf-8"
	buf = appendIPPAttribute(buf, ippTagCharset, "attributes-charset", "utf-8")

	// attributes-natural-language = "en-us"
	buf = appendIPPAttribute(buf, ippTagNaturalLanguage, "attributes-natural-language", "en-us")

	// printer-uri
	buf = appendIPPAttribute(buf, ippTagURI, "printer-uri", uri)

	// requested-attributes (first value has the name)
	buf = appendIPPAttribute(buf, ippTagKeyword, "requested-attributes", "printer-make-and-model")

	// Additional requested-attributes values (name-length = 0 for additional values)
	additionalAttrs := []string{
		"printer-firmware-string-version",
		"printer-state",
		"ipp-versions-supported",
		"printer-name",
		"printer-uri-supported",
	}
	for _, attr := range additionalAttrs {
		buf = appendIPPAdditionalValue(buf, ippTagKeyword, attr)
	}

	// end-of-attributes-tag
	buf = append(buf, ippTagEndOfAttributes)

	return buf
}

// appendIPPAttribute appends a named IPP attribute to the buffer.
// Format: value-tag (1) + name-length (2) + name + value-length (2) + value
func appendIPPAttribute(buf []byte, valueTag byte, name, value string) []byte {
	buf = append(buf, valueTag)
	buf = appendUint16(buf, uint16(len(name)))
	buf = append(buf, []byte(name)...)
	buf = appendUint16(buf, uint16(len(value)))
	buf = append(buf, []byte(value)...)
	return buf
}

// appendIPPAdditionalValue appends an additional value for the previous attribute
// (name-length = 0 indicates additional value for same attribute name).
func appendIPPAdditionalValue(buf []byte, valueTag byte, value string) []byte {
	buf = append(buf, valueTag)
	buf = appendUint16(buf, 0) // name-length = 0 (additional value)
	buf = appendUint16(buf, uint16(len(value)))
	buf = append(buf, []byte(value)...)
	return buf
}

// appendUint16 appends a big-endian uint16 to the buffer.
func appendUint16(buf []byte, v uint16) []byte {
	return append(buf, byte(v>>8), byte(v))
}

// buildIPPHTTPRequest wraps the binary IPP body in an HTTP POST request.
func buildIPPHTTPRequest(host string, port int, ippBody []byte) []byte {
	hostHeader := fmt.Sprintf("%s:%d", host, port)
	header := fmt.Sprintf(
		"POST /ipp/print HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"Content-Type: application/ipp\r\n"+
			"Content-Length: %d\r\n"+
			"User-Agent: nerva/1.0\r\n"+
			"Connection: close\r\n"+
			"\r\n",
		hostHeader, len(ippBody),
	)
	result := []byte(header)
	result = append(result, ippBody...)
	return result
}

// extractContentType extracts the Content-Type header value from an HTTP response.
// Returns empty string if not found.
func extractContentType(response []byte) string {
	responseStr := string(response)
	lines := strings.Split(responseStr, "\r\n")
	for _, line := range lines {
		// Stop at blank line (end of headers)
		if line == "" {
			break
		}
		lower := strings.ToLower(line)
		if strings.HasPrefix(lower, "content-type:") {
			return strings.TrimSpace(line[len("content-type:"):])
		}
	}
	return ""
}

// extractHTTPBody extracts the HTTP body from the raw response by locating
// the header/body separator (\r\n\r\n).
func extractHTTPBody(response []byte) []byte {
	for i := 0; i < len(response)-3; i++ {
		if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
			if i+4 < len(response) {
				return response[i+4:]
			}
			return nil
		}
	}
	return nil
}

// parseIPPResponse parses the binary IPP response body and returns detection result.
// Returns nil if the response is not a valid IPP response.
//
// A valid IPP response is identified by:
//   - At least 8 bytes (IPP header length)
//   - A reasonable IPP version (major version 1 or 2)
//
// The presence of Content-Type: application/ipp plus a structurally valid IPP
// binary response is sufficient proof of an IPP server, even when the status
// code indicates an error (e.g. 0x0406 client-error-not-found returned by CUPS
// when no specific printer is configured at /ipp/print). Printer attributes are
// only parsed for successful responses (status <= 0x00FF); error responses will
// not carry printer attribute data.
func parseIPPResponse(body []byte) *ippDetectionResult {
	if len(body) < 8 {
		return nil
	}

	// Parse IPP header
	// Bytes 0-1: version
	// Bytes 2-3: status-code
	// Bytes 4-7: request-id
	versionMajor := body[0]
	statusCode := binary.BigEndian.Uint16(body[2:4])

	// Validate IPP version is reasonable (1.x or 2.x)
	if versionMajor < 1 || versionMajor > 2 {
		return nil
	}

	result := &ippDetectionResult{
		detected: true,
	}

	// Only parse printer attributes for successful responses.
	// Error responses (e.g. 0x0406 client-error-not-found) still confirm IPP
	// detection but will not contain printer attribute data.
	if statusCode > ippStatusSuccessMax {
		return result
	}

	// Parse attributes starting at byte 8
	attrs := parseIPPAttributes(body[8:])

	if v, ok := attrs["printer-make-and-model"]; ok {
		result.printerMakeAndModel = v
	}
	if v, ok := attrs["printer-firmware-string-version"]; ok {
		result.firmwareVersion = v
	}
	if v, ok := attrs["printer-state"]; ok {
		result.printerState = v
	}
	if v, ok := attrs["printer-name"]; ok {
		result.printerName = v
	}
	if v, ok := attrs["printer-uri-supported"]; ok {
		result.printerURI = v
	}

	// ipp-versions-supported can have multiple values; collect all
	if v, ok := attrs["ipp-versions-supported"]; ok && v != "" {
		result.ippVersions = strings.Split(v, ",")
	}

	return result
}

// parseIPPAttributes parses IPP attribute groups from the response body
// (the portion after the 8-byte IPP header).
//
// Returns a map of attribute name to value (last value wins for multi-valued).
// For ipp-versions-supported, values are concatenated with comma.
func parseIPPAttributes(data []byte) map[string]string {
	attrs := make(map[string]string)
	idx := 0
	var lastName string

	for idx < len(data) {
		tag := data[idx]
		idx++

		// Group delimiter tags
		if tag == ippTagEndOfAttributes {
			break
		}
		if tag == ippTagOperationAttributes || tag == ippTagPrinterAttributes {
			lastName = ""
			continue
		}
		// Skip other group delimiter tags (0x02, 0x05, 0x06, 0x07)
		if tag < 0x10 {
			lastName = ""
			continue
		}

		// Value attribute
		if idx+2 > len(data) {
			break
		}
		nameLen := int(binary.BigEndian.Uint16(data[idx : idx+2]))
		idx += 2

		var name string
		if nameLen > 0 {
			if idx+nameLen > len(data) {
				break
			}
			name = string(data[idx : idx+nameLen])
			idx += nameLen
			lastName = name
		} else {
			// name-length = 0 means additional value for previous attribute
			name = lastName
		}

		if idx+2 > len(data) {
			break
		}
		valueLen := int(binary.BigEndian.Uint16(data[idx : idx+2]))
		idx += 2

		if valueLen < 0 || idx+valueLen > len(data) {
			break
		}
		value := string(data[idx : idx+valueLen])
		idx += valueLen

		if name == "" {
			continue
		}

		// For multi-valued attributes like ipp-versions-supported, concatenate
		if existing, exists := attrs[name]; exists && name == "ipp-versions-supported" {
			attrs[name] = existing + "," + value
		} else {
			attrs[name] = value
		}
	}

	return attrs
}

// generateIPPCPE generates a CPE string from printer make-and-model and version.
// Format: cpe:2.3:h:{vendor}:{product}:{version}:*:*:*:*:*:*:*
func generateIPPCPE(makeAndModel, version string) string {
	if makeAndModel == "" {
		return ""
	}

	// Split make-and-model into vendor and product
	// Common format: "HP LaserJet Pro M404n" or "Canon imageRUNNER 2425"
	parts := strings.SplitN(makeAndModel, " ", 2)
	if len(parts) < 2 {
		return ""
	}

	vendor := normalizeCPEComponent(parts[0])
	product := normalizeCPEComponent(parts[1])

	if vendor == "" || product == "" {
		return ""
	}

	versionNorm := version
	if versionNorm == "" {
		versionNorm = "*"
	} else {
		versionNorm = normalizeCPEComponent(versionNorm)
		if versionNorm == "" {
			versionNorm = "*"
		}
	}

	return fmt.Sprintf("cpe:2.3:h:%s:%s:%s:*:*:*:*:*:*:*", vendor, product, versionNorm)
}

// normalizeCPEComponent normalizes a string for use in CPE (lowercase, spaces to underscores,
// strip non-alphanumeric except hyphens and underscores).
func normalizeCPEComponent(s string) string {
	if s == "" {
		return ""
	}
	s = strings.ToLower(s)
	s = strings.ReplaceAll(s, " ", "_")
	reg := regexp.MustCompile(`[^a-z0-9_-]`)
	return reg.ReplaceAllString(s, "")
}

// sendRecvHTTP sends data and reads the response in a loop to ensure we get
// both HTTP headers and body. Standard Recv does a single read which may only
// return headers if the body arrives in a separate TCP segment.
func sendRecvHTTP(conn net.Conn, data []byte, timeout time.Duration) ([]byte, error) {
	err := utils.Send(conn, data, timeout)
	if err != nil {
		return nil, err
	}

	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	var buf []byte
	tmp := make([]byte, 4096)
	for {
		n, readErr := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}

		// Check if we have complete headers + some body
		if idx := bytes.Index(buf, []byte("\r\n\r\n")); idx >= 0 {
			bodyStart := idx + 4
			if len(buf) > bodyStart {
				break
			}
		}

		if readErr != nil {
			break
		}

		if len(buf) > 8192 {
			break
		}
	}

	return buf, nil
}
// detectIPP sends an IPP Get-Printer-Attributes probe and parses the response.
func detectIPP(conn net.Conn, target plugins.Target, timeout time.Duration, tls bool) (*plugins.Service, error) {
	host := target.Host
	if host == "" {
		host = target.Address.Addr().String()
	}
	port := int(target.Address.Port())

	// Build the binary IPP request body
	ippBody := buildIPPRequest(host, port)

	// Wrap in HTTP POST
	requestBytes := buildIPPHTTPRequest(host, port, ippBody)

	// Send request and receive response
	response, err := sendRecvHTTP(conn, requestBytes, timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, nil
	}

	// Validate Content-Type: application/ipp
	contentType := extractContentType(response)
	if !strings.Contains(strings.ToLower(contentType), "application/ipp") {
		return nil, nil
	}

	// Extract HTTP body (binary IPP response)
	body := extractHTTPBody(response)
	if body == nil {
		return nil, nil
	}

	// Parse binary IPP response
	result := parseIPPResponse(body)
	if result == nil || !result.detected {
		return nil, nil
	}

	// Build CPE from make-and-model
	cpe := generateIPPCPE(result.printerMakeAndModel, result.firmwareVersion)

	payload := plugins.ServiceIPP{
		PrinterMakeAndModel: result.printerMakeAndModel,
		FirmwareVersion:     result.firmwareVersion,
		PrinterState:        result.printerState,
		IPPVersions:         result.ippVersions,
		PrinterName:         result.printerName,
		PrinterURI:          result.printerURI,
	}
	if cpe != "" {
		payload.CPEs = []string{cpe}
	}

	version := result.firmwareVersion
	transport := plugins.TCP
	if tls {
		transport = plugins.TCPTLS
	}

	return plugins.CreateServiceFrom(target, payload, tls, version, transport), nil
}

// IPPPlugin methods (TCP - port 631)

func (p *IPPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectIPP(conn, target, timeout, false)
}

func (p *IPPPlugin) PortPriority(port uint16) bool {
	return port == IPPPort
}

func (p *IPPPlugin) Name() string {
	return IPPName
}

func (p *IPPPlugin) Type() plugins.Protocol {
	return plugins.TCP
}

func (p *IPPPlugin) Priority() int {
	return 100
}

// IPPTLSPlugin methods (TCPTLS - port 631)

func (p *IPPTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return detectIPP(conn, target, timeout, true)
}

func (p *IPPTLSPlugin) PortPriority(port uint16) bool {
	return port == IPPTLSPort
}

func (p *IPPTLSPlugin) Name() string {
	return IPPName
}

func (p *IPPTLSPlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *IPPTLSPlugin) Priority() int {
	return 101
}
