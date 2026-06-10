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
VMware vSphere SOAP API Fingerprinting

This plugin implements VMware vSphere fingerprinting using the vSphere SOAP API.
It detects ESXi, vCenter, and other vSphere products from the same SOAP endpoint.
The /sdk endpoint requires no authentication and returns rich metadata including
product name, version, build number, and API type.

SECURITY CONTEXT:
  Exposed VMware management interfaces provide detailed version information that can be
  used to identify vulnerable hosts. VMware management interfaces should not have their
  management interface exposed to the internet.

Detection Strategy:
  PHASE 1 - SOAP API QUERY (POST /sdk):
    - Send SOAP RetrieveServiceContent request to /sdk endpoint
    - Parse XML response for <about> block containing service metadata
    - Validate <vendor>VMware, Inc.</vendor> as positive identification marker
    - Validate <apiType> is present (non-empty) as structural confirmation
    - Validate response contains RetrieveServiceContentResponse or <about> as SOAP marker
    - Extract version, build, fullName, apiType, apiVersion, osType, productLineId
    - apiType distinguishes ESXi ("HostAgent") from vCenter ("VirtualCenter")

  The RetrieveServiceContent call is unauthenticated and available on all ESXi versions
  from 4.x through 8.x and vCenter versions. The response XML structure is stable.

Product Classification (by apiType):
  - "HostAgent"      → ESXi hypervisor    → protocol "vmware-esxi"
  - "VirtualCenter"  → vCenter Server     → protocol "vmware-vcenter"
  - (other)          → Unknown vSphere    → protocol "vmware-vsphere"

Response Structure (inside <about> block):
  <name>VMware ESXi</name>
  <fullName>VMware ESXi 6.0.0 build-3620759</fullName>
  <vendor>VMware, Inc.</vendor>
  <version>6.0.0</version>
  <build>3620759</build>
  <osType>vmnix-x86</osType>
  <productLineId>embeddedEsx</productLineId>
  <apiType>HostAgent</apiType>
  <apiVersion>6.0</apiVersion>

Port Configuration:
  - Port 443: vSphere SOAP API over TLS (primary, always present)

References:
  - https://developer.broadcom.com/xapis/vsphere-web-services-api/latest/
  - https://github.com/rapid7/metasploit-framework/blob/master/modules/auxiliary/scanner/vmware/esx_fingerprint.rb
*/

package vmware

import (
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const VMWARE = "vmware-vsphere"

type VMwarePlugin struct{}

func init() {
	plugins.RegisterPlugin(&VMwarePlugin{})
}

// vmwareResult holds parsed fields from the SOAP response
type vmwareResult struct {
	Name          string
	FullName      string
	Vendor        string
	Version       string
	Build         string
	ApiType       string
	ApiVersion    string
	OsType        string
	ProductLineId string
}

// soapRequest is the SOAP envelope for RetrieveServiceContent.
// This call is unauthenticated and returns service metadata on all ESXi versions.
const soapRequest = `<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
  <soap:Body>
    <RetrieveServiceContent xmlns="urn:vim25">
      <_this type="ServiceInstance">ServiceInstance</_this>
    </RetrieveServiceContent>
  </soap:Body>
</soap:Envelope>`

// XML field extraction regexes (compiled once at init)
var (
	reVendor        = regexp.MustCompile(`<vendor>([^<]+)</vendor>`)
	reName          = regexp.MustCompile(`<name>([^<]+)</name>`)
	reFullName      = regexp.MustCompile(`<fullName>([^<]+)</fullName>`)
	reVersion       = regexp.MustCompile(`<version>([^<]+)</version>`)
	reBuild         = regexp.MustCompile(`<build>([^<]+)</build>`)
	reApiType       = regexp.MustCompile(`<apiType>([^<]+)</apiType>`)
	reApiVersion    = regexp.MustCompile(`<apiVersion>([^<]+)</apiVersion>`)
	reOsType        = regexp.MustCompile(`<osType>([^<]+)</osType>`)
	reProductLineId = regexp.MustCompile(`<productLineId>([^<]+)</productLineId>`)
)

// buildSOAPHTTPRequest constructs an HTTP/1.1 POST request for the /sdk endpoint.
func buildSOAPHTTPRequest(host string) string {
	body := soapRequest
	return fmt.Sprintf(
		"POST /sdk HTTP/1.1\r\n"+
			"Host: %s\r\n"+
			"User-Agent: nerva/1.0\r\n"+
			"Content-Type: text/xml\r\n"+
			"SOAPAction: urn:vim25/6.0\r\n"+
			"Content-Length: %d\r\n"+
			"Connection: close\r\n"+
			"\r\n%s",
		host, len(body), body)
}

// extractHTTPBody extracts the body from an HTTP response by finding the
// header/body separator (\r\n\r\n).
func extractHTTPBody(response []byte) []byte {
	for i := 0; i < len(response)-3; i++ {
		if response[i] == '\r' && response[i+1] == '\n' && response[i+2] == '\r' && response[i+3] == '\n' {
			if i+4 < len(response) {
				return response[i+4:]
			}
			return nil
		}
	}
	return response
}

// extractXMLField extracts the first match of a compiled regex from XML content.
func extractXMLField(re *regexp.Regexp, xml string) string {
	m := re.FindStringSubmatch(xml)
	if len(m) >= 2 {
		return m[1]
	}
	return ""
}

// parseVMwareResponse parses the SOAP XML response and extracts VMware metadata.
//
// Validation uses a 3-signal gate to prevent false positives:
//  1. Requires <vendor>VMware, Inc.</vendor> to positively identify VMware.
//  2. Requires <apiType> to be present (non-empty) as a SOAP structural marker.
//  3. Requires RetrieveServiceContentResponse or <about> as a structural SOAP marker.
//
// Returns nil if any validation signal is missing.
func parseVMwareResponse(response []byte) *vmwareResult {
	if len(response) == 0 {
		return nil
	}

	xml := string(response)

	// Signal 1: Validate VMware vendor marker
	vendor := extractXMLField(reVendor, xml)
	if vendor != "VMware, Inc." {
		return nil
	}

	// Signal 2: Validate apiType is present (non-empty)
	apiType := extractXMLField(reApiType, xml)
	if apiType == "" {
		return nil
	}

	// Signal 3: Validate SOAP response structure
	if !strings.Contains(xml, "RetrieveServiceContentResponse") && !strings.Contains(xml, "<about>") {
		return nil
	}

	return &vmwareResult{
		Name:          extractXMLField(reName, xml),
		FullName:      extractXMLField(reFullName, xml),
		Vendor:        vendor,
		Version:       extractXMLField(reVersion, xml),
		Build:         extractXMLField(reBuild, xml),
		ApiType:       apiType,
		ApiVersion:    extractXMLField(reApiVersion, xml),
		OsType:        extractXMLField(reOsType, xml),
		ProductLineId: extractXMLField(reProductLineId, xml),
	}
}

// classifyVMwareProduct returns the product type string for a given apiType.
// "HostAgent" maps to "esxi", "VirtualCenter" maps to "vcenter", anything else to "vsphere".
func classifyVMwareProduct(apiType string) string {
	switch apiType {
	case "HostAgent":
		return "esxi"
	case "VirtualCenter":
		return "vcenter"
	default:
		return "vsphere"
	}
}

// buildVMwareCPE constructs a CPE string appropriate for the detected VMware product type.
//
// CPE formats:
//   - esxi:    cpe:2.3:o:vmware:esxi:{version}:*:*:*:*:*:*:*      (o = operating system)
//   - vcenter: cpe:2.3:a:vmware:vcenter_server:{version}:*:*:*:*:*:*:*  (a = application)
//   - vsphere: cpe:2.3:a:vmware:vsphere:{version}:*:*:*:*:*:*:*    (a = application)
func buildVMwareCPE(productType, version string) string {
	if version == "" {
		version = "*"
	}
	switch productType {
	case "esxi":
		return fmt.Sprintf("cpe:2.3:o:vmware:esxi:%s:*:*:*:*:*:*:*", version)
	case "vcenter":
		return fmt.Sprintf("cpe:2.3:a:vmware:vcenter_server:%s:*:*:*:*:*:*:*", version)
	default:
		return fmt.Sprintf("cpe:2.3:a:vmware:vsphere:%s:*:*:*:*:*:*:*", version)
	}
}

func (p *VMwarePlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	host := fmt.Sprintf("%s:%d", target.Host, target.Address.Port())

	request := buildSOAPHTTPRequest(host)
	response, err := utils.SendRecv(conn, []byte(request), timeout)
	if err != nil && len(response) == 0 {
		return nil, err
	}

	if len(response) == 0 {
		return nil, nil
	}

	body := extractHTTPBody(response)
	result := parseVMwareResponse(body)
	if result == nil {
		return nil, nil
	}

	productType := classifyVMwareProduct(result.ApiType)
	cpe := buildVMwareCPE(productType, result.Version)
	payload := plugins.ServiceVMware{
		ProductType:   productType,
		FullName:      result.FullName,
		Build:         result.Build,
		ApiType:       result.ApiType,
		ApiVersion:    result.ApiVersion,
		OsType:        result.OsType,
		ProductLineId: result.ProductLineId,
		CPEs:          []string{cpe},
	}

	service := plugins.CreateServiceFrom(target, payload, true, result.Version, plugins.TCPTLS)
	if target.Misconfigs {
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *VMwarePlugin) PortPriority(port uint16) bool {
	return port == 443
}

func (p *VMwarePlugin) Name() string {
	return VMWARE
}

func (p *VMwarePlugin) Type() plugins.Protocol {
	return plugins.TCPTLS
}

func (p *VMwarePlugin) Priority() int {
	return 0
}
