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
Oracle Infrastructure Bundle Fingerprinting (LAB-5055)

This package detects four Oracle infrastructure surfaces exposed over the
network and emits one technology per product:

  - Oracle Integrated Lights Out Manager (ILOM)  -> "oracle_ilom"
  - Oracle Data Integrator (ODI)                 -> "oracle_odi"
  - Oracle Linux Virtualization Manager (OLVM)    -> "oracle_olvm"
  - VirtualBox web service (vboxwebsrv, SOAP)     -> "virtualbox_web"

ILOM, ODI and OLVM are all HTTP(S) web surfaces, so a single shared detector
(InfraPlugin / InfraTLSPlugin) probes them on one connection and emits the right
technology via the dynamic ServiceOracleInfra.Type() (GlassFish precedent). The
VirtualBox web service uses a different transport (a single read-only SOAP POST
on 18083) and gets its own plugin, VBoxWebPlugin.

Detection (each product requires a product-specific Oracle marker):

  ILOM: GET /redfish/v1/ and require an Oracle marker in the Redfish ServiceRoot
    JSON (Vendor~Oracle OR an Oem.Oracle key OR Product naming ILOM); firmware is
    read from GET /redfish/v1/Managers/<id> FirmwareVersion. A branded ILOM web
    surface (title "Oracle Integrated Lights Out Manager" or an *-ILOM-Web-Server
    Server header) is accepted as a standalone Oracle marker when Redfish is
    disabled. A generic (non-Oracle) Redfish BMC (Dell iDRAC / HPE iLO /
    Supermicro) is NOT classified as ILOM. The self-signed cert is corroboration
    only (surfaced via CheckTLS under --misconfigs), never a standalone trigger.

  ODI: GET /oraclediagent/agentping requiring an ODI-specific token (a bare 200
    is not sufficient), and GET /odiconsole/ (non-404 with an "Oracle Data
    Integrator" title; the generic ADF /afr/ prefix alone is not sufficient).

  OLVM: GET /ovirt-engine/ + /ovirt-engine/api, requiring an ovirt-engine
    presence marker AND Oracle/OLVM branding. A generic upstream oVirt / RHV
    without Oracle branding is NOT classified as OLVM.

  VirtualBox: a single unauthenticated, read-only IVirtualBox_getVersion SOAP
    POST (empty object reference); identified by the vbox namespace
    http://www.virtualbox.org/ TOGETHER WITH a vbox-specific response/fault
    element (getVersionResponse, or an InvalidObjectFault / RuntimeFault vbox
    fault) that a request-echoing SOAP server would not add. Never
    logon/session/state change, never credentials.

Scanning safety: all HTTP probes are read-only GETs to fixed paths with
no-redirect and LimitReader-bounded bodies; the VirtualBox probe is a single
read-only SOAP call; no UDP/IPMI probing (the existing ipmi plugin covers
623/udp); no writes anywhere.

Version: ILOM firmware from Redfish Managers; ODI best-effort from agentping;
OLVM/VirtualBox versions live behind authentication and default to "" (wildcard
CPE). CPEs are NVD-verified (one per product).
*/

package oracleinfra

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const (
	// ProductILOM, ProductODI and ProductOLVM are the ServiceOracleInfra.Product
	// discriminators driving the dynamic Type().
	ProductILOM = "ilom"
	ProductODI  = "odi"
	ProductOLVM = "olvm"

	// DefaultODIAgentPort is the Oracle Data Integrator standalone-agent listener.
	DefaultODIAgentPort = 20910
	// DefaultVBoxWebPort is the vboxwebsrv SOAP default port.
	DefaultVBoxWebPort = 18083

	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(10 * 1024 * 1024)

	userAgent = "nerva/1.0"
)

// titlePattern extracts the contents of an HTML <title> element.
var titlePattern = regexp.MustCompile(`(?is)<title>(.*?)</title>`)

// odiVersionPattern matches an Oracle Fusion Middleware five-part version token
// (e.g. 12.2.1.4.0) as emitted by some ODI agentping builds. The five-part shape
// is distinctive enough to avoid matching unrelated numbers; anything else
// degrades to "" (wildcard CPE).
var odiVersionPattern = regexp.MustCompile(`\b(\d+\.\d+\.\d+\.\d+\.\d+)\b`)

// InfraPlugin is the shared Oracle infra web detector over cleartext TCP.
type InfraPlugin struct{}

// InfraTLSPlugin is the shared Oracle infra web detector over TLS.
type InfraTLSPlugin struct{}

// VBoxWebPlugin detects the VirtualBox web service (vboxwebsrv) SOAP endpoint.
type VBoxWebPlugin struct{}

func init() {
	plugins.RegisterPlugin(&InfraPlugin{})
	plugins.RegisterPlugin(&InfraTLSPlugin{})
	plugins.RegisterPlugin(&VBoxWebPlugin{})
}

// --- shared HTTP mechanics (house pattern) ---

// createHTTPClient wraps the already-dialed conn in an http.Client that does not
// follow redirects (so Location headers can be inspected directly).
func createHTTPClient(conn net.Conn, timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return conn, nil
			},
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse // Don't follow redirects
		},
	}
}

// doGet performs a read-only GET with the nerva User-Agent. When host is
// non-empty it is set as the HTTP Host header so name-based vhosts are reached.
func doGet(client *http.Client, url string, host string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	if host != "" {
		req.Host = host
	}
	return client.Do(req)
}

// readBody reads up to maxResponseSize of a response body and closes it.
func readBody(resp *http.Response) string {
	body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
	_ = resp.Body.Close()
	return string(body)
}

// extractTitle returns the trimmed contents of the first <title> element, if any.
func extractTitle(body string) string {
	if m := titlePattern.FindStringSubmatch(body); len(m) >= 2 {
		return strings.TrimSpace(m[1])
	}
	return ""
}

// isSuccessStatus reports whether an HTTP status code is a 2xx success.
func isSuccessStatus(code int) bool {
	return code >= 200 && code < 300
}

// cpeVersion returns the version token for a CPE, wildcarding an unknown version.
func cpeVersion(version string) string {
	if version == "" {
		return "*"
	}
	return version
}

// --- ILOM (Redfish + firmware; branded web surface fallback) ---

// redfishServiceRoot models the DMTF Redfish ServiceRoot fields inspected for an
// Oracle marker.
type redfishServiceRoot struct {
	Vendor   string                     `json:"Vendor"`
	Product  string                     `json:"Product"`
	Oem      map[string]json.RawMessage `json:"Oem"`
	Managers struct {
		ODataID string `json:"@odata.id"`
	} `json:"Managers"`
}

// redfishManagerCollection models the Managers collection member list.
type redfishManagerCollection struct {
	Members []struct {
		ODataID string `json:"@odata.id"`
	} `json:"Members"`
}

// redfishManager models the firmware version on a Manager resource.
type redfishManager struct {
	FirmwareVersion string `json:"FirmwareVersion"`
}

// isOracleRedfish reports whether a parsed Redfish ServiceRoot carries an
// Oracle-specific marker (FP guard). A generic BMC (Dell iDRAC -> Vendor "Dell",
// HPE iLO -> Oem.Hpe, Supermicro) fails all three checks.
func isOracleRedfish(root redfishServiceRoot) bool {
	if strings.Contains(strings.ToLower(root.Vendor), "oracle") {
		return true
	}
	for k := range root.Oem {
		if strings.EqualFold(k, "oracle") {
			return true
		}
	}
	product := strings.ToLower(root.Product)
	return strings.Contains(product, "integrated lights out manager") ||
		strings.Contains(product, "ilom")
}

// isILOMWebMarker reports whether an HTTP title or Server header carries the
// branded Oracle ILOM web-surface marker. This is a standalone Oracle marker
// (used when Redfish is disabled), not corroboration.
func isILOMWebMarker(title, server string) bool {
	return strings.Contains(strings.ToLower(title), "integrated lights out manager") ||
		strings.Contains(strings.ToLower(server), "ilom-web-server")
}

// fetchILOMFirmware follows the Redfish Managers collection to read the first
// Manager's FirmwareVersion. All GETs are read-only; any failure (including auth
// gating) degrades to "".
func fetchILOMFirmware(client *http.Client, baseURL, host, managersPath string) string {
	if managersPath == "" {
		return ""
	}
	collResp, err := doGet(client, baseURL+managersPath, host)
	if err != nil {
		return ""
	}
	var coll redfishManagerCollection
	if json.Unmarshal([]byte(readBody(collResp)), &coll) != nil || len(coll.Members) == 0 {
		return ""
	}
	mgrPath := coll.Members[0].ODataID
	if mgrPath == "" {
		return ""
	}
	mgrResp, err := doGet(client, baseURL+mgrPath, host)
	if err != nil {
		return ""
	}
	var mgr redfishManager
	if json.Unmarshal([]byte(readBody(mgrResp)), &mgr) != nil {
		return ""
	}
	return mgr.FirmwareVersion
}

// detectILOM probes the Redfish service root (and, as a fallback, the branded
// web front-end). anon reports a genuine 2xx on the detected surface.
func detectILOM(client *http.Client, baseURL, host string) (firmware string, redfish, anon, detected bool) {
	if resp, err := doGet(client, baseURL+"/redfish/v1/", host); err == nil {
		status := resp.StatusCode
		body := readBody(resp)
		if isSuccessStatus(status) {
			var root redfishServiceRoot
			if json.Unmarshal([]byte(body), &root) == nil && isOracleRedfish(root) {
				firmware = fetchILOMFirmware(client, baseURL, host, root.Managers.ODataID)
				return firmware, true, true, true
			}
		}
	}
	// Fallback: branded ILOM web surface (Redfish disabled).
	if resp, err := doGet(client, baseURL+"/", host); err == nil {
		status := resp.StatusCode
		server := resp.Header.Get("Server")
		body := readBody(resp)
		if isILOMWebMarker(extractTitle(body), server) {
			return "", false, isSuccessStatus(status), true
		}
	}
	return "", false, false, false
}

func buildILOMCPE(version string) string {
	return fmt.Sprintf("cpe:2.3:o:oracle:integrated_lights_out_manager_firmware:%s:*:*:*:*:*:*:*", cpeVersion(version))
}

func ilomFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-ilom-exposed",
		Severity:    plugins.SeverityMedium,
		Description: "Oracle Integrated Lights Out Manager (ILOM) lights-out management plane is reachable without authentication on the network; the BMC provides out-of-band server control and should not be exposed to untrusted networks",
		Evidence:    "Oracle ILOM management surface responded without credentials",
	}
}

// --- Oracle Data Integrator (ODI) ---

// hasODIAgentToken reports whether an agentping body carries a NON-reflective,
// product-emitted ODI token (not a bare 200 many app servers return on unknown
// paths, and not a mere echo of the requested path). The lowercase probe path
// "/oraclediagent/agentping" is deliberately NOT accepted: the real agent
// emits the mixed-case identity string "OracleDIAgent", which our lowercase
// path cannot reflect, so matching it case-sensitively defeats echo-of-path
// self-reflection.
func hasODIAgentToken(body string) bool {
	if strings.Contains(body, "ODI-") || strings.Contains(body, "OracleDIAgent") {
		return true
	}
	return strings.Contains(strings.ToLower(body), "oracle data integrator")
}

// parseODIVersion extracts a best-effort Oracle FMW version token from an
// agentping body, or "" when absent.
func parseODIVersion(body string) string {
	if m := odiVersionPattern.FindStringSubmatch(body); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// isODIConsole reports whether the /odiconsole/ response carries the
// ODI-specific "Oracle Data Integrator" title (case-insensitive). The generic
// ADF /afr/ static prefix is emitted by EVERY Oracle ADF/WebLogic app, so it is
// NOT accepted on its own; only the ODI title classifies. The caller additionally
// requires a non-404 status (a branded ADF 404 page must not classify).
func isODIConsole(title string) bool {
	return strings.Contains(strings.ToLower(title), "oracle data integrator")
}

// detectODI probes the standalone-agent liveness endpoint and the ODI Console.
func detectODI(client *http.Client, baseURL, host string) (version string, console, anon, detected bool) {
	if resp, err := doGet(client, baseURL+"/oraclediagent/agentping", host); err == nil {
		status := resp.StatusCode
		body := readBody(resp)
		if status != http.StatusNotFound && hasODIAgentToken(body) {
			detected = true
			version = parseODIVersion(body)
			if isSuccessStatus(status) {
				anon = true
			}
		}
	}
	if resp, err := doGet(client, baseURL+"/odiconsole/", host); err == nil {
		status := resp.StatusCode
		body := readBody(resp)
		if status != http.StatusNotFound && isODIConsole(extractTitle(body)) {
			detected = true
			console = true
			if isSuccessStatus(status) {
				anon = true
			}
		}
	}
	return version, console, anon, detected
}

func buildODICPE(version string) string {
	return fmt.Sprintf("cpe:2.3:a:oracle:data_integrator:%s:*:*:*:*:*:*:*", cpeVersion(version))
}

func odiFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-odi-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Data Integrator (ODI) agent/console surface is reachable without authentication on the network",
		Evidence:    "Oracle Data Integrator endpoint responded without credentials",
	}
}

// --- OLVM (Oracle Linux Virtualization Manager) ---

// olvmEvidence captures the inspectable parts of the OLVM probe responses.
type olvmEvidence struct {
	rootStatus   int
	rootLocation string
	rootTitle    string
	rootBody     string
	apiStatus    int
	apiBody      string
}

// hasOvirtPresence reports whether an ovirt-engine tier is present (a redirect
// Location / landing body referencing ovirt-engine, or a 401 challenge on the
// REST API). A 401 is presence, not anonymous access.
func hasOvirtPresence(ev olvmEvidence) bool {
	if strings.Contains(strings.ToLower(ev.rootLocation), "ovirt-engine") ||
		strings.Contains(strings.ToLower(ev.rootBody), "ovirt-engine") {
		return true
	}
	return ev.apiStatus == http.StatusUnauthorized
}

// hasOLVMBranding reports whether an Oracle/OLVM branding marker is present. This
// is what distinguishes OLVM from generic upstream oVirt / RHV.
func hasOLVMBranding(ev olvmEvidence) bool {
	hay := strings.ToLower(ev.rootTitle + " " + ev.rootBody + " " + ev.apiBody)
	return strings.Contains(hay, "oracle linux virtualization manager") ||
		strings.Contains(hay, "olvm")
}

// evaluateOLVM requires BOTH an ovirt-engine presence marker AND Oracle/OLVM
// branding (strict rule: generic oVirt without an Oracle marker is not claimed).
func evaluateOLVM(ev olvmEvidence) bool {
	return hasOvirtPresence(ev) && hasOLVMBranding(ev)
}

// detectOLVM probes the engine landing page and the REST API root.
func detectOLVM(client *http.Client, baseURL, host string) (anon, detected bool) {
	var ev olvmEvidence
	if resp, err := doGet(client, baseURL+"/ovirt-engine/", host); err == nil {
		ev.rootStatus = resp.StatusCode
		ev.rootLocation = resp.Header.Get("Location")
		ev.rootBody = readBody(resp)
		ev.rootTitle = extractTitle(ev.rootBody)
	}
	if resp, err := doGet(client, baseURL+"/ovirt-engine/api", host); err == nil {
		ev.apiStatus = resp.StatusCode
		ev.apiBody = readBody(resp)
	}
	if !evaluateOLVM(ev) {
		return false, false
	}
	return isSuccessStatus(ev.rootStatus), true
}

func buildOLVMCPE(version string) string {
	return fmt.Sprintf("cpe:2.3:a:ovirt:ovirt-engine:%s:*:*:*:*:*:*:*", cpeVersion(version))
}

func olvmFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-olvm-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Linux Virtualization Manager (OLVM) engine surface is reachable without authentication on the network",
		Evidence:    "Oracle Linux Virtualization Manager engine responded without credentials",
	}
}

// --- shared Oracle infra Run (InfraPlugin / InfraTLSPlugin) ---

// runInfra probes the ILOM -> ODI -> OLVM surfaces on one connection (ordered by
// signal specificity; the products do not share ports in practice, so at most
// one matches) and returns the first match, or nil when nothing is detected.
func runInfra(conn net.Conn, timeout time.Duration, target plugins.Target, tls bool, transport plugins.Protocol) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	if firmware, redfish, anon, detected := detectILOM(client, baseURL, target.Host); detected {
		payload := plugins.ServiceOracleInfra{
			Product:  ProductILOM,
			Firmware: firmware,
			Redfish:  redfish,
			CPEs:     []string{buildILOMCPE(firmware)},
		}
		return finishInfra(conn, target, payload, firmware, tls, transport, anon, ilomFinding()), nil
	}

	if version, console, anon, detected := detectODI(client, baseURL, target.Host); detected {
		payload := plugins.ServiceOracleInfra{
			Product: ProductODI,
			Console: console,
			CPEs:    []string{buildODICPE(version)},
		}
		return finishInfra(conn, target, payload, version, tls, transport, anon, odiFinding()), nil
	}

	if anon, detected := detectOLVM(client, baseURL, target.Host); detected {
		payload := plugins.ServiceOracleInfra{
			Product: ProductOLVM,
			CPEs:    []string{buildOLVMCPE("")},
		}
		return finishInfra(conn, target, payload, "", tls, transport, anon, olvmFinding()), nil
	}

	return nil, nil
}

// finishInfra builds the service and, under --misconfigs, sets AnonymousAccess
// and appends the product exposure finding only on a genuine 2xx (anon), and
// (TLS only) appends the generic TLS checks. Shared by both transport variants
// (DRY).
func finishInfra(conn net.Conn, target plugins.Target, payload plugins.ServiceOracleInfra, version string, tls bool, transport plugins.Protocol, anon bool, finding plugins.SecurityFinding) *plugins.Service {
	service := plugins.CreateServiceFrom(target, payload, tls, version, transport)
	if target.Misconfigs {
		// AnonymousAccess and the "responded without credentials" exposure
		// finding are asserted only when the surface actually answered
		// anonymously on a 2xx. A product detected from a 401 challenge or a
		// non-404 (auth-gated) response still emits the service (detection/CPE)
		// but does not claim anonymous access.
		if anon {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, finding)
		}
		if tls {
			service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
		}
	}
	return service
}

func (p *InfraPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return runInfra(conn, timeout, target, false, plugins.TCP)
}

func (p *InfraPlugin) PortPriority(port uint16) bool {
	return port == DefaultODIAgentPort || port == 80
}
func (p *InfraPlugin) Name() string           { return "oracle_infra" }
func (p *InfraPlugin) Type() plugins.Protocol { return plugins.TCP }
func (p *InfraPlugin) Priority() int          { return -1 } // Runs before generic HTTP so it can claim shared ports

func (p *InfraTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	return runInfra(conn, timeout, target, true, plugins.TCPTLS)
}

func (p *InfraTLSPlugin) PortPriority(port uint16) bool { return port == 443 || port == 8443 }
func (p *InfraTLSPlugin) Name() string                  { return "oracle_infra" }
func (p *InfraTLSPlugin) Type() plugins.Protocol        { return plugins.TCPTLS }
func (p *InfraTLSPlugin) Priority() int                 { return -1 } // Runs before generic HTTPS so it can claim shared ports (e.g. 443)

// --- VirtualBox web service (SOAP on 18083) ---

// vboxSOAPBody is a single read-only IVirtualBox_getVersion call with an empty
// object reference. vboxwebsrv replies with a SOAP fault whose envelope carries
// the vbox namespace, which is the fingerprint. This call takes no credentials,
// creates no session, and changes no state.
const vboxSOAPBody = `<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/"
  xmlns:xsd="http://www.w3.org/2001/XMLSchema"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xmlns:vbox="http://www.virtualbox.org/">
  <SOAP-ENV:Body>
    <vbox:IVirtualBox_getVersion><_this></_this></vbox:IVirtualBox_getVersion>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>`

// matchVBoxSOAP reports whether a response body carries the VirtualBox SOAP
// namespace TOGETHER WITH a vbox-SPECIFIC response/fault element that only a
// genuine vboxwebsrv reply emits. The vbox namespace alone is insufficient: it
// is also present in the request we POST (see vboxSOAPBody's xmlns:vbox
// declaration), so a server that merely echoes our request body — including a
// generic SOAP Fault that reflects our submitted XML in its fault detail — would
// otherwise match. Generic SOAP tokens (Fault/faultstring/returnval) are
// therefore NOT accepted: a request-echoing SOAP server carries our vbox
// namespace plus its own generic Fault/faultstring wrapper. Instead we require a
// vbox-specific element that our request never contains and a generic
// fault-with-echo would not add: the getVersion response element, or a documented
// vboxwebsrv fault type (InvalidObjectFault / RuntimeFault; see
// protocol-research.md §4). A generic gSOAP / SOAP 500 without the vbox namespace
// still does not match.
func matchVBoxSOAP(body string) bool {
	if !strings.Contains(body, "http://www.virtualbox.org/") {
		return false
	}
	return strings.Contains(body, "getVersionResponse") ||
		strings.Contains(body, "InvalidObjectFault") ||
		strings.Contains(body, "RuntimeFault")
}

// detectVBoxWeb sends the single read-only getVersion SOAP POST and matches the
// vbox namespace in the response.
func detectVBoxWeb(conn net.Conn, timeout time.Duration) bool {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	req, err := http.NewRequest("POST", baseURL+"/", strings.NewReader(vboxSOAPBody))
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Content-Type", "text/xml; charset=utf-8")
	req.Header.Set("SOAPAction", "")

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	return matchVBoxSOAP(readBody(resp))
}

func buildVBoxCPE() string {
	return "cpe:2.3:a:oracle:vm_virtualbox:*:*:*:*:*:*:*:*"
}

func vboxFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-virtualbox-websrv-exposed",
		Severity:    plugins.SeverityLow,
		Description: "VirtualBox web service (vboxwebsrv) SOAP API is reachable on the network; the API controls virtual machines and should not be exposed to untrusted networks",
		Evidence:    "VirtualBox web service responded to an unauthenticated SOAP request",
	}
}

func (p *VBoxWebPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	if !detectVBoxWeb(conn, timeout) {
		return nil, nil
	}
	payload := plugins.ServiceVirtualBoxWeb{
		CPEs: []string{buildVBoxCPE()},
	}
	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
	if target.Misconfigs {
		service.SecurityFindings = append(service.SecurityFindings, vboxFinding())
	}
	return service, nil
}

func (p *VBoxWebPlugin) PortPriority(port uint16) bool { return port == DefaultVBoxWebPort }
func (p *VBoxWebPlugin) Name() string                  { return plugins.ProtoVirtualBoxWeb }
func (p *VBoxWebPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *VBoxWebPlugin) Priority() int                 { return -1 } // Runs before generic http so it can claim 18083
