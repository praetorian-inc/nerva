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
Oracle HTTP Server / iPlanet Web Server HTTP Fingerprinting (LAB-5041)

This plugin detects the Oracle HTTP Server family via the Server response
header. It covers the Oracle HTTP Server (OHS), the legacy Oracle Application
Server, and the Oracle iPlanet / Sun / Netscape web server lineage (Oracle
iPlanet Web Server, Sun Java System Web Server, Sun ONE Web Server, Netscape
Enterprise Server).

Detection Strategy (best-effort, non-fatal errors):

  The plugin issues a GET request to "/" and inspects the Server response
  header. A host is classified as Oracle HTTP Server when the Server header
  matches (case-insensitive) any of the recognized product tokens:
    - Oracle-HTTP-Server
    - Oracle-Application-Server
    - Oracle-iPlanet-Web-Server
    - Sun-Java-System-Web-Server
    - Sun-ONE-Web-Server
    - Netscape-Enterprise

  Generic Apache/nginx Server headers are deliberately NOT matched.

Fields:
  - Server: the raw Server response header
  - Vendor: "Oracle" for OHS / Oracle Application Server, "Oracle/Sun" for the
    iPlanet / Sun / Netscape lineage
  - FusionMiddleware: true when an X-ORACLE-DMS-ECID or X-ORACLE-DMS-RID header
    is present (indicating an Oracle Fusion Middleware Dynamic Monitoring Service
    deployment)

Version:
  Parsed from the Server token (e.g. "Oracle-HTTP-Server/2.4.52" → "2.4.52").
  Degrades to "" when the version has been stripped from the header.

CPE Format:
  For Oracle HTTP Server / Oracle Application Server (the version is an
  http_server version):
    cpe:2.3:a:oracle:http_server:<ver-or-*>:*:*:*:*:*:*:*
  For the iPlanet / Sun / Netscape lineage (the version belongs to the iPlanet
  product, not http_server), the version is stamped onto iplanet_web_server and
  the http_server CPE is left unversioned as a coarse family marker:
    cpe:2.3:a:oracle:http_server:*:*:*:*:*:*:*:*
    cpe:2.3:a:oracle:iplanet_web_server:<ver-or-*>:*:*:*:*:*:*:*

Default Ports:
  - 7777 is the classic Oracle HTTP Server port (PortPriority for the TCP variant)
  - 4443 is the OHS TLS default (PortPriority for the TLS variant; the TLS variant
    also matches 443 traffic when scanned)
*/

package oraclehttp

import (
	"context"
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
	OracleHTTPServer = "oracle_http_server"
	// DefaultOHSPort is the classic Oracle HTTP Server port.
	DefaultOHSPort = 7777
	// DefaultOHSTLSPort is the Oracle HTTP Server TLS default port.
	DefaultOHSTLSPort = 4443
	// maxResponseSize caps how much of the HTTP body is read (and discarded).
	maxResponseSize = int64(10 * 1024 * 1024)
)

// ohsVersionPattern extracts the version following a recognized product token,
// e.g. "Oracle-HTTP-Server/2.4.52" → "2.4.52".
var ohsVersionPattern = regexp.MustCompile(`(?i)(?:Oracle-HTTP-Server|Oracle-Application-Server|Oracle-iPlanet-Web-Server|Sun-Java-System-Web-Server|Sun-ONE-Web-Server|Netscape-Enterprise)/([\d]+(?:\.[\d]+)+)`)

// ohsServerMarkers are the recognized Server header product tokens (lowercased).
var ohsServerMarkers = []string{
	"oracle-http-server",
	"oracle-application-server",
	"oracle-iplanet-web-server",
	"sun-java-system-web-server",
	"sun-one-web-server",
	"netscape-enterprise",
}

// iplanetLineageMarkers are the iPlanet / Sun / Netscape lineage tokens
// (lowercased) that also warrant the iplanet_web_server CPE.
var iplanetLineageMarkers = []string{
	"oracle-iplanet-web-server",
	"sun-java-system-web-server",
	"sun-one-web-server",
	"netscape-enterprise",
}

type OHSPlugin struct{}

// OHSTLSPlugin detects the Oracle HTTP Server family over TLS connections.
type OHSTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&OHSPlugin{})
	plugins.RegisterPlugin(&OHSTLSPlugin{})
}

// createHTTPClient creates an http.Client that wraps the provided net.Conn and
// does not follow redirects (so headers can be inspected directly).
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

// doGet performs a GET request with the nerva User-Agent header. When host is
// non-empty it is set as the HTTP Host header so name-based virtual hosts are
// reached (the connection is still dialed by IP via the client's transport).
func doGet(client *http.Client, url string, host string) (*http.Response, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nerva/1.0")
	if host != "" {
		req.Host = host
	}
	return client.Do(req)
}

// matchesOHSServer reports whether a Server header value names a recognized
// Oracle HTTP Server family product (case-insensitive).
func matchesOHSServer(server string) bool {
	lower := strings.ToLower(server)
	for _, m := range ohsServerMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// isIPlanetLineage reports whether a Server header value names the iPlanet /
// Sun / Netscape web server lineage (case-insensitive).
func isIPlanetLineage(server string) bool {
	lower := strings.ToLower(server)
	for _, m := range iplanetLineageMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	return false
}

// parseOHSVersion extracts the version from a recognized Server header token.
// Returns "" when no version is present (e.g. the version was stripped).
func parseOHSVersion(server string) string {
	if m := ohsVersionPattern.FindStringSubmatch(server); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// ohsVendor returns the vendor label for a recognized Server header value.
func ohsVendor(server string) string {
	if isIPlanetLineage(server) {
		return "Oracle/Sun"
	}
	return "Oracle"
}

// buildOHSCPEs returns the CPE list for a detected Oracle HTTP Server family host.
//
// The version token in a Server header belongs to the specific product named in
// that header. For the iPlanet / Sun / Netscape lineage that product is
// iplanet_web_server, NOT http_server, so the version must be stamped onto the
// iplanet_web_server CPE and the http_server CPE is left unversioned (a coarse
// family marker only). For an actual Oracle-HTTP-Server / Oracle-Application-
// Server, the version is an http_server version and is stamped there.
func buildOHSCPEs(version string, iplanet bool) []string {
	v := version
	if v == "" {
		v = "*"
	}
	if iplanet {
		return []string{
			"cpe:2.3:a:oracle:http_server:*:*:*:*:*:*:*:*",
			fmt.Sprintf("cpe:2.3:a:oracle:iplanet_web_server:%s:*:*:*:*:*:*:*", v),
		}
	}
	return []string{fmt.Sprintf("cpe:2.3:a:oracle:http_server:%s:*:*:*:*:*:*:*", v)}
}

// isSuccessStatus reports whether an HTTP status code is a 2xx success.
func isSuccessStatus(code int) bool {
	return code >= 200 && code < 300
}

// detectOHS fetches "/" and inspects the Server header (and Fusion Middleware
// DMS headers). Returns the raw Server header, parsed version, whether the host
// is in the iPlanet lineage, whether Fusion Middleware DMS headers are present,
// the root response status code, and whether the host was detected. Detection
// works on any status; the status code is threaded out so callers can gate
// anonymous-access reporting on a 2xx response.
func detectOHS(client *http.Client, baseURL string, host string) (server string, version string, iplanet bool, fusion bool, statusCode int, detected bool) {
	resp, err := doGet(client, baseURL+"/", host)
	if err != nil {
		return "", "", false, false, 0, false
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseSize))

	statusCode = resp.StatusCode
	server = resp.Header.Get("Server")
	fusion = resp.Header.Get("X-ORACLE-DMS-ECID") != "" || resp.Header.Get("X-ORACLE-DMS-RID") != ""
	if !matchesOHSServer(server) {
		return server, "", false, fusion, statusCode, false
	}
	version = parseOHSVersion(server)
	iplanet = isIPlanetLineage(server)
	return server, version, iplanet, fusion, statusCode, true
}

func ohsFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "oracle-http-server-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle HTTP Server is reachable and advertises its product and version via the Server response header, aiding targeted exploitation",
		Evidence:    "Oracle HTTP Server family Server header returned without credentials",
	}
}

func (p *OHSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	server, version, iplanet, fusion, statusCode, detected := detectOHS(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleHTTPServer{
		Server:           server,
		Vendor:           ohsVendor(server),
		FusionMiddleware: fusion,
		CPEs:             buildOHSCPEs(version, iplanet),
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	// A Server header on a 401/403 is not anonymous access: only report
	// anonymous access / the finding when the root response is a 2xx success.
	if target.Misconfigs && isSuccessStatus(statusCode) {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, ohsFinding())
	}
	return service, nil
}

func (p *OHSPlugin) PortPriority(port uint16) bool { return port == DefaultOHSPort }
func (p *OHSPlugin) Name() string                  { return OracleHTTPServer }
func (p *OHSPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *OHSPlugin) Priority() int                 { return -1 } // Runs before generic HTTP so it can claim OHS on shared ports

func (p *OHSTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	server, version, iplanet, fusion, statusCode, detected := detectOHS(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceOracleHTTPServer{
		Server:           server,
		Vendor:           ohsVendor(server),
		FusionMiddleware: fusion,
		CPEs:             buildOHSCPEs(version, iplanet),
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		// A Server header on a 401/403 is not anonymous access: only report
		// anonymous access / the finding when the root response is a 2xx success.
		if isSuccessStatus(statusCode) {
			service.AnonymousAccess = true
			service.SecurityFindings = append(service.SecurityFindings, ohsFinding())
		}
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

// PortPriority prioritizes the OHS TLS default (4443) and standard HTTPS (443).
func (p *OHSTLSPlugin) PortPriority(port uint16) bool {
	return port == DefaultOHSTLSPort || port == 443
}
func (p *OHSTLSPlugin) Name() string           { return OracleHTTPServer }
func (p *OHSTLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }
func (p *OHSTLSPlugin) Priority() int          { return -1 } // Runs before generic HTTPS so it can claim OHS on shared ports (e.g. 443)
