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
Oracle GlassFish / Payara Server HTTP Fingerprinting (LAB-5051)

This package detects Oracle GlassFish (the Jakarta EE / Java EE reference
application server, formerly Sun) and Payara Server (a production fork of
GlassFish Open Source Edition). Because Payara is a fork, the two products share
nearly identical HTTP surfaces, default ports, and admin console; they are
distinguished almost entirely by the product-name substring embedded in the
Server / X-Powered-By headers. One package therefore registers two transport
variants (TCP + TLS) and emits a dynamic product identity.

Detection Strategy (best-effort, non-fatal errors, single connection):

  1. GET "/"                 -> inspect the Server and X-Powered-By headers.
  2. GET "/common/index.jsf" -> Domain Admin Server (DAS) console corroboration.

  A host is classified only when a BRANDED token ("glassfish" or "payara",
  case-insensitive) appears in a Server or X-Powered-By header, or when the admin
  console path returns a branded 2xx page. A bare "X-Powered-By: Servlet/x"
  WITHOUT a branded token is NOT sufficient (Tomcat, Jetty, WildFly and WebLogic
  all emit it). A bare 200 on /common/index.jsf without a branded marker is NOT
  sufficient either.

Product discrimination:
  Any branded token containing "payara" -> Payara (protocol "payara"); otherwise
  the GlassFish family (protocol "oracle_glassfish"), which covers GlassFish
  Server Open Source Edition, Eclipse GlassFish and legacy Sun GlassFish
  Enterprise Server banners.

Version / JDK:
  Parsed preferentially from the X-Powered-By parenthetical (richest source:
  version + JDK), falling back to the Server header version token. JDK is only
  ever available from X-Powered-By. Degrades to "" (known product, unknown
  version) when stripped.

CPE Format (one product-appropriate CPE per host):
  GlassFish / Sun / Eclipse lineage:
    cpe:2.3:a:oracle:glassfish_server:<ver-or-*>:*:*:*:*:*:*:*
  Payara:
    cpe:2.3:a:payara:payara:<ver-or-*>:*:*:*:*:*:*:*

Default Ports:
  - 8080 default HTTP listener, 4848 admin console (TCP variant)
  - 8181 default HTTPS listener, 4848 admin console, 443 (TLS variant)
*/

package glassfish

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
	// DefaultHTTPPort is the GlassFish/Payara default HTTP listener.
	DefaultHTTPPort = 8080
	// DefaultHTTPSPort is the GlassFish/Payara default HTTPS listener.
	DefaultHTTPSPort = 8181
	// AdminPort is the Domain Admin Server (DAS) console port.
	AdminPort = 4848
	// maxResponseSize caps how much of each HTTP body is read.
	maxResponseSize = int64(10 * 1024 * 1024)

	productGlassFish = "glassfish"
	productPayara    = "payara"
	productEclipse   = "eclipse"

	rootPath  = "/"
	adminPath = "/common/index.jsf"
)

// xPoweredByPattern extracts the product, version and (optional) JDK from the
// X-Powered-By parenthetical, e.g.
// "(GlassFish Server Open Source Edition 4.1.1 Java/Oracle Corporation/1.8)".
//
//	Group 1 -> product family (GlassFish vs Payara)
//	Group 2 -> app-server version (4.1.1, 5.0, 5.2021.1)
//	Group 3 -> JDK version (1.8, 11, 17); empty when the build omits it
var xPoweredByPattern = regexp.MustCompile(`(?i)\((GlassFish Server Open Source Edition|Payara Server)\s+([0-9][0-9A-Za-z.]*)(?:[^)]*?Java/[^/)]+/([0-9._]+))?[^)]*\)`)

// serverVersionPattern extracts the version token that follows a branded Server
// header product name, tolerating the optional "v" prefix (Sun GlassFish
// Enterprise Server v2.1) and slash separator (Eclipse GlassFish/7.0.0).
var serverVersionPattern = regexp.MustCompile(`(?i)(?:GlassFish Server Open Source Edition|Payara Server|Eclipse GlassFish|Sun GlassFish Enterprise Server(?:\s+v)?)\s*/?\s*v?([0-9][0-9A-Za-z._]*)`)

type GlassFishPlugin struct{}

// GlassFishTLSPlugin detects the GlassFish/Payara family over TLS connections.
type GlassFishTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&GlassFishPlugin{})
	plugins.RegisterPlugin(&GlassFishTLSPlugin{})
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

// isSuccessStatus reports whether an HTTP status code is a 2xx success.
func isSuccessStatus(code int) bool {
	return code >= 200 && code < 300
}

// hasGlassFishMarker reports whether a header/body value carries the branded
// GlassFish token (case-insensitive). This covers "GlassFish Server Open Source
// Edition", "Eclipse GlassFish" and "Sun GlassFish Enterprise Server".
func hasGlassFishMarker(s string) bool {
	return strings.Contains(strings.ToLower(s), productGlassFish)
}

// hasPayaraMarker reports whether a header/body value carries the branded Payara
// token (case-insensitive).
func hasPayaraMarker(s string) bool {
	return strings.Contains(strings.ToLower(s), productPayara)
}

// hasEclipseMarker reports whether a value carries the Eclipse GlassFish brand
// ("Eclipse GlassFish", case-insensitive). Eclipse GlassFish is part of the
// GlassFish family for detection, but its CVEs are keyed to eclipse:glassfish
// rather than oracle:glassfish_server, so the lineage is tracked separately for
// CPE construction.
func hasEclipseMarker(s string) bool {
	return strings.Contains(strings.ToLower(s), "eclipse glassfish")
}

// isBranded reports whether a value carries any branded GlassFish/Payara token.
func isBranded(s string) bool {
	return hasGlassFishMarker(s) || hasPayaraMarker(s)
}

// classifyProduct returns the product ("payara" / "glassfish") named by a branded
// Server or X-Powered-By header, or "" when neither header is branded. Payara
// takes precedence (it is the more specific fork identity). A bare "Servlet/x"
// X-Powered-By or a generic Server header is deliberately NOT a classifier.
func classifyProduct(server, xpb string) string {
	if hasPayaraMarker(server) || hasPayaraMarker(xpb) {
		return productPayara
	}
	if hasGlassFishMarker(server) || hasGlassFishMarker(xpb) {
		return productGlassFish
	}
	return ""
}

// parseXPoweredBy extracts (product, version, jdk) from an X-Powered-By header.
// Any group absent from the header is returned as "".
func parseXPoweredBy(xpb string) (product, version, jdk string) {
	m := xPoweredByPattern.FindStringSubmatch(xpb)
	if len(m) < 4 {
		return "", "", ""
	}
	if strings.Contains(strings.ToLower(m[1]), productPayara) {
		product = productPayara
	} else {
		product = productGlassFish
	}
	return product, m[2], m[3]
}

// parseServerVersion extracts the version token from a branded Server header,
// returning "" when the version has been stripped or the header is unbranded.
func parseServerVersion(server string) string {
	if m := serverVersionPattern.FindStringSubmatch(server); len(m) >= 2 {
		return m[1]
	}
	return ""
}

// buildGlassFishCPEs returns the single product-appropriate CPE for a detected
// host. The version wildcards to "*" when unknown.
func buildGlassFishCPEs(product, version string) []string {
	v := version
	if v == "" {
		v = "*"
	}
	switch product {
	case productPayara:
		return []string{fmt.Sprintf("cpe:2.3:a:payara:payara:%s:*:*:*:*:*:*:*", v)}
	case productEclipse:
		// Eclipse GlassFish 5.1+/6/7 CVEs use eclipse:glassfish, e.g. CVE-2024-8646.
		return []string{fmt.Sprintf("cpe:2.3:a:eclipse:glassfish:%s:*:*:*:*:*:*:*", v)}
	default:
		return []string{fmt.Sprintf("cpe:2.3:a:oracle:glassfish_server:%s:*:*:*:*:*:*:*", v)}
	}
}

// gfEvidence captures the inspectable parts of a single GlassFish/Payara probe.
type gfEvidence struct {
	path       string
	statusCode int
	server     string
	xPoweredBy string
	body       string
}

// evaluate inspects collected evidence and decides whether the host is a
// GlassFish/Payara server. statusCode is the root ("/") response status (used to
// gate anonymous-access reporting). adminConsole is true only when the DAS
// console path returned a branded 2xx page.
func evaluate(evs []gfEvidence) (product, version, jdk string, adminConsole bool, statusCode int, detected bool) {
	var payara, glassfish, eclipse bool
	var xpbForVersion, serverForVersion string

	for _, ev := range evs {
		if ev.path == rootPath {
			statusCode = ev.statusCode
		}

		// Product classification from branded Server / X-Powered-By headers on
		// any probed path. classifyProduct is the single source of truth for
		// header-based branding (Payara wins over GlassFish; unbranded -> "").
		switch classifyProduct(ev.server, ev.xPoweredBy) {
		case productPayara:
			payara, detected = true, true
		case productGlassFish:
			glassfish, detected = true, true
		}

		// Eclipse GlassFish lineage: tracked separately from plain GlassFish so
		// the CPE can be keyed to eclipse:glassfish. Detection is unaffected
		// (classifyProduct already sets glassfish=true since "eclipse glassfish"
		// contains "glassfish").
		if hasEclipseMarker(ev.server) || hasEclipseMarker(ev.xPoweredBy) || hasEclipseMarker(ev.body) {
			eclipse = true
		}

		// Admin-console corroboration: a branded header or branded body on a 2xx
		// response to the DAS console path. A bare 200 without a branded marker is
		// NOT sufficient.
		if ev.path == adminPath && isSuccessStatus(ev.statusCode) && (isBranded(ev.server) || isBranded(ev.xPoweredBy) || isBranded(ev.body)) {
			adminConsole, detected = true, true
			if hasPayaraMarker(ev.server) || hasPayaraMarker(ev.xPoweredBy) || hasPayaraMarker(ev.body) {
				payara = true
			} else {
				glassfish = true
			}
		}

		// Version sources: first branded X-Powered-By (richest), else first
		// branded Server header.
		if xpbForVersion == "" && isBranded(ev.xPoweredBy) {
			xpbForVersion = ev.xPoweredBy
		}
		if serverForVersion == "" && isBranded(ev.server) {
			serverForVersion = ev.server
		}
	}

	if !detected {
		return "", "", "", false, statusCode, false
	}

	// Product/CPE lineage precedence: Payara wins, then Eclipse GlassFish, then
	// plain GlassFish. Only the CPE vendor differs; the emitted technology stays
	// oracle_glassfish for both eclipse and glassfish (ServiceGlassFish.Type()).
	switch {
	case payara:
		product = productPayara
	case eclipse:
		product = productEclipse
	default:
		_ = glassfish
		product = productGlassFish
	}

	// Prefer the X-Powered-By version + JDK; fall back to the Server version.
	_, version, jdk = parseXPoweredBy(xpbForVersion)
	if version == "" {
		version = parseServerVersion(serverForVersion)
	}

	return product, version, jdk, adminConsole, statusCode, true
}

// detectGlassFish fetches the probe paths on the single connection and evaluates
// the collected evidence. server/xpb returned are the raw root ("/") headers for
// the service payload.
func detectGlassFish(client *http.Client, baseURL, host string) (product, version, jdk, server, xpb string, adminConsole bool, statusCode int, detected bool) {
	var evs []gfEvidence
	for _, p := range []string{rootPath, adminPath} {
		resp, err := doGet(client, baseURL+p, host)
		if err != nil {
			// Non-fatal: continue with whatever other evidence we can gather.
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		ev := gfEvidence{
			path:       p,
			statusCode: resp.StatusCode,
			server:     resp.Header.Get("Server"),
			xPoweredBy: resp.Header.Get("X-Powered-By"),
			body:       string(body),
		}
		if p == rootPath {
			server = ev.server
			xpb = ev.xPoweredBy
		}
		evs = append(evs, ev)
		_ = resp.Body.Close()
	}
	product, version, jdk, adminConsole, statusCode, detected = evaluate(evs)
	return product, version, jdk, server, xpb, adminConsole, statusCode, detected
}

// glassfishExposedFinding reports data-plane banner / version disclosure via the
// Server / X-Powered-By headers.
func glassfishExposedFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "glassfish-payara-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle GlassFish / Payara application server is reachable and advertises its product and version via the Server / X-Powered-By response header, aiding targeted exploitation",
		Evidence:    "GlassFish/Payara Server header returned without credentials",
	}
}

// glassfishAdminConsoleFinding reports that the Domain Admin Server (DAS) console
// is reachable on the network without authentication.
func glassfishAdminConsoleFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "glassfish-payara-admin-console-exposed",
		Severity:    plugins.SeverityMedium,
		Description: "Oracle GlassFish / Payara administration console (Domain Admin Server) is reachable without authentication on the network; the DAS provides application deployment and server configuration and should not be exposed to untrusted networks",
		Evidence:    "GlassFish/Payara admin console (/common/index.jsf) responded without credentials",
	}
}

// applyMisconfigs appends the appropriate exposure finding and sets
// AnonymousAccess. The admin-console finding (Medium) takes precedence over the
// data-plane banner finding (Low) when the DAS console is confirmed reachable;
// neither fires on a non-2xx surface. Shared by both transport variants (DRY).
func applyMisconfigs(service *plugins.Service, adminConsole bool, statusCode int) {
	switch {
	case adminConsole:
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, glassfishAdminConsoleFinding())
	case isSuccessStatus(statusCode):
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, glassfishExposedFinding())
	}
}

func (p *GlassFishPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	product, version, jdk, server, xpb, adminConsole, statusCode, detected := detectGlassFish(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceGlassFish{
		Product:      product,
		Server:       server,
		XPoweredBy:   xpb,
		JDK:          jdk,
		AdminConsole: adminConsole,
		CPEs:         buildGlassFishCPEs(product, version),
	}
	service := plugins.CreateServiceFrom(target, payload, false, version, plugins.TCP)
	if target.Misconfigs {
		applyMisconfigs(service, adminConsole, statusCode)
	}
	return service, nil
}

func (p *GlassFishPlugin) PortPriority(port uint16) bool {
	return port == DefaultHTTPPort || port == AdminPort
}
func (p *GlassFishPlugin) Name() string           { return "glassfish" }
func (p *GlassFishPlugin) Type() plugins.Protocol { return plugins.TCP }
func (p *GlassFishPlugin) Priority() int          { return -1 } // Runs before generic HTTP so it can claim the port

func (p *GlassFishTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	client := createHTTPClient(conn, timeout)
	baseURL := fmt.Sprintf("http://%s", conn.RemoteAddr().String())

	product, version, jdk, server, xpb, adminConsole, statusCode, detected := detectGlassFish(client, baseURL, target.Host)
	if !detected {
		return nil, nil
	}

	payload := plugins.ServiceGlassFish{
		Product:      product,
		Server:       server,
		XPoweredBy:   xpb,
		JDK:          jdk,
		AdminConsole: adminConsole,
		CPEs:         buildGlassFishCPEs(product, version),
	}
	service := plugins.CreateServiceFrom(target, payload, true, version, plugins.TCPTLS)
	if target.Misconfigs {
		applyMisconfigs(service, adminConsole, statusCode)
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

// PortPriority prioritizes the GlassFish/Payara HTTPS listener (8181), the admin
// console (4848), and standard HTTPS (443).
func (p *GlassFishTLSPlugin) PortPriority(port uint16) bool {
	return port == DefaultHTTPSPort || port == AdminPort || port == 443
}
func (p *GlassFishTLSPlugin) Name() string           { return "glassfish" }
func (p *GlassFishTLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }
func (p *GlassFishTLSPlugin) Priority() int          { return -1 } // Runs before generic HTTPS so it can claim the port
