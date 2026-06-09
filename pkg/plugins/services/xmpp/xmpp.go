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

package xmpp

import (
	"encoding/xml"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	XMPP            = "xmpp"
	DefaultXMPPPort = 5222
)

// streamFeatures represents the XMPP stream:features element.
type streamFeatures struct {
	XMLName     xml.Name     `xml:"features"`
	StartTLS    *startTLS    `xml:"starttls"`
	Mechanisms  *mechanisms  `xml:"mechanisms"`
	Compression *compression `xml:"compression"`
	Caps        *caps        `xml:"c"`
}

type startTLS struct {
	Required *struct{} `xml:"required"`
}

type mechanisms struct {
	Mechanism []string `xml:"mechanism"`
}

type compression struct {
	Method []string `xml:"method"`
}

type caps struct {
	Hash string `xml:"hash,attr"`
	Node string `xml:"node,attr"`
	Ver  string `xml:"ver,attr"`
}

// serverPatterns matches XMPP server software by the caps node URI.
var serverPatterns = []struct {
	product string
	pattern *regexp.Regexp
}{
	{"ejabberd", regexp.MustCompile(`process-one\.net/en/ejabberd`)},
	{"Prosody", regexp.MustCompile(`prosody\.im`)},
	{"Openfire", regexp.MustCompile(`igniterealtime\.org`)},
	{"Tigase", regexp.MustCompile(`tigase\.org`)},
	{"MongooseIM", regexp.MustCompile(`erlang-solutions\.com`)},
}

// cpeVendors maps server software names to CPE 2.3 format strings.
var cpeVendors = map[string]string{
	"ejabberd":   "cpe:2.3:a:process-one:ejabberd:%s:*:*:*:*:*:*:*",
	"Prosody":    "cpe:2.3:a:prosody:prosody:%s:*:*:*:*:*:*:*",
	"Openfire":   "cpe:2.3:a:igniterealtime:openfire:%s:*:*:*:*:*:*:*",
	"Tigase":     "cpe:2.3:a:tigase:tigase:%s:*:*:*:*:*:*:*",
	"MongooseIM": "cpe:2.3:a:erlang-solutions:mongooseim:%s:*:*:*:*:*:*:*",
}

// streamAttrPattern extracts attributes from the <stream:stream> opening tag.
var streamAttrPattern = regexp.MustCompile(`<stream:stream[^>]+>`)
var streamIDPattern = regexp.MustCompile(`id=['"]([^'"]+)['"]`)
var streamFromPattern = regexp.MustCompile(`from=['"]([^'"]+)['"]`)

type TCPPlugin struct{}

func init() {
	plugins.RegisterPlugin(&TCPPlugin{})
}

func (p *TCPPlugin) PortPriority(port uint16) bool { return port == DefaultXMPPPort }
func (p *TCPPlugin) Name() string                  { return XMPP }
func (p *TCPPlugin) Type() plugins.Protocol        { return plugins.TCP }
func (p *TCPPlugin) Priority() int                 { return 100 }

// buildXMPPProbe returns the XMPP stream initiation probe bytes.
// host is used as the 'to' attribute in the stream header; falls back to "localhost" if empty.
func buildXMPPProbe(host string) []byte {
	if host == "" {
		host = "localhost"
	}
	probe := fmt.Sprintf("<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' to='%s' version='1.0'>", host)
	return []byte(probe)
}

// isXMPPResponse validates that the response is an XMPP stream response.
func isXMPPResponse(response []byte) bool {
	resp := string(response)
	if !strings.Contains(resp, "<stream:stream") {
		return false
	}
	return strings.Contains(resp, "jabber:client") || strings.Contains(resp, "etherx.jabber.org/streams")
}

// extractStreamAttributes parses stream ID and from attributes from the stream opening tag.
func extractStreamAttributes(response string) (streamID, serverFrom string) {
	// Find the stream:stream opening tag
	match := streamAttrPattern.FindString(response)
	if match == "" {
		return "", ""
	}

	idMatches := streamIDPattern.FindStringSubmatch(match)
	if len(idMatches) >= 2 {
		streamID = idMatches[1]
	}

	fromMatches := streamFromPattern.FindStringSubmatch(match)
	if len(fromMatches) >= 2 {
		serverFrom = fromMatches[1]
	}

	return streamID, serverFrom
}

// extractFeaturesBlock finds and returns the content of <stream:features>...</stream:features>.
func extractFeaturesBlock(response string) string {
	start := strings.Index(response, "<stream:features>")
	if start == -1 {
		// Try without namespace prefix
		start = strings.Index(response, "<features>")
		if start == -1 {
			return ""
		}
		end := strings.Index(response[start:], "</features>")
		if end == -1 {
			return ""
		}
		return response[start : start+end+len("</features>")]
	}

	end := strings.Index(response[start:], "</stream:features>")
	if end == -1 {
		return ""
	}
	return response[start : start+end+len("</stream:features>")]
}

// parseFeaturesXML parses the stream:features block into a streamFeatures struct.
// XMPP responses are incomplete XML (the stream is left open), so we extract only
// the features block and normalize it before parsing.
func parseFeaturesXML(featuresBlock string) *streamFeatures {
	if featuresBlock == "" {
		return nil
	}

	// Normalize: replace stream:features tags with plain features tags to avoid
	// namespace prefix issues with Go's xml.Decoder.
	normalized := strings.ReplaceAll(featuresBlock, "<stream:features>", "<features>")
	normalized = strings.ReplaceAll(normalized, "</stream:features>", "</features>")

	// Strip xmlns attributes that would confuse namespace-unaware parsing.
	// Use a simple approach: parse without namespace enforcement.
	normalized = stripXMLNamespaces(normalized)

	var sf streamFeatures
	if err := xml.Unmarshal([]byte(normalized), &sf); err != nil {
		return nil
	}
	return &sf
}

// Namespace stripping patterns (compiled once for performance).
var (
	nsSingleQuote  = regexp.MustCompile(`\s+xmlns='[^']*'`)
	nsDoubleQuote  = regexp.MustCompile(`\s+xmlns="[^"]*"`)
	nsPrefixSingle = regexp.MustCompile(`\s+xmlns:[a-z]+='[^']*'`)
	nsPrefixDouble = regexp.MustCompile(`\s+xmlns:[a-z]+="[^"]*"`)
)

// stripXMLNamespaces removes xmlns="..." and xmlns:prefix="..." attributes from XML.
// This is necessary because Go's xml.Decoder treats xmlns as namespaces and the
// XMPP feature elements use varying namespace URIs.
func stripXMLNamespaces(s string) string {
	s = nsSingleQuote.ReplaceAllString(s, "")
	s = nsDoubleQuote.ReplaceAllString(s, "")
	s = nsPrefixSingle.ReplaceAllString(s, "")
	s = nsPrefixDouble.ReplaceAllString(s, "")
	return s
}

// identifyServerSoftware matches a caps node URI against known server patterns.
func identifyServerSoftware(capsNode string) string {
	if capsNode == "" {
		return ""
	}
	for _, sp := range serverPatterns {
		if sp.pattern.MatchString(capsNode) {
			return sp.product
		}
	}
	return ""
}

// buildXMPPCPE generates a CPE 2.3 string for a known XMPP server.
func buildXMPPCPE(product, version string) string {
	if product == "" {
		return ""
	}
	cpeTemplate, exists := cpeVendors[product]
	if !exists {
		return ""
	}
	if version == "" {
		version = "*"
	}
	return fmt.Sprintf(cpeTemplate, version)
}

// tlsSupportString converts startTLS presence and required flag to a descriptive string.
func tlsSupportString(tls *startTLS) string {
	if tls == nil {
		return ""
	}
	if tls.Required != nil {
		return "required"
	}
	return "optional"
}

func (p *TCPPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	// Phase 1: Send XMPP stream initiation probe and validate response.
	probe := buildXMPPProbe(target.Host)
	response, err := utils.SendRecv(conn, probe, timeout)
	if err != nil {
		return nil, err
	}

	if len(response) == 0 {
		return nil, nil
	}

	if !isXMPPResponse(response) {
		return nil, nil
	}

	// Some servers send <stream:stream> and <stream:features> in separate TCP
	// segments. If the features block is not in the first read, try a second read.
	if !strings.Contains(string(response), "<stream:features") {
		more, err := utils.Recv(conn, timeout)
		if err == nil && len(more) > 0 {
			response = append(response, more...)
		}
	}

	// Phase 2: Enrich - parse features from the response.
	respStr := string(response)

	streamID, serverFrom := extractStreamAttributes(respStr)
	featuresBlock := extractFeaturesBlock(respStr)
	sf := parseFeaturesXML(featuresBlock)

	var authMechanisms []string
	var compressionMethods []string
	tlsSupport := ""
	capsNode := ""
	capsVer := ""

	if sf != nil {
		if sf.Mechanisms != nil {
			authMechanisms = sf.Mechanisms.Mechanism
		}
		tlsSupport = tlsSupportString(sf.StartTLS)
		if sf.Compression != nil {
			compressionMethods = sf.Compression.Method
		}
		if sf.Caps != nil {
			capsNode = sf.Caps.Node
			capsVer = sf.Caps.Ver
		}
	}

	// Identify server software from caps node URI.
	serverSoftware := identifyServerSoftware(capsNode)
	cpe := buildXMPPCPE(serverSoftware, "")

	var cpes []string
	if cpe != "" {
		cpes = []string{cpe}
	}

	payload := plugins.ServiceXMPP{
		StreamID:       streamID,
		ServerFrom:     serverFrom,
		AuthMechanisms: authMechanisms,
		TLSSupport:     tlsSupport,
		Compression:    compressionMethods,
		CapsNode:       capsNode,
		CapsVer:        capsVer,
		ServerSoftware: serverSoftware,
		CPEs:           cpes,
	}

	service := plugins.CreateServiceFrom(target, payload, false, "", plugins.TCP)
	if target.Misconfigs && sf != nil && tlsSupport == "" {
		service.SecurityFindings = []plugins.SecurityFinding{{
			ID:          "xmpp-cleartext",
			Severity:    plugins.SeverityMedium,
			Description: "XMPP transmits data including credentials in cleartext",
			Evidence:    "STARTTLS not offered in stream features",
		}}
	}
	return service, nil
}
