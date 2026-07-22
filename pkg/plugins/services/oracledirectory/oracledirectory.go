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

// Package oracledirectory fingerprints Oracle Unified Directory (OUD) and Oracle
// Internet Directory (OID) via an anonymous rootDSE read over LDAP (1389/3060) and
// LDAPS (1636/3131). All ASN.1/BER is hand-built (no LDAP library), matching ldap.go.
package oracledirectory

import (
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	utils "github.com/praetorian-inc/nerva/pkg/plugins/pluginutils"
)

const (
	oudPortLDAP  = 1389
	oudPortLDAPS = 1636
	oidPortLDAP  = 3060
	oidPortLDAPS = 3131
)

type DirectoryPlugin struct{}
type DirectoryTLSPlugin struct{}

func init() {
	plugins.RegisterPlugin(&DirectoryPlugin{})
	plugins.RegisterPlugin(&DirectoryTLSPlugin{})
}

// tlv prepends a BER tag and definite length to content (long form when >127).
func tlv(tag byte, content []byte) []byte {
	out := []byte{tag}
	n := len(content)
	switch {
	case n < 0x80:
		out = append(out, byte(n))
	case n < 0x100:
		out = append(out, 0x81, byte(n))
	default:
		out = append(out, 0x82, byte(n>>8), byte(n))
	}
	return append(out, content...)
}

func concat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// anonBindRequest is the fixed 14-byte anonymous simple bind (msgID=2, empty DN/pw).
// SEQUENCE{ INTEGER msgID=2, [APP0] bindRequest{ INTEGER version=3, OCTET ""=name, [0] ""=pw }}.
func anonBindRequest() []byte {
	return []byte{0x30, 0x0c, 0x02, 0x01, 0x02, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00}
}

// buildRootDSESearch builds a base-scope rootDSE SearchRequest (msgID=3) requesting a
// fixed, targeted attribute set. scope=base(0), deref=never(0), sizeLimit=1, timeLimit=10.
func buildRootDSESearch() []byte {
	attr := func(s string) []byte { return tlv(0x04, []byte(s)) }
	attrList := tlv(0x30, concat(
		attr("vendorName"), attr("vendorVersion"),
		attr("orcldirectoryversion"), attr("orclProductVersion"),
	))
	filter := append([]byte{0x87, byte(len("objectClass"))}, []byte("objectClass")...) // present [7]
	body := concat(
		tlv(0x04, []byte{}),      // baseObject ""
		[]byte{0x0a, 0x01, 0x00}, // scope base(0)
		[]byte{0x0a, 0x01, 0x00}, // deref never(0)
		[]byte{0x02, 0x01, 0x01}, // sizeLimit 1
		[]byte{0x02, 0x01, 0x0a}, // timeLimit 10
		[]byte{0x01, 0x01, 0x00}, // typesOnly FALSE
		filter,
		attrList,
	)
	searchReq := tlv(0x63, body) // [APPLICATION 3] constructed
	msgID := []byte{0x02, 0x01, 0x03}
	return tlv(0x30, concat(msgID, searchReq))
}

// readTLV reads one BER element at buf[i]. Returns tag, content slice, index after the
// element, and ok=false on malformed/short input. Supports 1-byte and long-form
// (0x81/0x82) lengths; other long forms are rejected (not expected in a rootDSE reply).
func readTLV(buf []byte, i int) (tag byte, content []byte, next int, ok bool) {
	if i < 0 || i+1 >= len(buf) {
		return 0, nil, i, false
	}
	tag = buf[i]
	l := int(buf[i+1])
	j := i + 2
	switch {
	case l == 0x81:
		if j >= len(buf) {
			return 0, nil, i, false
		}
		l = int(buf[j])
		j++
	case l == 0x82:
		if j+1 >= len(buf) {
			return 0, nil, i, false
		}
		l = int(buf[j])<<8 | int(buf[j+1])
		j += 2
	case l > 0x82:
		return 0, nil, i, false
	}
	if j+l > len(buf) {
		return 0, nil, i, false
	}
	return tag, buf[j : j+l], j + l, true
}

// parseRootDSE walks all top-level LDAPMessage SEQUENCEs, finds the SearchResultEntry
// (protocolOp tag 0x64) and returns a lowercased attr->firstValue map plus the raw
// attribute-type names (needed to detect any orcl* attribute). Malformed/truncated
// input yields an empty map (no panic).
func parseRootDSE(resp []byte) (map[string]string, []string) {
	attrs := map[string]string{}
	var names []string
	pos := 0
	for pos < len(resp) {
		tag, msg, next, ok := readTLV(resp, pos)
		if !ok {
			break
		}
		pos = next
		if tag != 0x30 {
			continue
		}
		// msg = [ msgID (0x02 ...) ][ protocolOp ]
		_, _, p2, ok := readTLV(msg, 0)
		if !ok {
			continue
		}
		opTag, op, _, ok := readTLV(msg, p2)
		if !ok || opTag != 0x64 { // only SearchResultEntry
			continue
		}
		// op = [ objectName (0x04) ][ attributes SEQUENCE (0x30) ]
		_, _, q, ok := readTLV(op, 0)
		if !ok {
			continue
		}
		seqTag, seq, _, ok := readTLV(op, q)
		if !ok || seqTag != 0x30 {
			continue
		}
		r := 0
		for r < len(seq) {
			paTag, pa, rn, ok := readTLV(seq, r)
			if !ok {
				break
			}
			r = rn
			if paTag != 0x30 {
				continue
			}
			tTag, tContent, s, ok := readTLV(pa, 0) // type OCTET STRING
			if !ok || tTag != 0x04 {
				continue
			}
			name := string(tContent)
			var val string
			if setTag, set, _, ok := readTLV(pa, s); ok && setTag == 0x31 { // vals SET
				if vTag, v, _, ok := readTLV(set, 0); ok && vTag == 0x04 {
					val = string(v)
				}
			}
			names = append(names, name)
			attrs[strings.ToLower(name)] = val
		}
	}
	return attrs, names
}

var versionRE = regexp.MustCompile(`\d+(?:\.\d+)+`)

func firstVersion(s string) string {
	return versionRE.FindString(s)
}

// classify applies OID-then-OUD precedence. Returns (nil,false) for non-Oracle LDAP so
// that a generic rootDSE is left to the generic ldap plugin.
func classify(attrs map[string]string, names []string) (*plugins.ServiceOracleDirectory, bool) {
	// 1) OID: a returned attribute whose name (case-insensitive) begins with "orcl"
	// AND carries a non-empty value. An echoed/empty key is not a marker.
	for _, n := range names {
		if strings.HasPrefix(strings.ToLower(n), "orcl") && attrs[strings.ToLower(n)] != "" {
			raw := attrs["orcldirectoryversion"]
			cpeVer := firstVersion(raw)
			if cpeVer == "" {
				cpeVer = "*"
			}
			return &plugins.ServiceOracleDirectory{
				Product:          "oid",
				DirectoryVersion: raw,
				CPEs:             []string{"cpe:2.3:a:oracle:internet_directory:" + cpeVer + ":*:*:*:*:*:*:*"},
			}, true
		}
	}
	// 2) OUD: vendorVersion value contains "Oracle Unified Directory".
	vv := attrs["vendorversion"]
	if strings.Contains(strings.ToLower(vv), "oracle unified directory") {
		cpeVer := firstVersion(vv)
		if cpeVer == "" {
			cpeVer = "*"
		}
		return &plugins.ServiceOracleDirectory{
			Product:       "oud",
			VendorName:    attrs["vendorname"],
			VendorVersion: vv,
			CPEs:          []string{"cpe:2.3:a:oracle:unified_directory:" + cpeVer + ":*:*:*:*:*:*:*"},
		}, true
	}
	// 3) Not Oracle.
	return nil, false
}

// productVersion returns the version string to pass to CreateServiceFrom ("" when unknown).
func productVersion(svc *plugins.ServiceOracleDirectory) string {
	if svc.Product == "oid" {
		return firstVersion(svc.DirectoryVersion)
	}
	return firstVersion(svc.VendorVersion)
}

// detect performs an anonymous bind (best-effort; also confirms the peer speaks LDAP)
// then a single base-scope rootDSE search, parses the entry, and classifies. Returns
// (nil,false) if the peer is not an Oracle directory or the response is unusable.
func detect(conn net.Conn, timeout time.Duration) (*plugins.ServiceOracleDirectory, bool) {
	if _, err := utils.SendRecv(conn, anonBindRequest(), timeout); err != nil {
		return nil, false
	}
	resp, err := utils.SendRecv(conn, buildRootDSESearch(), timeout)
	if err != nil || len(resp) == 0 {
		return nil, false
	}
	attrs, names := parseRootDSE(resp)
	if len(attrs) == 0 {
		return nil, false
	}
	return classify(attrs, names)
}

// exposureFinding returns the product-specific "exposed" finding mandated by the
// security contract (security-lead.md §1). Evidence carries only the product+version
// fact — never namingContexts DNs or returned attribute values (types.go:50-52).
func exposureFinding(product string) plugins.SecurityFinding {
	if product == "oid" {
		return plugins.SecurityFinding{
			ID:          "oracle-oid-exposed",
			Severity:    plugins.SeverityLow,
			Description: "Oracle Internet Directory rootDSE is readable over an anonymous LDAP bind; the directory vendor, version, and naming contexts are exposed to unauthenticated clients, aiding targeted exploitation",
			Evidence:    "Oracle Internet Directory rootDSE returned Oracle directory attributes anonymously (no bind credentials)",
		}
	}
	return plugins.SecurityFinding{
		ID:          "oracle-oud-exposed",
		Severity:    plugins.SeverityLow,
		Description: "Oracle Unified Directory rootDSE is readable over an anonymous LDAP bind; the directory vendor, version, and naming contexts are exposed to unauthenticated clients, aiding targeted exploitation",
		Evidence:    "Oracle Unified Directory rootDSE returned vendor and version anonymously (no bind credentials)",
	}
}

func cleartextFinding() plugins.SecurityFinding {
	return plugins.SecurityFinding{
		ID:          "ldap-cleartext",
		Severity:    plugins.SeverityMedium,
		Description: "LDAP transmits data including credentials in cleartext",
	}
}

func (p *DirectoryPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	svc, ok := detect(conn, timeout)
	if !ok {
		return nil, nil
	}
	service := plugins.CreateServiceFrom(target, *svc, false, productVersion(svc), plugins.TCP)
	if target.Misconfigs {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, exposureFinding(svc.Product), cleartextFinding())
	}
	return service, nil
}

func (p *DirectoryPlugin) PortPriority(port uint16) bool {
	return port == oudPortLDAP || port == oidPortLDAP
}
func (p *DirectoryPlugin) Name() string           { return "oracle_directory" } // stable registry/log key; emitted tech via Service.Type()
func (p *DirectoryPlugin) Type() plugins.Protocol { return plugins.TCP }
func (p *DirectoryPlugin) Priority() int          { return -1 } // before generic ldap on shared/fallback ordering

func (p *DirectoryTLSPlugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	svc, ok := detect(conn, timeout)
	if !ok {
		return nil, nil
	}
	service := plugins.CreateServiceFrom(target, *svc, true, productVersion(svc), plugins.TCPTLS)
	if target.Misconfigs {
		service.AnonymousAccess = true
		service.SecurityFindings = append(service.SecurityFindings, exposureFinding(svc.Product))
		service.SecurityFindings = append(service.SecurityFindings, plugins.CheckTLS(conn)...)
	}
	return service, nil
}

func (p *DirectoryTLSPlugin) PortPriority(port uint16) bool {
	return port == oudPortLDAPS || port == oidPortLDAPS
}
func (p *DirectoryTLSPlugin) Name() string           { return "oracle_directory" }
func (p *DirectoryTLSPlugin) Type() plugins.Protocol { return plugins.TCPTLS }
func (p *DirectoryTLSPlugin) Priority() int          { return -1 }
