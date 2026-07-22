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

package oracledirectory

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// ---------------------------------------------------------------------------
// BER fixture builders (test-local; independent of the production tlv helper so
// a bug in production tlv cannot mask itself in the fixtures).
// ---------------------------------------------------------------------------

func fxTLV(tag byte, content []byte) []byte {
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

func fxConcat(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// fxPartialAttr => 0x30{ type OCTET(0x04), vals SET(0x31){ OCTET(0x04) } }
func fxPartialAttr(name, val string) []byte {
	return fxTLV(0x30, fxConcat(
		fxTLV(0x04, []byte(name)),
		fxTLV(0x31, fxTLV(0x04, []byte(val))),
	))
}

// fxEntry => LDAPMessage(msgID=3){ SearchResultEntry(0x64){ objectName "", attrs } }
func fxEntry(attrs ...[]byte) []byte {
	op := fxTLV(0x64, fxConcat(fxTLV(0x04, []byte{}), fxTLV(0x30, fxConcat(attrs...))))
	return fxTLV(0x30, fxConcat([]byte{0x02, 0x01, 0x03}, op))
}

// fxDone => LDAPMessage(msgID=3){ SearchResultDone(0x65){ resultCode=success } }
func fxDone() []byte {
	op := fxTLV(0x65, fxConcat([]byte{0x0a, 0x01, 0x00}, fxTLV(0x04, []byte{}), fxTLV(0x04, []byte{})))
	return fxTLV(0x30, fxConcat([]byte{0x02, 0x01, 0x03}, op))
}

// fxBindSuccess => minimal LDAP anonymous bind success (msgID=2, resultCode=0).
func fxBindSuccess() []byte {
	return []byte{0x30, 0x0c, 0x02, 0x01, 0x02, 0x61, 0x07, 0x0a, 0x01, 0x00, 0x04, 0x00, 0x04, 0x00}
}

// Realistic rootDSE fixtures (values sourced from Oracle docs / rootDSE samples).
func fxOUDEntry() []byte {
	return fxEntry(
		fxPartialAttr("vendorName", "Oracle Corporation"),
		fxPartialAttr("vendorVersion", "Oracle Unified Directory 12.2.1.4.0"),
	)
}

func fxOIDEntry() []byte {
	return fxEntry(
		fxPartialAttr("orcldirectoryversion", "12.2.1.3.0"),
		fxPartialAttr("orclProductVersion", "12.2.1.3.0"),
	)
}

func fxGenericEntry() []byte {
	return fxEntry(
		fxPartialAttr("vendorName", "OpenLDAP Foundation"),
		fxPartialAttr("vendorVersion", "OpenLDAP 2.6.3"),
	)
}

// fxOracleVendorNoMarkerEntry simulates Oracle Directory Server Enterprise Edition
// (ODSEE, a non-OUD/OID Oracle-vendored LDAP server): vendorName is "Oracle
// Corporation" but vendorVersion carries no "Oracle Unified Directory" marker and
// no orcl* attribute is present. Must NOT be classified as OUD/OID.
func fxOracleVendorNoMarkerEntry() []byte {
	return fxEntry(
		fxPartialAttr("vendorName", "Oracle Corporation"),
		fxPartialAttr("vendorVersion", "Oracle Directory Server Enterprise Edition 11.1.1.7.0"),
	)
}

// fxSelfReflectionEntry simulates a non-Oracle server that echoes back the exact
// requested attribute type names (vendorName/vendorVersion) but supplies empty
// values, e.g. because it doesn't recognize/support the attribute. The mere
// presence of the requested attribute *names* in the reply must not be enough to
// classify as Oracle; only recognized values (or orcl* names) count.
func fxSelfReflectionEntry() []byte {
	return fxEntry(
		fxPartialAttr("vendorName", ""),
		fxPartialAttr("vendorVersion", ""),
	)
}

// fxOrclEmptyValueEntry simulates a server that echoes back an orcl*-prefixed
// attribute type name (orcldirectoryversion) with an empty value, e.g.
// because it doesn't recognize/support the attribute. Per the LAB-5052 guard
// tightening, classify requires an orcl* attribute to carry a NON-EMPTY value
// to count as an OID marker; the mere presence of an echoed/empty orcl* key
// must not be enough to classify as OID.
func fxOrclEmptyValueEntry() []byte {
	return fxEntry(fxPartialAttr("orcldirectoryversion", ""))
}

// ---------------------------------------------------------------------------
// Mock LDAP server: reads req1 (anon bind) -> bind success; reads req2 (search)
// -> the supplied SearchResultEntry followed by SearchResultDone.
// ---------------------------------------------------------------------------

func runMock(t *testing.T, entry []byte, misconfigs, tls bool) (*plugins.Service, error) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		if _, err := conn.Read(buf); err != nil { // anon bind
			return
		}
		_, _ = conn.Write(fxBindSuccess())
		if _, err := conn.Read(buf); err != nil { // rootDSE search
			return
		}
		_, _ = conn.Write(fxConcat(entry, fxDone()))
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port)),
		Misconfigs: misconfigs,
	}
	if tls {
		return (&DirectoryTLSPlugin{}).Run(conn, 5*time.Second, target)
	}
	return (&DirectoryPlugin{}).Run(conn, 5*time.Second, target)
}

// ---------------------------------------------------------------------------
// Pure-helper tests (white-box; no network).
// ---------------------------------------------------------------------------

func TestBuildRootDSESearch_WellFormed(t *testing.T) {
	msg := buildRootDSESearch()
	if len(msg) == 0 || msg[0] != 0x30 {
		t.Fatalf("expected leading SEQUENCE 0x30, got % x", msg)
	}
	tag, body, _, ok := readTLV(msg, 0)
	if !ok || tag != 0x30 {
		t.Fatalf("outer tag = %#x", tag)
	}
	idTag, id, next, ok := readTLV(body, 0)
	if !ok || idTag != 0x02 || len(id) != 1 || id[0] != 0x03 {
		t.Fatalf("msgID malformed: tag=%#x val=% x", idTag, id)
	}
	opTag, op, _, ok := readTLV(body, next)
	if !ok || opTag != 0x63 {
		t.Fatalf("protocolOp tag = %#x, want 0x63 (searchRequest)", opTag)
	}

	// Scanning-safety: baseObject must be empty and scope must be base(0), not a
	// wildcard subtree/onelevel search. baseObject (0x04) comes first in the
	// SearchRequest body, followed by scope (ENUMERATED 0x0a).
	baseTag, baseObj, p2, ok := readTLV(op, 0)
	if !ok || baseTag != 0x04 || len(baseObj) != 0 {
		t.Fatalf("baseObject = tag %#x val %q, want empty OCTET STRING", baseTag, baseObj)
	}
	scopeTag, scopeVal, _, ok := readTLV(op, p2)
	if !ok || scopeTag != 0x0a || len(scopeVal) != 1 || scopeVal[0] != 0x00 {
		t.Fatalf("scope = tag %#x val % x, want ENUMERATED base(0)", scopeTag, scopeVal)
	}
}

func TestFirstVersion(t *testing.T) {
	cases := []struct {
		name, in, want string
	}{
		{"dotted in vendorVersion", "Oracle Unified Directory 12.2.1.4.0", "12.2.1.4.0"},
		{"dotted plain", "12.2.1.3.0", "12.2.1.3.0"},
		{"two-part version", "OpenLDAP 2.6.3", "2.6.3"},
		{"no version present", "Oracle Unified Directory", ""},
		{"no version at all", "no version here", ""},
		{"single number is not a version", "Oracle Unified Directory 12", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstVersion(tc.in); got != tc.want {
				t.Errorf("firstVersion(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestParseRootDSE_OUD(t *testing.T) {
	attrs, names := parseRootDSE(fxConcat(fxOUDEntry(), fxDone()))
	if attrs["vendorversion"] != "Oracle Unified Directory 12.2.1.4.0" {
		t.Errorf("vendorversion = %q", attrs["vendorversion"])
	}
	if attrs["vendorname"] != "Oracle Corporation" {
		t.Errorf("vendorname = %q", attrs["vendorname"])
	}
	if len(names) != 2 {
		t.Errorf("names = %v", names)
	}
}

func TestParseRootDSE_OID(t *testing.T) {
	attrs, names := parseRootDSE(fxConcat(fxOIDEntry(), fxDone()))
	if attrs["orcldirectoryversion"] != "12.2.1.3.0" {
		t.Errorf("orcldirectoryversion = %q", attrs["orcldirectoryversion"])
	}
	foundOrcl := false
	for _, n := range names {
		if strings.HasPrefix(strings.ToLower(n), "orcl") {
			foundOrcl = true
		}
	}
	if !foundOrcl {
		t.Errorf("expected an orcl* name, got %v", names)
	}
}

func TestParseRootDSE_Generic(t *testing.T) {
	attrs, names := parseRootDSE(fxConcat(fxGenericEntry(), fxDone()))
	if attrs["vendorname"] != "OpenLDAP Foundation" {
		t.Errorf("vendorname = %q", attrs["vendorname"])
	}
	if attrs["vendorversion"] != "OpenLDAP 2.6.3" {
		t.Errorf("vendorversion = %q", attrs["vendorversion"])
	}
	if len(names) != 2 {
		t.Errorf("names = %v", names)
	}
}

func TestParseRootDSE_Truncated(t *testing.T) {
	full := fxConcat(fxOUDEntry(), fxDone())
	attrs, names := parseRootDSE(full[:len(full)/2]) // half a TLV
	if len(attrs) != 0 || len(names) != 0 {
		t.Errorf("expected empty map/names on truncated input, got attrs=%v names=%v", attrs, names)
	}
}

func TestParseRootDSE_Empty(t *testing.T) {
	attrs, names := parseRootDSE(nil)
	if len(attrs) != 0 || len(names) != 0 {
		t.Errorf("expected empty map/names on nil input, got attrs=%v names=%v", attrs, names)
	}
}

func TestClassify_OUD(t *testing.T) {
	attrs, names := parseRootDSE(fxConcat(fxOUDEntry(), fxDone()))
	svc, ok := classify(attrs, names)
	if !ok || svc.Product != "oud" {
		t.Fatalf("classify OUD = %+v ok=%v", svc, ok)
	}
	if svc.VendorName != "Oracle Corporation" {
		t.Errorf("VendorName = %q", svc.VendorName)
	}
	if svc.VendorVersion != "Oracle Unified Directory 12.2.1.4.0" {
		t.Errorf("VendorVersion = %q", svc.VendorVersion)
	}
	if productVersion(svc) != "12.2.1.4.0" {
		t.Errorf("version = %q", productVersion(svc))
	}
	if len(svc.CPEs) != 1 || svc.CPEs[0] != "cpe:2.3:a:oracle:unified_directory:12.2.1.4.0:*:*:*:*:*:*:*" {
		t.Errorf("cpe = %v", svc.CPEs)
	}
}

func TestClassify_OID(t *testing.T) {
	attrs, names := parseRootDSE(fxConcat(fxOIDEntry(), fxDone()))
	svc, ok := classify(attrs, names)
	if !ok || svc.Product != "oid" {
		t.Fatalf("classify OID = %+v ok=%v", svc, ok)
	}
	if svc.DirectoryVersion != "12.2.1.3.0" {
		t.Errorf("DirectoryVersion = %q", svc.DirectoryVersion)
	}
	if productVersion(svc) != "12.2.1.3.0" {
		t.Errorf("version = %q", productVersion(svc))
	}
	if len(svc.CPEs) != 1 || svc.CPEs[0] != "cpe:2.3:a:oracle:internet_directory:12.2.1.3.0:*:*:*:*:*:*:*" {
		t.Errorf("cpe = %v", svc.CPEs)
	}
}

func TestClassify_GenericLDAP(t *testing.T) {
	attrs, names := parseRootDSE(fxConcat(fxGenericEntry(), fxDone()))
	if svc, ok := classify(attrs, names); ok {
		t.Fatalf("generic LDAP must not classify, got %+v", svc)
	}
}

// TestClassify_OracleVendorNoProductMarker guards against false-positive OUD
// classification for other Oracle-vendored LDAP servers (e.g. ODSEE) that report
// vendorName "Oracle Corporation" but do not carry the OUD-specific
// "Oracle Unified Directory" marker in vendorVersion, and expose no orcl*
// attribute.
func TestClassify_OracleVendorNoProductMarker(t *testing.T) {
	attrs, names := parseRootDSE(fxConcat(fxOracleVendorNoMarkerEntry(), fxDone()))
	if svc, ok := classify(attrs, names); ok {
		t.Fatalf("Oracle vendorName without product marker must not classify, got %+v", svc)
	}
}

// TestClassify_SelfReflectionGuard guards against a non-Oracle server that
// merely echoes back the requested attribute type names (vendorName,
// vendorVersion) with empty values. Presence of the attribute *name* in the
// reply must not be mistaken for an Oracle value.
func TestClassify_SelfReflectionGuard(t *testing.T) {
	attrs, names := parseRootDSE(fxConcat(fxSelfReflectionEntry(), fxDone()))
	if len(names) != 2 {
		t.Fatalf("expected both requested attribute names echoed, got %v", names)
	}
	if svc, ok := classify(attrs, names); ok {
		t.Fatalf("echoed empty-valued attribute names must not classify, got %+v", svc)
	}
}

func TestClassify_OID_precedes_OUD(t *testing.T) {
	// A pathological host exposing both an orcl* attr and an OUD vendorVersion.
	entry := fxEntry(
		fxPartialAttr("orcldirectoryversion", "11.1.1.9.0"),
		fxPartialAttr("vendorVersion", "Oracle Unified Directory 12.2.1.4.0"),
	)
	attrs, names := parseRootDSE(fxConcat(entry, fxDone()))
	svc, ok := classify(attrs, names)
	if !ok || svc.Product != "oid" {
		t.Fatalf("expected OID precedence, got %+v ok=%v", svc, ok)
	}
}

func TestClassify_WildcardVersion_OUD(t *testing.T) {
	// OUD marker present but no dotted version -> wildcard CPE, empty version.
	entry := fxEntry(fxPartialAttr("vendorVersion", "Oracle Unified Directory"))
	attrs, names := parseRootDSE(fxConcat(entry, fxDone()))
	svc, ok := classify(attrs, names)
	if !ok {
		t.Fatal("expected OUD classification")
	}
	if productVersion(svc) != "" {
		t.Errorf("version = %q, want empty", productVersion(svc))
	}
	if svc.CPEs[0] != "cpe:2.3:a:oracle:unified_directory:*:*:*:*:*:*:*:*" {
		t.Errorf("cpe = %q", svc.CPEs[0])
	}
}

func TestClassify_WildcardVersion_OID(t *testing.T) {
	// orcl* attribute present but no dotted version -> wildcard CPE, empty version.
	entry := fxEntry(fxPartialAttr("orcldirectoryversion", "unknown"))
	attrs, names := parseRootDSE(fxConcat(entry, fxDone()))
	svc, ok := classify(attrs, names)
	if !ok || svc.Product != "oid" {
		t.Fatalf("expected OID classification, got %+v ok=%v", svc, ok)
	}
	if productVersion(svc) != "" {
		t.Errorf("version = %q, want empty", productVersion(svc))
	}
	if svc.CPEs[0] != "cpe:2.3:a:oracle:internet_directory:*:*:*:*:*:*:*:*" {
		t.Errorf("cpe = %q", svc.CPEs[0])
	}
}

// TestClassify_OrclAttributeEmptyValue_NotOID guards the LAB-5052 tightening:
// an orcl*-prefixed attribute name alone is not enough to classify as OID —
// it must also carry a non-empty value. An echoed/empty orcldirectoryversion
// key must not classify.
func TestClassify_OrclAttributeEmptyValue_NotOID(t *testing.T) {
	attrs, names := parseRootDSE(fxConcat(fxOrclEmptyValueEntry(), fxDone()))
	if len(names) != 1 || !strings.HasPrefix(strings.ToLower(names[0]), "orcl") {
		t.Fatalf("expected the orcl* attribute name echoed, got %v", names)
	}
	if svc, ok := classify(attrs, names); ok {
		t.Fatalf("orcl* attribute with empty value must not classify, got %+v", svc)
	}
}

// TestClassify_OrclEmptyValue_FallsThroughToNonEmptyOrclAttr pins precedence
// when one orcl* attribute has an empty value but another orcl* attribute
// carries a non-empty value: the entry must still classify as OID (the empty
// orcldirectoryversion is skipped in favor of the non-empty orclProductVersion),
// with DirectoryVersion (sourced from orcldirectoryversion) empty and the CPE
// version recovered from the matched non-empty orcl* attribute
// (orclProductVersion) rather than defaulting to the wildcard.
func TestClassify_OrclEmptyValue_FallsThroughToNonEmptyOrclAttr(t *testing.T) {
	entry := fxEntry(
		fxPartialAttr("orcldirectoryversion", ""),
		fxPartialAttr("orclProductVersion", "12.2.1.3.0"),
	)
	attrs, names := parseRootDSE(fxConcat(entry, fxDone()))
	svc, ok := classify(attrs, names)
	if !ok || svc.Product != "oid" {
		t.Fatalf("expected OID classification via non-empty orclProductVersion, got %+v ok=%v", svc, ok)
	}
	if svc.DirectoryVersion != "" {
		t.Errorf("DirectoryVersion = %q, want empty (orcldirectoryversion was empty)", svc.DirectoryVersion)
	}
	if svc.CPEs[0] != "cpe:2.3:a:oracle:internet_directory:12.2.1.3.0:*:*:*:*:*:*:*" {
		t.Errorf("cpe = %q, want version recovered from orclProductVersion", svc.CPEs[0])
	}
}

// ---------------------------------------------------------------------------
// Black-box Run tests (mock server, DirectoryPlugin / TCP).
// ---------------------------------------------------------------------------

func TestRun_OUD_TCP(t *testing.T) {
	svc, err := runMock(t, fxOUDEntry(), false, false)
	if err != nil || svc == nil {
		t.Fatalf("Run = %v, %v", svc, err)
	}
	if svc.Protocol != "oracle_oud" {
		t.Errorf("protocol = %q", svc.Protocol)
	}
	if svc.Version != "12.2.1.4.0" {
		t.Errorf("version = %q", svc.Version)
	}
	if svc.TLS {
		t.Error("TLS should be false for plain TCP plugin")
	}
	d, ok := svc.Metadata().(plugins.ServiceOracleDirectory)
	if !ok {
		t.Fatalf("Metadata() type = %T, want ServiceOracleDirectory", svc.Metadata())
	}
	if d.Type() != "oracle_oud" {
		t.Errorf("Metadata().Type() = %q", d.Type())
	}
	if len(d.CPEs) != 1 || d.CPEs[0] != "cpe:2.3:a:oracle:unified_directory:12.2.1.4.0:*:*:*:*:*:*:*" {
		t.Errorf("cpes = %v", d.CPEs)
	}
}

func TestRun_OID_TCP(t *testing.T) {
	svc, err := runMock(t, fxOIDEntry(), false, false)
	if err != nil || svc == nil {
		t.Fatalf("Run = %v, %v", svc, err)
	}
	if svc.Protocol != "oracle_oid" {
		t.Errorf("protocol = %q", svc.Protocol)
	}
	if svc.Version != "12.2.1.3.0" {
		t.Errorf("version = %q", svc.Version)
	}
	d, ok := svc.Metadata().(plugins.ServiceOracleDirectory)
	if !ok {
		t.Fatalf("Metadata() type = %T, want ServiceOracleDirectory", svc.Metadata())
	}
	if d.Type() != "oracle_oid" {
		t.Errorf("Metadata().Type() = %q", d.Type())
	}
	if len(d.CPEs) != 1 || d.CPEs[0] != "cpe:2.3:a:oracle:internet_directory:12.2.1.3.0:*:*:*:*:*:*:*" {
		t.Errorf("cpes = %v", d.CPEs)
	}
}

func TestRun_GenericLDAP_ReturnsNil(t *testing.T) {
	svc, err := runMock(t, fxGenericEntry(), true, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if svc != nil {
		t.Fatalf("expected nil for generic LDAP, got %+v", svc)
	}
}

func TestRun_OracleVendorNoProductMarker_ReturnsNil(t *testing.T) {
	svc, err := runMock(t, fxOracleVendorNoMarkerEntry(), true, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if svc != nil {
		t.Fatalf("expected nil for Oracle vendorName without product marker, got %+v", svc)
	}
}

func TestRun_SelfReflectionGuard_ReturnsNil(t *testing.T) {
	svc, err := runMock(t, fxSelfReflectionEntry(), true, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if svc != nil {
		t.Fatalf("expected nil for self-reflected empty-valued attributes, got %+v", svc)
	}
}

// TestRun_OrclAttributeEmptyValue_ReturnsNil is the black-box counterpart to
// TestClassify_OrclAttributeEmptyValue_NotOID: an orcl*-prefixed attribute
// name with an empty value must yield a nil Service end-to-end.
func TestRun_OrclAttributeEmptyValue_ReturnsNil(t *testing.T) {
	svc, err := runMock(t, fxOrclEmptyValueEntry(), true, false)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if svc != nil {
		t.Fatalf("expected nil for orcl* attribute with empty value, got %+v", svc)
	}
}

// ---------------------------------------------------------------------------
// Misconfigs gating.
// ---------------------------------------------------------------------------

func TestRun_Misconfigs_False_NoFindings(t *testing.T) {
	svc, err := runMock(t, fxOUDEntry(), false, false)
	if err != nil || svc == nil {
		t.Fatalf("Run = %v, %v", svc, err)
	}
	if len(svc.SecurityFindings) != 0 || svc.AnonymousAccess {
		t.Errorf("expected no findings/anon when Misconfigs=false, got findings=%v anon=%v",
			svc.SecurityFindings, svc.AnonymousAccess)
	}
}

func TestRun_Misconfigs_True_OUD(t *testing.T) {
	svc, err := runMock(t, fxOUDEntry(), true, false)
	if err != nil || svc == nil {
		t.Fatalf("Run = %v, %v", svc, err)
	}
	if !svc.AnonymousAccess {
		t.Error("AnonymousAccess should be true")
	}
	ids := map[string]plugins.Severity{}
	for _, f := range svc.SecurityFindings {
		ids[f.ID] = f.Severity
	}
	if sev, ok := ids["oracle-oud-exposed"]; !ok || sev != plugins.SeverityLow {
		t.Errorf("missing/incorrect oracle-oud-exposed: %v", ids)
	}
	if sev, ok := ids["ldap-cleartext"]; !ok || sev != plugins.SeverityMedium {
		t.Errorf("missing/incorrect ldap-cleartext: %v", ids)
	}
}

func TestRun_Misconfigs_True_OID(t *testing.T) {
	svc, err := runMock(t, fxOIDEntry(), true, false)
	if err != nil || svc == nil {
		t.Fatalf("Run = %v, %v", svc, err)
	}
	if !svc.AnonymousAccess {
		t.Error("AnonymousAccess should be true")
	}
	ids := map[string]plugins.Severity{}
	for _, f := range svc.SecurityFindings {
		ids[f.ID] = f.Severity
	}
	if sev, ok := ids["oracle-oid-exposed"]; !ok || sev != plugins.SeverityLow {
		t.Errorf("missing/incorrect oracle-oid-exposed: %v", ids)
	}
	if sev, ok := ids["ldap-cleartext"]; !ok || sev != plugins.SeverityMedium {
		t.Errorf("missing/incorrect ldap-cleartext: %v", ids)
	}
}

// TestFindingEvidence_NoSensitiveData asserts the Evidence text is limited to the
// product+version fact and never leaks namingContext DNs or raw rootDSE attribute
// values, per security-lead.md contract (types.go SecurityFinding doc comment).
func TestFindingEvidence_NoSensitiveData(t *testing.T) {
	svc, err := runMock(t, fxOUDEntry(), true, false)
	if err != nil || svc == nil {
		t.Fatalf("Run = %v, %v", svc, err)
	}
	sensitiveMarkers := []string{"dc=", "namingContext", "12.2.1.4.0", "Oracle Corporation"}
	for _, f := range svc.SecurityFindings {
		for _, marker := range sensitiveMarkers {
			if strings.Contains(f.Evidence, marker) {
				t.Errorf("finding %q Evidence leaks sensitive data (%q): %q", f.ID, marker, f.Evidence)
			}
		}
	}
}

// TestExposureFinding_Wording pins the review-fix wording: exposureFinding
// Descriptions must no longer reference LDAP "naming contexts" (the finding
// only ever carries the product+version fact, never rootDSE DN data), and must
// still mention that the directory vendor and version are exposed.
func TestExposureFinding_Wording(t *testing.T) {
	for _, product := range []string{"oid", "oud"} {
		f := exposureFinding(product)
		lower := strings.ToLower(f.Description)
		if strings.Contains(lower, "naming context") {
			t.Errorf("exposureFinding(%q) Description must not mention naming context, got %q", product, f.Description)
		}
		if !strings.Contains(lower, "vendor") || !strings.Contains(lower, "version") {
			t.Errorf("exposureFinding(%q) Description must mention vendor and version, got %q", product, f.Description)
		}
	}
}

// ---------------------------------------------------------------------------
// TLS variant parity (DirectoryTLSPlugin over a plain mock conn; CheckTLS is a
// documented no-op on non-*tls.Conn, so detection/protocol parity is what's
// under test here, not certificate inspection).
// ---------------------------------------------------------------------------

func TestRun_TLS_OUD_Parity(t *testing.T) {
	svc, err := runMock(t, fxOUDEntry(), true, true)
	if err != nil || svc == nil {
		t.Fatalf("Run = %v, %v", svc, err)
	}
	if !svc.TLS {
		t.Error("TLS should be true")
	}
	if svc.Protocol != "oracle_oud" {
		t.Errorf("protocol = %q, want oracle_oud (parity with plain TCP)", svc.Protocol)
	}
	if svc.Version != "12.2.1.4.0" {
		t.Errorf("version = %q", svc.Version)
	}
	for _, f := range svc.SecurityFindings {
		if f.ID == "ldap-cleartext" {
			t.Error("TLS variant must not emit ldap-cleartext")
		}
	}
}

func TestRun_TLS_OID_Parity(t *testing.T) {
	svc, err := runMock(t, fxOIDEntry(), true, true)
	if err != nil || svc == nil {
		t.Fatalf("Run = %v, %v", svc, err)
	}
	if !svc.TLS {
		t.Error("TLS should be true")
	}
	if svc.Protocol != "oracle_oid" {
		t.Errorf("protocol = %q, want oracle_oid (parity with plain TCP)", svc.Protocol)
	}
	for _, f := range svc.SecurityFindings {
		if f.ID == "ldap-cleartext" {
			t.Error("TLS variant must not emit ldap-cleartext")
		}
	}
}

func TestRun_TLS_GenericLDAP_ReturnsNil(t *testing.T) {
	svc, err := runMock(t, fxGenericEntry(), true, true)
	if err != nil {
		t.Fatalf("err = %v", err)
	}
	if svc != nil {
		t.Fatalf("expected nil for generic LDAP over TLS variant, got %+v", svc)
	}
}

// ---------------------------------------------------------------------------
// Metadata: PortPriority, Priority, Name, Type.
// ---------------------------------------------------------------------------

func TestDirectoryPlugin_PortPriority(t *testing.T) {
	dp := &DirectoryPlugin{}
	if !dp.PortPriority(1389) {
		t.Error("TCP plugin should own port 1389")
	}
	if !dp.PortPriority(3060) {
		t.Error("TCP plugin should own port 3060")
	}
	if dp.PortPriority(389) {
		t.Error("TCP plugin should not own standard LDAP port 389")
	}
	if dp.PortPriority(443) {
		t.Error("TCP plugin should not own port 443")
	}
}

func TestDirectoryTLSPlugin_PortPriority(t *testing.T) {
	tp := &DirectoryTLSPlugin{}
	if !tp.PortPriority(1636) {
		t.Error("TLS plugin should own port 1636")
	}
	if !tp.PortPriority(3131) {
		t.Error("TLS plugin should own port 3131")
	}
	if tp.PortPriority(636) {
		t.Error("TLS plugin should not own standard LDAPS port 636")
	}
	if tp.PortPriority(443) {
		t.Error("TLS plugin should not own port 443")
	}
}

// ---------------------------------------------------------------------------
// BER primitive edge cases (readTLV / tlv). These exercise long-form length
// encodings and malformed/truncated inputs that the realistic rootDSE
// fixtures above never trigger, since they only ever use short attribute
// names/values.
// ---------------------------------------------------------------------------

func TestTLV_LongForms(t *testing.T) {
	t.Run("0x81 form for content 128-255 bytes", func(t *testing.T) {
		content := strings.Repeat("a", 200)
		out := tlv(0x04, []byte(content))
		if out[0] != 0x04 || out[1] != 0x81 || out[2] != 200 {
			t.Fatalf("header = % x, want [04 81 c8]", out[:3])
		}
		if len(out) != 3+200 {
			t.Fatalf("len(out) = %d, want %d", len(out), 3+200)
		}
	})

	t.Run("0x82 form for content >= 256 bytes", func(t *testing.T) {
		content := strings.Repeat("b", 300)
		out := tlv(0x04, []byte(content))
		if out[0] != 0x04 || out[1] != 0x82 || out[2] != 0x01 || out[3] != 0x2c {
			t.Fatalf("header = % x, want [04 82 01 2c]", out[:4])
		}
		if len(out) != 4+300 {
			t.Fatalf("len(out) = %d, want %d", len(out), 4+300)
		}
	})
}

func TestReadTLV_EdgeCases(t *testing.T) {
	t.Run("negative index", func(t *testing.T) {
		_, _, _, ok := readTLV([]byte{0x04, 0x00}, -1)
		if ok {
			t.Error("expected ok=false for negative index")
		}
	})

	t.Run("buffer too short for tag+length header", func(t *testing.T) {
		_, _, _, ok := readTLV([]byte{0x04}, 0)
		if ok {
			t.Error("expected ok=false for 1-byte buffer")
		}
	})

	t.Run("0x81 long form truncated (missing length byte)", func(t *testing.T) {
		_, _, _, ok := readTLV([]byte{0x04, 0x81}, 0)
		if ok {
			t.Error("expected ok=false when length byte is missing")
		}
	})

	t.Run("0x81 long form valid round-trip", func(t *testing.T) {
		content := strings.Repeat("x", 130)
		buf := fxTLV(0x04, []byte(content))
		tag, got, next, ok := readTLV(buf, 0)
		if !ok || tag != 0x04 || string(got) != content || next != len(buf) {
			t.Fatalf("readTLV = tag=%#x len=%d ok=%v next=%d, want tag=0x04 len=%d ok=true next=%d",
				tag, len(got), ok, next, len(content), len(buf))
		}
	})

	t.Run("0x82 long form truncated (missing second length byte)", func(t *testing.T) {
		_, _, _, ok := readTLV([]byte{0x04, 0x82, 0x01}, 0)
		if ok {
			t.Error("expected ok=false when second length byte is missing")
		}
	})

	t.Run("0x82 long form valid round-trip", func(t *testing.T) {
		content := strings.Repeat("y", 300)
		buf := fxTLV(0x04, []byte(content))
		tag, got, next, ok := readTLV(buf, 0)
		if !ok || tag != 0x04 || string(got) != content || next != len(buf) {
			t.Fatalf("readTLV = tag=%#x len=%d ok=%v next=%d, want tag=0x04 len=%d ok=true next=%d",
				tag, len(got), ok, next, len(content), len(buf))
		}
	})

	t.Run("indefinite length form (0x80) rejected", func(t *testing.T) {
		_, _, _, ok := readTLV([]byte{0x04, 0x80, 0x01, 0x02, 0x03}, 0)
		if ok {
			t.Error("expected ok=false for unsupported BER indefinite length 0x80")
		}
	})

	t.Run("reserved length form (0x83) rejected", func(t *testing.T) {
		_, _, _, ok := readTLV([]byte{0x04, 0x83, 0x01, 0x02, 0x03}, 0)
		if ok {
			t.Error("expected ok=false for unsupported long-form length 0x83")
		}
	})

	t.Run("declared length exceeds remaining buffer", func(t *testing.T) {
		// Declares length 5 but only 2 content bytes are actually present.
		_, _, _, ok := readTLV([]byte{0x04, 0x05, 0x01, 0x02}, 0)
		if ok {
			t.Error("expected ok=false when declared length exceeds buffer")
		}
	})
}

// ---------------------------------------------------------------------------
// parseRootDSE malformed-structure branches not reachable via the realistic
// fixtures (which are always well-formed BER). Each case asserts parsing
// degrades gracefully (skips the malformed element) rather than panicking or
// returning corrupted data.
// ---------------------------------------------------------------------------

func TestParseRootDSE_SkipsNonSequenceTopLevelElement(t *testing.T) {
	garbage := fxTLV(0x02, []byte{0x01}) // an INTEGER, not an LDAPMessage SEQUENCE
	resp := fxConcat(garbage, fxOUDEntry(), fxDone())
	attrs, _ := parseRootDSE(resp)
	if attrs["vendorversion"] != "Oracle Unified Directory 12.2.1.4.0" {
		t.Errorf("expected OUD entry parsed despite leading garbage, got %v", attrs)
	}
}

func TestParseRootDSE_SkipsMessageWithUnreadableMsgID(t *testing.T) {
	// LDAPMessage SEQUENCE whose content is a single byte: too short for the
	// nested msgID TLV to be read (readTLV needs at least a tag+length header).
	badMsg := fxTLV(0x30, []byte{0x02})
	resp := fxConcat(badMsg, fxOUDEntry(), fxDone())
	attrs, _ := parseRootDSE(resp)
	if attrs["vendorversion"] != "Oracle Unified Directory 12.2.1.4.0" {
		t.Errorf("expected OUD entry parsed despite unreadable leading message, got %v", attrs)
	}
}

func TestParseRootDSE_SkipsMessageWithUnreadableProtocolOp(t *testing.T) {
	// msgID parses fine, but only one byte follows for protocolOp: too short.
	badMsg := fxTLV(0x30, fxConcat([]byte{0x02, 0x01, 0x03}, []byte{0x64}))
	resp := fxConcat(badMsg, fxOUDEntry(), fxDone())
	attrs, _ := parseRootDSE(resp)
	if attrs["vendorversion"] != "Oracle Unified Directory 12.2.1.4.0" {
		t.Errorf("expected OUD entry parsed despite unreadable protocolOp, got %v", attrs)
	}
}

func TestParseRootDSE_SkipsEntryWithUnreadableObjectName(t *testing.T) {
	// SearchResultEntry (tag 0x64) whose content is a single byte: too short
	// for the nested objectName TLV header to be read.
	op := fxTLV(0x64, []byte{0x04})
	badMsg := fxTLV(0x30, fxConcat([]byte{0x02, 0x01, 0x03}, op))
	resp := fxConcat(badMsg, fxOUDEntry(), fxDone())
	attrs, _ := parseRootDSE(resp)
	if attrs["vendorversion"] != "Oracle Unified Directory 12.2.1.4.0" {
		t.Errorf("expected OUD entry parsed despite unreadable objectName, got %v", attrs)
	}
}

func TestParseRootDSE_SkipsEntryWithNonSequenceAttributesField(t *testing.T) {
	// SearchResultEntry whose second element (normally the attributes SEQUENCE)
	// is an INTEGER instead of a SEQUENCE.
	op := fxTLV(0x64, fxConcat(fxTLV(0x04, []byte{}), fxTLV(0x02, []byte{0x01})))
	badMsg := fxTLV(0x30, fxConcat([]byte{0x02, 0x01, 0x03}, op))
	resp := fxConcat(badMsg, fxOUDEntry(), fxDone())
	attrs, _ := parseRootDSE(resp)
	if attrs["vendorversion"] != "Oracle Unified Directory 12.2.1.4.0" {
		t.Errorf("expected OUD entry parsed despite non-SEQUENCE attributes field, got %v", attrs)
	}
}

func TestParseRootDSE_SkipsNonSequenceAttributeInList(t *testing.T) {
	// The attributes SEQUENCE contains one garbage (non-SEQUENCE) element ahead
	// of a well-formed attribute; the garbage element must be skipped, not
	// abort parsing of the rest of the list.
	attrsList := fxConcat(fxTLV(0x02, []byte{0x01}), fxPartialAttr("vendorName", "OpenLDAP Foundation"))
	op := fxTLV(0x64, fxConcat(fxTLV(0x04, []byte{}), fxTLV(0x30, attrsList)))
	entry := fxTLV(0x30, fxConcat([]byte{0x02, 0x01, 0x03}, op))
	attrs, names := parseRootDSE(fxConcat(entry, fxDone()))
	if attrs["vendorname"] != "OpenLDAP Foundation" {
		t.Errorf("expected vendorName parsed despite leading garbage element, got %v", attrs)
	}
	if len(names) != 1 {
		t.Errorf("expected only the valid attribute name recorded, got %v", names)
	}
}

func TestParseRootDSE_SkipsAttributeWithNonOctetStringType(t *testing.T) {
	// AttributeTypeAndValues whose first element (normally the type OCTET
	// STRING) is an INTEGER instead.
	badAttr := fxTLV(0x30, fxConcat(fxTLV(0x02, []byte{0x01}), fxTLV(0x31, fxTLV(0x04, []byte("val")))))
	attrsList := fxConcat(badAttr, fxPartialAttr("vendorName", "OpenLDAP Foundation"))
	op := fxTLV(0x64, fxConcat(fxTLV(0x04, []byte{}), fxTLV(0x30, attrsList)))
	entry := fxTLV(0x30, fxConcat([]byte{0x02, 0x01, 0x03}, op))
	attrs, names := parseRootDSE(fxConcat(entry, fxDone()))
	if attrs["vendorname"] != "OpenLDAP Foundation" {
		t.Errorf("expected vendorName parsed despite malformed leading attribute, got %v", attrs)
	}
	if len(names) != 1 {
		t.Errorf("expected only the well-formed attribute name recorded, got %v", names)
	}
}

func TestParseRootDSE_BreaksOnTruncatedTrailingAttribute(t *testing.T) {
	// A well-formed attribute followed by a truncated trailing TLV header
	// (single byte) inside the attributes SEQUENCE: the loop must stop
	// cleanly instead of panicking or looping forever.
	attrsList := fxConcat(fxPartialAttr("vendorName", "OpenLDAP Foundation"), []byte{0x30})
	op := fxTLV(0x64, fxConcat(fxTLV(0x04, []byte{}), fxTLV(0x30, attrsList)))
	entry := fxTLV(0x30, fxConcat([]byte{0x02, 0x01, 0x03}, op))
	attrs, names := parseRootDSE(fxConcat(entry, fxDone()))
	if attrs["vendorname"] != "OpenLDAP Foundation" {
		t.Errorf("expected vendorName parsed before truncation, got %v", attrs)
	}
	if len(names) != 1 {
		t.Errorf("expected exactly one attribute name before truncation, got %v", names)
	}
}

// ---------------------------------------------------------------------------
// detect() network-error branches: bind failure, search failure/timeout, and
// a well-formed-but-empty rootDSE response.
// ---------------------------------------------------------------------------

// runMockFragmented behaves like runMock's bind/search handshake, but splits
// the SEARCH response into three separate TCP writes (entry first half, entry
// second half, then SearchResultDone) with small sleeps between each write.
// This exercises detect's bounded read loop (searchComplete), which must
// accumulate reads across segments rather than assuming a complete
// SearchResultEntry/SearchResultDone arrives in a single Recv call.
func runMockFragmented(t *testing.T, entry []byte) (*plugins.ServiceOracleDirectory, bool) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		if _, err := conn.Read(buf); err != nil { // anon bind
			return
		}
		_, _ = conn.Write(fxBindSuccess())
		if _, err := conn.Read(buf); err != nil { // rootDSE search
			return
		}
		mid := len(entry) / 2
		_, _ = conn.Write(entry[:mid])
		time.Sleep(20 * time.Millisecond)
		_, _ = conn.Write(entry[mid:])
		time.Sleep(20 * time.Millisecond)
		_, _ = conn.Write(fxDone())
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	return detect(conn, 2*time.Second)
}

func TestDetect_FragmentedSearchResponse_OUD(t *testing.T) {
	svc, ok := runMockFragmented(t, fxOUDEntry())
	if !ok || svc == nil || svc.Product != "oud" {
		t.Fatalf("expected OUD detected across a fragmented SEARCH response, got %+v ok=%v", svc, ok)
	}
}

func TestDetect_FragmentedSearchResponse_OID(t *testing.T) {
	svc, ok := runMockFragmented(t, fxOIDEntry())
	if !ok || svc == nil || svc.Product != "oid" {
		t.Fatalf("expected OID detected across a fragmented SEARCH response, got %+v ok=%v", svc, ok)
	}
}

// TestDetect_EmptyBindResponse_ShortCircuits guards the review-fix
// short-circuit: when the anonymous bind response is empty (peer accepts the
// connection, reads the bind request, then never replies so the client's
// Recv times out and returns empty+nil), detect must return (nil,false)
// immediately without ever sending the SEARCH request.
func TestDetect_EmptyBindResponse_ShortCircuits(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	sawSecondRequest := make(chan bool, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		if _, err := conn.Read(buf); err != nil { // anon bind request
			return
		}
		// Never respond to the bind. If detect() short-circuits correctly, no
		// second (search) request will ever arrive on this connection; wait a
		// short window to confirm silence rather than assuming it.
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, err := conn.Read(buf)
		sawSecondRequest <- (err == nil && n > 0)
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	svc, ok := detect(conn, 100*time.Millisecond)
	if ok || svc != nil {
		t.Fatalf("expected detect to short-circuit on empty bind response, got %+v ok=%v", svc, ok)
	}

	select {
	case got := <-sawSecondRequest:
		if got {
			t.Error("expected no second (search) request to be sent after an empty bind response")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for mock server to observe silence")
	}
}

func TestDetect_BindFails_ReturnsFalse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		conn.Close() // close immediately: bind SendRecv's Recv fails (EOF, not a timeout)
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	svc, ok := detect(conn, 2*time.Second)
	if ok || svc != nil {
		t.Fatalf("expected detect to fail when bind response is unreadable, got %+v ok=%v", svc, ok)
	}
}

func TestDetect_SearchFails_ReturnsFalse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		if _, err := conn.Read(buf); err != nil { // anon bind
			return
		}
		_, _ = conn.Write(fxBindSuccess())
		if _, err := conn.Read(buf); err != nil { // rootDSE search
			return
		}
		// Close without responding: the search SendRecv's Recv fails (EOF).
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	svc, ok := detect(conn, 2*time.Second)
	if ok || svc != nil {
		t.Fatalf("expected detect to fail when search response is unreadable, got %+v ok=%v", svc, ok)
	}
}

func TestDetect_SearchTimesOut_ReturnsFalse(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		if _, err := conn.Read(buf); err != nil { // anon bind
			return
		}
		_, _ = conn.Write(fxBindSuccess())
		if _, err := conn.Read(buf); err != nil { // rootDSE search
			return
		}
		// Never respond: client's read deadline expires -> Recv returns
		// ([]byte{}, nil), exercising the len(resp)==0 branch (not an error).
		time.Sleep(500 * time.Millisecond)
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	svc, ok := detect(conn, 200*time.Millisecond)
	if ok || svc != nil {
		t.Fatalf("expected detect to fail on search timeout, got %+v ok=%v", svc, ok)
	}
}

func TestDetect_EmptyAttrs_ReturnsFalse(t *testing.T) {
	// Response parses without error but contains no SearchResultEntry at all
	// (e.g. an immediate SearchResultDone with no matching entries), so attrs
	// ends up empty.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write(fxBindSuccess())
		if _, err := conn.Read(buf); err != nil {
			return
		}
		_, _ = conn.Write(fxDone()) // no SearchResultEntry, only SearchResultDone
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	svc, ok := detect(conn, 2*time.Second)
	if ok || svc != nil {
		t.Fatalf("expected detect to fail with no SearchResultEntry, got %+v ok=%v", svc, ok)
	}
}

func TestPluginIdentity(t *testing.T) {
	dp := &DirectoryPlugin{}
	tp := &DirectoryTLSPlugin{}

	if dp.Priority() != -1 {
		t.Errorf("DirectoryPlugin.Priority() = %d, want -1", dp.Priority())
	}
	if tp.Priority() != -1 {
		t.Errorf("DirectoryTLSPlugin.Priority() = %d, want -1", tp.Priority())
	}
	if dp.Name() != "oracle_directory" {
		t.Errorf("DirectoryPlugin.Name() = %q", dp.Name())
	}
	if tp.Name() != "oracle_directory" {
		t.Errorf("DirectoryTLSPlugin.Name() = %q", tp.Name())
	}
	if dp.Type() != plugins.TCP {
		t.Errorf("DirectoryPlugin.Type() = %v, want TCP", dp.Type())
	}
	if tp.Type() != plugins.TCPTLS {
		t.Errorf("DirectoryTLSPlugin.Type() = %v, want TCPTLS", tp.Type())
	}
}
