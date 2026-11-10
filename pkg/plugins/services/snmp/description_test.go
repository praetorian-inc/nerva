package snmp

import (
	"encoding/asn1"
	"strings"
	"testing"
)

func descriptionResponse(t *testing.T, description string) []byte {
	t.Helper()
	pdu, err := asn1.Marshal(struct {
		RequestID   int
		ErrorStatus int
		ErrorIndex  int
		Bindings    []struct {
			Name  asn1.ObjectIdentifier
			Value []byte
		}
	}{-1, 0, 0, []struct {
		Name  asn1.ObjectIdentifier
		Value []byte
	}{{asn1.ObjectIdentifier{1, 3, 6, 1, 2, 1, 1, 1, 0}, []byte(description)}}})
	if err != nil {
		t.Fatal(err)
	}
	var raw asn1.RawValue
	if _, err = asn1.Unmarshal(pdu, &raw); err != nil {
		t.Fatal(err)
	}
	response, err := asn1.Marshal(struct {
		Version   int
		Community []byte
		PDU       asn1.RawValue
	}{0, []byte("public"), asn1.RawValue{Class: 2, Tag: 2, IsCompound: true, Bytes: raw.Bytes}})
	if err != nil {
		t.Fatal(err)
	}
	return response
}

func TestParseDescription_LongBERLengths(t *testing.T) {
	description := "FreeBSD 12.4-RELEASE " + strings.Repeat("x", 200)
	got, ok := parseDescription(descriptionResponse(t, description))
	if !ok || got != description {
		t.Fatalf("got %q, %v", got, ok)
	}
}

func TestParseDescription_RejectsMalformed(t *testing.T) {
	valid := descriptionResponse(t, "Fedora 38")
	for _, data := range [][]byte{nil, []byte("public FreeBSD 12.4"), valid[:len(valid)-1], append(append([]byte{}, valid...), 0)} {
		if _, ok := parseDescription(data); ok {
			t.Fatalf("accepted malformed response %x", data)
		}
	}
}
