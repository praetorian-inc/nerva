package snmp

import (
	"bytes"
	"encoding/asn1"
	"strings"
	"testing"
)

func descriptionResponse(t testing.TB, description string) []byte {
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

func TestParseDescription_AcceptsBERLengthEncoding(t *testing.T) {
	response := descriptionResponse(t, "FreeBSD 12.4-RELEASE")
	// SNMP uses BER, which permits long-form lengths even below 128 bytes.
	response = append([]byte{response[0], 0x82, 0, response[1]}, response[2:]...)
	if got, ok := parseDescription(response); !ok || got != "FreeBSD 12.4-RELEASE" {
		t.Fatalf("valid BER response rejected: %q, %v", got, ok)
	}
}

func TestParseDescription_RejectsDifferentRequestOrCommunity(t *testing.T) {
	valid := descriptionResponse(t, "Fedora 38")
	for _, response := range [][]byte{
		bytes.Replace(valid, []byte("public"), []byte("secret"), 1),
		bytes.Replace(valid, []byte{2, 1, 0xff}, []byte{2, 1, 1}, 1),
		bytes.Replace(valid, []byte{2, 1, 0xff, 2, 1, 0, 2, 1, 0}, []byte{2, 1, 0xff, 2, 1, 1, 2, 1, 0}, 1),
		bytes.Replace(valid, []byte{2, 1, 0xff, 2, 1, 0, 2, 1, 0}, []byte{2, 1, 0xff, 2, 1, 0, 2, 1, 1}, 1),
		bytes.Replace(valid, []byte{6, 8, 43, 6, 1, 2, 1, 1, 1, 0}, []byte{6, 8, 43, 6, 1, 2, 1, 1, 2, 0}, 1),
	} {
		if _, ok := parseDescription(response); ok {
			t.Fatalf("accepted unrelated response: %x", response)
		}
	}
}

func FuzzParseDescription(f *testing.F) {
	f.Add(descriptionResponse(f, "FreeBSD 12.4-RELEASE"))
	f.Add(descriptionResponse(f, strings.Repeat("x", 200)))
	f.Add([]byte{0x30, 0x84, 0x7f, 0xff, 0xff, 0xff})
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		description, ok := parseDescription(data)
		if ok && len(description) > len(data) {
			t.Fatal("decoded description exceeds response size")
		}
	})
}

func TestParseDescription_RejectsMalformed(t *testing.T) {
	valid := descriptionResponse(t, "Fedora 38")
	for _, data := range [][]byte{nil, []byte("public FreeBSD 12.4"), valid[:len(valid)-1], append(append([]byte{}, valid...), 0)} {
		if _, ok := parseDescription(data); ok {
			t.Fatalf("accepted malformed response %x", data)
		}
	}
}
