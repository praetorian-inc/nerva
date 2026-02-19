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

package ipp

import (
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

// buildIPPResponseBytes constructs a minimal binary IPP response for testing.
func buildIPPResponseBytes(statusCode uint16, attrs map[string]string) []byte {
	var body []byte

	// IPP header
	body = append(body, 0x02, 0x00)                        // version 2.0
	body = append(body, byte(statusCode>>8), byte(statusCode)) // status-code
	body = append(body, 0x00, 0x00, 0x00, 0x01)            // request-id: 1

	// begin printer-attributes-tag
	body = append(body, ippTagPrinterAttributes)

	for name, value := range attrs {
		body = append(body, ippTagTextWithoutLanguage)
		nameBytes := []byte(name)
		valueBytes := []byte(value)
		body = append(body, byte(len(nameBytes)>>8), byte(len(nameBytes)))
		body = append(body, nameBytes...)
		body = append(body, byte(len(valueBytes)>>8), byte(len(valueBytes)))
		body = append(body, valueBytes...)
	}

	// end-of-attributes-tag
	body = append(body, ippTagEndOfAttributes)
	return body
}

// buildIPPKeywordResponseBytes builds an IPP response with keyword-valued attributes
// (used for ipp-versions-supported).
func buildIPPKeywordResponseBytes(statusCode uint16, name, value string) []byte {
	var body []byte

	body = append(body, 0x02, 0x00)
	body = append(body, byte(statusCode>>8), byte(statusCode))
	body = append(body, 0x00, 0x00, 0x00, 0x01)

	body = append(body, ippTagPrinterAttributes)

	// keyword attribute
	body = append(body, ippTagKeyword)
	nameBytes := []byte(name)
	valueBytes := []byte(value)
	body = append(body, byte(len(nameBytes)>>8), byte(len(nameBytes)))
	body = append(body, nameBytes...)
	body = append(body, byte(len(valueBytes)>>8), byte(len(valueBytes)))
	body = append(body, valueBytes...)

	body = append(body, ippTagEndOfAttributes)
	return body
}

// TestBuildIPPRequest verifies the binary IPP request body is correctly structured.
func TestBuildIPPRequest(t *testing.T) {
	req := buildIPPRequest("192.0.2.1", 631)

	// Must be non-empty
	assert.Greater(t, len(req), 8, "IPP request should have content beyond 8-byte header")

	// Check IPP version 2.0
	assert.Equal(t, byte(0x02), req[0], "IPP major version should be 2")
	assert.Equal(t, byte(0x00), req[1], "IPP minor version should be 0")

	// Check operation-id: Get-Printer-Attributes (0x000B)
	assert.Equal(t, byte(0x00), req[2], "operation-id high byte")
	assert.Equal(t, byte(0x0B), req[3], "operation-id low byte should be 0x0B")

	// Check request-id: 1
	assert.Equal(t, byte(0x00), req[4], "request-id byte 0")
	assert.Equal(t, byte(0x00), req[5], "request-id byte 1")
	assert.Equal(t, byte(0x00), req[6], "request-id byte 2")
	assert.Equal(t, byte(0x01), req[7], "request-id byte 3 should be 1")

	// Check operation-attributes-tag at position 8
	assert.Equal(t, byte(ippTagOperationAttributes), req[8], "should begin with operation-attributes-tag")

	// Last byte should be end-of-attributes-tag
	assert.Equal(t, byte(ippTagEndOfAttributes), req[len(req)-1], "request should end with end-of-attributes-tag")
}

// TestBuildIPPHTTPRequest verifies the HTTP POST wrapper is correctly formed.
func TestBuildIPPHTTPRequest(t *testing.T) {
	ippBody := []byte{0x01, 0x02, 0x03}
	httpReq := buildIPPHTTPRequest("192.0.2.1", 631, ippBody)

	// Convert to string for header inspection (binary body will be there but checks are substring)
	reqStr := string(httpReq)

	assert.Contains(t, reqStr, "POST /ipp/print HTTP/1.1", "should contain POST /ipp/print")
	assert.Contains(t, reqStr, "Host: 192.0.2.1:631", "should contain Host header")
	assert.Contains(t, reqStr, "Content-Type: application/ipp", "should contain Content-Type: application/ipp")
	assert.Contains(t, reqStr, "Content-Length: 3", "Content-Length should match body size")
	assert.Contains(t, reqStr, "User-Agent: nerva/1.0", "should contain User-Agent")
	assert.Contains(t, reqStr, "Connection: close", "should contain Connection: close")

	// The full request should have both headers and binary body
	// headers alone are > 100 bytes, body is 3 bytes, total > 103
	assert.Greater(t, len(httpReq), 100, "request should include headers and body")

	// Last 3 bytes should be the ipp body
	assert.Equal(t, ippBody, httpReq[len(httpReq)-3:], "IPP body should be appended after headers")
}

// TestExtractContentType verifies content-type header extraction.
func TestExtractContentType(t *testing.T) {
	tests := []struct {
		name     string
		response string
		want     string
	}{
		{
			name:     "application/ipp",
			response: "HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\nContent-Length: 10\r\n\r\nbody",
			want:     "application/ipp",
		},
		{
			name:     "application/ipp with charset",
			response: "HTTP/1.1 200 OK\r\nContent-Type: application/ipp; charset=utf-8\r\n\r\nbody",
			want:     "application/ipp; charset=utf-8",
		},
		{
			name:     "content-type is case-insensitive in header name",
			response: "HTTP/1.1 200 OK\r\ncontent-type: application/ipp\r\n\r\nbody",
			want:     "application/ipp",
		},
		{
			name:     "no content-type header",
			response: "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\nbody",
			want:     "",
		},
		{
			name:     "non-IPP content type",
			response: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nbody",
			want:     "text/html",
		},
		{
			name:     "empty response",
			response: "",
			want:     "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractContentType([]byte(tt.response))
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestParseIPPResponse verifies binary IPP response parsing.
func TestParseIPPResponse(t *testing.T) {
	t.Run("valid successful response with attributes", func(t *testing.T) {
		body := buildIPPResponseBytes(0x0000, map[string]string{
			"printer-make-and-model": "HP LaserJet Pro M404n",
			"printer-name":           "HP_Printer",
		})
		result := parseIPPResponse(body)
		assert.NotNil(t, result)
		assert.True(t, result.detected)
		assert.Equal(t, "HP LaserJet Pro M404n", result.printerMakeAndModel)
		assert.Equal(t, "HP_Printer", result.printerName)
	})

	t.Run("valid response with ignored attributes (status 0x0001)", func(t *testing.T) {
		body := buildIPPResponseBytes(0x0001, map[string]string{
			"printer-make-and-model": "Canon imageRUNNER",
		})
		result := parseIPPResponse(body)
		assert.NotNil(t, result)
		assert.True(t, result.detected)
	})

	t.Run("status code at upper success boundary (0x00FF)", func(t *testing.T) {
		body := buildIPPResponseBytes(0x00FF, nil)
		result := parseIPPResponse(body)
		assert.NotNil(t, result)
		assert.True(t, result.detected)
	})

	t.Run("error status code (0x0400) still detects IPP server", func(t *testing.T) {
		body := buildIPPResponseBytes(0x0400, nil)
		result := parseIPPResponse(body)
		assert.NotNil(t, result)
		assert.True(t, result.detected)
		assert.Empty(t, result.printerMakeAndModel, "error responses should have no printer attributes")
	})

	t.Run("client error status code (0x0401) still detects IPP server", func(t *testing.T) {
		body := buildIPPResponseBytes(0x0401, nil)
		result := parseIPPResponse(body)
		assert.NotNil(t, result)
		assert.True(t, result.detected)
		assert.Empty(t, result.printerMakeAndModel, "error responses should have no printer attributes")
	})

	t.Run("server error status code (0x0500) still detects IPP server", func(t *testing.T) {
		body := buildIPPResponseBytes(0x0500, nil)
		result := parseIPPResponse(body)
		assert.NotNil(t, result)
		assert.True(t, result.detected)
		assert.Empty(t, result.printerMakeAndModel, "error responses should have no printer attributes")
	})

	t.Run("client-error-not-found (0x0406) detects IPP server (CUPS no printer configured)", func(t *testing.T) {
		body := buildIPPResponseBytes(0x0406, nil)
		result := parseIPPResponse(body)
		assert.NotNil(t, result)
		assert.True(t, result.detected)
		assert.Empty(t, result.printerMakeAndModel, "not-found error should have no printer attributes")
	})

	t.Run("empty response returns nil", func(t *testing.T) {
		result := parseIPPResponse([]byte{})
		assert.Nil(t, result)
	})

	t.Run("truncated response (less than 8 bytes) returns nil", func(t *testing.T) {
		result := parseIPPResponse([]byte{0x02, 0x00, 0x00, 0x00})
		assert.Nil(t, result)
	})

	t.Run("minimal valid response no attributes", func(t *testing.T) {
		body := buildIPPResponseBytes(0x0000, nil)
		result := parseIPPResponse(body)
		assert.NotNil(t, result)
		assert.True(t, result.detected)
		assert.Empty(t, result.printerMakeAndModel)
	})
}

// TestParseIPPAttributes verifies the binary attribute parsing logic.
func TestParseIPPAttributes(t *testing.T) {
	t.Run("single text attribute", func(t *testing.T) {
		var data []byte
		data = append(data, ippTagPrinterAttributes)
		data = append(data, ippTagTextWithoutLanguage)
		name := []byte("printer-name")
		value := []byte("TestPrinter")
		data = append(data, byte(len(name)>>8), byte(len(name)))
		data = append(data, name...)
		data = append(data, byte(len(value)>>8), byte(len(value)))
		data = append(data, value...)
		data = append(data, ippTagEndOfAttributes)

		attrs := parseIPPAttributes(data)
		assert.Equal(t, "TestPrinter", attrs["printer-name"])
	})

	t.Run("multiple attributes", func(t *testing.T) {
		var data []byte
		data = append(data, ippTagPrinterAttributes)

		// First attribute
		data = append(data, ippTagTextWithoutLanguage)
		n1 := []byte("printer-name")
		v1 := []byte("MyPrinter")
		data = append(data, byte(len(n1)>>8), byte(len(n1)))
		data = append(data, n1...)
		data = append(data, byte(len(v1)>>8), byte(len(v1)))
		data = append(data, v1...)

		// Second attribute
		data = append(data, ippTagTextWithoutLanguage)
		n2 := []byte("printer-make-and-model")
		v2 := []byte("HP LaserJet")
		data = append(data, byte(len(n2)>>8), byte(len(n2)))
		data = append(data, n2...)
		data = append(data, byte(len(v2)>>8), byte(len(v2)))
		data = append(data, v2...)

		data = append(data, ippTagEndOfAttributes)

		attrs := parseIPPAttributes(data)
		assert.Equal(t, "MyPrinter", attrs["printer-name"])
		assert.Equal(t, "HP LaserJet", attrs["printer-make-and-model"])
	})

	t.Run("multi-valued ipp-versions-supported", func(t *testing.T) {
		var data []byte
		data = append(data, ippTagPrinterAttributes)

		// First value of ipp-versions-supported (has name)
		data = append(data, ippTagKeyword)
		n1 := []byte("ipp-versions-supported")
		v1 := []byte("1.1")
		data = append(data, byte(len(n1)>>8), byte(len(n1)))
		data = append(data, n1...)
		data = append(data, byte(len(v1)>>8), byte(len(v1)))
		data = append(data, v1...)

		// Second value (name-length = 0)
		data = append(data, ippTagKeyword)
		v2 := []byte("2.0")
		data = append(data, 0x00, 0x00) // name-length = 0
		data = append(data, byte(len(v2)>>8), byte(len(v2)))
		data = append(data, v2...)

		data = append(data, ippTagEndOfAttributes)

		attrs := parseIPPAttributes(data)
		versions := attrs["ipp-versions-supported"]
		assert.Contains(t, versions, "1.1")
		assert.Contains(t, versions, "2.0")
	})

	t.Run("keyword value tag", func(t *testing.T) {
		var data []byte
		data = append(data, ippTagPrinterAttributes)
		data = append(data, ippTagKeyword)
		n := []byte("printer-state")
		v := []byte("idle")
		data = append(data, byte(len(n)>>8), byte(len(n)))
		data = append(data, n...)
		data = append(data, byte(len(v)>>8), byte(len(v)))
		data = append(data, v...)
		data = append(data, ippTagEndOfAttributes)

		attrs := parseIPPAttributes(data)
		assert.Equal(t, "idle", attrs["printer-state"])
	})

	t.Run("uri value tag", func(t *testing.T) {
		var data []byte
		data = append(data, ippTagPrinterAttributes)
		data = append(data, ippTagURI)
		n := []byte("printer-uri-supported")
		v := []byte("ipp://printer.example.com:631/ipp/print")
		data = append(data, byte(len(n)>>8), byte(len(n)))
		data = append(data, n...)
		data = append(data, byte(len(v)>>8), byte(len(v)))
		data = append(data, v...)
		data = append(data, ippTagEndOfAttributes)

		attrs := parseIPPAttributes(data)
		assert.Equal(t, "ipp://printer.example.com:631/ipp/print", attrs["printer-uri-supported"])
	})

	t.Run("empty data returns empty map", func(t *testing.T) {
		attrs := parseIPPAttributes([]byte{})
		assert.Empty(t, attrs)
	})

	t.Run("truncated data handled gracefully", func(t *testing.T) {
		// Only a few bytes - name-length points past end of data
		data := []byte{ippTagPrinterAttributes, ippTagTextWithoutLanguage, 0x00, 0x20}
		attrs := parseIPPAttributes(data)
		assert.Empty(t, attrs)
	})

	t.Run("end-of-attributes stops parsing", func(t *testing.T) {
		var data []byte
		data = append(data, ippTagPrinterAttributes)
		data = append(data, ippTagEndOfAttributes)
		// More bytes after end tag - should be ignored
		data = append(data, ippTagTextWithoutLanguage, 0x00, 0x05, 'h', 'e', 'l', 'l', 'o',
			0x00, 0x03, 'f', 'o', 'o')

		attrs := parseIPPAttributes(data)
		assert.Empty(t, attrs, "no attributes before end-of-attributes tag")
	})
}

// TestGenerateIPPCPE verifies CPE generation from printer make-and-model.
func TestGenerateIPPCPE(t *testing.T) {
	tests := []struct {
		name         string
		makeAndModel string
		version      string
		wantPrefix   string
		wantEmpty    bool
	}{
		{
			name:         "HP printer with version",
			makeAndModel: "HP LaserJet Pro M404n",
			version:      "2612091_578495",
			wantPrefix:   "cpe:2.3:h:hp:laserjet_pro_m404n:",
		},
		{
			name:         "Canon printer no version",
			makeAndModel: "Canon imageRUNNER 2425",
			version:      "",
			wantPrefix:   "cpe:2.3:h:canon:imagerunner_2425:*",
		},
		{
			name:         "Epson printer",
			makeAndModel: "Epson WorkForce WF-3820",
			version:      "1.0",
			wantPrefix:   "cpe:2.3:h:epson:workforce_wf-3820:",
		},
		{
			name:         "empty make-and-model returns empty",
			makeAndModel: "",
			version:      "1.0",
			wantEmpty:    true,
		},
		{
			name:         "single word (no space) returns empty",
			makeAndModel: "HP",
			version:      "1.0",
			wantEmpty:    true,
		},
		{
			name:         "CPE format correct",
			makeAndModel: "Brother MFC-L2750DW",
			version:      "J",
			wantPrefix:   "cpe:2.3:h:brother:mfc-l2750dw:",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := generateIPPCPE(tt.makeAndModel, tt.version)
			if tt.wantEmpty {
				assert.Empty(t, got)
			} else {
				assert.NotEmpty(t, got)
				assert.Contains(t, got, tt.wantPrefix)
				// Verify the CPE ends with the wildcard suffix
				assert.True(t, len(got) > len(tt.wantPrefix), "CPE should have version part")
			}
		})
	}
}

// TestPluginMetadata verifies the TCP plugin metadata.
func TestPluginMetadata(t *testing.T) {
	p := &IPPPlugin{}

	assert.Equal(t, "ipp", p.Name())
	assert.Equal(t, 100, p.Priority())
	assert.True(t, p.PortPriority(631), "port 631 should be priority port")
	assert.False(t, p.PortPriority(80), "port 80 should not be priority")
	assert.False(t, p.PortPriority(443), "port 443 should not be priority")
}

// TestTLSPluginMetadata verifies the TLS plugin metadata.
func TestTLSPluginMetadata(t *testing.T) {
	p := &IPPTLSPlugin{}

	assert.Equal(t, "ipp", p.Name())
	assert.Equal(t, 101, p.Priority())
	assert.True(t, p.PortPriority(631), "port 631 should be priority port for TLS")
	assert.False(t, p.PortPriority(443), "port 443 should not be priority")
}

// TestAppendIPPAttribute verifies attribute binary encoding.
func TestAppendIPPAttribute(t *testing.T) {
	var buf []byte
	buf = appendIPPAttribute(buf, ippTagCharset, "attributes-charset", "utf-8")

	// Check value tag
	assert.Equal(t, byte(ippTagCharset), buf[0])

	// Check name-length (big-endian uint16)
	expectedNameLen := uint16(len("attributes-charset"))
	actualNameLen := binary.BigEndian.Uint16(buf[1:3])
	assert.Equal(t, expectedNameLen, actualNameLen)

	// Check name bytes
	assert.Equal(t, "attributes-charset", string(buf[3:3+int(expectedNameLen)]))

	// Check value-length
	offset := 3 + int(expectedNameLen)
	expectedValueLen := uint16(len("utf-8"))
	actualValueLen := binary.BigEndian.Uint16(buf[offset : offset+2])
	assert.Equal(t, expectedValueLen, actualValueLen)

	// Check value bytes
	assert.Equal(t, "utf-8", string(buf[offset+2:offset+2+int(expectedValueLen)]))
}

// TestAppendIPPAdditionalValue verifies additional value encoding (name-length = 0).
func TestAppendIPPAdditionalValue(t *testing.T) {
	var buf []byte
	buf = appendIPPAdditionalValue(buf, ippTagKeyword, "2.0")

	// Check value tag
	assert.Equal(t, byte(ippTagKeyword), buf[0])

	// Name-length must be 0 (big-endian)
	nameLen := binary.BigEndian.Uint16(buf[1:3])
	assert.Equal(t, uint16(0), nameLen, "additional value should have name-length = 0")

	// Value-length
	expectedValueLen := uint16(len("2.0"))
	actualValueLen := binary.BigEndian.Uint16(buf[3:5])
	assert.Equal(t, expectedValueLen, actualValueLen)

	// Value bytes
	assert.Equal(t, "2.0", string(buf[5:8]))
}

// TestNormalizeCPEComponent verifies CPE component normalization.
func TestNormalizeCPEComponent(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"HP", "hp"},
		{"LaserJet Pro M404n", "laserjet_pro_m404n"},
		{"imageRUNNER 2425", "imagerunner_2425"},
		{"WorkForce WF-3820", "workforce_wf-3820"},
		{"", ""},
		{"Special!@#$Characters", "specialcharacters"},
		{"Already_normalized", "already_normalized"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeCPEComponent(tt.input)
			assert.Equal(t, tt.want, got)
		})
	}
}

// TestExtractHTTPBody verifies HTTP body extraction from raw response.
func TestExtractHTTPBody(t *testing.T) {
	t.Run("standard HTTP response", func(t *testing.T) {
		response := []byte("HTTP/1.1 200 OK\r\nContent-Type: application/ipp\r\n\r\nbinary_body_here")
		body := extractHTTPBody(response)
		assert.Equal(t, []byte("binary_body_here"), body)
	})

	t.Run("response with no body", func(t *testing.T) {
		response := []byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
		body := extractHTTPBody(response)
		assert.Nil(t, body)
	})

	t.Run("no CRLF CRLF separator", func(t *testing.T) {
		response := []byte("not an http response")
		body := extractHTTPBody(response)
		assert.Nil(t, body)
	})

	t.Run("empty response", func(t *testing.T) {
		body := extractHTTPBody([]byte{})
		assert.Nil(t, body)
	})
}
