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

package mongodb

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TestParseBSONInt32 tests parsing of int32 values from BSON documents
func TestParseBSONInt32(t *testing.T) {
	tests := []struct {
		name     string
		bsonDoc  []byte
		key      string
		expected int32
		found    bool
	}{
		{
			name: "valid int32 value",
			bsonDoc: func() []byte {
				// Build BSON document: {maxWireVersion: 17}
				doc := make([]byte, 0, 64)
				// Document size (will be set at end)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				// Type: int32 (0x10)
				doc = append(doc, 0x10)
				// Key: "maxWireVersion" + null
				doc = append(doc, []byte("maxWireVersion")...)
				doc = append(doc, 0x00)
				// Value: 17 (int32, little-endian)
				valBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(valBuf, 17)
				doc = append(doc, valBuf...)
				// Document terminator
				doc = append(doc, 0x00)
				// Set document size
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "maxWireVersion",
			expected: 17,
			found:    true,
		},
		{
			name: "zero value",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x10) // int32 type
				doc = append(doc, []byte("minWireVersion")...)
				doc = append(doc, 0x00)
				valBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(valBuf, 0)
				doc = append(doc, valBuf...)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "minWireVersion",
			expected: 0,
			found:    true,
		},
		{
			name: "key not found",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x10) // int32 type
				doc = append(doc, []byte("otherKey")...)
				doc = append(doc, 0x00)
				valBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(valBuf, 42)
				doc = append(doc, valBuf...)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "maxWireVersion",
			expected: 0,
			found:    false,
		},
		{
			name:     "empty document",
			bsonDoc:  []byte{0x05, 0x00, 0x00, 0x00, 0x00}, // Minimal valid BSON doc
			key:      "maxWireVersion",
			expected: 0,
			found:    false,
		},
		{
			name:     "document too short",
			bsonDoc:  []byte{0x01, 0x02},
			key:      "maxWireVersion",
			expected: 0,
			found:    false,
		},
		{
			name: "wrong type (string instead of int32)",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x02) // string type, not int32
				doc = append(doc, []byte("maxWireVersion")...)
				doc = append(doc, 0x00)
				// String value
				strLenBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(strLenBuf, 3) // "17" + null
				doc = append(doc, strLenBuf...)
				doc = append(doc, []byte("17")...)
				doc = append(doc, 0x00)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "maxWireVersion",
			expected: 0,
			found:    false,
		},
		{
			name: "multiple fields with target int32",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 128)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)

				// First field: string
				doc = append(doc, 0x02)
				doc = append(doc, []byte("msg")...)
				doc = append(doc, 0x00)
				strLenBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(strLenBuf, 9) // "isdbgrid" + null = 9 bytes
				doc = append(doc, strLenBuf...)
				doc = append(doc, []byte("isdbgrid")...)
				doc = append(doc, 0x00)

				// Second field: int32 (target)
				doc = append(doc, 0x10)
				doc = append(doc, []byte("maxWireVersion")...)
				doc = append(doc, 0x00)
				valBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(valBuf, 25)
				doc = append(doc, valBuf...)

				// Third field: another int32
				doc = append(doc, 0x10)
				doc = append(doc, []byte("minWireVersion")...)
				doc = append(doc, 0x00)
				minValBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(minValBuf, 6)
				doc = append(doc, minValBuf...)

				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "maxWireVersion",
			expected: 25,
			found:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, found := parseBSONInt32(tt.bsonDoc, tt.key)
			if found != tt.found {
				t.Errorf("parseBSONInt32() found = %v, want %v", found, tt.found)
			}
			if value != tt.expected {
				t.Errorf("parseBSONInt32() value = %v, want %v", value, tt.expected)
			}
		})
	}
}

// TestParseBSONString tests the existing parseBSONString function with edge cases
func TestParseBSONString(t *testing.T) {
	tests := []struct {
		name     string
		bsonDoc  []byte
		key      string
		expected string
	}{
		{
			name: "valid string value",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x02) // string type
				doc = append(doc, []byte("msg")...)
				doc = append(doc, 0x00)
				strLenBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(strLenBuf, 9) // "isdbgrid" + null
				doc = append(doc, strLenBuf...)
				doc = append(doc, []byte("isdbgrid")...)
				doc = append(doc, 0x00)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "msg",
			expected: "isdbgrid",
		},
		{
			name: "version string",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x02) // string type
				doc = append(doc, []byte("version")...)
				doc = append(doc, 0x00)
				strLenBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(strLenBuf, 6) // "8.0.4" + null
				doc = append(doc, strLenBuf...)
				doc = append(doc, []byte("8.0.4")...)
				doc = append(doc, 0x00)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "version",
			expected: "8.0.4",
		},
		{
			name:     "key not found",
			bsonDoc:  []byte{0x05, 0x00, 0x00, 0x00, 0x00},
			key:      "version",
			expected: "",
		},
		{
			name:     "empty document",
			bsonDoc:  []byte{},
			key:      "msg",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseBSONString(tt.bsonDoc, tt.key)
			if result != tt.expected {
				t.Errorf("parseBSONString() = %v, want %v", result, tt.expected)
			}
		})
	}
}

// TestCheckMongoDBResponse tests OP_REPLY validation
func TestCheckMongoDBResponse(t *testing.T) {
	tests := []struct {
		name              string
		response          []byte
		expectedRequestID uint32
		wantValid         bool
		wantErr           bool
	}{
		{
			name: "valid OP_REPLY response",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				// Message length
				lengthBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(lengthBuf, 60) // Will be adjusted
				resp = append(resp, lengthBuf...)
				// Request ID
				reqIDBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(reqIDBuf, 123)
				resp = append(resp, reqIDBuf...)
				// Response To
				respToBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(respToBuf, 100) // Expected request ID
				resp = append(resp, respToBuf...)
				// OpCode (OP_REPLY = 1)
				opcodeBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(opcodeBuf, OP_REPLY)
				resp = append(resp, opcodeBuf...)
				// Response flags (0)
				resp = append(resp, 0x00, 0x00, 0x00, 0x00)
				// CursorID
				resp = append(resp, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
				// StartingFrom
				resp = append(resp, 0x00, 0x00, 0x00, 0x00)
				// NumberReturned
				resp = append(resp, 0x01, 0x00, 0x00, 0x00)
				// Minimal BSON document
				resp = append(resp, 0x05, 0x00, 0x00, 0x00, 0x00)
				// Update length
				binary.LittleEndian.PutUint32(resp[0:4], uint32(len(resp)))
				return resp
			}(),
			expectedRequestID: 100,
			wantValid:         true,
			wantErr:           false,
		},
		{
			name:              "response too short",
			response:          []byte{0x01, 0x02, 0x03},
			expectedRequestID: 100,
			wantValid:         false,
			wantErr:           true,
		},
		{
			name: "wrong opcode",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				lengthBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(lengthBuf, 60)
				resp = append(resp, lengthBuf...)
				reqIDBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(reqIDBuf, 123)
				resp = append(resp, reqIDBuf...)
				respToBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(respToBuf, 100)
				resp = append(resp, respToBuf...)
				// Wrong opcode (OP_MSG instead of OP_REPLY)
				opcodeBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(opcodeBuf, OP_MSG)
				resp = append(resp, opcodeBuf...)
				// Rest of data
				resp = append(resp, make([]byte, 20)...)
				resp = append(resp, 0x05, 0x00, 0x00, 0x00, 0x00) // BSON
				binary.LittleEndian.PutUint32(resp[0:4], uint32(len(resp)))
				return resp
			}(),
			expectedRequestID: 100,
			wantValid:         false,
			wantErr:           true,
		},
		{
			name: "mismatched request ID",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				lengthBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(lengthBuf, 60)
				resp = append(resp, lengthBuf...)
				reqIDBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(reqIDBuf, 123)
				resp = append(resp, reqIDBuf...)
				// Wrong responseTo value
				respToBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(respToBuf, 999) // Should be 100
				resp = append(resp, respToBuf...)
				opcodeBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(opcodeBuf, OP_REPLY)
				resp = append(resp, opcodeBuf...)
				resp = append(resp, make([]byte, 20)...)
				resp = append(resp, 0x05, 0x00, 0x00, 0x00, 0x00) // BSON
				binary.LittleEndian.PutUint32(resp[0:4], uint32(len(resp)))
				return resp
			}(),
			expectedRequestID: 100,
			wantValid:         false,
			wantErr:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := checkMongoDBResponse(tt.response, tt.expectedRequestID)
			if valid != tt.wantValid {
				t.Errorf("checkMongoDBResponse() valid = %v, want %v", valid, tt.wantValid)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("checkMongoDBResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestCheckMongoDBMsgResponse tests OP_MSG validation
func TestCheckMongoDBMsgResponse(t *testing.T) {
	tests := []struct {
		name              string
		response          []byte
		expectedRequestID uint32
		wantValid         bool
		wantErr           bool
	}{
		{
			name: "valid OP_MSG response",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				// Message length
				lengthBuf := make([]byte, 4)
				resp = append(resp, lengthBuf...)
				// Request ID
				reqIDBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(reqIDBuf, 456)
				resp = append(resp, reqIDBuf...)
				// Response To
				respToBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(respToBuf, 200) // Expected request ID
				resp = append(resp, respToBuf...)
				// OpCode (OP_MSG = 2013)
				opcodeBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(opcodeBuf, OP_MSG)
				resp = append(resp, opcodeBuf...)
				// Flag bits
				resp = append(resp, 0x00, 0x00, 0x00, 0x00)
				// Section kind 0
				resp = append(resp, 0x00)
				// Minimal BSON document
				resp = append(resp, 0x05, 0x00, 0x00, 0x00, 0x00)
				// Update length
				binary.LittleEndian.PutUint32(resp[0:4], uint32(len(resp)))
				return resp
			}(),
			expectedRequestID: 200,
			wantValid:         true,
			wantErr:           false,
		},
		{
			name:              "response too short",
			response:          []byte{0x01, 0x02},
			expectedRequestID: 200,
			wantValid:         false,
			wantErr:           true,
		},
		{
			name: "wrong section kind",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				lengthBuf := make([]byte, 4)
				resp = append(resp, lengthBuf...)
				reqIDBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(reqIDBuf, 456)
				resp = append(resp, reqIDBuf...)
				respToBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(respToBuf, 200)
				resp = append(resp, respToBuf...)
				opcodeBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(opcodeBuf, OP_MSG)
				resp = append(resp, opcodeBuf...)
				resp = append(resp, 0x00, 0x00, 0x00, 0x00) // flags
				// Wrong section kind (1 instead of 0)
				resp = append(resp, 0x01)
				resp = append(resp, 0x05, 0x00, 0x00, 0x00, 0x00) // BSON
				binary.LittleEndian.PutUint32(resp[0:4], uint32(len(resp)))
				return resp
			}(),
			expectedRequestID: 200,
			wantValid:         false,
			wantErr:           true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := checkMongoDBMsgResponse(tt.response, tt.expectedRequestID)
			if valid != tt.wantValid {
				t.Errorf("checkMongoDBMsgResponse() valid = %v, want %v", valid, tt.wantValid)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("checkMongoDBMsgResponse() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestBuildMongoDBQuery tests OP_QUERY message construction
func TestBuildMongoDBQuery(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		requestID uint32
	}{
		{
			name:      "hello command",
			command:   "hello",
			requestID: 1,
		},
		{
			name:      "isMaster command",
			command:   "isMaster",
			requestID: 2,
		},
		{
			name:      "buildInfo command",
			command:   "buildInfo",
			requestID: 100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := buildMongoDBQuery(tt.command, tt.requestID)

			// Verify message length field
			if len(query) < 16 {
				t.Fatal("Query too short")
			}

			messageLength := binary.LittleEndian.Uint32(query[0:4])
			if messageLength != uint32(len(query)) {
				t.Errorf("Message length mismatch: header says %d, actual %d", messageLength, len(query))
			}

			// Verify request ID
			requestID := binary.LittleEndian.Uint32(query[4:8])
			if requestID != tt.requestID {
				t.Errorf("Request ID mismatch: got %d, want %d", requestID, tt.requestID)
			}

			// Verify responseTo is 0
			responseTo := binary.LittleEndian.Uint32(query[8:12])
			if responseTo != 0 {
				t.Errorf("ResponseTo should be 0, got %d", responseTo)
			}

			// Verify opCode is OP_QUERY (2004)
			opCode := binary.LittleEndian.Uint32(query[12:16])
			if opCode != OP_QUERY {
				t.Errorf("OpCode should be OP_QUERY (2004), got %d", opCode)
			}
		})
	}
}

// TestBuildMongoDBMsgQuery tests OP_MSG message construction
func TestBuildMongoDBMsgQuery(t *testing.T) {
	tests := []struct {
		name      string
		command   string
		requestID uint32
	}{
		{
			name:      "hello command",
			command:   "hello",
			requestID: 3,
		},
		{
			name:      "isMaster command",
			command:   "isMaster",
			requestID: 4,
		},
		{
			name:      "buildInfo command",
			command:   "buildInfo",
			requestID: 101,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			msg := buildMongoDBMsgQuery(tt.command, tt.requestID)

			// Verify message length field
			if len(msg) < 16 {
				t.Fatal("Message too short")
			}

			messageLength := binary.LittleEndian.Uint32(msg[0:4])
			if messageLength != uint32(len(msg)) {
				t.Errorf("Message length mismatch: header says %d, actual %d", messageLength, len(msg))
			}

			// Verify request ID
			requestID := binary.LittleEndian.Uint32(msg[4:8])
			if requestID != tt.requestID {
				t.Errorf("Request ID mismatch: got %d, want %d", requestID, tt.requestID)
			}

			// Verify responseTo is 0
			responseTo := binary.LittleEndian.Uint32(msg[8:12])
			if responseTo != 0 {
				t.Errorf("ResponseTo should be 0, got %d", responseTo)
			}

			// Verify opCode is OP_MSG (2013)
			opCode := binary.LittleEndian.Uint32(msg[12:16])
			if opCode != OP_MSG {
				t.Errorf("OpCode should be OP_MSG (2013), got %d", opCode)
			}

			// Verify section kind is 0
			if len(msg) < 21 {
				t.Fatal("Message too short for section kind")
			}
			sectionKind := msg[20]
			if sectionKind != 0 {
				t.Errorf("Section kind should be 0, got %d", sectionKind)
			}
		})
	}
}

// TestBuildMongoDBCPE tests CPE generation from MongoDB version strings
func TestBuildMongoDBCPE(t *testing.T) {
	tests := []struct {
		name    string
		version string
		wantCPE string
	}{
		// Valid CPE generation with version
		{"MongoDB 8.0.4", "8.0.4", "cpe:2.3:a:mongodb:mongodb:8.0.4:*:*:*:*:*:*:*"},
		{"MongoDB 7.0.15", "7.0.15", "cpe:2.3:a:mongodb:mongodb:7.0.15:*:*:*:*:*:*:*"},
		{"MongoDB 6.0.3", "6.0.3", "cpe:2.3:a:mongodb:mongodb:6.0.3:*:*:*:*:*:*:*"},
		{"MongoDB 5.0.0", "5.0.0", "cpe:2.3:a:mongodb:mongodb:5.0.0:*:*:*:*:*:*:*"},
		{"MongoDB 4.4.29", "4.4.29", "cpe:2.3:a:mongodb:mongodb:4.4.29:*:*:*:*:*:*:*"},
		{"MongoDB 4.2.24", "4.2.24", "cpe:2.3:a:mongodb:mongodb:4.2.24:*:*:*:*:*:*:*"},

		// Version with metadata (should sanitize)
		{"Version with metadata", "8.0.4 some extra info", "cpe:2.3:a:mongodb:mongodb:8.0.4:*:*:*:*:*:*:*"},

		// CPE with wildcard version - unknown version but known product (matches FTP/RMI/Wappalyzer pattern)
		{"No version - wildcard", "", "cpe:2.3:a:mongodb:mongodb:*:*:*:*:*:*:*:*"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildMongoDBCPE(tt.version)
			if cpe != tt.wantCPE {
				t.Errorf("buildMongoDBCPE(%q) = %q, want %q", tt.version, cpe, tt.wantCPE)
			}
		})
	}
}

// TestParseBSONDouble tests parsing of float64 values from BSON documents
func TestParseBSONDouble(t *testing.T) {
	tests := []struct {
		name     string
		bsonDoc  []byte
		key      string
		expected float64
		found    bool
	}{
		{
			name: "valid double 1.0",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x01) // double type
				doc = append(doc, []byte("ok")...)
				doc = append(doc, 0x00)
				// 1.0 as IEEE 754 little-endian
				doc = append(doc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "ok",
			expected: 1.0,
			found:    true,
		},
		{
			name: "valid double 0.0",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x01) // double type
				doc = append(doc, []byte("ok")...)
				doc = append(doc, 0x00)
				// 0.0 as IEEE 754 little-endian
				doc = append(doc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "ok",
			expected: 0.0,
			found:    true,
		},
		{
			name: "key not found",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x01) // double type
				doc = append(doc, []byte("other")...)
				doc = append(doc, 0x00)
				doc = append(doc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "ok",
			expected: 0.0,
			found:    false,
		},
		{
			name:     "empty document",
			bsonDoc:  []byte{0x05, 0x00, 0x00, 0x00, 0x00},
			key:      "ok",
			expected: 0.0,
			found:    false,
		},
		{
			name:     "document too short",
			bsonDoc:  []byte{0x01, 0x02},
			key:      "ok",
			expected: 0.0,
			found:    false,
		},
		{
			name: "wrong type (string instead of double)",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 64)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)
				doc = append(doc, 0x02) // string type, not double
				doc = append(doc, []byte("ok")...)
				doc = append(doc, 0x00)
				strLenBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(strLenBuf, 2) // "1" + null
				doc = append(doc, strLenBuf...)
				doc = append(doc, []byte("1")...)
				doc = append(doc, 0x00)
				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "ok",
			expected: 0.0,
			found:    false,
		},
		{
			name: "multiple fields with target double",
			bsonDoc: func() []byte {
				doc := make([]byte, 0, 128)
				sizeBuf := make([]byte, 4)
				doc = append(doc, sizeBuf...)

				// First field: int32
				doc = append(doc, 0x10)
				doc = append(doc, []byte("maxWireVersion")...)
				doc = append(doc, 0x00)
				valBuf := make([]byte, 4)
				binary.LittleEndian.PutUint32(valBuf, 21)
				doc = append(doc, valBuf...)

				// Second field: double (target)
				doc = append(doc, 0x01)
				doc = append(doc, []byte("ok")...)
				doc = append(doc, 0x00)
				doc = append(doc, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F) // 1.0

				doc = append(doc, 0x00) // terminator
				binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
				return doc
			}(),
			key:      "ok",
			expected: 1.0,
			found:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			value, found := parseBSONDouble(tt.bsonDoc, tt.key)
			if found != tt.found {
				t.Errorf("parseBSONDouble() found = %v, want %v", found, tt.found)
			}
			if value != tt.expected {
				t.Errorf("parseBSONDouble() value = %v, want %v", value, tt.expected)
			}
		})
	}
}

// TestParseBSONCommandOk tests the parseBSONCommandOk helper
func TestParseBSONCommandOk(t *testing.T) {
	buildOkDoubleDoc := func(val []byte) []byte {
		doc := make([]byte, 0, 32)
		sizeBuf := make([]byte, 4)
		doc = append(doc, sizeBuf...)
		doc = append(doc, 0x01) // double type
		doc = append(doc, []byte("ok")...)
		doc = append(doc, 0x00)
		doc = append(doc, val...)
		doc = append(doc, 0x00) // terminator
		binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
		return doc
	}

	buildOkInt32Doc := func(val int32) []byte {
		doc := make([]byte, 0, 32)
		sizeBuf := make([]byte, 4)
		doc = append(doc, sizeBuf...)
		doc = append(doc, 0x10) // int32 type
		doc = append(doc, []byte("ok")...)
		doc = append(doc, 0x00)
		valBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(valBuf, uint32(val))
		doc = append(doc, valBuf...)
		doc = append(doc, 0x00) // terminator
		binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
		return doc
	}

	tests := []struct {
		name    string
		bsonDoc []byte
		want    bool
	}{
		{
			name:    "ok=1.0 double returns true",
			bsonDoc: buildOkDoubleDoc([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F}),
			want:    true,
		},
		{
			name:    "ok=0.0 double returns false",
			bsonDoc: buildOkDoubleDoc([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
			want:    false,
		},
		{
			name:    "ok=1 int32 returns true",
			bsonDoc: buildOkInt32Doc(1),
			want:    true,
		},
		{
			name:    "ok=0 int32 returns false",
			bsonDoc: buildOkInt32Doc(0),
			want:    false,
		},
		{
			name:    "missing ok field returns false",
			bsonDoc: []byte{0x05, 0x00, 0x00, 0x00, 0x00},
			want:    false,
		},
		{
			name:    "empty document returns false",
			bsonDoc: []byte{},
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseBSONCommandOk(tt.bsonDoc)
			if got != tt.want {
				t.Errorf("parseBSONCommandOk() = %v, want %v", got, tt.want)
			}
		})
	}
}

// buildTestBSONDoc builds a BSON document with the given "ok" double value,
// and optionally includes maxWireVersion and version string fields.
func buildTestBSONDoc(okVal []byte, includeVersion bool) []byte {
	doc := make([]byte, 0, 128)
	sizeBuf := make([]byte, 4)
	doc = append(doc, sizeBuf...)

	// ok field (double)
	doc = append(doc, 0x01)
	doc = append(doc, []byte("ok")...)
	doc = append(doc, 0x00)
	doc = append(doc, okVal...)

	if includeVersion {
		// maxWireVersion field (int32 = 21)
		doc = append(doc, 0x10)
		doc = append(doc, []byte("maxWireVersion")...)
		doc = append(doc, 0x00)
		mwv := make([]byte, 4)
		binary.LittleEndian.PutUint32(mwv, 21)
		doc = append(doc, mwv...)

		// version field (string = "7.0.0")
		versionStr := "7.0.0"
		doc = append(doc, 0x02)
		doc = append(doc, []byte("version")...)
		doc = append(doc, 0x00)
		strLenBuf := make([]byte, 4)
		binary.LittleEndian.PutUint32(strLenBuf, uint32(len(versionStr)+1))
		doc = append(doc, strLenBuf...)
		doc = append(doc, []byte(versionStr)...)
		doc = append(doc, 0x00)
	}

	doc = append(doc, 0x00) // terminator
	binary.LittleEndian.PutUint32(doc[0:4], uint32(len(doc)))
	return doc
}

// buildTestOPReply builds an OP_REPLY message wrapping a BSON document.
func buildTestOPReply(requestID uint32, bsonDoc []byte) []byte {
	msg := make([]byte, 0, 36+len(bsonDoc))
	// Message length placeholder
	msg = append(msg, 0x00, 0x00, 0x00, 0x00)
	// Request ID (server-assigned, arbitrary)
	reqIDBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(reqIDBuf, requestID+1000)
	msg = append(msg, reqIDBuf...)
	// ResponseTo = requestID
	respToBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(respToBuf, requestID)
	msg = append(msg, respToBuf...)
	// OpCode OP_REPLY = 1
	msg = append(msg, 0x01, 0x00, 0x00, 0x00)
	// ResponseFlags = 0
	msg = append(msg, 0x00, 0x00, 0x00, 0x00)
	// CursorID = 0
	msg = append(msg, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00)
	// StartingFrom = 0
	msg = append(msg, 0x00, 0x00, 0x00, 0x00)
	// NumberReturned = 1
	msg = append(msg, 0x01, 0x00, 0x00, 0x00)
	// BSON document
	msg = append(msg, bsonDoc...)
	// Set message length
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

// buildTestOPMsg builds an OP_MSG message wrapping a BSON document.
func buildTestOPMsg(requestID uint32, bsonDoc []byte) []byte {
	msg := make([]byte, 0, 21+len(bsonDoc))
	// Message length placeholder
	msg = append(msg, 0x00, 0x00, 0x00, 0x00)
	// Request ID (server-assigned, arbitrary)
	reqIDBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(reqIDBuf, requestID+1000)
	msg = append(msg, reqIDBuf...)
	// ResponseTo = requestID
	respToBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(respToBuf, requestID)
	msg = append(msg, respToBuf...)
	// OpCode OP_MSG = 2013
	msg = append(msg, 0xDD, 0x07, 0x00, 0x00)
	// FlagBits = 0
	msg = append(msg, 0x00, 0x00, 0x00, 0x00)
	// Section kind 0
	msg = append(msg, 0x00)
	// BSON document
	msg = append(msg, bsonDoc...)
	// Set message length
	binary.LittleEndian.PutUint32(msg[0:4], uint32(len(msg)))
	return msg
}

// handleMongoDBConn handles incoming connections on the mock MongoDB server.
// For OP_QUERY (opCode 2004): respond with OP_REPLY containing a full doc with ok=1.0,
// maxWireVersion=21, version="7.0.0".
// For OP_MSG with requestID 200 (the listDatabases auth check): respond with ok=1.0
// (no auth required) or ok=0.0 (auth required) based on authRequired.
// For other OP_MSG: respond with full doc (ok=1.0, maxWireVersion=21, version="7.0.0").
func handleMongoDBConn(conn net.Conn, authRequired bool) {
	defer conn.Close()
	okTrue := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xF0, 0x3F}  // 1.0
	okFalse := []byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // 0.0

	for {
		// Read 4-byte message length header
		header := make([]byte, 4)
		_, err := io.ReadFull(conn, header)
		if err != nil {
			return
		}
		msgLen := binary.LittleEndian.Uint32(header)
		if msgLen < 16 {
			return
		}
		// Read rest of message
		rest := make([]byte, msgLen-4)
		_, err = io.ReadFull(conn, rest)
		if err != nil {
			return
		}
		msg := append(header, rest...)

		requestID := binary.LittleEndian.Uint32(msg[4:8])
		opCode := binary.LittleEndian.Uint32(msg[12:16])

		var response []byte
		switch opCode {
		case OP_QUERY: // 2004
			if requestID == 201 {
				// listDatabases OP_QUERY fallback — honor authRequired
				okVal := okTrue
				if authRequired {
					okVal = okFalse
				}
				bsonDoc := buildTestBSONDoc(okVal, false)
				response = buildTestOPReply(requestID, bsonDoc)
			} else {
				bsonDoc := buildTestBSONDoc(okTrue, true)
				response = buildTestOPReply(requestID, bsonDoc)
			}
		case OP_MSG: // 2013
			if requestID == 200 {
				// listDatabases auth check
				var okVal []byte
				if authRequired {
					okVal = okFalse
				} else {
					okVal = okTrue
				}
				bsonDoc := buildTestBSONDoc(okVal, false)
				response = buildTestOPMsg(requestID, bsonDoc)
			} else {
				// Other OP_MSG (hello, isMaster, buildInfo, etc.)
				bsonDoc := buildTestBSONDoc(okTrue, true)
				response = buildTestOPMsg(requestID, bsonDoc)
			}
		default:
			return
		}

		if _, err := conn.Write(response); err != nil {
			return
		}
	}
}

// TestMongoDBSecurityFindings verifies security finding detection via mock TCP server.
func TestMongoDBSecurityFindings(t *testing.T) {
	tests := []struct {
		name          string
		misconfigs    bool
		authRequired  bool
		wantAnon      bool
		wantFindings  int
		wantFindingID string
		wantSeverity  plugins.Severity
	}{
		{
			name:          "misconfigs=true auth not required",
			misconfigs:    true,
			authRequired:  false,
			wantAnon:      true,
			wantFindings:  1,
			wantFindingID: "mongodb-no-auth",
			wantSeverity:  plugins.SeverityCritical,
		},
		{
			name:         "misconfigs=true auth required",
			misconfigs:   true,
			authRequired: true,
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:         "misconfigs=false",
			misconfigs:   false,
			authRequired: false,
			wantAnon:     false,
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("Failed to start mock server: %v", err)
			}
			defer listener.Close()

			tcpAddr := listener.Addr().(*net.TCPAddr)
			serverPort := tcpAddr.Port

			go func() {
				for {
					conn, err := listener.Accept()
					if err != nil {
						return
					}
					go handleMongoDBConn(conn, tt.authRequired)
				}
			}()

			conn, err := net.DialTimeout("tcp", listener.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatalf("Failed to connect to mock server: %v", err)
			}
			defer conn.Close()

			addrStr := net.JoinHostPort("127.0.0.1", strconv.Itoa(serverPort))
			addrPort := netip.MustParseAddrPort(addrStr)
			target := plugins.Target{
				Host:       "127.0.0.1",
				Address:    addrPort,
				Misconfigs: tt.misconfigs,
			}

			plugin := &MONGODBPlugin{}
			service, err := plugin.Run(conn, 5*time.Second, target)
			if err != nil {
				t.Fatalf("Run() returned unexpected error: %v", err)
			}
			if service == nil {
				t.Fatal("Run() returned nil, want non-nil service")
			}

			if service.AnonymousAccess != tt.wantAnon {
				t.Errorf("AnonymousAccess = %v, want %v", service.AnonymousAccess, tt.wantAnon)
			}
			if len(service.SecurityFindings) != tt.wantFindings {
				t.Fatalf("len(SecurityFindings) = %d, want %d", len(service.SecurityFindings), tt.wantFindings)
			}
			if tt.wantFindings > 0 {
				if service.SecurityFindings[0].ID != tt.wantFindingID {
					t.Errorf("SecurityFindings[0].ID = %q, want %q", service.SecurityFindings[0].ID, tt.wantFindingID)
				}
				if service.SecurityFindings[0].Severity != tt.wantSeverity {
					t.Errorf("SecurityFindings[0].Severity = %q, want %q", service.SecurityFindings[0].Severity, tt.wantSeverity)
				}
			}
		})
	}
}

// startMongoContainer spins up a mongo:7 Docker container and returns a live connection,
// the parsed address, and a cleanup function.
func startMongoContainer(t *testing.T, env []string) (net.Conn, netip.AddrPort, func()) {
	t.Helper()

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "mongo",
		Tag:        "7",
		Env:        env,
	})
	if err != nil {
		t.Fatalf("could not start mongodb container: %s", err)
	}

	cleanup := func() { pool.Purge(resource) } //nolint:errcheck

	rawAddr := resource.GetHostPort("27017/tcp")
	host, port, err := net.SplitHostPort(rawAddr)
	if err != nil {
		cleanup()
		t.Fatalf("could not split host:port %q: %v", rawAddr, err)
	}
	if host == "localhost" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	targetAddr := net.JoinHostPort(host, port)

	err = pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", targetAddr, 5*time.Second)
		if dialErr != nil {
			return dialErr
		}
		defer conn.Close()
		// TCP open doesn't mean MongoDB is ready; send a hello probe to confirm
		// the server is accepting wire protocol commands.
		hello := buildMongoDBMsgQuery("hello", 1)
		_, sendErr := conn.Write(hello)
		if sendErr != nil {
			return sendErr
		}
		buf := make([]byte, 4096)
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		n, readErr := conn.Read(buf)
		if readErr != nil || n == 0 {
			return fmt.Errorf("mongodb not ready")
		}
		return nil
	})
	if err != nil {
		cleanup()
		t.Fatalf("failed to connect to mongodb container: %s", err)
	}

	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		cleanup()
		t.Fatalf("failed to open connection to mongodb container: %s", err)
	}

	addrPort := netip.MustParseAddrPort(targetAddr)
	return conn, addrPort, cleanup
}

// TestMongoDBSecurityFindingsLive runs live Docker integration tests for MongoDB security findings.
func TestMongoDBSecurityFindingsLive(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	tests := []struct {
		name         string
		env          []string
		misconfigs   bool
		wantAnon     bool
		wantFindings int
	}{
		{
			name:         "no auth - finding detected",
			env:          nil,
			misconfigs:   true,
			wantAnon:     true,
			wantFindings: 1,
		},
		{
			name: "auth enabled - no findings",
			env: []string{
				"MONGO_INITDB_ROOT_USERNAME=admin",
				"MONGO_INITDB_ROOT_PASSWORD=testpassword123",
			},
			misconfigs:   true,
			wantAnon:     false,
			wantFindings: 0,
		},
		{
			name:         "no auth but misconfigs disabled - no findings",
			env:          nil,
			misconfigs:   false,
			wantAnon:     false,
			wantFindings: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, addrPort, cleanup := startMongoContainer(t, tt.env)
			defer cleanup()
			defer conn.Close()

			target := plugins.Target{
				Host:       addrPort.Addr().String(),
				Address:    addrPort,
				Misconfigs: tt.misconfigs,
			}

			plugin := &MONGODBPlugin{}
			service, err := plugin.Run(conn, 5*time.Second, target)
			if err != nil {
				t.Fatalf("Run() returned unexpected error: %v", err)
			}
			if service == nil {
				t.Fatal("Run() returned nil, want non-nil service")
			}

			if service.Protocol != "mongodb" {
				t.Errorf("expected Protocol %q, got %q", "mongodb", service.Protocol)
			}
			if service.AnonymousAccess != tt.wantAnon {
				t.Errorf("AnonymousAccess = %v, want %v", service.AnonymousAccess, tt.wantAnon)
			}
			if len(service.SecurityFindings) != tt.wantFindings {
				t.Fatalf("len(SecurityFindings) = %d, want %d", len(service.SecurityFindings), tt.wantFindings)
			}
			if tt.wantFindings > 0 {
				if service.SecurityFindings[0].ID != "mongodb-no-auth" {
					t.Errorf("expected finding ID 'mongodb-no-auth', got %q", service.SecurityFindings[0].ID)
				}
				if service.SecurityFindings[0].Severity != plugins.SeverityCritical {
					t.Errorf("expected severity Critical, got %s", service.SecurityFindings[0].Severity)
				}
			}
		})
	}
}
