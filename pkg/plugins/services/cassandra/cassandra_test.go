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

package cassandra

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// TestBuildOPTIONSFrame tests OPTIONS frame construction
func TestBuildOPTIONSFrame(t *testing.T) {
	frame := buildOPTIONSFrame()

	// Expected frame: [version|flags|stream|opcode|length]
	//                 [0x04   |0x00 |0x0000|0x05  |0x00000000]
	expectedLength := 9
	if len(frame) != expectedLength {
		t.Errorf("buildOPTIONSFrame() length = %d, want %d", len(frame), expectedLength)
	}

	// Verify version byte
	if frame[0] != PROTOCOL_V4_REQUEST {
		t.Errorf("buildOPTIONSFrame() version = 0x%02x, want 0x%02x", frame[0], PROTOCOL_V4_REQUEST)
	}

	// Verify flags byte
	if frame[1] != 0x00 {
		t.Errorf("buildOPTIONSFrame() flags = 0x%02x, want 0x00", frame[1])
	}

	// Verify stream ID (big-endian uint16)
	stream := binary.BigEndian.Uint16(frame[2:4])
	if stream != 0 {
		t.Errorf("buildOPTIONSFrame() stream = %d, want 0", stream)
	}

	// Verify opcode
	if frame[4] != OP_OPTIONS {
		t.Errorf("buildOPTIONSFrame() opcode = 0x%02x, want 0x%02x (OP_OPTIONS)", frame[4], OP_OPTIONS)
	}

	// Verify length field (big-endian uint32)
	length := binary.BigEndian.Uint32(frame[5:9])
	if length != 0 {
		t.Errorf("buildOPTIONSFrame() body length = %d, want 0", length)
	}
}

// TestIsCassandraSUPPORTED tests SUPPORTED response validation
func TestIsCassandraSUPPORTED(t *testing.T) {
	tests := []struct {
		name          string
		response      []byte
		requestStream uint16
		wantValid     bool
		wantErr       bool
	}{
		{
			name: "valid SUPPORTED response v4",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_RESPONSE) // version: 0x84
				resp = append(resp, 0x00)                 // flags
				resp = append(resp, 0x00, 0x00)           // stream: 0
				resp = append(resp, OP_SUPPORTED)         // opcode: 0x06
				// Body: minimal multimap with 1 entry (key "A", empty value list)
				// Body length: 2 (n) + 2 (key len) + 1 (key) + 2 (value count) = 7 bytes
				resp = append(resp, 0x00, 0x00, 0x00, 0x07)
				resp = append(resp, 0x00, 0x01) // n=1
				resp = append(resp, 0x00, 0x01) // key length: 1
				resp = append(resp, byte('A'))  // key: "A"
				resp = append(resp, 0x00, 0x00) // value count: 0
				return resp
			}(),
			requestStream: 0,
			wantValid:     true,
			wantErr:       false,
		},
		{
			name: "valid SUPPORTED response v5",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V5_RESPONSE)   // version: 0x85
				resp = append(resp, 0x00)                   // flags
				resp = append(resp, 0x00, 0x01)             // stream: 1
				resp = append(resp, OP_SUPPORTED)           // opcode: 0x06
				resp = append(resp, 0x00, 0x00, 0x00, 0x07) // length: 7
				resp = append(resp, 0x00, 0x01)             // n=1
				resp = append(resp, 0x00, 0x01)             // key length: 1
				resp = append(resp, byte('A'))              // key: "A"
				resp = append(resp, 0x00, 0x00)             // value count: 0
				return resp
			}(),
			requestStream: 1,
			wantValid:     true,
			wantErr:       false,
		},
		{
			name: "valid SUPPORTED response v6",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V6_RESPONSE)   // version: 0x86
				resp = append(resp, 0x00)                   // flags
				resp = append(resp, 0x00, 0x00)             // stream: 0
				resp = append(resp, OP_SUPPORTED)           // opcode: 0x06
				resp = append(resp, 0x00, 0x00, 0x00, 0x07) // length: 7
				resp = append(resp, 0x00, 0x01)             // n=1
				resp = append(resp, 0x00, 0x01)             // key length: 1
				resp = append(resp, byte('A'))              // key: "A"
				resp = append(resp, 0x00, 0x00)             // value count: 0
				return resp
			}(),
			requestStream: 0,
			wantValid:     true,
			wantErr:       false,
		},
		{
			name:          "response too short (header truncated)",
			response:      []byte{0x84, 0x00, 0x00},
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name:          "response minimum length (missing body)",
			response:      []byte{0x84, 0x00, 0x00, 0x00, 0x06, 0x00, 0x00, 0x00, 0x05, 0x00},
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "invalid version byte (request instead of response)",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_REQUEST) // 0x04 (should be 0x84)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x05)
				resp = append(resp, 0x00, 0x00)
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "invalid version byte (too high)",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, 0x87) // Invalid version
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x05)
				resp = append(resp, 0x00, 0x00)
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "stream mismatch",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x05) // stream: 5 (should be 0)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x05)
				resp = append(resp, 0x00, 0x00)
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "wrong opcode (OPTIONS instead of SUPPORTED)",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_OPTIONS) // 0x05 (should be 0x06)
				resp = append(resp, 0x00, 0x00, 0x00, 0x05)
				resp = append(resp, 0x00, 0x00)
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "length field too small",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x02) // length: 2 (< 5)
				resp = append(resp, 0x00, 0x00)
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "length field too large (1MB+)",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x01, 0x00, 0x00, 0x01) // length: 16MB+
				resp = append(resp, 0x00, 0x00)
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
		{
			name: "response shorter than declared length",
			response: func() []byte {
				resp := make([]byte, 0, 100)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x64) // length: 100 bytes
				resp = append(resp, 0x00, 0x00)             // Only 2 bytes of body
				return resp
			}(),
			requestStream: 0,
			wantValid:     false,
			wantErr:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			valid, err := isCassandraSUPPORTED(tt.response, tt.requestStream)
			if valid != tt.wantValid {
				t.Errorf("isCassandraSUPPORTED() valid = %v, want %v", valid, tt.wantValid)
			}
			if (err != nil) != tt.wantErr {
				t.Errorf("isCassandraSUPPORTED() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// buildValidSUPPORTEDFrame constructs a valid SUPPORTED response frame with given multimap
func buildValidSUPPORTEDFrame(multimap map[string][]string) []byte {
	resp := make([]byte, 0, 512)

	// Calculate body first to know total length
	body := make([]byte, 0, 512)

	// Number of entries
	numEntries := uint16(len(multimap))
	entriesBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(entriesBuf, numEntries)
	body = append(body, entriesBuf...)

	// Encode each key-value pair
	for key, values := range multimap {
		// Encode key (CQL [string])
		keyLen := uint16(len(key))
		keyLenBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(keyLenBuf, keyLen)
		body = append(body, keyLenBuf...)
		body = append(body, []byte(key)...)

		// Encode value list (CQL [string list])
		numValues := uint16(len(values))
		numValuesBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(numValuesBuf, numValues)
		body = append(body, numValuesBuf...)

		for _, val := range values {
			valLen := uint16(len(val))
			valLenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(valLenBuf, valLen)
			body = append(body, valLenBuf...)
			body = append(body, []byte(val)...)
		}
	}

	// Build header
	resp = append(resp, PROTOCOL_V4_RESPONSE) // version
	resp = append(resp, 0x00)                 // flags
	resp = append(resp, 0x00, 0x00)           // stream
	resp = append(resp, OP_SUPPORTED)         // opcode

	// Body length (big-endian uint32)
	lengthBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lengthBuf, uint32(len(body)))
	resp = append(resp, lengthBuf...)

	// Body
	resp = append(resp, body...)

	return resp
}

// TestParseSUPPORTEDMultimap tests multimap parsing with real byte sequences
func TestParseSUPPORTEDMultimap(t *testing.T) {
	tests := []struct {
		name         string
		response     []byte
		wantMultimap map[string][]string
		wantErr      bool
	}{
		{
			name:         "empty multimap",
			response:     buildValidSUPPORTEDFrame(map[string][]string{}),
			wantMultimap: map[string][]string{},
			wantErr:      false,
		},
		{
			name: "single key with single value",
			response: buildValidSUPPORTEDFrame(map[string][]string{
				"CQL_VERSION": {"3.4.7"},
			}),
			wantMultimap: map[string][]string{
				"CQL_VERSION": {"3.4.7"},
			},
			wantErr: false,
		},
		{
			name: "single key with multiple values",
			response: buildValidSUPPORTEDFrame(map[string][]string{
				"COMPRESSION": {"lz4", "snappy", "zstd"},
			}),
			wantMultimap: map[string][]string{
				"COMPRESSION": {"lz4", "snappy", "zstd"},
			},
			wantErr: false,
		},
		{
			name: "multiple keys with mixed values (Cassandra 5.0)",
			response: buildValidSUPPORTEDFrame(map[string][]string{
				"CQL_VERSION":       {"3.4.7"},
				"COMPRESSION":       {"lz4", "snappy", "zstd"},
				"PROTOCOL_VERSIONS": {"4/v4", "5/v5", "6/v6"},
			}),
			wantMultimap: map[string][]string{
				"CQL_VERSION":       {"3.4.7"},
				"COMPRESSION":       {"lz4", "snappy", "zstd"},
				"PROTOCOL_VERSIONS": {"4/v4", "5/v5", "6/v6"},
			},
			wantErr: false,
		},
		{
			name: "Cassandra 4.0 markers",
			response: buildValidSUPPORTEDFrame(map[string][]string{
				"CQL_VERSION":       {"3.4.5"},
				"COMPRESSION":       {"lz4", "snappy", "zstd"},
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4", "5/v5"},
			}),
			wantMultimap: map[string][]string{
				"CQL_VERSION":       {"3.4.5"},
				"COMPRESSION":       {"lz4", "snappy", "zstd"},
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4", "5/v5"},
			},
			wantErr: false,
		},
		{
			name: "Cassandra 3.11 markers",
			response: buildValidSUPPORTEDFrame(map[string][]string{
				"CQL_VERSION":       {"3.4.4"},
				"COMPRESSION":       {"lz4", "snappy"},
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4"},
			}),
			wantMultimap: map[string][]string{
				"CQL_VERSION":       {"3.4.4"},
				"COMPRESSION":       {"lz4", "snappy"},
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4"},
			},
			wantErr: false,
		},
		{
			name: "ScyllaDB markers",
			response: buildValidSUPPORTEDFrame(map[string][]string{
				"CQL_VERSION":               {"3.3.1"},
				"SCYLLA_SHARD":              {"0"},
				"SCYLLA_NR_SHARDS":          {"4"},
				"SCYLLA_SHARDING_ALGORITHM": {"biased-token-round-robin"},
			}),
			wantMultimap: map[string][]string{
				"CQL_VERSION":               {"3.3.1"},
				"SCYLLA_SHARD":              {"0"},
				"SCYLLA_NR_SHARDS":          {"4"},
				"SCYLLA_SHARDING_ALGORITHM": {"biased-token-round-robin"},
			},
			wantErr: false,
		},
		{
			name:         "response too short (no header)",
			response:     []byte{0x84, 0x00},
			wantMultimap: nil,
			wantErr:      true,
		},
		{
			name: "body too short (no entry count)",
			response: func() []byte {
				resp := make([]byte, 0, 20)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x01) // length: 1
				resp = append(resp, 0x00)                   // Only 1 byte of body
				return resp
			}(),
			wantMultimap: nil,
			wantErr:      true,
		},
		{
			name: "truncated string key",
			response: func() []byte {
				resp := make([]byte, 0, 30)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x04) // length: 4
				resp = append(resp, 0x00, 0x01)             // n=1
				resp = append(resp, 0x00, 0x0A)             // key length: 10 bytes (truncated)
				return resp
			}(),
			wantMultimap: nil,
			wantErr:      true,
		},
		{
			name: "truncated string list count",
			response: func() []byte {
				resp := make([]byte, 0, 50)
				resp = append(resp, PROTOCOL_V4_RESPONSE)
				resp = append(resp, 0x00)
				resp = append(resp, 0x00, 0x00)
				resp = append(resp, OP_SUPPORTED)
				resp = append(resp, 0x00, 0x00, 0x00, 0x08) // length: 8
				resp = append(resp, 0x00, 0x01)             // n=1
				resp = append(resp, 0x00, 0x03)             // key length: 3
				resp = append(resp, []byte("FOO")...)       // key: "FOO"
				// Missing value list count
				return resp
			}(),
			wantMultimap: nil,
			wantErr:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			multimap, err := parseSUPPORTEDMultimap(tt.response)

			if (err != nil) != tt.wantErr {
				t.Errorf("parseSUPPORTEDMultimap() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Compare multimap lengths
			if len(multimap) != len(tt.wantMultimap) {
				t.Errorf("parseSUPPORTEDMultimap() got %d keys, want %d keys", len(multimap), len(tt.wantMultimap))
			}

			// Compare each key-value pair
			for key, wantValues := range tt.wantMultimap {
				gotValues, ok := multimap[key]
				if !ok {
					t.Errorf("parseSUPPORTEDMultimap() missing key %q", key)
					continue
				}

				if len(gotValues) != len(wantValues) {
					t.Errorf("parseSUPPORTEDMultimap() key %q: got %d values, want %d values", key, len(gotValues), len(wantValues))
					continue
				}

				for i := range wantValues {
					if gotValues[i] != wantValues[i] {
						t.Errorf("parseSUPPORTEDMultimap() key %q value[%d]: got %q, want %q", key, i, gotValues[i], wantValues[i])
					}
				}
			}
		})
	}
}

// TestExtractCassandraVersion tests version detection from SUPPORTED multimap markers
func TestExtractCassandraVersion(t *testing.T) {
	tests := []struct {
		name           string
		multimap       map[string][]string
		wantProduct    string
		wantVersion    string
		wantConfidence string
	}{
		{
			name: "Cassandra 5.0 (CQL 3.4.7)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.4.7"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "5.0",
			wantConfidence: "high",
		},
		{
			name: "Cassandra 4.1 (CQL 3.4.6)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.4.6"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "4.1",
			wantConfidence: "high",
		},
		{
			name: "Cassandra 4.0 (CQL 3.4.5)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.4.5"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "4.0",
			wantConfidence: "high",
		},
		{
			name: "Cassandra 3.11 (CQL 3.4.4)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.4.4"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "3.11",
			wantConfidence: "high",
		},
		{
			name: "Cassandra 2.2 (CQL 3.3.x)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.3.1"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "2.2",
			wantConfidence: "medium",
		},
		{
			name: "Cassandra 2.1 (CQL 3.2.x)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.2.0"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "2.1",
			wantConfidence: "medium",
		},
		{
			name: "Protocol v6 fallback (no CQL_VERSION)",
			multimap: map[string][]string{
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4", "5/v5", "6/v6"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "5.0+",
			wantConfidence: "high",
		},
		{
			name: "Protocol v5 fallback (no CQL_VERSION)",
			multimap: map[string][]string{
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4", "5/v5"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "4.0+",
			wantConfidence: "medium",
		},
		{
			name: "Protocol v4 only (no v5, no CQL_VERSION)",
			multimap: map[string][]string{
				"PROTOCOL_VERSIONS": {"3/v3", "4/v4"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "2.2-3.x",
			wantConfidence: "medium",
		},
		{
			name: "Protocol v3 only (no v4, no CQL_VERSION)",
			multimap: map[string][]string{
				"PROTOCOL_VERSIONS": {"3/v3"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "2.1.x",
			wantConfidence: "medium",
		},
		{
			name: "Zstd compression marker (fallback version)",
			multimap: map[string][]string{
				"COMPRESSION": {"lz4", "snappy", "zstd"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "4.0+",
			wantConfidence: "high",
		},
		{
			name: "No zstd compression (older version)",
			multimap: map[string][]string{
				"COMPRESSION": {"lz4", "snappy"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "",
			wantConfidence: "low",
		},
		{
			name: "ScyllaDB detection",
			multimap: map[string][]string{
				"CQL_VERSION":  {"3.3.1"},
				"SCYLLA_SHARD": {"0"},
			},
			wantProduct:    "ScyllaDB",
			wantVersion:    "2.2",
			wantConfidence: "medium",
		},
		{
			name: "DataStax Enterprise detection",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.4.5"},
				"DSE_VERSION": {"6.8.0"},
			},
			wantProduct:    "DataStax Enterprise",
			wantVersion:    "4.0",
			wantConfidence: "high",
		},
		{
			name:           "Empty multimap (no markers)",
			multimap:       map[string][]string{},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "",
			wantConfidence: "low",
		},
		{
			name: "Unknown CQL version with zstd (trust zstd)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.5.0"},
				"COMPRESSION": {"lz4", "snappy", "zstd"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "4.0+",
			wantConfidence: "high",
		},
		{
			name: "CQL 3.4.x unknown minor (medium confidence)",
			multimap: map[string][]string{
				"CQL_VERSION": {"3.4.99"},
			},
			wantProduct:    "Apache Cassandra",
			wantVersion:    "3.*",
			wantConfidence: "medium",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			metadata := extractCassandraVersion(tt.multimap)

			if metadata.Product != tt.wantProduct {
				t.Errorf("extractCassandraVersion() product = %q, want %q", metadata.Product, tt.wantProduct)
			}

			if metadata.Version != tt.wantVersion {
				t.Errorf("extractCassandraVersion() version = %q, want %q", metadata.Version, tt.wantVersion)
			}

			if metadata.Confidence != tt.wantConfidence {
				t.Errorf("extractCassandraVersion() confidence = %q, want %q", metadata.Confidence, tt.wantConfidence)
			}
		})
	}
}

// TestBuildCassandraCPE tests CPE generation for Cassandra/ScyllaDB/DSE
func TestBuildCassandraCPE(t *testing.T) {
	tests := []struct {
		name    string
		product string
		version string
		wantCPE string
	}{
		// Apache Cassandra CPEs
		{
			name:    "Cassandra 5.0",
			product: "Apache Cassandra",
			version: "5.0",
			wantCPE: "cpe:2.3:a:apache:cassandra:5.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra 4.1",
			product: "Apache Cassandra",
			version: "4.1",
			wantCPE: "cpe:2.3:a:apache:cassandra:4.1:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra 4.0",
			product: "Apache Cassandra",
			version: "4.0",
			wantCPE: "cpe:2.3:a:apache:cassandra:4.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra 3.11",
			product: "Apache Cassandra",
			version: "3.11",
			wantCPE: "cpe:2.3:a:apache:cassandra:3.11:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra 2.2",
			product: "Apache Cassandra",
			version: "2.2",
			wantCPE: "cpe:2.3:a:apache:cassandra:2.2:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra unknown version (wildcard)",
			product: "Apache Cassandra",
			version: "",
			wantCPE: "cpe:2.3:a:apache:cassandra:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra empty product defaults to Apache",
			product: "",
			version: "4.0",
			wantCPE: "cpe:2.3:a:apache:cassandra:4.0:*:*:*:*:*:*:*",
		},
		{
			name:    "Cassandra version range (4.0+)",
			product: "Apache Cassandra",
			version: "4.0+",
			wantCPE: "cpe:2.3:a:apache:cassandra:4.0+:*:*:*:*:*:*:*",
		},

		// ScyllaDB CPEs
		{
			name:    "ScyllaDB with version",
			product: "ScyllaDB",
			version: "5.2",
			wantCPE: "cpe:2.3:a:scylladb:scylla:5.2:*:*:*:*:*:*:*",
		},
		{
			name:    "ScyllaDB unknown version",
			product: "ScyllaDB",
			version: "",
			wantCPE: "cpe:2.3:a:scylladb:scylla:*:*:*:*:*:*:*:*",
		},

		// DataStax Enterprise CPEs
		{
			name:    "DSE with version",
			product: "DataStax Enterprise",
			version: "6.8",
			wantCPE: "cpe:2.3:a:datastax:datastax_enterprise:6.8:*:*:*:*:*:*:*",
		},
		{
			name:    "DSE unknown version",
			product: "DataStax Enterprise",
			version: "",
			wantCPE: "cpe:2.3:a:datastax:datastax_enterprise:*:*:*:*:*:*:*:*",
		},

		// Unknown product fallback
		{
			name:    "Unknown product falls back to Cassandra",
			product: "Unknown Product",
			version: "1.0",
			wantCPE: "cpe:2.3:a:apache:cassandra:1.0:*:*:*:*:*:*:*",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cpe := buildCassandraCPE(tt.product, tt.version)
			if cpe != tt.wantCPE {
				t.Errorf("buildCassandraCPE(%q, %q) = %q, want %q", tt.product, tt.version, cpe, tt.wantCPE)
			}
		})
	}
}

// buildSTARTUPAuthResponse builds a STARTUP response with the given opcode.
// opcode 0x02 = READY (no auth), 0x03 = AUTHENTICATE (auth required)
func buildSTARTUPAuthResponse(stream uint16, opcode byte) []byte {
	// Build a minimal READY or AUTHENTICATE response frame
	// Header: version(1) + flags(1) + stream(2) + opcode(1) + length(4) = 9 bytes
	resp := make([]byte, 0, 9)
	resp = append(resp, PROTOCOL_V4_RESPONSE) // version
	resp = append(resp, 0x00)                 // flags
	// stream (big-endian)
	resp = append(resp, byte(stream>>8), byte(stream))
	resp = append(resp, opcode) // opcode
	// Body length: 0 for READY, minimal for AUTHENTICATE
	if opcode == 0x03 {
		// AUTHENTICATE has a string body (authenticator class name)
		authClass := "org.apache.cassandra.auth.PasswordAuthenticator"
		classLen := uint16(len(authClass))
		bodyLen := uint32(2 + int(classLen)) // 2-byte length + string
		resp = append(resp, byte(bodyLen>>24), byte(bodyLen>>16), byte(bodyLen>>8), byte(bodyLen))
		resp = append(resp, byte(classLen>>8), byte(classLen))
		resp = append(resp, []byte(authClass)...)
	} else {
		resp = append(resp, 0x00, 0x00, 0x00, 0x00) // length 0
	}
	return resp
}

// TestCheckCassandraAuth_ShortResponse verifies that checkCassandraAuth returns false when the
// server sends fewer than 9 bytes (header cannot be parsed).
func TestCheckCassandraAuth_ShortResponse(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	go func() {
		defer serverConn.Close()
		buf := make([]byte, 4096)
		_, _ = serverConn.Read(buf)
		// Send only 5 bytes — not enough for a full CQL response header (9 bytes)
		_, _ = serverConn.Write([]byte{0x84, 0x00, 0x00, 0x00, 0x02})
	}()

	got := checkCassandraAuth(clientConn, 5*time.Second, "3.0.0")
	clientConn.Close()
	assert.False(t, got, "expected false for short response")
}

// TestCheckCassandraAuth_ConnectionError verifies that checkCassandraAuth returns false when
// the server closes the connection immediately.
func TestCheckCassandraAuth_ConnectionError(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	go func() {
		serverConn.Close() // close immediately without sending anything
	}()

	got := checkCassandraAuth(clientConn, 5*time.Second, "3.0.0")
	clientConn.Close()
	assert.False(t, got, "expected false when connection is immediately closed")
}

// TestCheckCassandraAuth_UnexpectedOpcode verifies that checkCassandraAuth returns false when
// the server sends an ERROR frame (opcode 0x00).
func TestCheckCassandraAuth_UnexpectedOpcode(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	go func() {
		defer serverConn.Close()
		buf := make([]byte, 4096)
		_, _ = serverConn.Read(buf)
		// Send an ERROR response (opcode 0x00) with no body
		resp := []byte{
			PROTOCOL_V4_RESPONSE, // version
			0x00,                 // flags
			0x00, 0x01,           // stream: 1
			0x00,                 // opcode: ERROR
			0x00, 0x00, 0x00, 0x00, // body length: 0
		}
		_, _ = serverConn.Write(resp)
	}()

	got := checkCassandraAuth(clientConn, 5*time.Second, "3.0.0")
	clientConn.Close()
	assert.False(t, got, "expected false for ERROR opcode response")
}

// TestCheckCassandraAuth_VersionPassthrough verifies that the CQL_VERSION sent in the STARTUP
// frame matches the version passed into checkCassandraAuth.
func TestCheckCassandraAuth_VersionPassthrough(t *testing.T) {
	serverConn, clientConn := net.Pipe()

	const expectedVersion = "3.4.5"
	startupReceived := make(chan []byte, 1)

	go func() {
		defer serverConn.Close()
		buf := make([]byte, 4096)
		n, err := serverConn.Read(buf)
		if err != nil {
			close(startupReceived)
			return
		}
		startupReceived <- buf[:n]
		// Respond with READY so checkCassandraAuth returns true
		resp := buildSTARTUPAuthResponse(1, 0x02)
		_, _ = serverConn.Write(resp)
	}()

	_ = checkCassandraAuth(clientConn, 5*time.Second, expectedVersion)
	clientConn.Close()

	data, ok := <-startupReceived
	if !ok {
		t.Fatal("server did not receive any data")
	}
	// The STARTUP frame body is a CQL string map — verify expectedVersion appears in it
	assert.Contains(t, string(data), expectedVersion,
		"STARTUP frame should contain the requested CQL_VERSION")
}

// TestCassandraSecurityFindingFields validates all SecurityFinding fields are populated correctly.
func TestCassandraSecurityFindingFields(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				reqCount := 0
				for {
					_, err := c.Read(buf)
					if err != nil {
						return
					}
					reqCount++
					if reqCount == 1 {
						_, _ = c.Write(buildCassandraSUPPORTEDResponse())
					} else {
						_, _ = c.Write(buildSTARTUPAuthResponse(1, 0x02))
					}
				}
			}(conn)
		}
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &CassandraPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	assert.Len(t, service.SecurityFindings, 1, "expected 1 security finding")
	if len(service.SecurityFindings) == 0 {
		return
	}
	f := service.SecurityFindings[0]
	assert.Equal(t, "cassandra-no-auth", f.ID, "finding ID mismatch")
	assert.Equal(t, plugins.SeverityHigh, f.Severity, "finding severity mismatch")
	assert.NotEmpty(t, f.Description, "Description must be non-empty")
	assert.NotEmpty(t, f.Evidence, "Evidence must be non-empty")
}

// TestCassandraDockerNoAuth is a Docker integration test that verifies anonymous access
// detection against a real Cassandra 4.1 container with default AllowAllAuthenticator.
func TestCassandraDockerNoAuth(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository: "cassandra",
		Tag:        "4.1",
	})
	if err != nil {
		t.Fatalf("could not start cassandra container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	port := resource.GetPort("9042/tcp")
	addr := fmt.Sprintf("127.0.0.1:%s", port)

	// Cassandra takes ~30-60 seconds to start
	time.Sleep(30 * time.Second)

	var service *plugins.Service
	retryErr := pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", addr, 5*time.Second)
		if dialErr != nil {
			return dialErr
		}
		defer conn.Close()

		addrPort := netip.MustParseAddrPort(addr)
		target := plugins.Target{
			Host:       "127.0.0.1",
			Address:    addrPort,
			Misconfigs: true,
		}

		svc, runErr := (&CassandraPlugin{}).Run(conn, 10*time.Second, target)
		if runErr != nil {
			return runErr
		}
		if svc == nil {
			return fmt.Errorf("cassandra not yet ready")
		}
		service = svc
		return nil
	})
	if retryErr != nil {
		t.Fatalf("cassandra plugin never connected: %s", retryErr)
	}

	assert.True(t, service.AnonymousAccess, "expected AnonymousAccess=true for default Cassandra")
	assert.NotEmpty(t, service.SecurityFindings, "expected SecurityFindings for default Cassandra")
	if len(service.SecurityFindings) > 0 {
		assert.Equal(t, "cassandra-no-auth", service.SecurityFindings[0].ID)
	}
}

// TestCheckCassandraAuth_Ready tests that checkCassandraAuth returns true when server sends READY.
func TestCheckCassandraAuth_Ready(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		defer serverConn.Close()
		// Read the STARTUP frame
		buf := make([]byte, 4096)
		_, _ = serverConn.Read(buf)
		// Send back READY (opcode 0x02)
		resp := buildSTARTUPAuthResponse(1, 0x02)
		_, _ = serverConn.Write(resp)
	}()

	got := checkCassandraAuth(clientConn, 5*time.Second, "3.0.0")
	assert.True(t, got, "expected checkCassandraAuth to return true for READY response")
}

// TestCheckCassandraAuth_Authenticate tests that checkCassandraAuth returns false when server sends AUTHENTICATE.
func TestCheckCassandraAuth_Authenticate(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()

	go func() {
		defer serverConn.Close()
		buf := make([]byte, 4096)
		_, _ = serverConn.Read(buf)
		// Send back AUTHENTICATE (opcode 0x03)
		resp := buildSTARTUPAuthResponse(1, 0x03)
		_, _ = serverConn.Write(resp)
	}()

	got := checkCassandraAuth(clientConn, 5*time.Second, "3.0.0")
	assert.False(t, got, "expected checkCassandraAuth to return false for AUTHENTICATE response")
}

// buildCassandraSUPPORTEDResponse builds a valid SUPPORTED frame for DetectCassandra.
func buildCassandraSUPPORTEDResponse() []byte {
	multimap := map[string][]string{
		"CQL_VERSION": {"3.4.5"},
		"COMPRESSION": {"lz4", "snappy"},
	}
	return buildValidSUPPORTEDFrame(multimap)
}

// TestCassandraRun_MisconfigsEnabled tests the full Run() flow with misconfigs=true.
// When the server responds SUPPORTED then READY, the service has AnonymousAccess=true.
func TestCassandraRun_MisconfigsEnabled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				reqCount := 0
				for {
					_, err := c.Read(buf)
					if err != nil {
						return
					}
					reqCount++
					if reqCount == 1 {
						// First request: OPTIONS → respond with SUPPORTED
						_, _ = c.Write(buildCassandraSUPPORTEDResponse())
					} else {
						// Second request: STARTUP → respond with READY (no auth)
						_, _ = c.Write(buildSTARTUPAuthResponse(1, 0x02))
					}
				}
			}(conn)
		}
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	}

	plugin := &CassandraPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	assert.True(t, service.AnonymousAccess, "expected AnonymousAccess=true when READY")
	assert.Len(t, service.SecurityFindings, 1, "expected 1 security finding")
	if len(service.SecurityFindings) == 1 {
		assert.Equal(t, "cassandra-no-auth", service.SecurityFindings[0].ID)
		assert.Equal(t, plugins.SeverityHigh, service.SecurityFindings[0].Severity)
	}
}

// TestCassandraRun_MisconfigsDisabled tests that no auth check runs when Misconfigs=false.
func TestCassandraRun_MisconfigsDisabled(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to start mock server: %v", err)
	}
	defer listener.Close()

	serverPort := listener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 4096)
				_, _ = c.Read(buf)
				// OPTIONS → SUPPORTED only. No STARTUP expected when Misconfigs=false.
				_, _ = c.Write(buildCassandraSUPPORTEDResponse())
				// Drain any extra reads without blocking forever
				_, _ = c.Read(buf)
			}(conn)
		}
	}()

	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", serverPort), 5*time.Second)
	if err != nil {
		t.Fatalf("failed to connect to mock server: %v", err)
	}
	defer conn.Close()

	addrStr := fmt.Sprintf("127.0.0.1:%d", serverPort)
	addrPort := netip.MustParseAddrPort(addrStr)
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: false,
	}

	plugin := &CassandraPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run() returned unexpected error: %v", err)
	}
	if service == nil {
		t.Fatal("Run() returned nil, want non-nil service")
	}

	assert.False(t, service.AnonymousAccess, "expected AnonymousAccess=false when Misconfigs=false")
	assert.Empty(t, service.SecurityFindings, "expected no SecurityFindings when Misconfigs=false")
}
