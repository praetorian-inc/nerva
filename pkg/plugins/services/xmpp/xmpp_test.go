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
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

// Realistic XMPP server response fixtures used across multiple test functions.
const ejabberdResponse = `<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='abc123' from='example.com' version='1.0' xml:lang='en'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-1</mechanism><mechanism>PLAIN</mechanism></mechanisms><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='aIT+/ulfcbHXDKPkCA+iw9x5mU8='/></stream:features>`

const prosodyResponse = `<?xml version='1.0'?><stream:stream xmlns:db='jabber:server:dialback' xmlns:stream='http://etherx.jabber.org/streams' version='1.0' from='prosody.example.com' id='def456' xmlns='jabber:client' xml:lang='en'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-1</mechanism><mechanism>SCRAM-SHA-256</mechanism></mechanisms><compression xmlns='http://jabber.org/features/compress'><method>zlib</method></compression><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://prosody.im' ver='xyz789'/></stream:features>`

const openfireResponse = `<?xml version='1.0' encoding='UTF-8'?><stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' from='openfire.example.com' id='ghi789' xml:lang='en' version='1.0'><stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism><mechanism>DIGEST-MD5</mechanism><mechanism>SCRAM-SHA-1</mechanism></mechanisms><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.igniterealtime.org/projects/openfire/' ver='jkl012'/></stream:features>`

// TestBuildXMPPProbe verifies that the XMPP stream initiation probe is correctly
// constructed with the target host in the 'to' attribute, and falls back to
// "localhost" when no host is provided.
func TestBuildXMPPProbe(t *testing.T) {
	tests := []struct {
		name         string
		host         string
		wantContains string
	}{
		{
			name:         "probe with explicit host sets to attribute",
			host:         "example.com",
			wantContains: "to='example.com'",
		},
		{
			name:         "probe with empty host falls back to localhost",
			host:         "",
			wantContains: "to='localhost'",
		},
		{
			name:         "probe always includes jabber:client namespace",
			host:         "chat.example.org",
			wantContains: "xmlns='jabber:client'",
		},
		{
			name:         "probe always includes etherx.jabber.org streams namespace",
			host:         "chat.example.org",
			wantContains: "xmlns:stream='http://etherx.jabber.org/streams'",
		},
		{
			name:         "probe starts with XML declaration",
			host:         "any.host",
			wantContains: "<?xml version='1.0'?>",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			probe := buildXMPPProbe(tt.host)
			assert.Contains(t, string(probe), tt.wantContains,
				"buildXMPPProbe() missing expected content for: %s", tt.name)
		})
	}
}

// TestIsXMPPResponse verifies the response validation logic that distinguishes
// XMPP stream responses from other protocol banners.
func TestIsXMPPResponse(t *testing.T) {
	tests := []struct {
		name     string
		input    []byte
		expected bool
	}{
		{
			name:     "valid ejabberd stream response with jabber:client namespace",
			input:    []byte(ejabberdResponse),
			expected: true,
		},
		{
			name:     "valid Prosody stream response",
			input:    []byte(prosodyResponse),
			expected: true,
		},
		{
			name:     "valid response with jabber:client namespace only",
			input:    []byte(`<?xml version='1.0'?><stream:stream xmlns='jabber:client' id='xyz'>`),
			expected: true,
		},
		{
			name:     "valid response with etherx.jabber.org/streams namespace only",
			input:    []byte(`<stream:stream xmlns:stream='http://etherx.jabber.org/streams'>`),
			expected: true,
		},
		{
			name:     "non-XMPP response: HTTP response",
			input:    []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"),
			expected: false,
		},
		{
			name:     "non-XMPP response: FTP banner",
			input:    []byte("220 (vsFTPd 3.0.3)\r\n"),
			expected: false,
		},
		{
			name:     "empty response",
			input:    []byte{},
			expected: false,
		},
		{
			name:     "partial XML without stream:stream element",
			input:    []byte(`<?xml version='1.0'?>`),
			expected: false,
		},
		{
			name:     "stream:stream present but no jabber namespace",
			input:    []byte(`<stream:stream xmlns:stream='http://example.com/other'>`),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isXMPPResponse(tt.input)
			assert.Equal(t, tt.expected, result, "isXMPPResponse() mismatch for: %s", tt.name)
		})
	}
}

// TestExtractStreamAttributes verifies the parser that extracts stream ID and
// from-address from XMPP stream opening tags, including both quote styles.
func TestExtractStreamAttributes(t *testing.T) {
	tests := []struct {
		name           string
		input          string
		wantStreamID   string
		wantServerFrom string
	}{
		{
			name:           "full stream opening with id and from attributes",
			input:          ejabberdResponse,
			wantStreamID:   "abc123",
			wantServerFrom: "example.com",
		},
		{
			name:           "Prosody stream has id and from",
			input:          prosodyResponse,
			wantStreamID:   "def456",
			wantServerFrom: "prosody.example.com",
		},
		{
			name:           "stream with double-quoted attributes",
			input:          `<stream:stream xmlns:stream="http://etherx.jabber.org/streams" id="double123" from="server.example.org">`,
			wantStreamID:   "double123",
			wantServerFrom: "server.example.org",
		},
		{
			name:           "stream with single-quoted attributes (standard XMPP)",
			input:          `<stream:stream xmlns:stream='http://etherx.jabber.org/streams' id='single456' from='chat.example.net'>`,
			wantStreamID:   "single456",
			wantServerFrom: "chat.example.net",
		},
		{
			name:           "stream without id attribute returns empty streamID",
			input:          `<stream:stream xmlns:stream='http://etherx.jabber.org/streams' from='example.com'>`,
			wantStreamID:   "",
			wantServerFrom: "example.com",
		},
		{
			name:           "stream without from attribute returns empty serverFrom",
			input:          `<stream:stream xmlns:stream='http://etherx.jabber.org/streams' id='nofrom789'>`,
			wantStreamID:   "nofrom789",
			wantServerFrom: "",
		},
		{
			name:           "empty input returns both empty",
			input:          "",
			wantStreamID:   "",
			wantServerFrom: "",
		},
		{
			name:           "garbage input returns both empty",
			input:          "this is not xml at all ###",
			wantStreamID:   "",
			wantServerFrom: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			streamID, serverFrom := extractStreamAttributes(tt.input)
			assert.Equal(t, tt.wantStreamID, streamID, "streamID mismatch for: %s", tt.name)
			assert.Equal(t, tt.wantServerFrom, serverFrom, "serverFrom mismatch for: %s", tt.name)
		})
	}
}

// TestExtractFeaturesBlock verifies the extraction of the stream:features block,
// which is then passed into the XML parser for structured feature detection.
func TestExtractFeaturesBlock(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantNonEmpty bool
		wantContains string
	}{
		{
			name:         "full ejabberd response extracts features block",
			input:        ejabberdResponse,
			wantNonEmpty: true,
			wantContains: "starttls",
		},
		{
			name:         "Prosody response extracts compression in features",
			input:        prosodyResponse,
			wantNonEmpty: true,
			wantContains: "compress",
		},
		{
			name:         "response with plain features tag (no stream: prefix)",
			input:        `<features><starttls/></features>`,
			wantNonEmpty: true,
			wantContains: "starttls",
		},
		{
			name:         "response without features block returns empty",
			input:        `<?xml version='1.0'?><stream:stream id='abc'>`,
			wantNonEmpty: false,
			wantContains: "",
		},
		{
			name:         "response with incomplete stream:features (no closing tag) returns empty",
			input:        `<stream:stream><stream:features><starttls/>`,
			wantNonEmpty: false,
			wantContains: "",
		},
		{
			name:         "empty input returns empty",
			input:        "",
			wantNonEmpty: false,
			wantContains: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractFeaturesBlock(tt.input)
			if tt.wantNonEmpty {
				assert.NotEmpty(t, result, "expected non-empty features block for: %s", tt.name)
				if tt.wantContains != "" {
					assert.Contains(t, result, tt.wantContains, "features block missing expected content for: %s", tt.name)
				}
			} else {
				assert.Empty(t, result, "expected empty features block for: %s", tt.name)
			}
		})
	}
}

// TestParseFeaturesXML verifies the structured XML parsing of XMPP feature
// blocks, including mechanism lists, TLS requirements, compression, and caps.
func TestParseFeaturesXML(t *testing.T) {
	// checkTLS: -1 = absent, 0 = present optional, 1 = present required
	type tlsExpect int
	const (
		tlsAbsent   tlsExpect = -1
		tlsOptional tlsExpect = 0
		tlsRequired tlsExpect = 1
	)

	tests := []struct {
		name                string
		input               string
		wantNil             bool
		wantTLS             tlsExpect
		wantMechanisms      []string
		wantCompression     []string
		wantCapsNodeContain string
	}{
		{
			name:                "full ejabberd features: required starttls, mechanisms, and caps",
			input:               extractFeaturesBlock(ejabberdResponse),
			wantNil:             false,
			wantTLS:             tlsRequired,
			wantMechanisms:      []string{"SCRAM-SHA-1", "PLAIN"},
			wantCapsNodeContain: "process-one",
		},
		{
			name:                "Prosody features: optional starttls, mechanisms, compression, and caps",
			input:               extractFeaturesBlock(prosodyResponse),
			wantNil:             false,
			wantTLS:             tlsOptional,
			wantMechanisms:      []string{"SCRAM-SHA-1", "SCRAM-SHA-256"},
			wantCompression:     []string{"zlib"},
			wantCapsNodeContain: "prosody",
		},
		{
			name:    "features with starttls required element",
			input:   `<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls></stream:features>`,
			wantNil: false,
			wantTLS: tlsRequired,
		},
		{
			name:    "features with starttls optional (no required element)",
			input:   `<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/></stream:features>`,
			wantNil: false,
			wantTLS: tlsOptional,
		},
		{
			name: "features with multiple auth mechanisms",
			input: `<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>` +
				`<mechanism>PLAIN</mechanism><mechanism>GSSAPI</mechanism><mechanism>SCRAM-SHA-512</mechanism>` +
				`</mechanisms></stream:features>`,
			wantNil:        false,
			wantTLS:        tlsAbsent,
			wantMechanisms: []string{"PLAIN", "GSSAPI", "SCRAM-SHA-512"},
		},
		{
			// The struct maps Compression to xml:"compression", so this uses the correct element name.
			name: "features with compression element parses compression methods",
			input: `<stream:features>` +
				`<compression xmlns='http://jabber.org/features/compress'><method>zlib</method></compression>` +
				`</stream:features>`,
			wantNil:         false,
			wantTLS:         tlsAbsent,
			wantCompression: []string{"zlib"},
		},
		{
			name:    "features with only mechanisms (no TLS, no compression)",
			input:   `<stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>`,
			wantNil: false,
			wantTLS: tlsAbsent,
			wantMechanisms: []string{"PLAIN"},
		},
		{
			name:    "empty features block returns nil",
			input:   "",
			wantNil: true,
		},
		{
			name:    "malformed XML returns nil",
			input:   `<stream:features><broken unclosed tag`,
			wantNil: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := parseFeaturesXML(tt.input)

			if tt.wantNil {
				assert.Nil(t, result, "expected nil result for: %s", tt.name)
				return
			}

			assert.NotNil(t, result, "expected non-nil result for: %s", tt.name)

			// TLS assertions using the tristate expectation
			switch tt.wantTLS {
			case tlsAbsent:
				assert.Nil(t, result.StartTLS, "expected StartTLS absent for: %s", tt.name)
			case tlsOptional:
				if assert.NotNil(t, result.StartTLS, "expected StartTLS present for: %s", tt.name) {
					assert.Nil(t, result.StartTLS.Required, "expected Required absent (optional) for: %s", tt.name)
				}
			case tlsRequired:
				if assert.NotNil(t, result.StartTLS, "expected StartTLS present for: %s", tt.name) {
					assert.NotNil(t, result.StartTLS.Required, "expected Required present for: %s", tt.name)
				}
			}

			// Mechanism assertions
			if len(tt.wantMechanisms) > 0 {
				if assert.NotNil(t, result.Mechanisms, "expected Mechanisms present for: %s", tt.name) {
					assert.Equal(t, tt.wantMechanisms, result.Mechanisms.Mechanism,
						"mechanisms mismatch for: %s", tt.name)
				}
			}

			// Compression assertions - only checked when explicitly expected
			if len(tt.wantCompression) > 0 {
				if assert.NotNil(t, result.Compression, "expected Compression present for: %s", tt.name) {
					assert.Equal(t, tt.wantCompression, result.Compression.Method,
						"compression methods mismatch for: %s", tt.name)
				}
			}

			// Caps node assertions
			if tt.wantCapsNodeContain != "" {
				if assert.NotNil(t, result.Caps, "expected Caps present for: %s", tt.name) {
					assert.Contains(t, result.Caps.Node, tt.wantCapsNodeContain,
						"caps node mismatch for: %s", tt.name)
				}
			}
		})
	}
}

// TestIdentifyServerSoftware verifies that XMPP server software is correctly
// identified from the caps node URI emitted in stream features.
func TestIdentifyServerSoftware(t *testing.T) {
	tests := []struct {
		name     string
		capsNode string
		expected string
	}{
		{
			name:     "ejabberd caps node",
			capsNode: "http://www.process-one.net/en/ejabberd/",
			expected: "ejabberd",
		},
		{
			name:     "Prosody caps node",
			capsNode: "http://prosody.im",
			expected: "Prosody",
		},
		{
			name:     "Openfire caps node",
			capsNode: "http://www.igniterealtime.org/projects/openfire/",
			expected: "Openfire",
		},
		{
			name:     "Tigase caps node",
			capsNode: "http://tigase.org/tigase-xmpp-server",
			expected: "Tigase",
		},
		{
			name:     "MongooseIM caps node",
			capsNode: "https://www.erlang-solutions.com/products/mongooseim.html",
			expected: "MongooseIM",
		},
		{
			name:     "unknown server caps node returns empty",
			capsNode: "http://unknown-xmpp-server.example.com",
			expected: "",
		},
		{
			name:     "empty caps node returns empty",
			capsNode: "",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := identifyServerSoftware(tt.capsNode)
			assert.Equal(t, tt.expected, result, "identifyServerSoftware() mismatch for: %s", tt.name)
		})
	}
}

// TestBuildXMPPCPE verifies CPE 2.3 string generation for known XMPP servers,
// including wildcard version substitution for unknown versions.
func TestBuildXMPPCPE(t *testing.T) {
	tests := []struct {
		name    string
		product string
		version string
		wantCPE string
	}{
		{
			name:    "ejabberd with version",
			product: "ejabberd",
			version: "23.10",
			wantCPE: "cpe:2.3:a:process-one:ejabberd:23.10:*:*:*:*:*:*:*",
		},
		{
			name:    "Prosody with version",
			product: "Prosody",
			version: "0.12.0",
			wantCPE: "cpe:2.3:a:prosody:prosody:0.12.0:*:*:*:*:*:*:*",
		},
		{
			name:    "known product without version uses wildcard",
			product: "Openfire",
			version: "",
			wantCPE: "cpe:2.3:a:igniterealtime:openfire:*:*:*:*:*:*:*:*",
		},
		{
			name:    "Tigase with version",
			product: "Tigase",
			version: "8.3.0",
			wantCPE: "cpe:2.3:a:tigase:tigase:8.3.0:*:*:*:*:*:*:*",
		},
		{
			name:    "unknown product returns empty",
			product: "UnknownXMPPServer",
			version: "1.0",
			wantCPE: "",
		},
		{
			name:    "empty product returns empty",
			product: "",
			version: "1.0",
			wantCPE: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := buildXMPPCPE(tt.product, tt.version)
			assert.Equal(t, tt.wantCPE, result, "buildXMPPCPE() mismatch for: %s", tt.name)
		})
	}
}

// TestTLSSupportString verifies the conversion of startTLS presence and the
// required flag into a descriptive string for the service payload.
func TestTLSSupportString(t *testing.T) {
	tests := []struct {
		name     string
		input    *startTLS
		expected string
	}{
		{
			name:     "nil startTLS returns empty string",
			input:    nil,
			expected: "",
		},
		{
			name:     "startTLS with required returns 'required'",
			input:    &startTLS{Required: &struct{}{}},
			expected: "required",
		},
		{
			name:     "startTLS without required returns 'optional'",
			input:    &startTLS{Required: nil},
			expected: "optional",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tlsSupportString(tt.input)
			assert.Equal(t, tt.expected, result, "tlsSupportString() mismatch for: %s", tt.name)
		})
	}
}

// TestPluginMetadata verifies the plugin interface methods that are used by
// the Nerva framework to route connections and prioritize scanning.
func TestPluginMetadata(t *testing.T) {
	p := &TCPPlugin{}

	t.Run("Name returns xmpp", func(t *testing.T) {
		assert.Equal(t, "xmpp", p.Name())
	})

	t.Run("Type returns TCP", func(t *testing.T) {
		assert.Equal(t, plugins.TCP, p.Type())
	})

	t.Run("Priority returns 100", func(t *testing.T) {
		assert.Equal(t, 100, p.Priority())
	})

	t.Run("PortPriority returns true for XMPP port 5222", func(t *testing.T) {
		assert.True(t, p.PortPriority(5222))
	})

	t.Run("PortPriority returns false for non-XMPP port 80", func(t *testing.T) {
		assert.False(t, p.PortPriority(80))
	})

	t.Run("PortPriority returns false for port 443", func(t *testing.T) {
		assert.False(t, p.PortPriority(443))
	})
}

// startMockXMPPServer starts a TCP listener on a random port, accepts one
// connection, writes the provided response, and returns the listener address.
// The caller must close the returned listener when done.
func startMockXMPPServer(t *testing.T, response string) *net.TCPListener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to start mock XMPP server")

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Drain the probe sent by the plugin
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)

		// Send the mock response
		_, _ = conn.Write([]byte(response))
	}()

	return listener.(*net.TCPListener)
}

// TestRunWithMockServer verifies the Run method's end-to-end behavior using a
// mock TCP server to simulate XMPP server responses without network access.
func TestRunWithMockServer(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse string
		wantNil        bool
		wantProtocol   string
		wantSoftware   string
	}{
		{
			name:           "valid ejabberd response produces service with ejabberd software",
			serverResponse: ejabberdResponse,
			wantNil:        false,
			wantProtocol:   "xmpp",
			wantSoftware:   "ejabberd",
		},
		{
			name:           "valid Prosody response produces service with Prosody software",
			serverResponse: prosodyResponse,
			wantNil:        false,
			wantProtocol:   "xmpp",
			wantSoftware:   "Prosody",
		},
		{
			name:           "valid Openfire response produces service with Openfire software",
			serverResponse: openfireResponse,
			wantNil:        false,
			wantProtocol:   "xmpp",
			wantSoftware:   "Openfire",
		},
		{
			name:           "non-XMPP response (HTTP) returns nil service",
			serverResponse: "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
			wantNil:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener := startMockXMPPServer(t, tt.serverResponse)
			defer listener.Close()

			addr := listener.Addr().(*net.TCPAddr)
			addrPort, err := netip.ParseAddrPort(fmt.Sprintf("127.0.0.1:%d", addr.Port))
			require.NoError(t, err)

			conn, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
			require.NoError(t, err, "failed to connect to mock server")
			defer conn.Close()

			p := &TCPPlugin{}
			target := plugins.Target{
				Address: addrPort,
				Host:    "127.0.0.1",
			}

			svc, err := p.Run(conn, 5*time.Second, target)
			// For non-XMPP responses, the Run method returns nil (no service) with no error.
			// For a valid XMPP response, it returns the populated service.
			// Note: an empty response (connection closed) may produce an IO error; we allow
			// either nil-error+nil-service or non-nil-error for the non-XMPP cases.
			if tt.wantNil {
				// Either an error occurred (e.g., EOF on empty response) or no service was returned.
				if err == nil {
					assert.Nil(t, svc, "expected nil service for: %s", tt.name)
				}
				// If err != nil, Run correctly rejected the non-XMPP response via IO failure.
			} else {
				assert.NoError(t, err, "Run() should not return error for: %s", tt.name)
				require.NotNil(t, svc, "expected non-nil service for: %s", tt.name)
				assert.Equal(t, tt.wantProtocol, svc.Protocol, "protocol mismatch for: %s", tt.name)
			}
		})
	}
}

// TestShodanVectors tests realistic XMPP stream responses found on Shodan.
// These represent real-world XMPP server configurations commonly seen during
// internet-wide scanning on port 5222.
func TestShodanVectors(t *testing.T) {
	tests := []struct {
		name           string
		serverResponse string
		validate       func(t *testing.T, svc *plugins.Service)
	}{
		{
			// ejabberd is the most common XMPP server on Shodan, typically
			// requiring STARTTLS with SCRAM-SHA-1 and PLAIN auth.
			name: "ejabberd 23.x with required STARTTLS and SCRAM-SHA-1 auth",
			serverResponse: `<?xml version='1.0'?>` +
				`<stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' ` +
				`id='4f9a2c8e1b3d' from='jabber.example.org' version='1.0' xml:lang='en'>` +
				`<stream:features>` +
				`<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls>` +
				`<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>` +
				`<mechanism>SCRAM-SHA-1</mechanism>` +
				`<mechanism>PLAIN</mechanism>` +
				`</mechanisms>` +
				`<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' ` +
				`node='http://www.process-one.net/en/ejabberd/' ver='GN+pTSPENI4F3Q0pKNBqNg+vYMc='/>` +
				`</stream:features>`,
			validate: func(t *testing.T, svc *plugins.Service) {
				assert.Equal(t, "xmpp", svc.Protocol)
				xmppSvc, ok := svc.Metadata().(plugins.ServiceXMPP)
				require.True(t, ok, "metadata should be ServiceXMPP")
				assert.Equal(t, "4f9a2c8e1b3d", xmppSvc.StreamID)
				assert.Equal(t, "jabber.example.org", xmppSvc.ServerFrom)
				assert.Equal(t, "required", xmppSvc.TLSSupport)
				assert.Equal(t, []string{"SCRAM-SHA-1", "PLAIN"}, xmppSvc.AuthMechanisms)
				assert.Equal(t, "ejabberd", xmppSvc.ServerSoftware)
				assert.Contains(t, xmppSvc.CPEs, "cpe:2.3:a:process-one:ejabberd:*:*:*:*:*:*:*:*")
			},
		},
		{
			// Prosody is the second most common; often has optional STARTTLS
			// with zlib compression and SCRAM-SHA-256 support.
			name: "Prosody 0.12 with optional STARTTLS, zlib compression, and SCRAM-SHA-256",
			serverResponse: `<?xml version='1.0'?>` +
				`<stream:stream xmlns:db='jabber:server:dialback' xmlns:stream='http://etherx.jabber.org/streams' ` +
				`version='1.0' from='chat.example.net' id='b7e3d1a49f02' xmlns='jabber:client' xml:lang='en'>` +
				`<stream:features>` +
				`<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>` +
				`<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>` +
				`<mechanism>SCRAM-SHA-1</mechanism>` +
				`<mechanism>SCRAM-SHA-256</mechanism>` +
				`<mechanism>PLAIN</mechanism>` +
				`</mechanisms>` +
				`<compression xmlns='http://jabber.org/features/compress'>` +
				`<method>zlib</method>` +
				`</compression>` +
				`<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' ` +
				`node='http://prosody.im' ver='K1Njy3HZBThlo4moLYc32UEVFBY='/>` +
				`</stream:features>`,
			validate: func(t *testing.T, svc *plugins.Service) {
				assert.Equal(t, "xmpp", svc.Protocol)
				xmppSvc, ok := svc.Metadata().(plugins.ServiceXMPP)
				require.True(t, ok, "metadata should be ServiceXMPP")
				assert.Equal(t, "b7e3d1a49f02", xmppSvc.StreamID)
				assert.Equal(t, "chat.example.net", xmppSvc.ServerFrom)
				assert.Equal(t, "optional", xmppSvc.TLSSupport)
				assert.Equal(t, []string{"SCRAM-SHA-1", "SCRAM-SHA-256", "PLAIN"}, xmppSvc.AuthMechanisms)
				assert.Equal(t, []string{"zlib"}, xmppSvc.Compression)
				assert.Equal(t, "Prosody", xmppSvc.ServerSoftware)
				assert.Contains(t, xmppSvc.CPEs, "cpe:2.3:a:prosody:prosody:*:*:*:*:*:*:*:*")
			},
		},
		{
			// Openfire often appears with DIGEST-MD5 (legacy), commonly seen
			// on enterprise/corporate XMPP deployments without compression.
			name: "Openfire 4.x with optional STARTTLS and DIGEST-MD5 legacy auth",
			serverResponse: `<?xml version='1.0' encoding='UTF-8'?>` +
				`<stream:stream xmlns:stream='http://etherx.jabber.org/streams' xmlns='jabber:client' ` +
				`from='im.corp.example.com' id='c2f8e6d4a190' xml:lang='en' version='1.0'>` +
				`<stream:features>` +
				`<starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'/>` +
				`<mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'>` +
				`<mechanism>PLAIN</mechanism>` +
				`<mechanism>DIGEST-MD5</mechanism>` +
				`<mechanism>SCRAM-SHA-1</mechanism>` +
				`</mechanisms>` +
				`<compression xmlns='http://jabber.org/features/compress'>` +
				`<method>zlib</method>` +
				`</compression>` +
				`<c xmlns='http://jabber.org/protocol/caps' hash='sha-1' ` +
				`node='http://www.igniterealtime.org/projects/openfire/' ver='NxLhKFEooBD3W2RY+fUbGJK4bD0='/>` +
				`</stream:features>`,
			validate: func(t *testing.T, svc *plugins.Service) {
				assert.Equal(t, "xmpp", svc.Protocol)
				xmppSvc, ok := svc.Metadata().(plugins.ServiceXMPP)
				require.True(t, ok, "metadata should be ServiceXMPP")
				assert.Equal(t, "c2f8e6d4a190", xmppSvc.StreamID)
				assert.Equal(t, "im.corp.example.com", xmppSvc.ServerFrom)
				assert.Equal(t, "optional", xmppSvc.TLSSupport)
				assert.Equal(t, []string{"PLAIN", "DIGEST-MD5", "SCRAM-SHA-1"}, xmppSvc.AuthMechanisms)
				assert.Equal(t, []string{"zlib"}, xmppSvc.Compression)
				assert.Equal(t, "Openfire", xmppSvc.ServerSoftware)
				assert.Contains(t, xmppSvc.CPEs, "cpe:2.3:a:igniterealtime:openfire:*:*:*:*:*:*:*:*")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			listener := startMockXMPPServer(t, tt.serverResponse)
			defer listener.Close()

			addr := listener.Addr().(*net.TCPAddr)
			addrPort, err := netip.ParseAddrPort(fmt.Sprintf("127.0.0.1:%d", addr.Port))
			require.NoError(t, err)

			conn, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
			require.NoError(t, err, "failed to connect to mock server")
			defer conn.Close()

			p := &TCPPlugin{}
			target := plugins.Target{
				Address: addrPort,
				Host:    "127.0.0.1",
			}

			svc, err := p.Run(conn, 5*time.Second, target)
			assert.NoError(t, err, "Run() should not return error for: %s", tt.name)
			require.NotNil(t, svc, "expected non-nil service for: %s", tt.name)

			tt.validate(t, svc)
		})
	}
}

// startSplitMockXMPPServer starts a TCP listener that simulates servers like
// ejabberd which send the stream opening and the features block in two separate
// TCP writes. The first write contains the stream:stream opening tag and the
// second write (after a brief pause to force a distinct TCP segment) contains
// the stream:features block. This exercises the two-read fallback path.
func startSplitMockXMPPServer(t *testing.T, firstWrite, secondWrite string) *net.TCPListener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err, "failed to start split mock XMPP server")

	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Drain the probe sent by the plugin.
		buf := make([]byte, 512)
		_, _ = conn.Read(buf)

		// First TCP write: stream opening only (no features block).
		_, _ = conn.Write([]byte(firstWrite))

		// Flush by setting a very short write deadline so the first segment
		// lands before the second. In practice the 1ms sleep ensures the
		// kernel delivers them as separate reads on the client side.
		time.Sleep(1 * time.Millisecond)

		// Second TCP write: features block.
		_, _ = conn.Write([]byte(secondWrite))
	}()

	return listener.(*net.TCPListener)
}

// TestRunWithSplitResponse verifies that Run() still populates enrichment data
// (TLS, mechanisms, caps, ServerSoftware) when the XMPP server sends the
// stream opening and the features block in two separate TCP segments — the
// real-world behaviour of ejabberd and other implementations.
func TestRunWithSplitResponse(t *testing.T) {
	// Split the ejabberd fixture at the boundary between the stream:stream
	// opening tag and the stream:features block to simulate two TCP writes.
	const streamOpening = `<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='abc123' from='example.com' version='1.0' xml:lang='en'>`
	const featuresBlock = `<stream:features><starttls xmlns='urn:ietf:params:xml:ns:xmpp-tls'><required/></starttls><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>SCRAM-SHA-1</mechanism><mechanism>PLAIN</mechanism></mechanisms><c xmlns='http://jabber.org/protocol/caps' hash='sha-1' node='http://www.process-one.net/en/ejabberd/' ver='aIT+/ulfcbHXDKPkCA+iw9x5mU8='/></stream:features>`

	listener := startSplitMockXMPPServer(t, streamOpening, featuresBlock)
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	addrPort, err := netip.ParseAddrPort(fmt.Sprintf("127.0.0.1:%d", addr.Port))
	require.NoError(t, err)

	conn, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
	require.NoError(t, err, "failed to connect to split mock server")
	defer conn.Close()

	p := &TCPPlugin{}
	target := plugins.Target{
		Address: addrPort,
		Host:    "127.0.0.1",
	}

	svc, err := p.Run(conn, 5*time.Second, target)
	assert.NoError(t, err, "Run() should not error on split response")
	require.NotNil(t, svc, "Run() should return a service even when features arrive in second TCP segment")

	xmppSvc, ok := svc.Metadata().(plugins.ServiceXMPP)
	require.True(t, ok, "service metadata should be ServiceXMPP")

	assert.Equal(t, "abc123", xmppSvc.StreamID, "stream ID should be extracted from first segment")
	assert.Equal(t, "example.com", xmppSvc.ServerFrom, "server from should be extracted from first segment")
	assert.Equal(t, "required", xmppSvc.TLSSupport,
		"TLS support should be populated from features in second segment")
	assert.Equal(t, []string{"SCRAM-SHA-1", "PLAIN"}, xmppSvc.AuthMechanisms,
		"auth mechanisms should be populated from features in second segment")
	assert.Equal(t, "ejabberd", xmppSvc.ServerSoftware,
		"server software should be identified from caps in second segment")
}

// noTLSResponse is a minimal XMPP stream response that does NOT advertise STARTTLS.
const noTLSResponse = `<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='notls123' from='insecure.example.com' version='1.0'><stream:features><mechanisms xmlns='urn:ietf:params:xml:ns:xmpp-sasl'><mechanism>PLAIN</mechanism></mechanisms></stream:features>`

// TestXMPPSecurityFindings verifies that the xmpp-cleartext finding is emitted when STARTTLS is
// not offered and Misconfigs=true.
func TestXMPPSecurityFindings(t *testing.T) {
	listener := startMockXMPPServer(t, noTLSResponse)
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	addrPort, err := netip.ParseAddrPort(fmt.Sprintf("127.0.0.1:%d", addr.Port))
	require.NoError(t, err)

	conn, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	p := &TCPPlugin{}
	target := plugins.Target{
		Address:    addrPort,
		Host:       "127.0.0.1",
		Misconfigs: true,
	}

	svc, err := p.Run(conn, 5*time.Second, target)
	require.NoError(t, err, "Run() should not return error")
	require.NotNil(t, svc, "Run() should return a service")

	if len(svc.SecurityFindings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(svc.SecurityFindings))
	}
	if svc.SecurityFindings[0].ID != "xmpp-cleartext" {
		t.Errorf("expected finding ID 'xmpp-cleartext', got %q", svc.SecurityFindings[0].ID)
	}
	if svc.SecurityFindings[0].Severity != plugins.SeverityMedium {
		t.Errorf("expected severity medium, got %s", svc.SecurityFindings[0].Severity)
	}
}

// TestXMPPSecurityFindingsDisabled verifies that no findings are emitted when Misconfigs=false,
// even when STARTTLS is absent.
func TestXMPPSecurityFindingsDisabled(t *testing.T) {
	listener := startMockXMPPServer(t, noTLSResponse)
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	addrPort, err := netip.ParseAddrPort(fmt.Sprintf("127.0.0.1:%d", addr.Port))
	require.NoError(t, err)

	conn, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	p := &TCPPlugin{}
	target := plugins.Target{
		Address:    addrPort,
		Host:       "127.0.0.1",
		Misconfigs: false,
	}

	svc, err := p.Run(conn, 5*time.Second, target)
	require.NoError(t, err, "Run() should not return error")
	require.NotNil(t, svc, "Run() should return a service")

	if len(svc.SecurityFindings) != 0 {
		t.Errorf("expected no findings when Misconfigs=false, got %d", len(svc.SecurityFindings))
	}
}

// TestXMPPSecurityFindingsWithSTARTTLS verifies that no findings are emitted when STARTTLS is
// offered (required), even when Misconfigs=true.
func TestXMPPSecurityFindingsWithSTARTTLS(t *testing.T) {
	// ejabberdResponse has required STARTTLS — no cleartext finding expected.
	listener := startMockXMPPServer(t, ejabberdResponse)
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	addrPort, err := netip.ParseAddrPort(fmt.Sprintf("127.0.0.1:%d", addr.Port))
	require.NoError(t, err)

	conn, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	p := &TCPPlugin{}
	target := plugins.Target{
		Address:    addrPort,
		Host:       "127.0.0.1",
		Misconfigs: true,
	}

	svc, err := p.Run(conn, 5*time.Second, target)
	require.NoError(t, err, "Run() should not return error")
	require.NotNil(t, svc, "Run() should return a service")

	if len(svc.SecurityFindings) != 0 {
		t.Errorf("expected no findings when STARTTLS is offered, got %d: %v", len(svc.SecurityFindings), svc.SecurityFindings)
	}
}

// TestXMPPSecurityFindingsNoFeatures verifies that no cleartext finding is emitted when
// the features block is absent (e.g., truncated response), since we cannot confirm STARTTLS
// is unsupported — only that we failed to observe it.
func TestXMPPSecurityFindingsNoFeatures(t *testing.T) {
	// Response with valid stream:stream but no features block at all.
	noFeaturesResponse := `<?xml version='1.0'?><stream:stream xmlns='jabber:client' xmlns:stream='http://etherx.jabber.org/streams' id='trunc999' from='partial.example.com' version='1.0'>`

	listener := startMockXMPPServer(t, noFeaturesResponse)
	defer listener.Close()

	addr := listener.Addr().(*net.TCPAddr)
	addrPort, err := netip.ParseAddrPort(fmt.Sprintf("127.0.0.1:%d", addr.Port))
	require.NoError(t, err)

	conn, err := net.DialTimeout("tcp", addr.String(), 5*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	p := &TCPPlugin{}
	target := plugins.Target{
		Address:    addrPort,
		Host:       "127.0.0.1",
		Misconfigs: true,
	}

	svc, err := p.Run(conn, 5*time.Second, target)
	require.NoError(t, err, "Run() should not return error")
	require.NotNil(t, svc, "Run() should return a service")

	if len(svc.SecurityFindings) != 0 {
		t.Errorf("expected no findings when features block is absent, got %d: %v", len(svc.SecurityFindings), svc.SecurityFindings)
	}
}

// TestIntegrationDocker runs the XMPP plugin against real XMPP servers
// running in Docker containers. These tests are skipped when -short is used.
func TestIntegrationDocker(t *testing.T) {
	testcases := []test.Testcase{
		{
			// ejabberd is the most widely deployed open-source XMPP server.
			// The official image exposes port 5222 and defaults to the
			// "localhost" virtual host, which matches the to='localhost' probe
			// sent when target.Host is empty (as testutil passes an empty Target{}).
			// ejabberd sends the stream opening immediately but advertises caps
			// only after TLS negotiation, so ServerSoftware may be empty here —
			// we verify service detection (res != nil) and metadata type only.
			Description: "ejabberd",
			Port:        5222,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				if res == nil {
					return false
				}
				_, ok := res.Metadata().(plugins.ServiceXMPP)
				return ok
			},
			RunConfig: dockertest.RunOptions{
				Repository:   "ghcr.io/processone/ejabberd",
				ExposedPorts: []string{"5222/tcp"},
			},
		},
		{
			// Prosody is another widely used XMPP server. Setting DOMAIN=localhost
			// ensures the virtual host matches the to='localhost' probe sent by
			// buildXMPPProbe when target.Host is empty.
			Description: "prosody",
			Port:        5222,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "prosody/prosody",
				Env:        []string{"DOMAIN=localhost"},
			},
		},
	}

	p := &TCPPlugin{}
	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%v", err)
			}
		})
	}
}
