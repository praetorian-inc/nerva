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

package managesieve

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const dovecotGreeting = "\"IMPLEMENTATION\" \"Dovecot (Ubuntu) Pigeonhole\"\r\n" +
	"\"SIEVE\" \"fileinto reject envelope encoded-character vacation subaddress comparator-i;ascii-numeric relational regex imap4flags copy include variables body enotify environment mailbox date ihave\"\r\n" +
	"\"NOTIFY\" \"mailto\"\r\n" +
	"\"SASL\" \"PLAIN LOGIN\"\r\n" +
	"\"STARTTLS\"\r\n" +
	"\"VERSION\" \"1.0\"\r\n" +
	"OK \"Dovecot (Ubuntu) ready.\"\r\n"

const cyrusGreeting = "\"IMPLEMENTATION\" \"Cyrus timsieved v3.8.3\"\r\n" +
	"\"VERSION\" \"1.0\"\r\n" +
	"\"SASL\" \"ANONYMOUS PLAIN GSSAPI\"\r\n" +
	"\"SIEVE\" \"fileinto reject envelope vacation imapflags notify subaddress regex\"\r\n" +
	"\"NOTIFY\" \"mailto\"\r\n" +
	"\"UNAUTHENTICATE\"\r\n" +
	"OK\r\n"

// newMockConn creates a net.Pipe-backed connection whose server side writes
// greeting immediately (ManageSieve is a passive-read protocol, no probe sent).
func newMockConn(t *testing.T, greeting string) net.Conn {
	t.Helper()
	serverConn, clientConn := net.Pipe()
	go func() {
		defer serverConn.Close()
		_, _ = serverConn.Write([]byte(greeting))
	}()
	t.Cleanup(func() { clientConn.Close() })
	return clientConn
}

func testTarget() plugins.Target {
	return plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:4190"),
		Host:    "127.0.0.1",
	}
}

func TestParseCapabilityLine(t *testing.T) {
	tests := []struct {
		name      string
		line      string
		wantKey   string
		wantValue string
		wantOK    bool
	}{
		{
			name:      "valid keyword and value",
			line:      `"IMPLEMENTATION" "Cyrus timsieved v3.8.3"`,
			wantKey:   "IMPLEMENTATION",
			wantValue: "Cyrus timsieved v3.8.3",
			wantOK:    true,
		},
		{
			name:      "lowercase keyword normalized to uppercase",
			line:      `"sasl" "PLAIN LOGIN"`,
			wantKey:   "SASL",
			wantValue: "PLAIN LOGIN",
			wantOK:    true,
		},
		{
			name:      "bare quoted keyword no value",
			line:      `"STARTTLS"`,
			wantKey:   "STARTTLS",
			wantValue: "",
			wantOK:    true,
		},
		{
			name:      "no-value keyword with trailing whitespace",
			line:      `"UNAUTHENTICATE"   `,
			wantKey:   "UNAUTHENTICATE",
			wantValue: "",
			wantOK:    true,
		},
		{
			name:   "non-capability line",
			line:   `OK "Dovecot ready."`,
			wantOK: false,
		},
		{
			name:   "empty string",
			line:   "",
			wantOK: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key, value, ok := parseCapabilityLine(tt.line)
			assert.Equal(t, tt.wantOK, ok)
			if tt.wantOK {
				assert.Equal(t, tt.wantKey, key)
				assert.Equal(t, tt.wantValue, value)
			}
		})
	}
}

func TestDetectManageSieve_Dovecot(t *testing.T) {
	conn := newMockConn(t, dovecotGreeting)
	plugin := &ManageSievePlugin{}

	service, err := plugin.Run(conn, 2*time.Second, testTarget())

	require.NoError(t, err)
	require.NotNil(t, service, "expected service result for Dovecot greeting")
	assert.Equal(t, plugins.ProtoManageSieve, service.Protocol)

	metadata := service.Metadata()
	msMeta, ok := metadata.(plugins.ServiceManageSieve)
	require.True(t, ok, "metadata should be ServiceManageSieve")

	assert.Equal(t, "Dovecot (Ubuntu) Pigeonhole", msMeta.Implementation)
	assert.Equal(t, []string{"PLAIN", "LOGIN"}, msMeta.SASLMechanisms)
	assert.True(t, msMeta.StarttlsAvailable)
	assert.Contains(t, msMeta.SieveExtensions, "vacation")
	assert.Contains(t, msMeta.SieveExtensions, "imap4flags")
	assert.Empty(t, service.Version, "Dovecot greeting has no parseable version")
}

func TestDetectManageSieve_Cyrus(t *testing.T) {
	conn := newMockConn(t, cyrusGreeting)
	plugin := &ManageSievePlugin{}

	service, err := plugin.Run(conn, 2*time.Second, testTarget())

	require.NoError(t, err)
	require.NotNil(t, service, "expected service result for Cyrus greeting")

	metadata := service.Metadata()
	msMeta, ok := metadata.(plugins.ServiceManageSieve)
	require.True(t, ok, "metadata should be ServiceManageSieve")

	assert.Equal(t, "Cyrus timsieved v3.8.3", msMeta.Implementation)
	assert.False(t, msMeta.StarttlsAvailable, "Cyrus greeting in fixture does not advertise STARTTLS")
	assert.Equal(t, "3.8.3", service.Version)
	require.Len(t, msMeta.CPEs, 1)
	assert.Equal(t, "cpe:2.3:a:cyrusimap:cyrus_imap:3.8.3:*:*:*:*:*:*:*", msMeta.CPEs[0])
}

func TestDetectManageSieve_InvalidBanner(t *testing.T) {
	httpResponse := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n<html></html>"
	conn := newMockConn(t, httpResponse)
	plugin := &ManageSievePlugin{}

	service, err := plugin.Run(conn, 2*time.Second, testTarget())

	require.NoError(t, err)
	assert.Nil(t, service, "HTTP response should not be detected as ManageSieve")
}

func TestDetectManageSieve_EmptyResponse(t *testing.T) {
	conn := newMockConn(t, "")
	plugin := &ManageSievePlugin{}

	service, err := plugin.Run(conn, 2*time.Second, testTarget())

	require.NoError(t, err)
	assert.Nil(t, service, "empty response should not be detected as ManageSieve")
}

// TestDetectManageSieve_GenericQuotedLine verifies that a generic quoted-line
// protocol response with an OK terminator is NOT detected as ManageSieve.
// Note: uses "product" rather than "version" as the example keyword because
// VERSION is itself a real RFC 5804 ManageSieve capability keyword.
func TestDetectManageSieve_GenericQuotedLine(t *testing.T) {
	genericGreeting := "\"product\" \"1.2.3\"\r\nOK\r\n"
	conn := newMockConn(t, genericGreeting)
	plugin := &ManageSievePlugin{}

	service, err := plugin.Run(conn, 2*time.Second, testTarget())

	require.NoError(t, err)
	assert.Nil(t, service, "generic quoted-line protocol should not be detected as ManageSieve")
}

// TestDetectManageSieve_BareEmptyQuotedString verifies that a bare empty quoted
// string followed by OK is NOT detected as ManageSieve.
func TestDetectManageSieve_BareEmptyQuotedString(t *testing.T) {
	bareGreeting := "\"\"\r\nOK\r\n"
	conn := newMockConn(t, bareGreeting)
	plugin := &ManageSievePlugin{}

	service, err := plugin.Run(conn, 2*time.Second, testTarget())

	require.NoError(t, err)
	assert.Nil(t, service, "bare empty quoted string + OK should not be detected as ManageSieve")
}

func TestVersionExtraction(t *testing.T) {
	tests := []struct {
		name           string
		implementation string
		wantVersion    string
	}{
		{
			name:           "Cyrus with patch version",
			implementation: "Cyrus timsieved v3.8.3",
			wantVersion:    "3.8.3",
		},
		{
			name:           "Cyrus with minor version only",
			implementation: "Cyrus timsieved v3.8",
			wantVersion:    "3.8",
		},
		{
			name:           "Dovecot has no version marker",
			implementation: "Dovecot (Ubuntu) Pigeonhole",
			wantVersion:    "",
		},
		{
			name:           "Dovecot distro variant has no version marker",
			implementation: "Dovecot Pigeonhole",
			wantVersion:    "",
		},
		{
			name:           "empty implementation",
			implementation: "",
			wantVersion:    "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.wantVersion, extractVersion(tt.implementation))
		})
	}
}

func TestCPEBuilder(t *testing.T) {
	tests := []struct {
		name           string
		implementation string
		version        string
		want           []string
	}{
		{
			name:           "Cyrus CPE with version",
			implementation: "Cyrus timsieved v3.8.3",
			version:        "3.8.3",
			want:           []string{"cpe:2.3:a:cyrusimap:cyrus_imap:3.8.3:*:*:*:*:*:*:*"},
		},
		{
			name:           "Dovecot CPE with empty version defaults to wildcard",
			implementation: "Dovecot (Ubuntu) Pigeonhole",
			version:        "",
			want:           []string{"cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*"},
		},
		{
			name:           "Dovecot pigeonhole-only implementation string",
			implementation: "Pigeonhole Sieve",
			version:        "",
			want:           []string{"cpe:2.3:a:dovecot:dovecot:*:*:*:*:*:*:*:*"},
		},
		{
			name:           "unknown implementation emits no CPE",
			implementation: "Some Other Sieve Server",
			version:        "",
			want:           nil,
		},
		{
			name:           "empty implementation emits no CPE",
			implementation: "",
			version:        "",
			want:           nil,
		},
		{
			name:           "metacharacter guard rejects malicious version",
			implementation: "Cyrus timsieved v3.8.3",
			version:        "3.8.3:*:evil",
			want:           nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := buildCPEs(tt.implementation, tt.version)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestPortPriority(t *testing.T) {
	plugin := &ManageSievePlugin{}

	assert.True(t, plugin.PortPriority(4190), "4190 is the default ManageSieve port")
	assert.False(t, plugin.PortPriority(80), "80 is not a ManageSieve port")
}

func TestPluginMetadata(t *testing.T) {
	plugin := &ManageSievePlugin{}

	assert.Equal(t, MANAGESIEVE, plugin.Name())
	assert.Equal(t, plugins.TCP, plugin.Type())
	assert.NotZero(t, plugin.Priority())
}
