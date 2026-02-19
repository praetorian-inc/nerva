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

package svn

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/stretchr/testify/assert"
)

// mockConn implements net.Conn for testing
type mockConn struct {
	readData  []byte
	readIndex int
}

func (m *mockConn) Read(b []byte) (n int, err error) {
	if m.readIndex >= len(m.readData) {
		return 0, nil
	}
	n = copy(b, m.readData[m.readIndex:])
	m.readIndex += n
	return n, nil
}

func (m *mockConn) Write(b []byte) (n int, err error)         { return len(b), nil }
func (m *mockConn) Close() error                              { return nil }
func (m *mockConn) LocalAddr() net.Addr                       { return nil }
func (m *mockConn) RemoteAddr() net.Addr                      { return nil }
func (m *mockConn) SetDeadline(t time.Time) error             { return nil }
func (m *mockConn) SetReadDeadline(t time.Time) error         { return nil }
func (m *mockConn) SetWriteDeadline(t time.Time) error        { return nil }

func TestSVNPlugin_Name(t *testing.T) {
	plugin := &SVNPlugin{}
	assert.Equal(t, "svn", plugin.Name())
}

func TestSVNPlugin_Type(t *testing.T) {
	plugin := &SVNPlugin{}
	assert.Equal(t, plugins.TCP, plugin.Type())
}

func TestSVNPlugin_PortPriority(t *testing.T) {
	plugin := &SVNPlugin{}
	assert.True(t, plugin.PortPriority(3690))
	assert.False(t, plugin.PortPriority(22))
	assert.False(t, plugin.PortPriority(80))
}

func TestSVNPlugin_Priority(t *testing.T) {
	plugin := &SVNPlugin{}
	assert.Equal(t, 2, plugin.Priority())
}

func TestSVNPlugin_Run_SuccessfulDetection(t *testing.T) {
	// Mock SVN greeting: ( success ( 2 2 ( ) ( edit-pipeline svndiff1 absent-entries commit-revprops depth log-revprops atomic-revprops partial-replay ) ) )
	greeting := "( success ( 2 2 ( ) ( edit-pipeline svndiff1 absent-entries commit-revprops depth log-revprops atomic-revprops partial-replay ) ) )\n"

	conn := &mockConn{
		readData: []byte(greeting),
	}

	plugin := &SVNPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.1:3690"),
		Host:    "test-host",
	}

	service, err := plugin.Run(conn, time.Second*5, target)

	assert.NoError(t, err)
	assert.NotNil(t, service)
	assert.Equal(t, "svn", service.Protocol)
	assert.Equal(t, "192.168.1.1", service.IP)
	assert.Equal(t, 3690, service.Port)
	assert.Equal(t, "test-host", service.Host)

	// Verify metadata
	metadata := service.Metadata()
	svnMeta, ok := metadata.(plugins.ServiceSVN)
	assert.True(t, ok)
	assert.Equal(t, 2, svnMeta.MinVersion)
	assert.Equal(t, 2, svnMeta.MaxVersion)
	assert.Equal(t, 0, len(svnMeta.AuthMechs))
	assert.Contains(t, svnMeta.Capabilities, "edit-pipeline")
	assert.Contains(t, svnMeta.Capabilities, "svndiff1")
	assert.Contains(t, svnMeta.Capabilities, "atomic-revprops")
}

func TestSVNPlugin_Run_WithAnonymousAuth(t *testing.T) {
	// Mock SVN greeting with ANONYMOUS auth
	greeting := "( success ( 2 2 ( ANONYMOUS ) ( edit-pipeline svndiff1 ) ) )\n"

	conn := &mockConn{
		readData: []byte(greeting),
	}

	plugin := &SVNPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.2:3690"),
		Host:    "svn.example.com",
	}

	service, err := plugin.Run(conn, time.Second*5, target)

	assert.NoError(t, err)
	assert.NotNil(t, service)

	// Verify auth mechanisms
	metadata := service.Metadata()
	svnMeta, ok := metadata.(plugins.ServiceSVN)
	assert.True(t, ok)
	assert.Equal(t, 1, len(svnMeta.AuthMechs))
	assert.Contains(t, svnMeta.AuthMechs, "ANONYMOUS")
	assert.Equal(t, 2, len(svnMeta.Capabilities))
}

func TestSVNPlugin_Run_NonSVNResponse(t *testing.T) {
	// Mock non-SVN response
	response := "SSH-2.0-OpenSSH_8.2\n"

	conn := &mockConn{
		readData: []byte(response),
	}

	plugin := &SVNPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.3:3690"),
		Host:    "test-host",
	}

	service, err := plugin.Run(conn, time.Second*5, target)

	// Should return error for non-SVN response
	assert.Error(t, err)
	assert.Nil(t, service)
}

func TestSVNPlugin_Run_EmptyResponse(t *testing.T) {
	conn := &mockConn{
		readData: []byte(""),
	}

	plugin := &SVNPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.4:3690"),
		Host:    "test-host",
	}

	service, err := plugin.Run(conn, time.Second*5, target)

	assert.Nil(t, service)
	assert.NoError(t, err) // Empty response returns nil service with no error
}

func TestSVNPlugin_Run_MalformedResponse(t *testing.T) {
	// Malformed S-expression
	response := "( success ( 2 2 incomplete\n"

	conn := &mockConn{
		readData: []byte(response),
	}

	plugin := &SVNPlugin{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("192.168.1.5:3690"),
		Host:    "test-host",
	}

	service, err := plugin.Run(conn, time.Second*5, target)

	// Should handle malformed response gracefully
	assert.Error(t, err)
	assert.Nil(t, service)
}

func TestParseSVNGreeting_Success(t *testing.T) {
	greeting := "( success ( 2 2 ( ) ( edit-pipeline svndiff1 ) ) )\n"

	minVer, maxVer, authMechs, caps, err := parseSVNGreeting([]byte(greeting))

	assert.NoError(t, err)
	assert.Equal(t, 2, minVer)
	assert.Equal(t, 2, maxVer)
	assert.Equal(t, 0, len(authMechs))
	assert.Equal(t, 2, len(caps))
	assert.Contains(t, caps, "edit-pipeline")
	assert.Contains(t, caps, "svndiff1")
}

func TestParseSVNGreeting_WithMultipleAuthMechs(t *testing.T) {
	greeting := "( success ( 2 2 ( ANONYMOUS CRAM-MD5 ) ( edit-pipeline ) ) )\n"

	minVer, maxVer, authMechs, caps, err := parseSVNGreeting([]byte(greeting))

	assert.NoError(t, err)
	assert.Equal(t, 2, minVer)
	assert.Equal(t, 2, maxVer)
	assert.Equal(t, 2, len(authMechs))
	assert.Contains(t, authMechs, "ANONYMOUS")
	assert.Contains(t, authMechs, "CRAM-MD5")
	assert.Equal(t, 1, len(caps))
	assert.Contains(t, caps, "edit-pipeline")
}

func TestCheckSVN_ValidPrefix(t *testing.T) {
	data := []byte("( success ( 2 2 ( ) ( ) ) )")
	assert.True(t, checkSVN(data))
}

func TestCheckSVN_InvalidPrefix(t *testing.T) {
	data := []byte("HTTP/1.1 200 OK")
	assert.False(t, checkSVN(data))
}

func TestCheckSVN_TooShort(t *testing.T) {
	data := []byte("( s")
	assert.False(t, checkSVN(data))
}
