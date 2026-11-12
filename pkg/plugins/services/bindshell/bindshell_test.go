// Copyright 2026 Praetorian Security, Inc.
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

package bindshell

import (
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

type countingConn struct {
	net.Conn
	writes atomic.Int64
}

func (c *countingConn) Write(p []byte) (int, error) {
	c.writes.Add(1)
	return c.Conn.Write(p)
}

func serveBanner(t *testing.T, banner []byte) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(banner)
		// Keep the socket open until the client Recv finishes, then drain.
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, _ = io.Copy(io.Discard, conn)
	}()
	return ln.Addr().String(), func() {
		_ = ln.Close()
		<-done
	}
}

func runAgainst(t *testing.T, banner []byte) (*plugins.Service, *countingConn) {
	t.Helper()
	addr, stop := serveBanner(t, banner)
	t.Cleanup(stop)

	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	wrapped := &countingConn{Conn: raw}

	port := raw.RemoteAddr().(*net.TCPAddr).Port
	target := plugins.Target{
		Host:    "127.0.0.1",
		Address: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port)),
	}
	svc, err := (&Plugin{}).Run(wrapped, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return svc, wrapped
}

func TestShellPromptFixturesEmitMalwareBackdoor(t *testing.T) {
	cases := []struct {
		name   string
		banner string
		kind   string
		proto  string
	}{
		{name: "no job control", banner: "bash: no job control in this shell\n", kind: "bind-shell", proto: plugins.ProtoBindShell},
		{name: "bash prompt", banner: "bash-5.1# ", kind: "bind-shell", proto: plugins.ProtoBindShell},
		{name: "backdoor label", banner: "backdoor\n", kind: "backdoor", proto: plugins.ProtoBackdoor},
		{name: "nmap BACKDOOR", banner: "**BACKDOOR**\n", kind: "backdoor", proto: plugins.ProtoBackdoor},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, conn := runAgainst(t, []byte(tc.banner))
			if svc == nil {
				t.Fatal("expected service, got nil")
			}
			if conn.writes.Load() != 0 {
				t.Fatalf("detector wrote %d times; SHALL NOT POST exploit commands", conn.writes.Load())
			}
			if svc.Protocol != tc.proto {
				t.Errorf("protocol = %q, want %q (not a port-number service name)", svc.Protocol, tc.proto)
			}
			if len(svc.SecurityFindings) != 1 {
				t.Fatalf("findings = %d, want 1", len(svc.SecurityFindings))
			}
			if svc.SecurityFindings[0].ID != findingID {
				t.Errorf("finding ID = %q, want %q", svc.SecurityFindings[0].ID, findingID)
			}
			meta := svc.Metadata()
			bs, ok := meta.(plugins.ServiceBindShell)
			if !ok {
				t.Fatalf("metadata type %T, want ServiceBindShell", meta)
			}
			if bs.Kind != tc.kind {
				t.Errorf("kind = %q, want %q", bs.Kind, tc.kind)
			}
		})
	}
}

func TestNonMatchDoesNotEmit(t *testing.T) {
	svc, conn := runAgainst(t, []byte("SSH-2.0-OpenSSH_9.0\r\n"))
	if conn.writes.Load() != 0 {
		t.Fatalf("detector wrote %d times on non-match", conn.writes.Load())
	}
	if svc != nil {
		t.Fatalf("expected nil service, got protocol %q", svc.Protocol)
	}
}

func TestPortPriorityNeverWellKnown(t *testing.T) {
	p := &Plugin{}
	for _, port := range []uint16{22, 23, 80, 443, 4444, 31337} {
		if p.PortPriority(port) {
			t.Errorf("PortPriority(%d) = true; identity must not be a port number", port)
		}
	}
}

func TestFalsePositiveBannersDoNotEmit(t *testing.T) {
	banners := []string{
		"220 backdoor.example.com service ready\r\n",
		"Welcome to backdoor-lab\n",
		"Backdoor protection enabled\n",
		"Server: bash-4.4#1-Debian\r\n",
		"bash-completion#section\n",
	}
	for _, banner := range banners {
		t.Run(banner, func(t *testing.T) {
			svc, conn := runAgainst(t, []byte(banner))
			if conn.writes.Load() != 0 {
				t.Fatalf("wrote %d times", conn.writes.Load())
			}
			if svc != nil {
				t.Fatalf("false positive protocol %q finding %v", svc.Protocol, svc.SecurityFindings)
			}
		})
	}
}

func TestEmitsWithoutMisconfigs(t *testing.T) {
	addr, stop := serveBanner(t, []byte("bash: no job control in this shell\n"))
	t.Cleanup(stop)
	raw, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = raw.Close() })
	port := raw.RemoteAddr().(*net.TCPAddr).Port
	target := plugins.Target{
		Host:       "127.0.0.1",
		Address:    netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", port)),
		Misconfigs: false,
	}
	svc, err := (&Plugin{}).Run(raw, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if svc == nil || len(svc.SecurityFindings) != 1 || svc.SecurityFindings[0].ID != findingID {
		t.Fatalf("malware finding must emit without Misconfigs, got %#v", svc)
	}
}
