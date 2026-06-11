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

package smbudp

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func TestPlugin_Metadata(t *testing.T) {
	p := &Plugin{}

	if p.Name() != "smbudp" {
		t.Errorf("expected name smbudp, got %s", p.Name())
	}
	if p.Type() != plugins.UDP {
		t.Errorf("expected protocol type UDP, got %v", p.Type())
	}
	if p.Priority() != smbudpPriority {
		t.Errorf("expected priority %d, got %d", smbudpPriority, p.Priority())
	}
	if !p.PortPriority(443) {
		t.Error("expected PortPriority(443) to return true")
	}
	if p.PortPriority(80) {
		t.Error("expected PortPriority(80) to return false")
	}
}

func TestPlugin_RunEmptyTarget(t *testing.T) {
	p := &Plugin{}
	// Empty target should return nil (no address to dial)
	target := plugins.Target{}
	conn, _ := net.Dial("udp", "127.0.0.1:1")
	if conn != nil {
		defer conn.Close()
	}
	service, err := p.Run(conn, 1*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if service != nil {
		t.Error("expected nil service for empty target")
	}
}

func TestPlugin_RunNoServer(t *testing.T) {
	// Target a port with no QUIC server -- should return nil (timeout/no response)
	p := &Plugin{}
	addr := netip.MustParseAddrPort("127.0.0.1:19999")
	target := plugins.Target{Address: addr}

	conn, err := net.Dial("udp", "127.0.0.1:19999")
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	service, err := p.Run(conn, 2*time.Second, target)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if service != nil {
		t.Error("expected nil service when no QUIC server is running")
	}
}
