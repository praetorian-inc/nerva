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

//go:build integration

package pptp

import (
	"encoding/json"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// pptpdAddr returns the address of a live pptpd instance.
// Override with PPTP_TEST_ADDR env var; defaults to localhost:1723.
func pptpdAddr() string {
	if addr := os.Getenv("PPTP_TEST_ADDR"); addr != "" {
		return addr
	}
	return "127.0.0.1:1723"
}

// TestIntegrationPPTPDetection connects to a real pptpd instance and verifies
// full detection: protocol identification, hostname, vendor, and firmware extraction.
//
// Requires: docker run -d --privileged -p 1723:1723 mobtitude/vpn-pptp
func TestIntegrationPPTPDetection(t *testing.T) {
	addr := pptpdAddr()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("cannot connect to pptpd at %s: %v (is the container running?)", addr, err)
	}
	defer conn.Close()

	plugin := &Plugin{}
	target := plugins.Target{
		Address: addrPortFromString(addr),
	}

	svc, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Plugin.Run returned error: %v", err)
	}
	if svc == nil {
		t.Fatal("Plugin.Run returned nil service — PPTP not detected")
	}

	// Verify protocol identification.
	if svc.Protocol != PPTP {
		t.Errorf("Protocol = %q, want %q", svc.Protocol, PPTP)
	}

	// Unmarshal and validate payload.
	var payload plugins.ServicePPTP
	if err := json.Unmarshal(svc.Raw, &payload); err != nil {
		t.Fatalf("json.Unmarshal(service.Raw) error = %v", err)
	}

	// pptpd (PoPToP) on Linux returns these well-known values.
	if payload.Hostname != "local" {
		t.Errorf("Hostname = %q, want %q", payload.Hostname, "local")
	}
	if payload.VendorString != "linux" {
		t.Errorf("VendorString = %q, want %q", payload.VendorString, "linux")
	}
	if payload.FirmwareRevision != 1 {
		t.Errorf("FirmwareRevision = %d, want 1", payload.FirmwareRevision)
	}
	if payload.ProtocolVersion != "1.0" {
		t.Errorf("ProtocolVersion = %q, want %q", payload.ProtocolVersion, "1.0")
	}
	if payload.ResultCode != 1 {
		t.Errorf("ResultCode = %d, want 1 (success)", payload.ResultCode)
	}

	t.Logf("PPTP detected: hostname=%q vendor=%q firmware=%d version=%s",
		payload.Hostname, payload.VendorString, payload.FirmwareRevision, payload.ProtocolVersion)
}

// addrPortFromString parses a "host:port" string into netip.AddrPort.
func addrPortFromString(addr string) netip.AddrPort {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return netip.AddrPort{}
	}
	return ap
}
