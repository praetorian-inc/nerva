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

package jdwp

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// startJDWPContainer starts an Eclipse Temurin JDK 11 container with JDWP enabled
// on port 5005 and waits for the container to accept TCP connections.
func startJDWPContainer(t *testing.T, pool *dockertest.Pool) (*dockertest.Resource, string) {
	t.Helper()

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "eclipse-temurin",
		Tag:          "11-jdk",
		ExposedPorts: []string{"5005/tcp"},
		Cmd: []string{"sh", "-c",
			"printf 'class S{public static void main(String[]a)throws Exception{Thread.sleep(300000);}}' > /tmp/S.java && javac /tmp/S.java -d /tmp && java -agentlib:jdwp=transport=dt_socket,server=y,suspend=n,address=*:5005 -cp /tmp S"},
	})
	if err != nil {
		t.Fatalf("Could not start JDWP container: %v", err)
	}

	// Wait briefly for Docker to complete port mapping, then retry GetHostPort.
	var addr string
	for i := 0; i < 10; i++ {
		addr = resource.GetHostPort("5005/tcp")
		if addr != "" {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if addr == "" {
		pool.Purge(resource) //nolint:errcheck
		t.Fatalf("Docker port mapping not ready after 10s for port 5005/tcp")
	}
	t.Logf("JDWP container running at %s", addr)

	// JVM startup takes time; wait before beginning retry attempts.
	time.Sleep(10 * time.Second)

	err = pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", addr, 3*time.Second)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})
	if err != nil {
		pool.Purge(resource) //nolint:errcheck
		t.Fatalf("JDWP container never became ready: %v", err)
	}

	return resource, addr
}

// resolveAddrPort converts a host:port string (which may contain "localhost") to
// a numeric netip.AddrPort suitable for plugins.Target.
func resolveAddrPort(t *testing.T, hostPort string) netip.AddrPort {
	t.Helper()
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", hostPort, err)
	}
	if host == "localhost" {
		host = "127.0.0.1"
	}
	ap, err := netip.ParseAddrPort(fmt.Sprintf("%s:%s", host, port))
	if err != nil {
		t.Fatalf("ParseAddrPort: %v", err)
	}
	return ap
}

// TestJDWPIntegrationDetection verifies that a live JDWP service is detected
// (protocol=jdwp) and produces no SecurityFindings when Misconfigs is false.
func TestJDWPIntegrationDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to Docker: %v", err)
	}

	resource, addr := startJDWPContainer(t, pool)
	defer pool.Purge(resource) //nolint:errcheck

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to JDWP server: %v", err)
	}
	defer conn.Close()

	target := plugins.Target{
		Address:    resolveAddrPort(t, addr),
		Misconfigs: false,
	}

	plugin := &JDWPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Plugin Run returned error: %v", err)
	}
	if service == nil {
		t.Fatal("Plugin Run returned nil service (JDWP not detected)")
	}

	t.Logf("Detected service: protocol=%s tls=%v", service.Protocol, service.TLS)

	if service.Protocol != JDWP {
		t.Errorf("Expected protocol %q, got %q", JDWP, service.Protocol)
	}

	if len(service.SecurityFindings) != 0 {
		t.Errorf("Expected no SecurityFindings with Misconfigs=false, got %d", len(service.SecurityFindings))
	}
}

// TestJDWPIntegrationMisconfigs verifies that a live JDWP service produces a
// Critical "jdwp-exposed" finding whose evidence contains "JDWP handshake succeeded"
// when Misconfigs is true.
func TestJDWPIntegrationMisconfigs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to Docker: %v", err)
	}

	resource, addr := startJDWPContainer(t, pool)
	defer pool.Purge(resource) //nolint:errcheck

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to JDWP server: %v", err)
	}
	defer conn.Close()

	target := plugins.Target{
		Address:    resolveAddrPort(t, addr),
		Misconfigs: true,
	}

	plugin := &JDWPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Plugin Run returned error: %v", err)
	}
	if service == nil {
		t.Fatal("Plugin Run returned nil service (JDWP not detected)")
	}

	t.Logf("Detected service: protocol=%s tls=%v", service.Protocol, service.TLS)

	if service.Protocol != JDWP {
		t.Errorf("Expected protocol %q, got %q", JDWP, service.Protocol)
	}

	if len(service.SecurityFindings) == 0 {
		t.Fatal("Expected at least one SecurityFinding with Misconfigs=true, got none")
	}

	finding := service.SecurityFindings[0]
	if finding.ID != "jdwp-exposed" {
		t.Errorf("Expected finding ID %q, got %q", "jdwp-exposed", finding.ID)
	}
	if finding.Severity != plugins.SeverityCritical {
		t.Errorf("Expected severity %q, got %q", plugins.SeverityCritical, finding.Severity)
	}
	if len(finding.Evidence) == 0 {
		t.Error("Expected non-empty evidence")
	}

	if !strings.Contains(finding.Evidence, "JDWP handshake succeeded") {
		t.Errorf("Expected evidence to contain %q, got %q", "JDWP handshake succeeded", finding.Evidence)
	}

	t.Logf("SecurityFinding: id=%s severity=%s evidence=%s", finding.ID, finding.Severity, finding.Evidence)
}
