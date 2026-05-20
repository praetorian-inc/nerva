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

package amqp

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

const rabbitmqTestImage = "rabbitmq"
const rabbitmqTestTag = "3"
const rabbitmqPort = "5672"

// startRabbitMQContainer starts a rabbitmq:3 container and waits for it to accept TCP connections.
func startRabbitMQContainer(t *testing.T, pool *dockertest.Pool) (*dockertest.Resource, string) {
	t.Helper()

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   rabbitmqTestImage,
		Tag:          rabbitmqTestTag,
		ExposedPorts: []string{rabbitmqPort + "/tcp"},
	})
	if err != nil {
		t.Fatalf("Could not start RabbitMQ container: %v", err)
	}

	// Wait briefly for Docker to complete port mapping, then retry GetHostPort.
	var addr string
	for i := 0; i < 10; i++ {
		addr = resource.GetHostPort(rabbitmqPort + "/tcp")
		if addr != "" {
			break
		}
		time.Sleep(1 * time.Second)
	}
	if addr == "" {
		pool.Purge(resource) //nolint:errcheck
		t.Fatalf("Docker port mapping not ready after 10s for port %s/tcp", rabbitmqPort)
	}
	t.Logf("RabbitMQ container running at %s", addr)

	// Allow the container process to initialize before polling.
	time.Sleep(5 * time.Second)

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
		t.Fatalf("RabbitMQ container never became ready: %v", err)
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

func TestAMQPIntegrationDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to Docker: %v", err)
	}

	resource, addr := startRabbitMQContainer(t, pool)
	defer pool.Purge(resource) //nolint:errcheck

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to RabbitMQ server: %v", err)
	}
	defer conn.Close()

	target := plugins.Target{
		Address:    resolveAddrPort(t, addr),
		Misconfigs: false,
	}

	plugin := &AMQPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Plugin Run returned error: %v", err)
	}
	if service == nil {
		t.Fatal("Plugin Run returned nil service (AMQP not detected)")
	}

	t.Logf("Detected service: protocol=%s tls=%v", service.Protocol, service.TLS)

	if service.Protocol != AMQP {
		t.Errorf("Expected protocol %q, got %q", AMQP, service.Protocol)
	}

	if len(service.SecurityFindings) != 0 {
		t.Errorf("Expected no SecurityFindings with Misconfigs=false, got %d", len(service.SecurityFindings))
	}
}

func TestAMQPIntegrationDefaultCreds(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to Docker: %v", err)
	}

	resource, addr := startRabbitMQContainer(t, pool)
	defer pool.Purge(resource) //nolint:errcheck

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to RabbitMQ server: %v", err)
	}
	defer conn.Close()

	target := plugins.Target{
		Address:    resolveAddrPort(t, addr),
		Misconfigs: true,
	}

	plugin := &AMQPPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Plugin Run returned error: %v", err)
	}
	if service == nil {
		t.Fatal("Plugin Run returned nil service (AMQP not detected)")
	}

	t.Logf("Detected service: protocol=%s tls=%v", service.Protocol, service.TLS)

	if service.Protocol != AMQP {
		t.Errorf("Expected protocol %q, got %q", AMQP, service.Protocol)
	}

	if len(service.SecurityFindings) == 0 {
		t.Fatal("Expected at least one SecurityFinding with Misconfigs=true, got none")
	}

	finding := service.SecurityFindings[0]
	if finding.ID != "amqp-default-creds" {
		t.Errorf("Expected finding ID %q, got %q", "amqp-default-creds", finding.ID)
	}
	if finding.Severity != plugins.SeverityHigh {
		t.Errorf("Expected severity High, got %q", finding.Severity)
	}
	if !strings.Contains(finding.Evidence, "default credentials") {
		t.Errorf("Expected evidence to contain 'default credentials', got %q", finding.Evidence)
	}

	t.Logf("SecurityFinding: id=%s severity=%s evidence=%s", finding.ID, finding.Severity, finding.Evidence)
}

