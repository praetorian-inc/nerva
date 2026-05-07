package opcua

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const opcuaTestImage = "open62541/open62541"
const opcuaTestTag = "latest"
const opcuaPort = "4840"

// startOPCUAContainer starts the open62541 demo OPC UA server container and waits for it to accept connections.
func startOPCUAContainer(t *testing.T, pool *dockertest.Pool) (*dockertest.Resource, string) {
	t.Helper()

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   opcuaTestImage,
		Tag:          opcuaTestTag,
		ExposedPorts: []string{opcuaPort + "/tcp"},
	})
	if err != nil {
		t.Fatalf("Could not start OPC UA container: %v", err)
	}

	addr := resource.GetHostPort(opcuaPort + "/tcp")
	t.Logf("OPC UA container running at %s", addr)

	// Retry with a full OPC UA Hello/ACK handshake to ensure the application layer is ready.
	err = pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", addr, 3*time.Second)
		if dialErr != nil {
			return dialErr
		}
		defer conn.Close()
		hello := buildOPCUAHello(fmt.Sprintf("opc.tcp://%s", addr))
		if writeErr := conn.SetWriteDeadline(time.Now().Add(2 * time.Second)); writeErr != nil {
			return writeErr
		}
		if _, writeErr := conn.Write(hello); writeErr != nil {
			return writeErr
		}
		if readErr := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); readErr != nil {
			return readErr
		}
		buf := make([]byte, 64)
		n, readErr := conn.Read(buf)
		if readErr != nil {
			return readErr
		}
		if n < 3 || string(buf[:3]) != "ACK" {
			return fmt.Errorf("unexpected response: %q", buf[:n])
		}
		return nil
	})
	if err != nil {
		pool.Purge(resource) //nolint:errcheck
		t.Fatalf("OPC UA container never became ready: %v", err)
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

func TestOPCUAIntegrationFingerprint(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to Docker: %v", err)
	}

	resource, addr := startOPCUAContainer(t, pool)
	defer pool.Purge(resource) //nolint:errcheck

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to OPC UA server: %v", err)
	}
	defer conn.Close()

	target := plugins.Target{
		Address:    resolveAddrPort(t, addr),
		Misconfigs: false,
	}

	plugin := &OPCUAPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Plugin Run returned error: %v", err)
	}
	if service == nil {
		t.Fatal("Plugin Run returned nil service (OPC UA not detected)")
	}

	t.Logf("Detected service: protocol=%s tls=%v", service.Protocol, service.TLS)

	if service.Protocol != OPCUA {
		t.Errorf("Expected protocol %q, got %q", OPCUA, service.Protocol)
	}

	if len(service.SecurityFindings) != 0 {
		t.Errorf("Expected no SecurityFindings with Misconfigs=false, got %d", len(service.SecurityFindings))
	}
}

func TestOPCUAIntegrationMisconfigs(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to Docker: %v", err)
	}

	resource, addr := startOPCUAContainer(t, pool)
	defer pool.Purge(resource) //nolint:errcheck

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("Failed to connect to OPC UA server: %v", err)
	}
	defer conn.Close()

	target := plugins.Target{
		Address:    resolveAddrPort(t, addr),
		Misconfigs: true,
	}

	plugin := &OPCUAPlugin{}
	service, err := plugin.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("Plugin Run returned error: %v", err)
	}
	if service == nil {
		t.Fatal("Plugin Run returned nil service (OPC UA not detected)")
	}

	t.Logf("Detected service: protocol=%s tls=%v", service.Protocol, service.TLS)

	if service.Protocol != OPCUA {
		t.Errorf("Expected protocol %q, got %q", OPCUA, service.Protocol)
	}

	if len(service.SecurityFindings) == 0 {
		t.Error("Expected at least one SecurityFinding with Misconfigs=true, got none")
	} else {
		finding := service.SecurityFindings[0]
		if finding.ID != "opcua-no-security" && finding.ID != "opcua-weak-security" {
			t.Errorf("Expected finding ID %q or %q, got %q", "opcua-no-security", "opcua-weak-security", finding.ID)
		}
		t.Logf("SecurityFinding: id=%s severity=%s", finding.ID, finding.Severity)
	}

	var opcuaData plugins.ServiceOPCUA
	if err := json.Unmarshal(service.Raw, &opcuaData); err != nil {
		t.Fatalf("Failed to unmarshal OPC UA service data: %v", err)
	}

	if len(opcuaData.SecurityModes) == 0 {
		t.Error("Expected SecurityModes to be populated in service data, got none")
	} else {
		t.Logf("SecurityModes: %v", opcuaData.SecurityModes)
	}
}
