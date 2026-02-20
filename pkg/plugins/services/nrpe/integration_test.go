package nrpe

import (
	"encoding/json"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const nrpeTestImage = "nrpe-test"
const nrpeTestTag = "4.1.3"

// findTestdataDir locates the testdata/nrpe directory relative to this test file
func findTestdataDir(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"testdata/nrpe",
		"pkg/plugins/services/nrpe/testdata/nrpe",
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "Dockerfile")); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatal("Could not find testdata/nrpe/Dockerfile")
	return ""
}

// buildNRPEImage builds the NRPE Docker image from the Dockerfile.
// Uses docker CLI directly because dockertest's BuildAndRun uses an older Docker
// client API version (1.25) that's incompatible with newer Docker daemons (>=1.44).
func buildNRPEImage(t *testing.T) {
	t.Helper()
	testdataDir := findTestdataDir(t)
	imageTag := fmt.Sprintf("%s:%s", nrpeTestImage, nrpeTestTag)

	cmd := exec.Command("docker", "build", "-t", imageTag, testdataDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build NRPE image: %v\nOutput: %s", err, output)
	}
	t.Logf("Built Docker image %s", imageTag)
}

func TestNRPEIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	// Build the NRPE image from Dockerfile
	buildNRPEImage(t)

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to Docker: %v", err)
	}

	// Run pre-built NRPE 4.1.3 image (plaintext mode, args enabled)
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   nrpeTestImage,
		Tag:          nrpeTestTag,
		ExposedPorts: []string{"5666/tcp"},
	})
	if err != nil {
		t.Fatalf("Could not start NRPE container: %v", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	// Wait for NRPE to be ready
	targetAddr := resource.GetHostPort("5666/tcp")
	t.Logf("NRPE container running at %s", targetAddr)

	time.Sleep(5 * time.Second)
	err = pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", targetAddr, 3*time.Second)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})
	if err != nil {
		t.Fatalf("NRPE container never became ready: %v", err)
	}

	t.Run("tcp_detection", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to connect to NRPE: %v", err)
		}

		plugin := &NRPEPlugin{}
		host, portStr, _ := net.SplitHostPort(targetAddr)
		addr, _ := netip.ParseAddrPort(fmt.Sprintf("%s:%s", host, portStr))
		target := plugins.Target{Address: addr}

		result, err := plugin.Run(conn, 5*time.Second, target)
		if err != nil {
			t.Fatalf("Plugin Run returned error: %v", err)
		}
		if result == nil {
			t.Fatal("Plugin Run returned nil service (NRPE not detected)")
		}

		t.Logf("Detected service: protocol=%s version=%s tls=%v", result.Protocol, result.Version, result.TLS)

		// Validate protocol
		if result.Protocol != NRPE {
			t.Errorf("Expected protocol %q, got %q", NRPE, result.Protocol)
		}

		// Validate version extraction
		if result.Version != "4.1.3" {
			t.Errorf("Expected version '4.1.3', got '%s'", result.Version)
		}

		// Validate TLS flag (plaintext mode)
		if result.TLS {
			t.Error("Expected TLS=false for plaintext NRPE connection")
		}

		// Validate NRPE metadata
		var nrpeData plugins.ServiceNRPE
		if err := json.Unmarshal(result.Raw, &nrpeData); err != nil {
			t.Fatalf("Failed to unmarshal NRPE metadata: %v", err)
		}

		// Validate CPE
		expectedCPE := "cpe:2.3:a:nagios:nrpe:4.1.3:*:*:*:*:*:*:*"
		if len(nrpeData.CPEs) == 0 || nrpeData.CPEs[0] != expectedCPE {
			t.Errorf("Expected CPE %q, got %v", expectedCPE, nrpeData.CPEs)
		}

		// Validate command args detection (dont_blame_nrpe=1 in container)
		if nrpeData.CommandArgsEnabled == nil {
			t.Error("Expected CommandArgsEnabled to be non-nil")
		} else if !*nrpeData.CommandArgsEnabled {
			t.Error("Expected CommandArgsEnabled=true (dont_blame_nrpe=1)")
		} else {
			t.Log("CommandArgsEnabled correctly detected as true")
		}
	})
}
