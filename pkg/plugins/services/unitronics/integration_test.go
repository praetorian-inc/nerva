package unitronics

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

const pcomTestImage = "pcom-test"
const pcomTestTag = "latest"

// findTestdataDir locates the testdata/pcom directory relative to this test file
func findTestdataDir(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"testdata/pcom",
		"pkg/plugins/services/unitronics/testdata/pcom",
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "Dockerfile")); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatal("Could not find testdata/pcom/Dockerfile")
	return ""
}

// buildPCOMImage builds the PCOM Docker image from the Dockerfile.
// Uses docker CLI directly because dockertest's BuildAndRun uses an older Docker
// client API version (1.25) that's incompatible with newer Docker daemons (>=1.44).
func buildPCOMImage(t *testing.T) {
	t.Helper()
	testdataDir := findTestdataDir(t)
	imageTag := fmt.Sprintf("%s:%s", pcomTestImage, pcomTestTag)

	cmd := exec.Command("docker", "build", "-t", imageTag, testdataDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build PCOM image: %v\nOutput: %s", err, output)
	}
	t.Logf("Built Docker image %s", imageTag)
}

func TestPCOMIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	// Build the PCOM image from Dockerfile
	buildPCOMImage(t)

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to Docker: %v", err)
	}

	// Run PCOM mock server
	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   pcomTestImage,
		Tag:          pcomTestTag,
		ExposedPorts: []string{"20256/tcp"},
	})
	if err != nil {
		t.Fatalf("Could not start PCOM container: %v", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	// Wait for PCOM server to be ready
	targetAddr := resource.GetHostPort("20256/tcp")
	t.Logf("PCOM container running at %s", targetAddr)

	time.Sleep(2 * time.Second)
	err = pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", targetAddr, 3*time.Second)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})
	if err != nil {
		t.Fatalf("PCOM container never became ready: %v", err)
	}

	t.Run("tcp_detection", func(t *testing.T) {
		conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
		if err != nil {
			t.Fatalf("Failed to connect to PCOM: %v", err)
		}

		plugin := &PCOMPlugin{}
		host, portStr, _ := net.SplitHostPort(targetAddr)
		addr, _ := netip.ParseAddrPort(fmt.Sprintf("%s:%s", host, portStr))
		target := plugins.Target{Address: addr}

		result, err := plugin.Run(conn, 5*time.Second, target)
		if err != nil {
			t.Fatalf("Plugin Run returned error: %v", err)
		}
		if result == nil {
			t.Fatal("Plugin Run returned nil service (PCOM not detected)")
		}

		t.Logf("Detected service: protocol=%s version=%s tls=%v", result.Protocol, result.Version, result.TLS)

		// Validate protocol
		if result.Protocol != PCOM {
			t.Errorf("Expected protocol %q, got %q", PCOM, result.Protocol)
		}

		// Validate version extraction
		expectedVersion := "003.028.00"
		if result.Version != expectedVersion {
			t.Errorf("Expected version %q, got %q", expectedVersion, result.Version)
		}

		// Validate TLS flag (plaintext mode)
		if result.TLS {
			t.Error("Expected TLS=false for plaintext PCOM connection")
		}

		// Validate PCOM metadata
		var pcomData plugins.ServicePCOM
		if err := json.Unmarshal(result.Raw, &pcomData); err != nil {
			t.Fatalf("Failed to unmarshal PCOM metadata: %v", err)
		}

		// Validate model mapping (180701 -> V130-33-T38)
		expectedModel := "V130-33-T38"
		if pcomData.Model != expectedModel {
			t.Errorf("Expected model %q, got %q", expectedModel, pcomData.Model)
		}

		// Validate HW version
		if pcomData.HWVersion != "2" {
			t.Errorf("Expected HWVersion '2', got '%s'", pcomData.HWVersion)
		}

		// Validate OS version
		if pcomData.OSVersion != expectedVersion {
			t.Errorf("Expected OSVersion %q, got %q", expectedVersion, pcomData.OSVersion)
		}

		// Validate CPE
		expectedCPEPrefix := "cpe:2.3:h:unitronics:"
		if len(pcomData.CPEs) == 0 {
			t.Error("Expected at least one CPE, got none")
		} else {
			cpe := pcomData.CPEs[0]
			if len(cpe) < len(expectedCPEPrefix) || cpe[:len(expectedCPEPrefix)] != expectedCPEPrefix {
				t.Errorf("Expected CPE to start with %q, got %q", expectedCPEPrefix, cpe)
			}
			t.Logf("CPE: %s", cpe)
		}
	})
}
