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

package scan

import (
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const (
	tlsWeakCipherImage = "nerva-tls-weak-ciphers"
	tlsWeakCipherTag   = "test"
)

func findTLSWeakCipherTestdata(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"testdata/tls-weak-ciphers",
		filepath.Join("..", "..", "testdata", "tls-weak-ciphers"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "Dockerfile")); err == nil {
			abs, _ := filepath.Abs(c)
			return abs
		}
	}
	t.Fatal("Could not find testdata/tls-weak-ciphers/Dockerfile")
	return ""
}

func buildTLSWeakCipherImage(t *testing.T) {
	t.Helper()
	testdataDir := findTLSWeakCipherTestdata(t)
	imageTag := fmt.Sprintf("%s:%s", tlsWeakCipherImage, tlsWeakCipherTag)
	cmd := exec.Command("docker", "build", "-t", imageTag, testdataDir)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to build weak-cipher image: %v\nOutput: %s", err, output)
	}
	t.Logf("Built Docker image %s", imageTag)
}

func hostAddrPort(t *testing.T, resource *dockertest.Resource, containerPort string) netip.AddrPort {
	t.Helper()
	hostPort := resource.GetHostPort(containerPort)
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		t.Fatalf("split host:port %q: %v", hostPort, err)
	}
	if host == "localhost" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	ap, err := netip.ParseAddrPort(net.JoinHostPort(host, port))
	if err != nil {
		t.Fatalf("parse AddrPort %s:%s: %v", host, port, err)
	}
	return ap
}

// TestSimpleScanTarget_OpenSSLWeakCipherListeners runs the testdata/tls-weak-ciphers
// OpenSSL 1.0.2 fixture (ADH / AECDH / NULL / EXPORT, one port each) and checks
// SimpleScanTarget --misconfigs emits the matching finding IDs.
func TestSimpleScanTarget_OpenSSLWeakCipherListeners(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping Docker integration test in short mode")
	}

	buildTLSWeakCipherImage(t)

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Fatalf("Could not connect to Docker: %v", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   tlsWeakCipherImage,
		Tag:          tlsWeakCipherTag,
		ExposedPorts: []string{"4433/tcp", "4434/tcp", "4435/tcp", "4436/tcp"},
	})
	if err != nil {
		t.Fatalf("Could not start weak-cipher container: %v", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	if err := pool.Retry(func() error {
		for _, p := range []string{"4433/tcp", "4434/tcp", "4435/tcp", "4436/tcp"} {
			ap := hostAddrPort(t, resource, p)
			conn, dialErr := net.DialTimeout("tcp", ap.String(), 3*time.Second)
			if dialErr != nil {
				return dialErr
			}
			conn.Close()
		}
		return nil
	}); err != nil {
		t.Fatalf("weak-cipher container never became ready: %v", err)
	}

	cases := []struct {
		name          string
		containerPort string
		id            string
	}{
		{name: "ADH", containerPort: "4433/tcp", id: "tls-anon-cipher"},
		{name: "AECDH", containerPort: "4434/tcp", id: "tls-anon-cipher"},
		{name: "NULL", containerPort: "4435/tcp", id: "tls-null-cipher"},
		{name: "EXPORT", containerPort: "4436/tcp", id: "tls-export-cipher"},
	}

	config := &Config{DefaultTimeout: 5 * time.Second, Misconfigs: true}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ap := hostAddrPort(t, resource, tc.containerPort)
			target := plugins.Target{Address: ap, Host: ap.Addr().String()}
			services, err := config.SimpleScanTarget(target)
			if err != nil {
				t.Fatalf("SimpleScanTarget: %v", err)
			}
			if len(services) != 1 {
				t.Fatalf("SimpleScanTarget returned %d services, want 1 with %s", len(services), tc.id)
			}
			found := false
			for _, f := range services[0].SecurityFindings {
				if f.ID == tc.id {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("missing %s in %+v", tc.id, services[0].SecurityFindings)
			}
			if !services[0].TLS {
				t.Fatal("expected TLS=true")
			}
			t.Logf("%s:%s finding=%s", tc.name, strconv.Itoa(int(ap.Port())), tc.id)
		})
	}
}
