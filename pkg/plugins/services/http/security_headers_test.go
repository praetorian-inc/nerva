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

package http

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/ory/dockertest/v3"
	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/stretchr/testify/assert"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

func findSecurityFinding(findings []plugins.SecurityFinding, id string) *plugins.SecurityFinding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}

func TestCheckMissingSecurityHeaders_AllMissing(t *testing.T) {
	headers := http.Header{}
	findings := checkMissingSecurityHeaders(headers)

	assert.Len(t, findings, 3)

	hsts := findSecurityFinding(findings, "http-missing-hsts")
	assert.NotNil(t, hsts)
	assert.Equal(t, plugins.SeverityMedium, hsts.Severity)
	assert.Equal(t, "header not present: Strict-Transport-Security", hsts.Evidence)

	csp := findSecurityFinding(findings, "http-missing-csp")
	assert.NotNil(t, csp)
	assert.Equal(t, plugins.SeverityLow, csp.Severity)
	assert.Equal(t, "header not present: Content-Security-Policy", csp.Evidence)

	xfo := findSecurityFinding(findings, "http-missing-x-frame-options")
	assert.NotNil(t, xfo)
	assert.Equal(t, plugins.SeverityLow, xfo.Severity)
	assert.Equal(t, "header not present: X-Frame-Options", xfo.Evidence)
}

func TestCheckMissingSecurityHeaders_AllPresent(t *testing.T) {
	headers := http.Header{}
	headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	headers.Set("Content-Security-Policy", "default-src 'self'")
	headers.Set("X-Frame-Options", "DENY")

	findings := checkMissingSecurityHeaders(headers)

	assert.Len(t, findings, 0)
}

func TestCheckMissingSecurityHeaders_HSTSPresent(t *testing.T) {
	headers := http.Header{}
	headers.Set("Strict-Transport-Security", "max-age=31536000")

	findings := checkMissingSecurityHeaders(headers)

	assert.Len(t, findings, 2)
	assert.Nil(t, findSecurityFinding(findings, "http-missing-hsts"))
	assert.NotNil(t, findSecurityFinding(findings, "http-missing-csp"))
	assert.NotNil(t, findSecurityFinding(findings, "http-missing-x-frame-options"))
}

func TestCheckMissingSecurityHeaders_CSPPresent(t *testing.T) {
	headers := http.Header{}
	headers.Set("Content-Security-Policy", "default-src 'self'")

	findings := checkMissingSecurityHeaders(headers)

	assert.Len(t, findings, 2)
	assert.NotNil(t, findSecurityFinding(findings, "http-missing-hsts"))
	assert.Nil(t, findSecurityFinding(findings, "http-missing-csp"))
	assert.NotNil(t, findSecurityFinding(findings, "http-missing-x-frame-options"))
}

func TestCheckMissingSecurityHeaders_XFrameOptionsPresent(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Frame-Options", "SAMEORIGIN")

	findings := checkMissingSecurityHeaders(headers)

	assert.Len(t, findings, 2)
	assert.NotNil(t, findSecurityFinding(findings, "http-missing-hsts"))
	assert.NotNil(t, findSecurityFinding(findings, "http-missing-csp"))
	assert.Nil(t, findSecurityFinding(findings, "http-missing-x-frame-options"))
}

// ---------------------------------------------------------------------------
// Docker-based live integration test
// ---------------------------------------------------------------------------

// TestHTTPPlugin_MissingSecurityHeaders_Live spins up a mendhak/http-https-echo:24
// container on port 8080 and verifies that HTTPPlugin.Run() with Misconfigs=true
// produces all three expected security header findings.
func TestHTTPPlugin_MissingSecurityHeaders_Live(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		log.Fatalf("could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "mendhak/http-https-echo",
		Tag:          "24",
		ExposedPorts: []string{"8080/tcp"},
	})
	if err != nil {
		t.Fatalf("could not start container: %s", err)
	}
	defer pool.Purge(resource) //nolint:errcheck

	rawAddr := resource.GetHostPort("8080/tcp")
	host, port, err := net.SplitHostPort(rawAddr)
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", rawAddr, err)
	}
	if host == "localhost" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	targetAddr := net.JoinHostPort(host, port)

	// Wait for the HTTP server to be ready. Sleep briefly so the HTTP server
	// has time to finish initializing before the first retry attempt.
	time.Sleep(2 * time.Second)
	retryErr := pool.Retry(func() error {
		conn, dialErr := net.DialTimeout("tcp", targetAddr, 3*time.Second)
		if dialErr != nil {
			return dialErr
		}
		conn.Close()
		return nil
	})
	if retryErr != nil {
		t.Fatalf("server not ready: %s", retryErr)
	}

	addrPort := netip.MustParseAddrPort(fmt.Sprintf("%s:%s", host, port))
	target := plugins.Target{
		Address:    addrPort,
		Misconfigs: true,
	}

	conn, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("net.Dial: %v", err)
	}
	defer conn.Close()

	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		t.Fatalf("wappalyzer.New: %v", err)
	}
	p := &HTTPPlugin{analyzer: wappalyzerClient}

	service, err := p.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("HTTPPlugin.Run(): %v", err)
	}
	if service == nil {
		t.Fatal("HTTPPlugin.Run() returned nil service")
	}

	hsts := findSecurityFinding(service.SecurityFindings, "http-missing-hsts")
	if hsts == nil {
		t.Errorf("expected http-missing-hsts finding, got findings: %v", service.SecurityFindings)
	} else if hsts.Severity != plugins.SeverityMedium {
		t.Errorf("http-missing-hsts severity = %q, want %q", hsts.Severity, plugins.SeverityMedium)
	}

	csp := findSecurityFinding(service.SecurityFindings, "http-missing-csp")
	if csp == nil {
		t.Errorf("expected http-missing-csp finding, got findings: %v", service.SecurityFindings)
	} else if csp.Severity != plugins.SeverityLow {
		t.Errorf("http-missing-csp severity = %q, want %q", csp.Severity, plugins.SeverityLow)
	}

	xfo := findSecurityFinding(service.SecurityFindings, "http-missing-x-frame-options")
	if xfo == nil {
		t.Errorf("expected http-missing-x-frame-options finding, got findings: %v", service.SecurityFindings)
	} else if xfo.Severity != plugins.SeverityLow {
		t.Errorf("http-missing-x-frame-options severity = %q, want %q", xfo.Severity, plugins.SeverityLow)
	}
}
