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

func findFinding(findings []plugins.SecurityFinding, id string) *plugins.SecurityFinding {
	for i := range findings {
		if findings[i].ID == id {
			return &findings[i]
		}
	}
	return nil
}

func TestCheckMissingSecurityHeaders_AllMissing(t *testing.T) {
	headers := http.Header{}
	findings := checkMissingSecurityHeaders(headers, true)

	assert.Len(t, findings, 3)

	hsts := findFinding(findings, "http-missing-hsts")
	assert.NotNil(t, hsts)
	assert.Equal(t, plugins.SeverityMedium, hsts.Severity)
	assert.Equal(t, "header not present: Strict-Transport-Security", hsts.Evidence)

	csp := findFinding(findings, "http-missing-csp")
	assert.NotNil(t, csp)
	assert.Equal(t, plugins.SeverityLow, csp.Severity)
	assert.Equal(t, "header not present: Content-Security-Policy", csp.Evidence)

	xfo := findFinding(findings, "http-missing-x-frame-options")
	assert.NotNil(t, xfo)
	assert.Equal(t, plugins.SeverityLow, xfo.Severity)
	assert.Equal(t, "header not present: X-Frame-Options", xfo.Evidence)
}

func TestCheckMissingSecurityHeaders_AllPresent(t *testing.T) {
	headers := http.Header{}
	headers.Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	headers.Set("Content-Security-Policy", "default-src 'self'")
	headers.Set("X-Frame-Options", "DENY")

	findings := checkMissingSecurityHeaders(headers, true)

	assert.Len(t, findings, 0)
}

func TestCheckMissingSecurityHeaders_HSTSPresent(t *testing.T) {
	headers := http.Header{}
	headers.Set("Strict-Transport-Security", "max-age=31536000")

	findings := checkMissingSecurityHeaders(headers, true)

	assert.Len(t, findings, 2)
	assert.Nil(t, findFinding(findings, "http-missing-hsts"))
	assert.NotNil(t, findFinding(findings, "http-missing-csp"))
	assert.NotNil(t, findFinding(findings, "http-missing-x-frame-options"))
}

func TestCheckMissingSecurityHeaders_CSPPresent(t *testing.T) {
	headers := http.Header{}
	headers.Set("Content-Security-Policy", "default-src 'self'")

	findings := checkMissingSecurityHeaders(headers, true)

	assert.Len(t, findings, 2)
	assert.NotNil(t, findFinding(findings, "http-missing-hsts"))
	assert.Nil(t, findFinding(findings, "http-missing-csp"))
	assert.NotNil(t, findFinding(findings, "http-missing-x-frame-options"))
}

func TestCheckMissingSecurityHeaders_XFrameOptionsPresent(t *testing.T) {
	headers := http.Header{}
	headers.Set("X-Frame-Options", "SAMEORIGIN")

	findings := checkMissingSecurityHeaders(headers, true)

	assert.Len(t, findings, 2)
	assert.NotNil(t, findFinding(findings, "http-missing-hsts"))
	assert.NotNil(t, findFinding(findings, "http-missing-csp"))
	assert.Nil(t, findFinding(findings, "http-missing-x-frame-options"))
}

func TestCheckMissingSecurityHeaders_HTTPNoHSTS(t *testing.T) {
	headers := http.Header{}
	findings := checkMissingSecurityHeaders(headers, false)

	assert.Len(t, findings, 2)
	assert.Nil(t, findFinding(findings, "http-missing-hsts"))
	assert.NotNil(t, findFinding(findings, "http-missing-csp"))
	assert.NotNil(t, findFinding(findings, "http-missing-x-frame-options"))
}

// ---------------------------------------------------------------------------
// checkCORSWildcard tests
// ---------------------------------------------------------------------------

func TestCheckCORSWildcard_WildcardOnly(t *testing.T) {
	headers := http.Header{}
	headers.Set("Access-Control-Allow-Origin", "*")

	finding := checkCORSWildcard(headers)

	assert.NotNil(t, finding)
	assert.Equal(t, "http-cors-wildcard", finding.ID)
	assert.Equal(t, plugins.SeverityMedium, finding.Severity)
	assert.Equal(t, "Access-Control-Allow-Origin: *", finding.Evidence)
}

func TestCheckCORSWildcard_WildcardWithCredentials(t *testing.T) {
	headers := http.Header{}
	headers.Set("Access-Control-Allow-Origin", "*")
	headers.Set("Access-Control-Allow-Credentials", "true")

	finding := checkCORSWildcard(headers)

	assert.NotNil(t, finding)
	assert.Equal(t, "http-cors-wildcard-credentials", finding.ID)
	assert.Equal(t, plugins.SeverityCritical, finding.Severity)
}

func TestCheckCORSWildcard_WildcardWithCredentialsFalse(t *testing.T) {
	headers := http.Header{}
	headers.Set("Access-Control-Allow-Origin", "*")
	headers.Set("Access-Control-Allow-Credentials", "false")

	finding := checkCORSWildcard(headers)

	assert.NotNil(t, finding)
	assert.Equal(t, "http-cors-wildcard", finding.ID)
	assert.Equal(t, plugins.SeverityMedium, finding.Severity)
}

func TestCheckCORSWildcard_SpecificOrigin(t *testing.T) {
	headers := http.Header{}
	headers.Set("Access-Control-Allow-Origin", "https://example.com")

	finding := checkCORSWildcard(headers)

	assert.Nil(t, finding)
}

func TestCheckCORSWildcard_NoHeader(t *testing.T) {
	headers := http.Header{}

	finding := checkCORSWildcard(headers)

	assert.Nil(t, finding)
}

// ---------------------------------------------------------------------------
// checkServerVersion tests
// ---------------------------------------------------------------------------

func TestCheckServerVersion_NginxWithVersion(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "nginx/1.14.0")

	finding := checkServerVersion(headers)

	assert.NotNil(t, finding)
	assert.Equal(t, "http-server-version", finding.ID)
	assert.Equal(t, plugins.SeverityInfo, finding.Severity)
	assert.Equal(t, "Server: nginx/1.14.0", finding.Evidence)
}

func TestCheckServerVersion_ApacheWithVersion(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "Apache/2.4.29 (Ubuntu)")

	finding := checkServerVersion(headers)

	assert.NotNil(t, finding)
	assert.Equal(t, "http-server-version", finding.ID)
	assert.Equal(t, plugins.SeverityInfo, finding.Severity)
}

func TestCheckServerVersion_IISWithVersion(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "Microsoft-IIS/10.0")

	finding := checkServerVersion(headers)

	assert.NotNil(t, finding)
	assert.Equal(t, "http-server-version", finding.ID)
	assert.Equal(t, plugins.SeverityInfo, finding.Severity)
}

func TestCheckServerVersion_NginxNoVersion(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "nginx")

	finding := checkServerVersion(headers)

	assert.Nil(t, finding)
}

func TestCheckServerVersion_Cloudflare(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "cloudflare")

	finding := checkServerVersion(headers)

	assert.Nil(t, finding)
}

func TestCheckServerVersion_Openresty(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "openresty")

	finding := checkServerVersion(headers)

	assert.Nil(t, finding)
}

func TestCheckServerVersion_NoHeader(t *testing.T) {
	headers := http.Header{}

	finding := checkServerVersion(headers)

	assert.Nil(t, finding)
}

// ---------------------------------------------------------------------------
// checkDirectoryListing tests
// ---------------------------------------------------------------------------

func TestCheckDirectoryListing_ApacheTitle(t *testing.T) {
	body := []byte("<html><head><title>Index of /var/www</title></head></html>")

	finding := checkDirectoryListing(body)

	assert.NotNil(t, finding)
	assert.Equal(t, "http-directory-listing", finding.ID)
	assert.Equal(t, plugins.SeverityLow, finding.Severity)
}

func TestCheckDirectoryListing_PythonH1(t *testing.T) {
	body := []byte("<html><body><h1>Directory listing for /tmp</h1></body></html>")

	finding := checkDirectoryListing(body)

	assert.NotNil(t, finding)
	assert.Equal(t, "http-directory-listing", finding.ID)
	assert.Equal(t, plugins.SeverityLow, finding.Severity)
}

func TestCheckDirectoryListing_NginxAutoindex(t *testing.T) {
	body := []byte("<html><head><title>/ </title></head><body><h1>/ </h1><hr><pre><a href=\"../\">../</a>\n<a href=\"file.txt\">file.txt</a></pre></body></html>")

	finding := checkDirectoryListing(body)

	assert.NotNil(t, finding)
	assert.Equal(t, "http-directory-listing", finding.ID)
	assert.Equal(t, plugins.SeverityLow, finding.Severity)
}

func TestCheckDirectoryListing_NormalHTML(t *testing.T) {
	body := []byte("<html><head><title>Welcome</title></head><body><h1>Hello World</h1></body></html>")

	finding := checkDirectoryListing(body)

	assert.Nil(t, finding)
}

func TestCheckDirectoryListing_EmptyBody(t *testing.T) {
	finding := checkDirectoryListing([]byte{})

	assert.Nil(t, finding)
}

func TestCheckDirectoryListing_MentionsIndexInText(t *testing.T) {
	// A page that discusses "Index of" in prose but is NOT a directory listing.
	// The <title>index of / pattern requires the title tag, so this should NOT match.
	body := []byte("<html><body><p>The Apache directive generates a page titled Index of /path when autoindex is enabled.</p></body></html>")
	finding := checkDirectoryListing(body)
	assert.Nil(t, finding)
}

func TestCheckDirectoryListing_FalsePositiveSeparatedPatterns(t *testing.T) {
	// A page with <pre><a href="..."> and ../ in separate locations — should NOT trigger
	// after the fix to use compound pattern.
	body := []byte(`<html><body><pre><a href="https://example.com">link</a></pre><p>See <a href="../overview">overview</a></p></body></html>`)
	finding := checkDirectoryListing(body)
	assert.Nil(t, finding)
}

// ---------------------------------------------------------------------------
// checkCORSWildcard additional tests
// ---------------------------------------------------------------------------

func TestCheckCORSWildcard_WildcardWithCredentialsCaseInsensitive(t *testing.T) {
	headers := http.Header{}
	headers.Set("Access-Control-Allow-Origin", "*")
	headers.Set("Access-Control-Allow-Credentials", "TRUE")

	finding := checkCORSWildcard(headers)

	assert.NotNil(t, finding)
	assert.Equal(t, "http-cors-wildcard-credentials", finding.ID)
	assert.Equal(t, plugins.SeverityCritical, finding.Severity)
}

// ---------------------------------------------------------------------------
// checkServerVersion additional tests
// ---------------------------------------------------------------------------

func TestCheckServerVersion_AmazonS3(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "AmazonS3")
	finding := checkServerVersion(headers)
	assert.Nil(t, finding)
}

func TestCheckServerVersion_ECSCacheCode(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "ECS (dcb/7F83)")
	finding := checkServerVersion(headers)
	assert.Nil(t, finding)
}

func TestCheckServerVersion_GunicornWithVersion(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "gunicorn/21.2.0")
	finding := checkServerVersion(headers)
	assert.NotNil(t, finding)
	assert.Equal(t, "http-server-version", finding.ID)
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
		t.Skipf("skipping docker test; could not connect to docker: %s", err)
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

	addrPort, err := netip.ParseAddrPort(targetAddr)
	if err != nil {
		t.Fatalf("ParseAddrPort(%q): %v", targetAddr, err)
	}
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

	hsts := findFinding(service.SecurityFindings, "http-missing-hsts")
	if hsts != nil {
		t.Errorf("expected no http-missing-hsts finding for plain HTTP, got: %+v", *hsts)
	}

	csp := findFinding(service.SecurityFindings, "http-missing-csp")
	if csp == nil {
		t.Errorf("expected http-missing-csp finding, got findings: %v", service.SecurityFindings)
	} else if csp.Severity != plugins.SeverityLow {
		t.Errorf("http-missing-csp severity = %q, want %q", csp.Severity, plugins.SeverityLow)
	}

	xfo := findFinding(service.SecurityFindings, "http-missing-x-frame-options")
	if xfo == nil {
		t.Errorf("expected http-missing-x-frame-options finding, got findings: %v", service.SecurityFindings)
	} else if xfo.Severity != plugins.SeverityLow {
		t.Errorf("http-missing-x-frame-options severity = %q, want %q", xfo.Severity, plugins.SeverityLow)
	}
}
