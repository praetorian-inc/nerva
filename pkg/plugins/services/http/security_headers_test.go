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
	"bytes"
	"net"
	"net/http"
	"net/netip"
	"strings"
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
	assert.Equal(t, plugins.SeverityMedium, finding.Severity)
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
	assert.Equal(t, "Server: Apache/2.4.29 (Ubuntu)", finding.Evidence)
}

func TestCheckServerVersion_IISWithVersion(t *testing.T) {
	headers := http.Header{}
	headers.Set("Server", "Microsoft-IIS/10.0")

	finding := checkServerVersion(headers)

	assert.NotNil(t, finding)
	assert.Equal(t, "http-server-version", finding.ID)
	assert.Equal(t, plugins.SeverityInfo, finding.Severity)
	assert.Equal(t, "Server: Microsoft-IIS/10.0", finding.Evidence)
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

func TestCheckDirectoryListing_IIS(t *testing.T) {
	body := []byte(`<html><body><table><tr><td><a href="/">[To Parent Directory]</a></td></tr></table></body></html>`)

	finding := checkDirectoryListing(body)

	assert.NotNil(t, finding)
	assert.Equal(t, "http-directory-listing", finding.ID)
	assert.Equal(t, plugins.SeverityLow, finding.Severity)
}

func TestCheckDirectoryListing_NginxAutoindexSingleQuote(t *testing.T) {
	body := []byte("<html><head><title>/ </title></head><body><h1>/ </h1><hr><pre><a href='../'>../</a>\n<a href='file.txt'>file.txt</a></pre></body></html>")

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

func TestCheckDirectoryListing_FalsePositiveRelativeLinkInPre(t *testing.T) {
	// A page with a relative parent-directory link inside a <pre> block
	// should NOT trigger — only nginx autoindex format <pre><a href="../"> should match.
	body := []byte(`<html><body><pre><a href="../docs">Documentation</a></pre></body></html>`)
	finding := checkDirectoryListing(body)
	assert.Nil(t, finding)
}

func TestCheckDirectoryListing_LargeBodyPatternBeforeLimit(t *testing.T) {
	prefix := []byte("<html><head><title>Index of /</title></head><body>")
	padding := bytes.Repeat([]byte("x"), 8192)
	body := append(prefix, padding...)
	finding := checkDirectoryListing(body)
	assert.NotNil(t, finding)
	assert.Equal(t, "http-directory-listing", finding.ID)
}

func TestCheckDirectoryListing_LargeBodyPatternAfterLimit(t *testing.T) {
	padding := bytes.Repeat([]byte("x"), 8192)
	suffix := []byte("<title>Index of /</title>")
	body := append(padding, suffix...)
	finding := checkDirectoryListing(body)
	assert.Nil(t, finding)
}

func TestCheckServerVersion_NoFalsePositive_HTTPVersionFragment(t *testing.T) {
	// "1.1 proxy" looks version-like but lacks a product name prefix.
	// The regex requires name/version format to avoid this class of false positive.
	headers := http.Header{}
	headers.Set("Server", "1.1 proxy")
	finding := checkServerVersion(headers)
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
	assert.Equal(t, plugins.SeverityMedium, finding.Severity)
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

func TestCheckServerVersion_LongHeader(t *testing.T) {
	// Version number appears early; the rest is padding to exceed 256 chars.
	long := "CustomServer/1.2.3 " + strings.Repeat("x", 300)
	headers := http.Header{}
	headers.Set("Server", long)
	finding := checkServerVersion(headers)
	assert.NotNil(t, finding)
	assert.Equal(t, "http-server-version", finding.ID)
	assert.True(t, len(finding.Evidence) <= 265, "evidence should be truncated (Server: prefix + 256 chars max)")
}

func TestCheckServerVersion_LongHeaderNoVersion(t *testing.T) {
	long := strings.Repeat("x", 300)
	headers := http.Header{}
	headers.Set("Server", long)
	finding := checkServerVersion(headers)
	assert.Nil(t, finding)
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

// ---------------------------------------------------------------------------
// In-process integration tests – HTTPPlugin.Run() end-to-end
// ---------------------------------------------------------------------------

// startHTTPServer starts a plain TCP listener on a random localhost port.
// For each accepted connection it drains the request bytes and writes the
// provided raw HTTP response string back to the client.
// The caller is responsible for closing the returned listener.
func startHTTPServer(t *testing.T, response string) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("startHTTPServer: net.Listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func(c net.Conn) {
				defer c.Close()
				var buf [4096]byte
				var total int
				for {
					n, err := c.Read(buf[total:])
					total += n
					if bytes.Contains(buf[:total], []byte("\r\n\r\n")) || err != nil || total >= len(buf) {
						break
					}
				}
				c.Write([]byte(response)) //nolint:errcheck
			}(conn)
		}
	}()
	return ln
}

// runHTTPPlugin is a shared helper that starts an in-process HTTP server
// serving response, then calls HTTPPlugin.Run() against it and returns the
// resulting service.
func runHTTPPlugin(t *testing.T, response string) *plugins.Service {
	t.Helper()

	ln := startHTTPServer(t, response)
	defer ln.Close()

	addrPort := netip.MustParseAddrPort(ln.Addr().String())
	target := plugins.Target{
		Address:    addrPort,
		Misconfigs: true,
	}

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatalf("runHTTPPlugin: net.DialTimeout: %v", err)
	}
	defer conn.Close()

	wappalyzerClient, err := wappalyzer.New()
	if err != nil {
		t.Fatalf("runHTTPPlugin: wappalyzer.New: %v", err)
	}
	p := &HTTPPlugin{analyzer: wappalyzerClient}

	service, err := p.Run(conn, 5*time.Second, target)
	if err != nil {
		t.Fatalf("runHTTPPlugin: HTTPPlugin.Run(): %v", err)
	}
	if service == nil {
		t.Fatal("runHTTPPlugin: HTTPPlugin.Run() returned nil service")
	}
	return service
}

// TestHTTPPlugin_CORSWildcard_Live verifies that a CORS wildcard header
// (without credentials) produces an http-cors-wildcard finding with Medium
// severity, and does not produce http-cors-wildcard-credentials.
func TestHTTPPlugin_CORSWildcard_Live(t *testing.T) {
	const body = "<html><body><h1>Hello</h1></body></html>"
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Access-Control-Allow-Origin: *\r\n" +
		"Content-Length: 39\r\n" +
		"Connection: close\r\n\r\n" +
		body

	service := runHTTPPlugin(t, response)

	finding := findFinding(service.SecurityFindings, "http-cors-wildcard")
	if finding == nil {
		t.Fatalf("expected http-cors-wildcard finding, got findings: %v", service.SecurityFindings)
	}
	if finding.Severity != plugins.SeverityMedium {
		t.Errorf("http-cors-wildcard severity = %q, want %q", finding.Severity, plugins.SeverityMedium)
	}
	if creds := findFinding(service.SecurityFindings, "http-cors-wildcard-credentials"); creds != nil {
		t.Errorf("expected no http-cors-wildcard-credentials finding, got: %+v", *creds)
	}
}

// TestHTTPPlugin_CORSWildcardCredentials_Live verifies that a CORS wildcard
// header combined with Access-Control-Allow-Credentials: true produces an
// http-cors-wildcard-credentials finding with Medium severity.
func TestHTTPPlugin_CORSWildcardCredentials_Live(t *testing.T) {
	const body = "<html><body><h1>Hello</h1></body></html>"
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Access-Control-Allow-Origin: *\r\n" +
		"Access-Control-Allow-Credentials: true\r\n" +
		"Content-Length: 39\r\n" +
		"Connection: close\r\n\r\n" +
		body

	service := runHTTPPlugin(t, response)

	finding := findFinding(service.SecurityFindings, "http-cors-wildcard-credentials")
	if finding == nil {
		t.Fatalf("expected http-cors-wildcard-credentials finding, got findings: %v", service.SecurityFindings)
	}
	if finding.Severity != plugins.SeverityMedium {
		t.Errorf("http-cors-wildcard-credentials severity = %q, want %q", finding.Severity, plugins.SeverityMedium)
	}
}

// TestHTTPPlugin_ServerVersion_Live verifies that a versioned Server header
// produces an http-server-version finding with Info severity and that the
// evidence string contains the version value.
func TestHTTPPlugin_ServerVersion_Live(t *testing.T) {
	const body = "<html><body><h1>Hello</h1></body></html>"
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Server: nginx/1.24.0\r\n" +
		"Content-Length: 39\r\n" +
		"Connection: close\r\n\r\n" +
		body

	service := runHTTPPlugin(t, response)

	finding := findFinding(service.SecurityFindings, "http-server-version")
	if finding == nil {
		t.Fatalf("expected http-server-version finding, got findings: %v", service.SecurityFindings)
	}
	if finding.Severity != plugins.SeverityInfo {
		t.Errorf("http-server-version severity = %q, want %q", finding.Severity, plugins.SeverityInfo)
	}
	if !strings.Contains(finding.Evidence, "nginx/1.24.0") {
		t.Errorf("http-server-version evidence = %q, want it to contain %q", finding.Evidence, "nginx/1.24.0")
	}
}

// TestHTTPPlugin_ServerNoVersion_Live verifies that a Server header without a
// version number (e.g. "cloudflare") does not produce an http-server-version
// finding.
func TestHTTPPlugin_ServerNoVersion_Live(t *testing.T) {
	const body = "<html><body><h1>Hello</h1></body></html>"
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Server: cloudflare\r\n" +
		"Content-Length: 39\r\n" +
		"Connection: close\r\n\r\n" +
		body

	service := runHTTPPlugin(t, response)

	if finding := findFinding(service.SecurityFindings, "http-server-version"); finding != nil {
		t.Errorf("expected no http-server-version finding for generic Server header, got: %+v", *finding)
	}
}

// TestHTTPPlugin_DirectoryListing_Live verifies that an Apache-style directory
// listing body produces an http-directory-listing finding with Low severity.
func TestHTTPPlugin_DirectoryListing_Live(t *testing.T) {
	const body = "<html><head><title>Index of /var/www</title></head><body><h1>Index of /var/www</h1><pre>...</pre></body></html>"
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 109\r\n" +
		"Connection: close\r\n\r\n" +
		body

	service := runHTTPPlugin(t, response)

	finding := findFinding(service.SecurityFindings, "http-directory-listing")
	if finding == nil {
		t.Fatalf("expected http-directory-listing finding, got findings: %v", service.SecurityFindings)
	}
	if finding.Severity != plugins.SeverityLow {
		t.Errorf("http-directory-listing severity = %q, want %q", finding.Severity, plugins.SeverityLow)
	}
}

// TestHTTPPlugin_NormalPage_NoDirectoryListing_Live verifies that a normal HTML
// page does not trigger the http-directory-listing finding.
func TestHTTPPlugin_NormalPage_NoDirectoryListing_Live(t *testing.T) {
	const body = "<html><head><title>Welcome</title></head><body><h1>Home Page</h1><p>Nothing to see here.</p></body></html>"
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 104\r\n" +
		"Connection: close\r\n\r\n" +
		body

	service := runHTTPPlugin(t, response)

	if finding := findFinding(service.SecurityFindings, "http-directory-listing"); finding != nil {
		t.Errorf("expected no http-directory-listing finding for normal page, got: %+v", *finding)
	}
}

// TestHTTPPlugin_NoCORSNoVersion_Live verifies that a minimal response with no
// CORS headers, no Server header, and no directory listing does not produce any
// of the three new findings.
func TestHTTPPlugin_NoCORSNoVersion_Live(t *testing.T) {
	const body = "<html><body><h1>Hello</h1></body></html>"
	response := "HTTP/1.1 200 OK\r\n" +
		"Content-Type: text/html\r\n" +
		"Content-Length: 39\r\n" +
		"Connection: close\r\n\r\n" +
		body

	service := runHTTPPlugin(t, response)

	for _, id := range []string{"http-cors-wildcard", "http-cors-wildcard-credentials", "http-server-version", "http-directory-listing"} {
		if f := findFinding(service.SecurityFindings, id); f != nil {
			t.Errorf("expected no %s finding for minimal response, got: %+v", id, *f)
		}
	}
}

// ---------------------------------------------------------------------------
// Docker-based live test for directory listing
// ---------------------------------------------------------------------------

// TestHTTPPlugin_DirectoryListing_Docker spins up a python:3.13-alpine container
// running Python's built-in HTTP server, which generates real directory
// listings, and verifies that HTTPPlugin.Run() detects the http-directory-listing
// finding while not producing false-positive CORS findings.
func TestHTTPPlugin_DirectoryListing_Docker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		t.Skipf("skipping docker test; could not connect to docker: %s", err)
	}

	resource, err := pool.RunWithOptions(&dockertest.RunOptions{
		Repository:   "python",
		Tag:          "3.13-alpine",
		Cmd:          []string{"python3", "-m", "http.server", "8080"},
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

	// Wait for the Python HTTP server to be ready by probing for a valid HTTP
	// response, not just TCP connectivity.
	retryErr := pool.Retry(func() error {
		resp, dialErr := http.Get("http://" + targetAddr + "/") //nolint:noctx
		if dialErr != nil {
			return dialErr
		}
		resp.Body.Close()
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
		t.Fatalf("net.DialTimeout: %v", err)
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

	finding := findFinding(service.SecurityFindings, "http-directory-listing")
	if finding == nil {
		t.Fatalf("expected http-directory-listing finding, got findings: %v", service.SecurityFindings)
	}
	if finding.Severity != plugins.SeverityLow {
		t.Errorf("http-directory-listing severity = %q, want %q", finding.Severity, plugins.SeverityLow)
	}

	// Python http.server does not set CORS headers; verify no false positive.
	for _, id := range []string{"http-cors-wildcard", "http-cors-wildcard-credentials"} {
		if f := findFinding(service.SecurityFindings, id); f != nil {
			t.Errorf("expected no %s finding from Python http.server, got: %+v", id, *f)
		}
	}
}
