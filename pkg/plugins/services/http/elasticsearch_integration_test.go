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

//go:build integration

package http

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	wappalyzer "github.com/projectdiscovery/wappalyzergo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/plugins/fingerprinters"
)

const (
	esUnauthURL  = "http://127.0.0.1:19200/"
	esAuthURL    = "http://127.0.0.1:19201/"
	esUnauthAddr = "127.0.0.1:19200"
	esAuthAddr   = "127.0.0.1:19201"
	esTagline    = "You Know, for Search"
	esNoAuthID   = "elasticsearch-no-auth"
)

func findElasticsearchTestdata(t *testing.T) string {
	t.Helper()
	candidates := []string{
		"testdata/elasticsearch",
		filepath.Join("..", "..", "..", "..", "testdata", "elasticsearch"),
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "docker-compose.yml")); err == nil {
			abs, err := filepath.Abs(c)
			require.NoError(t, err)
			return abs
		}
	}
	t.Fatal("could not find testdata/elasticsearch/docker-compose.yml")
	return ""
}

func elasticsearchCompose(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	cmd := exec.Command("docker", append([]string{"compose", "-f", "docker-compose.yml"}, args...)...)
	cmd.Dir = findElasticsearchTestdata(t)
	return cmd
}

func startElasticsearchFixture(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping docker test in short mode")
	}
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not available")
	}

	up := elasticsearchCompose(t, "up", "-d", "--wait", "--wait-timeout", "180")
	out, err := up.CombinedOutput()
	require.NoError(t, err, "docker compose up: %s", string(out))

	t.Cleanup(func() {
		down := elasticsearchCompose(t, "down", "-v", "--remove-orphans")
		_ = down.Run()
	})
}

func getElasticsearchRoot(t *testing.T, url string) (status int, body []byte, header http.Header) {
	t.Helper()
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	require.NoError(t, err, "GET %s", url)
	defer resp.Body.Close()
	body, err = io.ReadAll(resp.Body)
	require.NoError(t, err)
	return resp.StatusCode, body, resp.Header.Clone()
}

func scanElasticsearchHTTP(t *testing.T, addr string) *plugins.Service {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	require.NoError(t, err, "dial %s", addr)
	defer conn.Close()

	addrPort, err := netip.ParseAddrPort(addr)
	require.NoError(t, err)

	analyzer, err := wappalyzer.New()
	require.NoError(t, err)

	svc, err := (&HTTPPlugin{analyzer: analyzer}).Run(conn, 10*time.Second, plugins.Target{
		Host:       "127.0.0.1",
		Address:    addrPort,
		Misconfigs: true,
	})
	require.NoError(t, err)
	require.NotNil(t, svc, "HTTPPlugin.Run returned nil service for %s", addr)
	return svc
}

func TestElasticsearchDockerTarget_DocumentedRootResponses(t *testing.T) {
	startElasticsearchFixture(t)

	t.Run("unauth GET / is 200 with tagline", func(t *testing.T) {
		status, body, header := getElasticsearchRoot(t, esUnauthURL)
		require.Equal(t, http.StatusOK, status, "body=%s", body)
		assert.Contains(t, header.Get("Content-Type"), "application/json")
		assert.Contains(t, string(body), esTagline)

		var root map[string]any
		require.NoError(t, json.Unmarshal(body, &root))
		assert.Equal(t, esTagline, root["tagline"])
	})

	t.Run("auth GET / is 401 security_exception", func(t *testing.T) {
		status, body, header := getElasticsearchRoot(t, esAuthURL)
		require.Equal(t, http.StatusUnauthorized, status, "body=%s", body)
		assert.Contains(t, header.Get("Content-Type"), "application/json")
		assert.Contains(t, string(body), "security_exception")

		var wrapped struct {
			Error struct {
				Type   string `json:"type"`
				Reason string `json:"reason"`
			} `json:"error"`
			Status int `json:"status"`
		}
		require.NoError(t, json.Unmarshal(body, &wrapped))
		assert.Equal(t, "security_exception", wrapped.Error.Type)
		assert.Equal(t, 401, wrapped.Status)
		assert.True(t, strings.Contains(strings.ToLower(wrapped.Error.Reason), "authentication"),
			"reason %q should mention authentication", wrapped.Error.Reason)
	})
}

func TestElasticsearchDockerTarget_NervaNoAuthFinding(t *testing.T) {
	startElasticsearchFixture(t)

	t.Run("unauth 200 emits elasticsearch-no-auth", func(t *testing.T) {
		status, body, header := getElasticsearchRoot(t, esUnauthURL)
		require.Equal(t, http.StatusOK, status)

		resp := &http.Response{
			StatusCode: status,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader(string(body))),
		}
		fp := &fingerprinters.ElasticsearchFingerprinter{}
		require.True(t, fp.Match(resp), "fingerprinter should match unauth root JSON")
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result)
		assert.Equal(t, "elasticsearch", result.Technology)

		svc := scanElasticsearchHTTP(t, esUnauthAddr)
		finding := findFinding(svc.SecurityFindings, esNoAuthID)
		if finding == nil && result != nil {
			finding = findFinding(result.SecurityFindings, esNoAuthID)
		}
		require.NotNil(t, finding, "expected %s on unauth GET /; findings=%v fingerprinter=%v",
			esNoAuthID, findingIDs(svc.SecurityFindings), findingIDs(result.SecurityFindings))
	})

	t.Run("auth 401 does not emit elasticsearch-no-auth", func(t *testing.T) {
		status, body, header := getElasticsearchRoot(t, esAuthURL)
		require.Equal(t, http.StatusUnauthorized, status)
		assert.Contains(t, string(body), "security_exception")

		resp := &http.Response{
			StatusCode: status,
			Header:     header,
			Body:       io.NopCloser(strings.NewReader(string(body))),
		}
		fp := &fingerprinters.ElasticsearchFingerprinter{}
		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		if result != nil {
			assert.Nil(t, findFinding(result.SecurityFindings, esNoAuthID),
				"fingerprinter must not emit %s on 401", esNoAuthID)
		}

		svc := scanElasticsearchHTTP(t, esAuthAddr)
		assert.Nil(t, findFinding(svc.SecurityFindings, esNoAuthID),
			"Nerva must not emit %s on auth-required GET /; findings=%v",
			esNoAuthID, findingIDs(svc.SecurityFindings))
	})
}

func findingIDs(findings []plugins.SecurityFinding) string {
	ids := make([]string, 0, len(findings))
	for _, f := range findings {
		ids = append(ids, f.ID)
	}
	return fmt.Sprintf("%v", ids)
}
