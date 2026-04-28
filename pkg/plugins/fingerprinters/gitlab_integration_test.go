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

//go:build integration

package fingerprinters

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	gitlabImage = "gitlab/gitlab-ce:17.0.0-ce.0"
	gitlabPort  = "8929"
)

var gitlabContainer = fmt.Sprintf("nerva-gitlab-test-%d", os.Getpid())

func TestGitLabFingerprinter_Docker(t *testing.T) {
	if os.Getenv("NERVA_INTEGRATION") == "" {
		t.Skip("Set NERVA_INTEGRATION=1 to run Docker integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	cleanup := startGitLabContainer(t, ctx)
	defer cleanup()

	waitForGitLab(t, ctx)

	t.Run("passive detection via root page", func(t *testing.T) {
		resp, body := httpGet(t, fmt.Sprintf("http://localhost:%s/", gitlabPort))

		fp := &GitLabFingerprinter{}
		require.True(t, fp.Match(resp))

		result, err := fp.Fingerprint(resp, body)
		require.NoError(t, err)
		require.NotNil(t, result, "GitLab should be detected from root page")

		assert.Equal(t, "gitlab", result.Technology)
	})

	t.Run("active detection via API version endpoint", func(t *testing.T) {
		resp, body := httpGet(t, fmt.Sprintf("http://localhost:%s/api/v4/version", gitlabPort))

		fp := &GitLabFingerprinter{}
		if resp.StatusCode == 200 && fp.Match(resp) {
			result, err := fp.Fingerprint(resp, body)
			require.NoError(t, err)
			if result != nil {
				assert.Equal(t, "gitlab", result.Technology)
				assert.NotEmpty(t, result.Version)
				t.Logf("Detected GitLab version: %s", result.Version)
			}
		} else {
			t.Logf("API version endpoint returned status %d (auth required)", resp.StatusCode)
		}
	})
}

func startGitLabContainer(t *testing.T, ctx context.Context) func() {
	t.Helper()

	// Remove existing container if present.
	exec.CommandContext(ctx, "docker", "rm", "-f", gitlabContainer).Run() //nolint:errcheck

	cmd := exec.CommandContext(ctx, "docker", "run", "-d",
		"--name", gitlabContainer,
		"-p", gitlabPort+":80",
		"--shm-size", "256m",
		gitlabImage,
	)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "Failed to start GitLab container: %s", string(out))

	return func() {
		exec.Command("docker", "rm", "-f", gitlabContainer).Run() //nolint:errcheck
	}
}

func waitForGitLab(t *testing.T, ctx context.Context) {
	t.Helper()
	t.Log("Waiting for GitLab to become healthy (this may take several minutes)...")

	deadline := time.Now().Add(8 * time.Minute)
	client := &http.Client{Timeout: 5 * time.Second}

	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			t.Fatal("Context cancelled while waiting for GitLab")
		default:
		}

		resp, err := client.Get(fmt.Sprintf("http://localhost:%s/users/sign_in", gitlabPort))
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == 200 || resp.StatusCode == 302 {
				t.Log("GitLab is ready")
				return
			}
		}
		time.Sleep(10 * time.Second)
	}
	t.Fatal("GitLab did not become healthy within timeout")
}

func httpGet(t *testing.T, url string) (*http.Response, []byte) {
	t.Helper()
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	require.NoError(t, err)
	body, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	require.NoError(t, err)
	return resp, body
}
