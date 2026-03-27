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

package ssh

import (
	"strings"
	"testing"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestBuildSSHFindings(t *testing.T) {
	t.Run("no weak algorithms", func(t *testing.T) {
		algo := map[string]string{
			"KexAlgos":            "curve25519-sha256,ecdh-sha2-nistp256",
			"CiphersClientServer": "aes128-ctr,aes256-ctr",
			"CiphersServerClient": "aes128-ctr,aes256-ctr",
			"MACsClientServer":    "hmac-sha2-256,hmac-sha2-512",
			"MACsServerClient":    "hmac-sha2-256,hmac-sha2-512",
		}
		findings := buildSSHFindings(algo, false)
		if len(findings) != 0 {
			t.Errorf("expected 0 findings, got %d: %v", len(findings), findings)
		}
	})

	t.Run("weak cipher detected", func(t *testing.T) {
		algo := map[string]string{
			"KexAlgos":            "curve25519-sha256",
			"CiphersClientServer": "aes128-ctr,arcfour",
			"CiphersServerClient": "aes128-ctr",
			"MACsClientServer":    "hmac-sha2-256",
			"MACsServerClient":    "hmac-sha2-256",
		}
		findings := buildSSHFindings(algo, false)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
		}
		if findings[0].ID != "ssh-weak-cipher" {
			t.Errorf("expected ID ssh-weak-cipher, got %s", findings[0].ID)
		}
		if findings[0].Severity != plugins.SeverityLow {
			t.Errorf("expected severity low, got %s", findings[0].Severity)
		}
		if !strings.Contains(findings[0].Evidence, "arcfour") {
			t.Errorf("expected evidence to contain arcfour, got %s", findings[0].Evidence)
		}
	})

	t.Run("weak KEX detected", func(t *testing.T) {
		algo := map[string]string{
			"KexAlgos":            "curve25519-sha256,diffie-hellman-group1-sha1",
			"CiphersClientServer": "aes128-ctr",
			"CiphersServerClient": "aes128-ctr",
			"MACsClientServer":    "hmac-sha2-256",
			"MACsServerClient":    "hmac-sha2-256",
		}
		findings := buildSSHFindings(algo, false)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
		}
		if findings[0].ID != "ssh-weak-kex" {
			t.Errorf("expected ID ssh-weak-kex, got %s", findings[0].ID)
		}
		if !strings.Contains(findings[0].Evidence, "diffie-hellman-group1-sha1") {
			t.Errorf("expected evidence to contain diffie-hellman-group1-sha1, got %s", findings[0].Evidence)
		}
	})

	t.Run("weak MAC detected", func(t *testing.T) {
		algo := map[string]string{
			"KexAlgos":            "curve25519-sha256",
			"CiphersClientServer": "aes128-ctr",
			"CiphersServerClient": "aes128-ctr",
			"MACsClientServer":    "hmac-sha2-256,hmac-md5",
			"MACsServerClient":    "hmac-sha2-256",
		}
		findings := buildSSHFindings(algo, false)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
		}
		if findings[0].ID != "ssh-weak-mac" {
			t.Errorf("expected ID ssh-weak-mac, got %s", findings[0].ID)
		}
		if !strings.Contains(findings[0].Evidence, "hmac-md5") {
			t.Errorf("expected evidence to contain hmac-md5, got %s", findings[0].Evidence)
		}
	})

	t.Run("multiple weak algorithm categories", func(t *testing.T) {
		algo := map[string]string{
			"KexAlgos":            "diffie-hellman-group1-sha1,diffie-hellman-group-exchange-sha1",
			"CiphersClientServer": "3des-cbc,blowfish-cbc",
			"CiphersServerClient": "arcfour256",
			"MACsClientServer":    "hmac-md5-96,hmac-sha1-96",
			"MACsServerClient":    "hmac-md5-etm@openssh.com",
		}
		findings := buildSSHFindings(algo, false)
		if len(findings) != 3 {
			t.Fatalf("expected 3 findings, got %d: %v", len(findings), findings)
		}
		ids := make(map[string]bool)
		for _, f := range findings {
			ids[f.ID] = true
		}
		for _, expected := range []string{"ssh-weak-cipher", "ssh-weak-kex", "ssh-weak-mac"} {
			if !ids[expected] {
				t.Errorf("expected finding with ID %s", expected)
			}
		}
	})

	t.Run("deduplicates ciphers across directions", func(t *testing.T) {
		algo := map[string]string{
			"KexAlgos":            "curve25519-sha256",
			"CiphersClientServer": "arcfour",
			"CiphersServerClient": "arcfour",
			"MACsClientServer":    "hmac-sha2-256",
			"MACsServerClient":    "hmac-sha2-256",
		}
		findings := buildSSHFindings(algo, false)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d", len(findings))
		}
		// arcfour should appear only once in evidence
		count := strings.Count(findings[0].Evidence, "arcfour")
		if count != 1 {
			t.Errorf("expected arcfour once in evidence, got %d occurrences: %s", count, findings[0].Evidence)
		}
	})

	t.Run("password auth enabled", func(t *testing.T) {
		algo := map[string]string{
			"KexAlgos":            "curve25519-sha256",
			"CiphersClientServer": "aes256-gcm@openssh.com",
			"CiphersServerClient": "aes256-gcm@openssh.com",
			"MACsClientServer":    "hmac-sha2-256",
			"MACsServerClient":    "hmac-sha2-256",
		}
		findings := buildSSHFindings(algo, true)
		if len(findings) != 1 {
			t.Fatalf("expected 1 finding, got %d: %v", len(findings), findings)
		}
		if findings[0].ID != "ssh-password-auth" {
			t.Errorf("expected ID ssh-password-auth, got %s", findings[0].ID)
		}
		if findings[0].Severity != plugins.SeverityMedium {
			t.Errorf("expected severity medium, got %s", findings[0].Severity)
		}
	})

	t.Run("password auth with weak cipher", func(t *testing.T) {
		algo := map[string]string{
			"KexAlgos":            "curve25519-sha256",
			"CiphersClientServer": "arcfour",
			"CiphersServerClient": "aes256-gcm@openssh.com",
			"MACsClientServer":    "hmac-sha2-256",
			"MACsServerClient":    "hmac-sha2-256",
		}
		findings := buildSSHFindings(algo, true)
		if len(findings) != 2 {
			t.Fatalf("expected 2 findings, got %d: %v", len(findings), findings)
		}
		ids := make(map[string]bool)
		for _, f := range findings {
			ids[f.ID] = true
		}
		for _, expected := range []string{"ssh-weak-cipher", "ssh-password-auth"} {
			if !ids[expected] {
				t.Errorf("expected finding with ID %s", expected)
			}
		}
	})
}

func TestSSH(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "ssh",
			Port:        22,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "sickp/alpine-sshd",
			},
		},
	}

	p := &SSHPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Errorf("%s", err.Error())
			}
		})
	}
}
