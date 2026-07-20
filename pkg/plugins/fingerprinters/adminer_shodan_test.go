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

package fingerprinters

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// shodanVectors captures realistic Adminer/AdminerEvo login-page HTML as it is
// observed on real-world internet-exposed hosts (per Shodan reconnaissance
// documented in .fingerprintx-development/protocol-research.md). Each vector
// is embedded as a static fixture rather than fetched live — no Shodan API
// calls or external network requests are made by this test file.
var shodanVectors = []struct {
	name        string
	query       string            // representative Shodan query that would surface this host
	rationale   string            // why this vector is a representative test case
	body        string            // realistic HTML captured/reconstructed from a live response
	headers     map[string]string // representative response headers
	wantTech    string
	wantVersion string
	wantVariant string
	wantCPE     string
}{
	{
		// Vector 1: Standard Adminer 4.8.1 behind Apache. This is the single
		// most common Shodan hit shape for Adminer — the default single-file
		// deployment (/adminer.php) fronted by Apache, with both Signal 1
		// (title) and Signal 2 (corroborated System<td> + auth[driver] pair)
		// present, plus a version span. It is the baseline "should always
		// detect" case.
		name:      "Shodan Vector 1: Adminer 4.8.1 on Apache (single-file deployment)",
		query:     `http.title:"Login - Adminer"`,
		rationale: "Most common Shodan result shape for Adminer: default /adminer.php deployment, Apache front end, title+corroborated-pair+version all present.",
		headers: map[string]string{
			"Content-Type": "text/html; charset=utf-8",
			"Server":       "Apache/2.4.52 (Ubuntu)",
		},
		body: `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Login - Adminer</title>
<link rel="stylesheet" type="text/css" href="../adminer/static/default.css">
<link rel="shortcut icon" type="image/x-icon" href="../adminer/static/favicon.ico">
</head>
<body class="ltr nojs auth">
<div id="content">
<div id="breadcrumb"><a href="https://www.adminer.org/" id="h1">Adminer</a> <span class="version">4.8.1</span> <a href="https://www.adminer.org/#download" id="version">supported version available</a></div>
<form action="" method="post" target="_top" id="form">
<h1>Login</h1>
<table cellspacing="0" class="layout">
<tr><th>System<td><select id="auth-driver" name="auth[driver]"><option value="server">MySQL</option><option value="pgsql">PostgreSQL</option></select>
<tr><th>Server<td><input name="auth[server]" value="" title="hostname[:port]" placeholder="localhost" id="auth-server">
<tr><th>Username<td><input id="auth-username" name="auth[username]" value="" autocapitalize="off" autocomplete="username">
<tr><th>Password<td><input type="password" name="auth[password]" id="auth-password" autocomplete="current-password">
<tr><th>Database<td><input name="auth[db]" value="" autocapitalize="off">
</table>
<p><input type="submit" value="Login">
</form>
</div>
</body>
</html>`,
		wantTech:    "adminer",
		wantVersion: "4.8.1",
		wantVariant: "adminer",
		wantCPE:     "cpe:2.3:a:adminer:adminer:4.8.1:*:*:*:*:*:*:*",
	},
	{
		// Vector 2: AdminerEvo 5.1.0, the community-maintained fork. Shodan
		// distinguishes this variant by title ("Login - AdminerEvo") and the
		// adminerevo.org branding link. Confirms variant discrimination logic
		// (detectAdminerVariant) works against a realistic fork response, not
		// just the upstream project.
		name:      "Shodan Vector 2: AdminerEvo 5.1.0 (community fork) behind nginx",
		query:     `http.title:"Login - AdminerEvo"`,
		rationale: "AdminerEvo is a distinct, actively maintained fork with growing Shodan presence; verifies adminerevo.org branding drives variant=adminerevo while Technology/CPE stay adminer:adminer.",
		headers: map[string]string{
			"Content-Type": "text/html; charset=UTF-8",
			"Server":       "nginx/1.18.0 (Ubuntu)",
		},
		body: `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Login - AdminerEvo</title>
<link rel="stylesheet" type="text/css" href="../adminer/static/default.css">
</head>
<body class="ltr nojs auth">
<div id="content">
<div id="breadcrumb"><a href="https://adminerevo.org" id="h1">AdminerEvo</a> <span class="version">5.1.0</span></div>
<form action="" method="post" target="_top" id="form">
<h1>Login</h1>
<table cellspacing="0" class="layout">
<tr><th>System<td><select id="auth-driver" name="auth[driver]"><option value="server">MySQL</option><option value="sqlite">SQLite 3</option></select>
<tr><th>Server<td><input name="auth[server]" value="" title="hostname[:port]" placeholder="localhost" id="auth-server">
<tr><th>Username<td><input id="auth-username" name="auth[username]" value="" autocapitalize="off">
<tr><th>Password<td><input type="password" name="auth[password]" id="auth-password">
</table>
<p><input type="submit" value="Login">
</form>
<div id="footer"><a href="https://adminerevo.org">AdminerEvo</a></div>
</div>
</body>
</html>`,
		wantTech:    "adminer",
		wantVersion: "5.1.0",
		wantVariant: "adminerevo",
		wantCPE:     "cpe:2.3:a:adminerevo:adminerevo:5.1.0:*:*:*:*:*:*:*",
	},
	{
		// Vector 3: Adminer 4.7.8 — the last version before CVE-2021-21311
		// (unauthenticated SSRF via the Elasticsearch driver's login form,
		// CISA KEV-listed) was patched in 4.7.9. Detecting and version-pinning
		// this exact release is the highest-value case for this fingerprinter:
		// it flags internet-exposed hosts still vulnerable to a KEV entry.
		name:      "Shodan Vector 3: Adminer 4.7.8 (pre-CVE-2021-21311 fix, critical detection target)",
		query:     `http.title:"Login - Adminer" html:"span class=\"version\">4.7.8"`,
		rationale: "4.7.8 is the last version vulnerable to CVE-2021-21311 (CISA KEV SSRF). Accurate version extraction on this exact release is required to flag hosts needing urgent patching.",
		headers: map[string]string{
			"Content-Type": "text/html",
			"Server":       "Apache/2.4.29 (Ubuntu)",
		},
		body: `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Login - Adminer</title>
<link rel="stylesheet" type="text/css" href="../adminer/static/default.css">
</head>
<body class="ltr nojs auth">
<div id="content">
<div id="breadcrumb"><a href="https://www.adminer.org/" id="h1">Adminer</a> <span class="version">4.7.8</span></div>
<form action="" method="post" target="_top" id="form">
<h1>Login</h1>
<table cellspacing="0" class="layout">
<tr><th>System<td><select id="auth-driver" name="auth[driver]"><option value="server">MySQL</option><option value="elastic">Elasticsearch</option></select>
<tr><th>Server<td><input name="auth[server]" value="" title="hostname[:port]" placeholder="localhost" id="auth-server">
<tr><th>Username<td><input id="auth-username" name="auth[username]" value="" autocapitalize="off">
<tr><th>Password<td><input type="password" name="auth[password]" id="auth-password">
</table>
<p><input type="submit" value="Login">
</form>
</div>
</body>
</html>`,
		wantTech:    "adminer",
		wantVersion: "4.7.8",
		wantVariant: "adminer",
		wantCPE:     "cpe:2.3:a:adminer:adminer:4.7.8:*:*:*:*:*:*:*",
	},
}

// TestAdminerFingerprinter_ShodanVectors validates AdminerFingerprinter
// against realistic HTML response fixtures representing what Shodan captures
// for real-world Adminer/AdminerEvo deployments. No Shodan API calls or
// external network requests are made; all responses are embedded fixtures.
func TestAdminerFingerprinter_ShodanVectors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Shodan validation vectors in short mode")
	}

	fp := &AdminerFingerprinter{}

	for _, tt := range shodanVectors {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tt.headers {
				h.Set(k, v)
			}
			resp := &http.Response{StatusCode: 200, Header: h}

			require.True(t, fp.Match(resp), "Match() should pre-filter this Shodan response as a candidate: %s", tt.rationale)

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result, "Fingerprint() should detect Shodan vector: %s (%s)", tt.name, tt.rationale)

			assert.Equal(t, tt.wantTech, result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			assert.Equal(t, tt.wantVariant, result.Metadata["variant"])
			assert.Contains(t, result.CPEs, tt.wantCPE)
		})
	}
}

// TestAdminerDirFingerprinter_ShodanVectors confirms the directory-deployment
// variant (/adminer/) shares identical detection behavior against the same
// Shodan-representative fixtures, since both fingerprinters call the shared
// fingerprintAdminer logic.
func TestAdminerDirFingerprinter_ShodanVectors(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping Shodan validation vectors in short mode")
	}

	fp := &AdminerDirFingerprinter{}

	for _, tt := range shodanVectors {
		t.Run(tt.name, func(t *testing.T) {
			h := http.Header{}
			for k, v := range tt.headers {
				h.Set(k, v)
			}
			resp := &http.Response{StatusCode: 200, Header: h}

			result, err := fp.Fingerprint(resp, []byte(tt.body))
			require.NoError(t, err)
			require.NotNil(t, result, "Fingerprint() should detect Shodan vector: %s (%s)", tt.name, tt.rationale)

			assert.Equal(t, tt.wantTech, result.Technology)
			assert.Equal(t, tt.wantVersion, result.Version)
			assert.Equal(t, tt.wantVariant, result.Metadata["variant"])
			assert.Contains(t, result.CPEs, tt.wantCPE)
		})
	}
}
