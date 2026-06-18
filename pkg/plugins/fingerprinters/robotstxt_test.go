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

func TestRobotsTxtFingerprinter_Name(t *testing.T) {
	fp := &RobotsTxtFingerprinter{}
	assert.Equal(t, "robotstxt", fp.Name())
}

func TestRobotsTxtFingerprinter_ProbeEndpoint(t *testing.T) {
	fp := &RobotsTxtFingerprinter{}
	assert.Equal(t, "/robots.txt", fp.ProbeEndpoint())
}

func TestRobotsTxtFingerprinter_ProbeAccept(t *testing.T) {
	fp := &RobotsTxtFingerprinter{}
	assert.Equal(t, "text/plain", fp.ProbeAccept())
}

func TestRobotsTxtFingerprinter_Match(t *testing.T) {
	tests := []struct {
		name        string
		statusCode  int
		contentType string
		expected    bool
	}{
		{
			name:        "200 with text/plain",
			statusCode:  200,
			contentType: "text/plain",
			expected:    true,
		},
		{
			name:        "200 with text/plain; charset=utf-8",
			statusCode:  200,
			contentType: "text/plain; charset=utf-8",
			expected:    true,
		},
		{
			name:        "200 with text/html",
			statusCode:  200,
			contentType: "text/html",
			expected:    true,
		},
		{
			name:        "404",
			statusCode:  404,
			contentType: "text/plain",
			expected:    false,
		},
		{
			name:        "200 with application/json",
			statusCode:  200,
			contentType: "application/json",
			expected:    false,
		},
		{
			name:        "200 with no content-type",
			statusCode:  200,
			contentType: "",
			expected:    false,
		},
		{
			name:        "200 with TEXT/PLAIN uppercase",
			statusCode:  200,
			contentType: "TEXT/PLAIN",
			expected:    true,
		},
		{
			name:        "200 with Text/Html mixed case",
			statusCode:  200,
			contentType: "Text/Html; charset=UTF-8",
			expected:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fp := &RobotsTxtFingerprinter{}
			resp := &http.Response{
				StatusCode: tt.statusCode,
				Header:     http.Header{},
			}
			if tt.contentType != "" {
				resp.Header.Set("Content-Type", tt.contentType)
			}
			assert.Equal(t, tt.expected, fp.Match(resp))
		})
	}
}

func TestRobotsTxtFingerprinter_Fingerprint_WordPress(t *testing.T) {
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}

	body := []byte(`User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Disallow: /wp-includes/
Disallow: /wp-content/plugins/
Disallow: /wp-content/uploads/
Sitemap: https://example.com/sitemap.xml
`)

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "wordpress", result.Technology)
}

func TestRobotsTxtFingerprinter_Fingerprint_Joomla(t *testing.T) {
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}

	body := []byte(`User-agent: *
Disallow: /administrator/
Disallow: /bin/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /libraries/
Disallow: /logs/
Disallow: /modules/
Disallow: /plugins/
Disallow: /templates/
Disallow: /tmp/
`)

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "joomla", result.Technology)
}

func TestRobotsTxtFingerprinter_Fingerprint_Drupal(t *testing.T) {
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}

	body := []byte(`User-agent: *
Disallow: /core/
Disallow: /profiles/
Disallow: /modules/
Disallow: /sites/default/files/
Sitemap: https://example.com/sitemap.xml
`)

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "drupal", result.Technology)
}

func TestRobotsTxtFingerprinter_Fingerprint_Ghost(t *testing.T) {
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}

	body := []byte(`User-agent: *
Disallow: /ghost/
Disallow: /p/
Disallow: /email/
Sitemap: https://example.com/sitemap.xml
`)

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "ghost", result.Technology)
}

func TestRobotsTxtFingerprinter_Fingerprint_Umbraco(t *testing.T) {
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}

	body := []byte(`User-agent: *
Disallow: /umbraco/
Disallow: /umbraco_client/
`)

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "umbraco", result.Technology)
}

func TestRobotsTxtFingerprinter_Fingerprint_Generic_NoMatch(t *testing.T) {
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}

	// Generic robots.txt with only Disallow: / should not match any technology
	body := []byte(`User-agent: *
Disallow: /
`)

	result, err := fp.Fingerprint(resp, body)

	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestRobotsTxtFingerprinter_Fingerprint_EmptyBody(t *testing.T) {
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}

	result, err := fp.Fingerprint(resp, []byte{})

	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestRobotsTxtFingerprinter_Fingerprint_NonRobotsContent(t *testing.T) {
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}

	// HTML page that doesn't contain robots.txt directives
	body := []byte(`<!DOCTYPE html>
<html>
<head><title>Example</title></head>
<body><p>Hello World</p></body>
</html>
`)

	result, err := fp.Fingerprint(resp, body)

	assert.NoError(t, err)
	assert.Nil(t, result)
}

func TestRobotsTxtFingerprinter_Fingerprint_MultipleMatches(t *testing.T) {
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}

	// Content that matches both WordPress and Umbraco paths
	// (contrived but tests the other_detections metadata behavior)
	body := []byte(`User-agent: *
Disallow: /wp-admin/
Disallow: /wp-includes/
Disallow: /umbraco/
`)

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result)
	// Primary match should be set
	assert.NotEmpty(t, result.Technology)
	// Secondary matches in metadata
	if others, ok := result.Metadata["other_detections"]; ok {
		otherSlice, ok := others.([]string)
		require.True(t, ok)
		assert.NotEmpty(t, otherSlice)
	}
}

func TestRobotsTxtFingerprinter_RealWorld_WordPressOrg(t *testing.T) {
	// wordpress.org actual robots.txt — minimal, only /wp-admin/ + AI bot directives
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	body := []byte(`User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Allow: /wp-admin/load-scripts.php
Allow: /wp-admin/load-styles.php

User-agent: *
Disallow: /search
Disallow: /?s=

User-agent: GPTBot
Allow: /

User-agent: *
Disallow: /plugins/search/
`)
	result, err := fp.Fingerprint(resp, body)
	assert.NoError(t, err)
	// Only 1 wp- pattern (/wp-admin/) — should NOT match with threshold 2
	assert.Nil(t, result, "wordpress.org minimal robots.txt should not match — only 1 wp- signal")
}

func TestRobotsTxtFingerprinter_RealWorld_TechCrunch(t *testing.T) {
	// techcrunch.com actual robots.txt — has /wp-admin/ + /wp-json/
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	body := []byte(`User-agent: *
Disallow: /wp-admin/
Disallow: /wp-json/
Allow: /wp-admin/admin-ajax.php
Disallow: /search/
Disallow: /?s=
Disallow: /*?customize_changeset_uuid=*
Sitemap: https://techcrunch.com/sitemap.xml
`)
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result, "techcrunch.com robots.txt should match wordpress (wp-admin + wp-json)")
	assert.Equal(t, "wordpress", result.Technology)
}

func TestRobotsTxtFingerprinter_RealWorld_JoomlaOrg(t *testing.T) {
	// joomla.org actual robots.txt
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	body := []byte(`User-agent: *
Allow: /*.js***************
Allow: /*.css**************
Disallow: /administrator/
Disallow: /cache/
Disallow: /cli/
Disallow: /components/
Disallow: /includes/
Disallow: /installation/
Disallow: /language/
Disallow: /libraries/
Disallow: /modules/
Disallow: /plugins/
Disallow: /templates/
Disallow: /tmp/
Sitemap: https://www.joomla.org/sitemap
`)
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "joomla", result.Technology)
}

func TestRobotsTxtFingerprinter_RealWorld_DrupalOrg(t *testing.T) {
	// drupal.org actual robots.txt (abbreviated to key patterns)
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	body := []byte(`User-agent: *
Crawl-delay: 10
Disallow: /includes/
Disallow: /misc/
Disallow: /modules/
Disallow: /profiles/
Disallow: /scripts/
Disallow: /themes/
Disallow: /CHANGELOG.txt
Disallow: /cron.php
Disallow: /INSTALL.mysql.txt
Disallow: /install.php
Disallow: /INSTALL.txt
Disallow: /LICENSE.txt
Disallow: /update.php
Disallow: /xmlrpc.php
Disallow: /admin/
Disallow: /comment/reply/
Disallow: /filter/tips/
Disallow: /node/add/
Disallow: /search/
Disallow: /user/register/
Disallow: /user/password/
Disallow: /user/login/
Disallow: /?q=admin/
Disallow: /?q=search/
`)
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "drupal", result.Technology)
}

func TestRobotsTxtFingerprinter_RealWorld_GhostOrg(t *testing.T) {
	// ghost.org actual robots.txt — does NOT contain /ghost/
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	body := []byte(`Sitemap: https://ghost.org/sitemap.xml
User-agent: *
Allow: /
Disallow: /explore/?*sortBy
Disallow: /explore/?*lang
Disallow: /explore/?*query
`)
	result, err := fp.Fingerprint(resp, body)
	assert.NoError(t, err)
	// Ghost's own site doesn't expose /ghost/ in robots.txt — expected false negative
	assert.Nil(t, result, "ghost.org robots.txt lacks /ghost/ path — expected miss")
}

func TestRobotsTxtFingerprinter_FalsePositive_AdminPaths(t *testing.T) {
	// A generic site with /admin/ and /static/ but NOT Django's sitemap pattern
	// Should NOT match Django (requires all 3: /admin/ + /static/ + sitemap:*/sitemap.xml)
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	body := []byte(`User-agent: *
Disallow: /admin/
Disallow: /static/
Disallow: /private/
`)
	result, err := fp.Fingerprint(resp, body)
	assert.NoError(t, err)
	assert.Nil(t, result, "generic /admin/ + /static/ should not match Django without sitemap")
}

func TestRobotsTxtFingerprinter_FalsePositive_ModulesPath(t *testing.T) {
	// A Node.js app with /modules/ and /storage/ paths — could look like Drupal or Laravel
	// Should NOT match Drupal (need 2 of: /core/, /profiles/, /modules/, /sites/default/files/, /misc/, /includes/, .php files)
	// /modules/ alone is only 1 match
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	body := []byte(`User-agent: *
Disallow: /modules/
Disallow: /storage/
Disallow: /api/
Disallow: /internal/
`)
	result, err := fp.Fingerprint(resp, body)
	assert.NoError(t, err)
	// /modules/ matches 1 Drupal pattern, /storage/ matches 1 Laravel pattern — neither hits threshold
	assert.Nil(t, result, "single /modules/ should not trigger Drupal, single /storage/ should not trigger Laravel")
}

func TestRobotsTxtFingerprinter_FalsePositive_CatalogCheckout(t *testing.T) {
	// An e-commerce site with /catalog/ and /checkout/ that's NOT Magento
	// With threshold 2, this WILL match Magento — but these paths are strongly Magento-associated
	// This test documents the known false-positive surface
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	body := []byte(`User-agent: *
Disallow: /catalog/
Disallow: /checkout/
Disallow: /cart/
`)
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	// This IS a known false-positive surface — /catalog/ + /checkout/ triggers Magento
	// Documenting rather than preventing: these paths are strongly associated with Magento
	require.NotNil(t, result, "known FP surface: /catalog/ + /checkout/ triggers Magento at threshold 2")
	assert.Equal(t, "magento", result.Technology)
}

func TestRobotsTxtFingerprinter_FalsePositive_ReverseProxyWPPaths(t *testing.T) {
	// A reverse proxy that blocks wp- paths as a security measure, not actually WordPress
	// With /wp-admin/ + /wp-content/ it hits threshold 2 — documents this FP surface
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	body := []byte(`User-agent: *
Disallow: /wp-admin/
Disallow: /wp-content/
Disallow: /wp-includes/
Disallow: /wp-json/
Disallow: /xmlrpc.php
`)
	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	// A reverse proxy blocking wp- paths is indistinguishable from WordPress itself
	// This is an accepted false-positive surface — the paths ARE WordPress-specific
	require.NotNil(t, result)
	assert.Equal(t, "wordpress", result.Technology)
}

func TestRobotsTxtFingerprinter_FalsePositive_DjangoSitemap(t *testing.T) {
	// Any site with /admin/, /static/, and a sitemap URL triggers Django detection.
	// This is a known false-positive surface — the 3-signal threshold is the strongest
	// we can require without missing real Django sites.
	fp := &RobotsTxtFingerprinter{}
	resp := &http.Response{StatusCode: 200, Header: http.Header{}}
	body := []byte("User-agent: *\nDisallow: /admin/\nDisallow: /static/\nSitemap: https://example.com/sitemap.xml\n")

	result, err := fp.Fingerprint(resp, body)

	require.NoError(t, err)
	require.NotNil(t, result, "known FP surface: /admin/ + /static/ + sitemap triggers Django")
	assert.Equal(t, "django", result.Technology)
}
