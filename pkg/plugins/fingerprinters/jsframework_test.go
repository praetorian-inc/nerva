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

// newHTMLResp creates a minimal *http.Response with Content-Type: text/html.
func newHTMLResp() *http.Response {
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{"text/html; charset=utf-8"}},
	}
}

// newNonHTMLResp creates a *http.Response with the provided Content-Type.
func newNonHTMLResp(contentType string) *http.Response {
	return &http.Response{
		StatusCode: 200,
		Header:     http.Header{"Content-Type": []string{contentType}},
	}
}

// jsFrameworkFP returns the fingerprinter registered for the named framework.
// It panics if not found so test failures are obvious.
func jsFrameworkFP(techName string) *jsFrameworkFingerprinter {
	for i := range jsFrameworkSignatures {
		if jsFrameworkSignatures[i].techName == techName {
			return &jsFrameworkFingerprinter{sig: jsFrameworkSignatures[i]}
		}
	}
	panic("jsframework fingerprinter not found: " + techName)
}

// ---------------------------------------------------------------------------
// Match() — content-type gating
// ---------------------------------------------------------------------------

func TestJSFrameworkFingerprinter_Match_AcceptsHTML(t *testing.T) {
	fp := jsFrameworkFP("react")
	tests := []struct {
		name        string
		contentType string
		want        bool
	}{
		{"text/html", "text/html", true},
		{"text/html with charset", "text/html; charset=utf-8", true},
		{"application/json", "application/json", false},
		{"image/png", "image/png", false},
		{"empty content-type", "", false},
		{"text/plain", "text/plain", false},
		{"application/xhtml+xml", "application/xhtml+xml", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resp := newNonHTMLResp(tt.contentType)
			if tt.contentType == "" {
				resp.Header.Del("Content-Type")
			}
			assert.Equal(t, tt.want, fp.Match(resp))
		})
	}
}

// ---------------------------------------------------------------------------
// Fingerprint() — empty body and no-match cases
// ---------------------------------------------------------------------------

func TestJSFrameworkFingerprinter_Fingerprint_EmptyBody(t *testing.T) {
	for _, sig := range jsFrameworkSignatures {
		sig := sig
		t.Run(sig.techName, func(t *testing.T) {
			fp := &jsFrameworkFingerprinter{sig: sig}
			result, err := fp.Fingerprint(newHTMLResp(), []byte{})
			assert.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

func TestJSFrameworkFingerprinter_Fingerprint_GenericHTML_NoMatch(t *testing.T) {
	body := []byte(`<!DOCTYPE html>
<html>
<head><title>Plain Site</title></head>
<body><h1>Hello</h1></body>
</html>`)
	for _, sig := range jsFrameworkSignatures {
		sig := sig
		t.Run(sig.techName, func(t *testing.T) {
			fp := &jsFrameworkFingerprinter{sig: sig}
			result, err := fp.Fingerprint(newHTMLResp(), body)
			assert.NoError(t, err)
			assert.Nil(t, result)
		})
	}
}

// ---------------------------------------------------------------------------
// Per-framework positive detection tests
// ---------------------------------------------------------------------------

func TestJSFrameworkFingerprinter_Fingerprint_NextJS(t *testing.T) {
	fp := jsFrameworkFP("nextjs")
	body := []byte(`<!DOCTYPE html>
<html>
<head>
  <script id="__NEXT_DATA__" type="application/json">{"props":{}}</script>
  <link rel="preload" href="/_next/static/chunks/main.js" as="script">
</head>
<body><div id="__next"></div></body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "nextjs", result.Technology)
	assert.Contains(t, result.CPEs[0], "cpe:2.3:a:vercel:next.js:")
}

func TestJSFrameworkFingerprinter_Fingerprint_NuxtJS(t *testing.T) {
	fp := jsFrameworkFP("nuxtjs")
	body := []byte(`<!DOCTYPE html>
<html>
<head>
  <link rel="preload" href="/_nuxt/entry.mjs" as="script">
</head>
<body>
<script>window.__NUXT__={"data":{}}</script>
</body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "nuxtjs", result.Technology)
	assert.Contains(t, result.CPEs[0], "cpe:2.3:a:nuxt:nuxt.js:")
}

func TestJSFrameworkFingerprinter_Fingerprint_React_DataReactRoot(t *testing.T) {
	fp := jsFrameworkFP("react")
	body := []byte(`<!DOCTYPE html>
<html>
<body>
  <div id="root" data-reactroot="">
    <main class="App">Hello</main>
  </div>
  <script src="/static/js/main.chunk.js"></script>
</body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "react", result.Technology)
	assert.Contains(t, result.CPEs[0], "cpe:2.3:a:facebook:react:")
}

func TestJSFrameworkFingerprinter_Fingerprint_React_DevtoolsHook(t *testing.T) {
	fp := jsFrameworkFP("react")
	body := []byte(`<!DOCTYPE html>
<html>
<head><title>CRA App</title></head>
<body>
<div id="root"></div>
<script>
window.__REACT_DEVTOOLS_GLOBAL_HOOK__ = { isDisabled: true };
</script>
</body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "react", result.Technology)
}

func TestJSFrameworkFingerprinter_Fingerprint_VueJS_GlobalVar(t *testing.T) {
	fp := jsFrameworkFP("vuejs")
	body := []byte(`<!DOCTYPE html>
<html>
<body>
<div id="app"></div>
<script>
window.__VUE__ = true;
</script>
</body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "vuejs", result.Technology)
	assert.Contains(t, result.CPEs[0], "cpe:2.3:a:vuejs:vue.js:")
}

func TestJSFrameworkFingerprinter_Fingerprint_VueJS_DataVAttr(t *testing.T) {
	fp := jsFrameworkFP("vuejs")
	// Scoped CSS hash attributes (data-v-XXXXXXX) without the __VUE__ global.
	body := []byte(`<!DOCTYPE html>
<html>
<body>
<div id="app">
  <header data-v-3f6f4d2b class="header">Navigation</header>
  <main data-v-a1b2c3d4>Content</main>
</div>
</body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "vuejs", result.Technology)
}

func TestJSFrameworkFingerprinter_Fingerprint_Angular_WithVersion(t *testing.T) {
	fp := jsFrameworkFP("angular")
	body := []byte(`<!DOCTYPE html>
<html>
<body>
<app-root ng-version="17.3.5"></app-root>
<script src="main.js"></script>
</body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "angular", result.Technology)
	assert.Equal(t, "17.3.5", result.Version)
	assert.Equal(t, "cpe:2.3:a:google:angular:17.3.5:*:*:*:*:*:*:*", result.CPEs[0])
}

func TestJSFrameworkFingerprinter_Fingerprint_Angular_NoVersion(t *testing.T) {
	// ng-version attribute present but no parseable version value (e.g., empty).
	fp := jsFrameworkFP("angular")
	// Use ng-version with a non-semver value to exercise the "attribute present
	// but versionRegex does not capture" path.
	body := []byte(`<app-root ng-version=""></app-root>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "angular", result.Technology)
	assert.Equal(t, "", result.Version)
	// CPE version should default to "*"
	assert.Equal(t, "cpe:2.3:a:google:angular:*:*:*:*:*:*:*:*", result.CPEs[0])
}

func TestJSFrameworkFingerprinter_Fingerprint_Svelte_GlobalVar(t *testing.T) {
	fp := jsFrameworkFP("svelte")
	body := []byte(`<!DOCTYPE html>
<html>
<body>
<div id="svelte-app"></div>
<script>
var __svelte = {};
</script>
</body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "svelte", result.Technology)
	assert.Contains(t, result.CPEs[0], "cpe:2.3:a:svelte:svelte:")
}

func TestJSFrameworkFingerprinter_Fingerprint_Svelte_ClassAttr(t *testing.T) {
	fp := jsFrameworkFP("svelte")
	// Svelte-generated scoped class names without the __svelte global.
	body := []byte(`<!DOCTYPE html>
<html>
<body>
<nav class="nav svelte-1q2w3e4r">Menu</nav>
<main class="content svelte-abc123">Body</main>
</body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "svelte", result.Technology)
}

func TestJSFrameworkFingerprinter_Fingerprint_Shopify(t *testing.T) {
	fp := jsFrameworkFP("shopify")
	body := []byte(`<!DOCTYPE html>
<html>
<head>
  <script>var Shopify = Shopify || {};
  Shopify.shop = "my-store.myshopify.com";</script>
  <link rel="stylesheet" href="https://cdn.shopify.com/s/files/1/0123/theme.css">
</head>
<body><div id="shopify-section-header"></div></body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "shopify", result.Technology)
	assert.Contains(t, result.CPEs[0], "cpe:2.3:a:shopify:shopify:")
}

func TestJSFrameworkFingerprinter_Fingerprint_GTM(t *testing.T) {
	fp := jsFrameworkFP("google-tag-manager")
	body := []byte(`<!DOCTYPE html>
<html>
<head>
<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':
new Date().getTime(),event:'gtm.js'});var f=d.getElementsByTagName(s)[0],
j=d.createElement(s),dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src=
'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);
})(window,document,'script','dataLayer','GTM-XXXX');</script>
</head>
<body>
<script>dataLayer.push({'event': 'pageview'});</script>
</body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "google-tag-manager", result.Technology)
	// GTM has no CPE
	assert.Empty(t, result.CPEs)
}

// ---------------------------------------------------------------------------
// False-positive boundary tests
// ---------------------------------------------------------------------------

func TestJSFrameworkFingerprinter_FalsePositive_PlainTextMentioningReact(t *testing.T) {
	fp := jsFrameworkFP("react")
	// Prose that mentions "react" and "vue" without the exact signal patterns.
	body := []byte(`<!DOCTYPE html>
<html>
<body>
<p>We use react and vue at this company for our projects.</p>
<p>The data-reactive pattern is fundamental to modern UI development.</p>
</body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	assert.NoError(t, err)
	assert.Nil(t, result, "plain text mentioning 'react' should not match — exact signals required")
}

func TestJSFrameworkFingerprinter_FalsePositive_PlainTextMentioningVue(t *testing.T) {
	fp := jsFrameworkFP("vuejs")
	// "vue" in text, no __VUE__ global or data-v- attributes.
	body := []byte(`<!DOCTYPE html>
<html>
<body>
<p>This page discusses vue philosophy and reactive patterns.</p>
</body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	assert.NoError(t, err)
	assert.Nil(t, result, "plain text mentioning 'vue' should not match")
}

func TestJSFrameworkFingerprinter_FalsePositive_VueDataAttr_WrongLength(t *testing.T) {
	fp := jsFrameworkFP("vuejs")
	// data-v- attribute with 6 hex chars (too short) and 9 hex chars (too long).
	body := []byte(`<div data-v-abc123 class="foo"></div><div data-v-abc123456 class="bar"></div>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	assert.NoError(t, err)
	assert.Nil(t, result, "data-v- with wrong hex length should not match Vue")
}

func TestJSFrameworkFingerprinter_FalsePositive_AngularNgVersionAbsent(t *testing.T) {
	fp := jsFrameworkFP("angular")
	// An AngularJS 1.x app that does not use ng-version (introduced in Angular 2+).
	body := []byte(`<!DOCTYPE html>
<html ng-app="myApp">
<body ng-controller="MainCtrl">
<h1 ng-bind="title"></h1>
</body>
</html>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	assert.NoError(t, err)
	assert.Nil(t, result, "AngularJS 1.x without ng-version attribute should not match Angular 2+")
}

func TestJSFrameworkFingerprinter_FalsePositive_SvelteClassName_WrongPattern(t *testing.T) {
	fp := jsFrameworkFP("svelte")
	// Class names that contain "svelte" but do not match the scoped pattern.
	body := []byte(`<div class="svelte-framework-comparison"></div>`)

	result, err := fp.Fingerprint(newHTMLResp(), body)

	assert.NoError(t, err)
	assert.Nil(t, result, "class name containing 'svelte' without scoped hash should not match")
}

func TestJSFrameworkFingerprinter_FalsePositive_GTM_DataLayerOnly(t *testing.T) {
	fp := jsFrameworkFP("google-tag-manager")
	body := []byte(`<script>window.dataLayer = window.dataLayer || []; dataLayer.push({'event': 'pageview'});</script>`)
	result, err := fp.Fingerprint(newHTMLResp(), body)
	assert.NoError(t, err)
	assert.Nil(t, result, "dataLayer.push alone (GA4 without GTM) should not match")
}

// ---------------------------------------------------------------------------
// CPE format verification
// ---------------------------------------------------------------------------

func TestBuildJSFrameworkCPE_WithVersion(t *testing.T) {
	cpe := buildJSFrameworkCPE("google", "angular", "17.3.5")
	assert.Equal(t, "cpe:2.3:a:google:angular:17.3.5:*:*:*:*:*:*:*", cpe)
}

func TestBuildJSFrameworkCPE_NoVersion(t *testing.T) {
	cpe := buildJSFrameworkCPE("vercel", "next.js", "")
	assert.Equal(t, "cpe:2.3:a:vercel:next.js:*:*:*:*:*:*:*:*", cpe)
}

// ---------------------------------------------------------------------------
// Name() uniqueness and stability
// ---------------------------------------------------------------------------

func TestJSFrameworkFingerprinter_Names_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := range jsFrameworkSignatures {
		fp := &jsFrameworkFingerprinter{sig: jsFrameworkSignatures[i]}
		name := fp.Name()
		assert.False(t, seen[name], "duplicate fingerprinter name: %s", name)
		seen[name] = true
	}
}

// ---------------------------------------------------------------------------
// Multiple-signal: any one signal suffices
// ---------------------------------------------------------------------------

func TestJSFrameworkFingerprinter_NextJS_SingleSignal(t *testing.T) {
	fp := jsFrameworkFP("nextjs")

	// Only the second byte signal, not the first.
	body := []byte(`<link rel="preload" href="/_next/static/css/app.css" as="style">`)
	result, err := fp.Fingerprint(newHTMLResp(), body)
	require.NoError(t, err)
	assert.NotNil(t, result, "single /_next/static signal should match Next.js")

	// Only the first byte signal.
	body2 := []byte(`<script id="__NEXT_DATA__" type="application/json">{}</script>`)
	result2, err2 := fp.Fingerprint(newHTMLResp(), body2)
	require.NoError(t, err2)
	assert.NotNil(t, result2, "single __NEXT_DATA__ signal should match Next.js")
}

func TestJSFrameworkFingerprinter_React_DataReactID(t *testing.T) {
	fp := jsFrameworkFP("react")
	// data-reactid signal only (legacy React pre-16).
	body := []byte(`<div data-reactid=".0">content</div>`)
	result, err := fp.Fingerprint(newHTMLResp(), body)
	require.NoError(t, err)
	assert.NotNil(t, result, "data-reactid should match React")
}
