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

//go:build live

package fingerprinters

import (
	"io"
	"net/http"
	"testing"
	"time"
)

func checkMark(ok bool) string {
	if ok {
		return "OK"
	}
	return "WRONG TECH"
}

func TestFaviconLive(t *testing.T) {
	type target struct {
		url            string
		expectedHashes []int32
		expectedTech   string
	}

	targets := []target{
		{
			url:            "https://jenkins.io/favicon.ico",
			expectedHashes: []int32{116323821},
			expectedTech:   "jenkins",
		},
		{
			url:            "https://grafana.com/favicon.ico",
			expectedHashes: []int32{1485257654},
			expectedTech:   "grafana",
		},
		{
			url:            "https://gitlab.com/favicon.ico",
			expectedHashes: []int32{988422585, 81586312},
			expectedTech:   "gitlab",
		},
		{
			url:            "https://www.phpmyadmin.net/favicon.ico",
			expectedHashes: []int32{-1182381299},
			expectedTech:   "phpmyadmin",
		},
		{
			url:            "https://roundcube.net/favicon.ico",
			expectedHashes: []int32{1640738920},
			expectedTech:   "roundcube",
		},
	}

	client := &http.Client{
		Timeout: 15 * time.Second,
	}

	matched := 0
	mismatched := 0
	failed := 0

	t.Log("=== Live Favicon Hash Validation ===")

	for _, tgt := range targets {
		resp, err := client.Get(tgt.url)
		if err != nil {
			t.Logf("SKIP %s: fetch error: %v", tgt.url, err)
			failed++
			continue
		}
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			t.Logf("SKIP %s: non-200 status %d", tgt.url, resp.StatusCode)
			failed++
			continue
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Logf("SKIP %s: read error: %v", tgt.url, err)
			failed++
			continue
		}

		hash := faviconMMH3Hash(body)
		tech, inTable := faviconHashes[hash]

		matchedExpected := false
		for _, eh := range tgt.expectedHashes {
			if hash == eh {
				matchedExpected = true
				break
			}
		}

		t.Logf("URL: %s", tgt.url)
		t.Logf("  bytes fetched:     %d", len(body))
		t.Logf("  computed hash:     %d", hash)
		t.Logf("  expected hash(es): %v", tgt.expectedHashes)
		t.Logf("  matched expected:  %v", matchedExpected)
		t.Logf("  in table:          %v (tech=%q)", inTable, tech)
		t.Log("")

		if matchedExpected {
			matched++
		} else {
			mismatched++
		}
	}

	t.Log("=== Summary ===")
	t.Logf("  matched:    %d", matched)
	t.Logf("  mismatched: %d", mismatched)
	t.Logf("  failed:     %d", failed)
	t.Log("")

	t.Log("=== Hash Table Verification ===")
	type tableCheck struct {
		hash         int32
		expectedTech string
	}
	checks := []tableCheck{
		{116323821, "jenkins"},
		{1485257654, "grafana"},
		{988422585, "gitlab"},
		{81586312, "gitlab"},
		{-1182381299, "phpmyadmin"},
		{1640738920, "roundcube"},
	}
	for _, c := range checks {
		actualTech, ok := faviconHashes[c.hash]
		correct := ok && actualTech == c.expectedTech
		t.Logf("  hash %d -> expected=%q actual=%q [%s]",
			c.hash, c.expectedTech, actualTech, checkMark(correct))
	}
}
