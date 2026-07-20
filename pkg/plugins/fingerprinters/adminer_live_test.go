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
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAdminerFingerprinter_LiveDocker exercises AdminerFingerprinter against a
// live Adminer 4.8.1 container.
//
// Expects: docker run -d --name adminer-test -p 18080:8080 adminer:4.8.1
func TestAdminerFingerprinter_LiveDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live Docker test in short mode")
	}

	baseURL := "http://localhost:18080"

	resp, err := http.Get(baseURL + "/")
	if err != nil {
		t.Skipf("Adminer not available at %s: %v", baseURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	fp := &AdminerFingerprinter{}
	require.True(t, fp.Match(resp), "Match() should return true for a live Adminer response")

	result, err := fp.Fingerprint(resp, body)
	require.NoError(t, err)
	require.NotNil(t, result, "Fingerprint() should detect the live Adminer instance")

	assert.Equal(t, "adminer", result.Technology)
	assert.Equal(t, "4.8.1", result.Version)
	assert.Contains(t, result.CPEs, "cpe:2.3:a:adminer:adminer:4.8.1:*:*:*:*:*:*:*")
	assert.Equal(t, "adminer", result.Metadata["variant"])
	assert.NotEmpty(t, result.Metadata["detection_method"], "detection_method metadata should be present")

	t.Logf("Detected Adminer: version=%s variant=%v detection_method=%v",
		result.Version, result.Metadata["variant"], result.Metadata["detection_method"])
}
