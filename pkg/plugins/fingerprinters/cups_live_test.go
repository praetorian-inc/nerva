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
	"time"
)

// TestCUPSFingerprinter_LiveDocker checks a local olbat/cupsd container.
// It skips when that container is not running.
//
//	docker run -d --name cups --platform linux/amd64 -p 631:631 olbat/cupsd
//
// GET /admin is open. GET /admin/conf challenges. print:print is 200.
func TestCUPSFingerprinter_LiveDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live Docker test in short mode")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1:631/")
	if err != nil {
		t.Skipf("CUPS not available: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&CUPSFingerprinter{}).Fingerprint(resp, body)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Technology != "cups" {
		t.Fatalf("live CUPS not detected: %+v", got)
	}
}
