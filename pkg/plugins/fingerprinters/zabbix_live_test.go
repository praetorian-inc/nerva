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

// TestZabbixFingerprinter_LiveDocker checks a local appliance container.
// It skips when that container is not running.
//
//	docker run -d --name zabbix --platform linux/amd64 -p 80:80 zabbix/zabbix-appliance
//
// Admin:zabbix redirects to zabbix.php?action=dashboard.view. admin:zabbix does not.
func TestZabbixFingerprinter_LiveDocker(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping live Docker test in short mode")
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get("http://127.0.0.1/index.php")
	if err != nil {
		t.Skipf("Zabbix not available: %v", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatal(err)
	}
	got, err := (&ZabbixFingerprinter{}).Fingerprint(resp, body)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil || got.Technology != "zabbix" {
		t.Fatalf("live Zabbix not detected: %+v", got)
	}
}
