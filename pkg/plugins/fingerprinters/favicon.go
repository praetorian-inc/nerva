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
	"encoding/base64"
	"fmt"
	"net/http"
	"strings"

	"github.com/twmb/murmur3"
)

// FaviconFingerprinter detects technologies by computing the Murmur3 hash of
// /favicon.ico and comparing it against a table of known hashes (same
// algorithm used by Shodan).
type FaviconFingerprinter struct{}

func init() {
	Register(&FaviconFingerprinter{})
}

func (f *FaviconFingerprinter) Name() string { return "favicon" }

func (f *FaviconFingerprinter) ProbeEndpoint() string { return "/favicon.ico" }

// ProbeAccept accepts any content type for favicon responses.
func (f *FaviconFingerprinter) ProbeAccept() string { return "*/*" }

func (f *FaviconFingerprinter) Match(resp *http.Response) bool {
	return resp.StatusCode == 200
}

func (f *FaviconFingerprinter) Fingerprint(resp *http.Response, body []byte) (*FingerprintResult, error) {
	if len(body) == 0 {
		return nil, nil
	}

	h := faviconMMH3Hash(body)

	tech, ok := faviconHashes[h]
	if !ok {
		return &FingerprintResult{
			Metadata: map[string]any{
				"favicon_hash": fmt.Sprintf("%d", h),
			},
		}, nil
	}

	return &FingerprintResult{
		Technology: tech,
		Metadata: map[string]any{
			"favicon_hash": fmt.Sprintf("%d", h),
		},
	}, nil
}

// faviconMMH3Hash computes the Shodan-compatible favicon hash:
// 1. Base64-encode the raw bytes using standard encoding.
// 2. Insert a newline after every 76 characters (MIME-style wrapping).
// 3. Return the signed 32-bit MurmurHash3 of the resulting string.
func faviconMMH3Hash(data []byte) int32 {
	b64 := base64.StdEncoding.EncodeToString(data)

	var sb strings.Builder
	for i := 0; i < len(b64); i += 76 {
		end := i + 76
		if end > len(b64) {
			end = len(b64)
		}
		sb.WriteString(b64[i:end])
		sb.WriteByte('\n')
	}

	h := murmur3.SeedNew32(0)
	_, _ = h.Write([]byte(sb.String()))
	return int32(h.Sum32()) // #nosec G115 -- intentional uint32→int32 reinterpretation for Shodan-compatible signed hash
}

// faviconHashes maps known Shodan favicon hashes to technology names.
var faviconHashes = map[int32]string{
	// CI / DevOps
	116323821:   "jenkins",
	-1073467747: "sonarqube",
	1279514273:  "harbor",

	// Monitoring
	1485257654:  "grafana",
	-674048714:  "kibana",
	-956533229:  "nagios",
	-316577091:  "prometheus",
	1076460449:  "zabbix",
	-1950415971: "portainer",
	-603795136:  "traefik",
	602508764:   "airflow",

	// Version control / project management
	988422585:  "gitlab",
	81586312:   "gitlab",
	-266008933: "jira",

	// Collaboration
	-2044357871: "confluence",
	1471196544:  "bitbucket",

	// Application servers / frameworks
	-928028886:  "spring-boot",
	-1293291977: "apache-tomcat",

	// Kubernetes
	2087906966: "kubernetes-dashboard",

	// CMS
	-1395125863: "wordpress",
	-880734024:  "drupal",
	1485890173:  "joomla",

	// Firewall / network appliances
	-1655029145: "pfsense",
	362091310:   "fortinet-fortigate",
	945408572:   "opnsense",
	-144494067:  "cisco-webui",
	298001061:   "mikrotik",
	-1588080585: "palo-alto-networks",

	// Storage / NAS
	735486030: "synology-dsm",
	247692498: "qnap",

	// Wireless
	-520888198: "unifi",

	// Cloud / Object storage
	1820867498:  "minio",
	1708240621:  "nextcloud",
	-1377723662: "owncloud",

	// Security / Identity
	-750029137: "keycloak",
	2032732288: "hashicorp-vault",

	// Databases / admin panels
	-1182381299: "phpmyadmin",
	-625037832:  "adminer",
	-1218642332: "elasticsearch",
	-113721813:  "rabbitmq",

	// Mail
	1640738920: "roundcube",
	-784560498: "zimbra",

	// Hosting control panels
	1993518473:  "cpanel",
	-649378830:  "whm",
	-981606721:  "plesk",
	-134375033:  "plesk",

	// System administration
	479413330:  "webmin",
	1453890729: "webmin",

	// Network security appliances
	631108382:   "sonicwall",
	1601194732:  "sophos",
	-1166125415: "citrix-netscaler",

	// Virtualization
	213144638: "proxmox-ve",
	45180380:  "vmware-esxi",

	// Wireless / networking
	1142227528: "aruba-networks",

	// Monitoring / observability
	1302486561:  "netdata",
	1585145626:  "netdata",
	-1797138069: "cacti",
	332375576:   "graylog",

	// Source code management / project tracking
	1969970750: "gitea",
	603314:     "redmine",
	662709064:  "mantis-bt",
}
