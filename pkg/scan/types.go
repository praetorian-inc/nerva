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

package scan

import (
	"time"
)

type Config struct {
	// UDP scan
	UDP bool

	// SCTP scan (Linux only, falls back to error on other platforms)
	SCTP bool

	FastMode bool

	// The timeout specifies how long certain tasks should wait during the scanning process.
	// This may include the timeouts set on the handshake process and the time to wait for a response to return.
	DefaultTimeout time.Duration

	// Prints logging messages to stderr
	Verbose bool

	// Number of concurrent scan workers. Values <= 0 are treated as 1 (sequential).
	// The CLI defaults this to 50 via --workers.
	Workers int

	// Max concurrent connections per host IP (0 = unlimited)
	MaxHostConn int

	// Max scans per second globally (0 = unlimited)
	RateLimit float64

	// Proxy URL string (e.g. socks5://127.0.0.1:1080)
	Proxy string

	// ProxyAuth string for socks5 proxy authentication (username:password)
	ProxyAuth string

	// DNSOrder controls DNS resolution (p, l, lp, pl)
	DNSOrder string

	// Enable security misconfiguration detection
	Misconfigs bool

	OnProgress ProgressCallback
}
