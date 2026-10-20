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

package pluginutils

import "crypto/tls"

// ScannerTLSConfig is Nerva's scanner TLS client policy: skip verify, TLS 1.0+,
// and both secure and insecure cipher suites. Callers that need a hostname
// should clone and set ServerName.
func ScannerTLSConfig() tls.Config {
	suites := make([]uint16, 0, len(tls.CipherSuites())+len(tls.InsecureCipherSuites()))
	for _, s := range tls.CipherSuites() {
		suites = append(suites, s.ID)
	}
	for _, s := range tls.InsecureCipherSuites() {
		suites = append(suites, s.ID)
	}
	return tls.Config{
		InsecureSkipVerify: true, //nolint:gosec
		CipherSuites:       suites,
		MinVersion:         tls.VersionTLS10,
		Renegotiation:      tls.RenegotiateFreelyAsClient,
	}
}
