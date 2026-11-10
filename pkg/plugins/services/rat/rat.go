// Copyright 2026 Praetorian Security, Inc.
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

// Package rat adds remote-access service fingerprints using protocol evidence,
// never port numbers alone. Existing detectors remain in their original packages.
package rat

import (
	"errors"
	"io"
	"net"
	"slices"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

const maxResponseBytes = 512

// Match the scanner's passive banner budget. Once a candidate starts arriving,
// retain the caller's deadline for completion. RFB greetings get a bounded idle
// window for optional server-first license failures, not a full-timeout stall.
const greetingIdleTimeout = 300 * time.Millisecond

// Plugin shares matching and result handling across the passive greeting scan
// and client-first probes. Each registration gets a fresh connection from Nerva.
// No login, authentication attempt, remote session, or UDP traversal is performed.
type Plugin struct {
	active *fingerprint
}

func init() {
	plugins.RegisterPlugin(&Plugin{})
	for i := range fingerprints {
		if fingerprints[i].probe != "" {
			plugins.RegisterPlugin(&Plugin{active: &fingerprints[i]})
		}
	}
}

func (p *Plugin) Name() string {
	if p.active != nil {
		return "rat-detector-" + p.active.product
	}
	return "rat-detector"
}
func (p *Plugin) Type() plugins.Protocol { return plugins.TCP }
func (p *Plugin) Priority() int          { return 90 } // Before the generic VNC detector.

func (p *Plugin) PortPriority(port uint16) bool {
	if p.active != nil {
		return slices.Contains(p.active.ports, port)
	}
	signature := fingerprintForPort(port)
	return signature != nil && signature.probe == ""
}

func (p *Plugin) Run(conn net.Conn, timeout time.Duration, target plugins.Target) (*plugins.Service, error) {
	if timeout <= 0 {
		return nil, nil
	}
	deadline := time.Now().Add(timeout)
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	if p.active != nil {
		_, err := io.WriteString(conn, p.active.probe)
		if err != nil {
			return nil, err
		}
	}
	return readService(conn, target, deadline, p.active == nil)
}

func readService(conn net.Conn, target plugins.Target, deadline time.Time, passive bool) (*plugins.Service, error) {
	response := make([]byte, maxResponseBytes)
	length := 0
	for length < len(response) {
		readDeadline := deadline
		if (passive && length == 0) || isRFBGreeting(response[:length]) {
			if idleDeadline := time.Now().Add(greetingIdleTimeout); idleDeadline.Before(readDeadline) {
				readDeadline = idleDeadline
			}
		}
		if err := conn.SetReadDeadline(readDeadline); err != nil {
			if errors.Is(err, net.ErrClosed) || errors.Is(err, io.ErrClosedPipe) {
				return nil, nil
			}
			return nil, err
		}
		n, err := conn.Read(response[length:])
		length += n
		if product, evidence := identifyResponse(response[:length]); product != "" {
			return createService(target, product, evidence), nil
		}
		if !mayMatchResponse(response[:length]) {
			return nil, nil
		}
		if err != nil {
			var networkError net.Error
			if errors.Is(err, io.EOF) || (errors.As(err, &networkError) && networkError.Timeout()) {
				return nil, nil
			}
			return nil, err
		}
		if n == 0 {
			return nil, io.ErrNoProgress
		}
	}
	return nil, nil
}

func createService(target plugins.Target, product, evidence string) *plugins.Service {
	return plugins.CreateServiceFrom(target, plugins.ServiceRemoteAccess{
		Product:  product,
		Evidence: evidence,
	}, false, "", plugins.TCP)
}
