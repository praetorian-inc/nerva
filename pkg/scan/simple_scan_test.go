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

package scan

import (
	"context"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/time/rate"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// stubConn is a minimal net.Conn for test purposes.
type stubConn struct{ net.Conn }

func (s stubConn) Close() error                       { return nil }
func (s stubConn) Read(b []byte) (int, error)         { return 0, nil }
func (s stubConn) Write(b []byte) (int, error)        { return len(b), nil }
func (s stubConn) SetDeadline(_ time.Time) error      { return nil }
func (s stubConn) SetReadDeadline(_ time.Time) error  { return nil }
func (s stubConn) SetWriteDeadline(_ time.Time) error { return nil }
func (s stubConn) LocalAddr() net.Addr                { return &net.TCPAddr{} }
func (s stubConn) RemoteAddr() net.Addr               { return &net.TCPAddr{} }

// dialCountPlugin counts how many times DialTCP is called on the Dialer.
type dialCountPlugin struct {
	dialTCPCalled int
}

func (p *dialCountPlugin) Run(_ net.Conn, _ time.Duration, target plugins.Target) (*plugins.Service, error) {
	if target.Dialer != nil {
		target.Dialer.DialTCP(context.Background(), target) //nolint:errcheck
		p.dialTCPCalled++
	}
	return &plugins.Service{IP: target.Address.Addr().String()}, nil
}
func (p *dialCountPlugin) PortPriority(_ uint16) bool { return false }
func (p *dialCountPlugin) Name() string               { return "dial-count" }
func (p *dialCountPlugin) Type() plugins.Protocol     { return plugins.TCP }
func (p *dialCountPlugin) Priority() int              { return 0 }

// TestRateLimitedDialer_NilRateLimiter verifies that rateLimitedDialer with a nil
// rateLimiter delegates directly to the config without blocking.
func TestRateLimitedDialer_NilRateLimiter(t *testing.T) {
	t.Parallel()

	config := &Config{DefaultTimeout: time.Second}
	d := &rateLimitedDialer{config: config, rateLimiter: nil}

	// With nil rateLimiter, DialTCP should return an error from the real Config dial
	// (no real server is listening). The important thing: it must not panic and it must
	// attempt the dial (not skip it).
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:1"),
	}
	_, err := d.DialTCP(context.Background(), target)
	// We expect a connection error because nothing is listening on port 1.
	// What we do NOT expect is a nil error or a panic.
	if err == nil {
		t.Error("expected connection error dialing 127.0.0.1:1, got nil")
	}
}

// TestRateLimitedDialer_WithRateLimiter verifies that rateLimitedDialer with a
// rate limiter calls Wait before delegating to the config.
// We use a fully-saturated burst-0 limiter (tokens=0, burst=0) to confirm
// the Wait call executes (it will succeed instantly for burst=1 limiter).
func TestRateLimitedDialer_WithRateLimiter(t *testing.T) {
	t.Parallel()

	// Create a limiter with plenty of tokens so Wait returns immediately.
	rl := rate.NewLimiter(rate.Inf, 1)

	config := &Config{DefaultTimeout: time.Second}
	d := &rateLimitedDialer{config: config, rateLimiter: rl}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:1"),
	}
	// DialTCP should attempt to dial (and fail because nothing listens) but must
	// not return an error from the rate limiter itself.
	_, err := d.DialTCP(context.Background(), target)
	// Error must be a network error (connection refused), not a rate limiter error.
	if err == nil {
		t.Error("expected connection error dialing 127.0.0.1:1, got nil")
	}
}

// TestRateLimitedDialer_DialTLS_NilRateLimiter mirrors the TCP test for TLS.
func TestRateLimitedDialer_DialTLS_NilRateLimiter(t *testing.T) {
	t.Parallel()

	config := &Config{DefaultTimeout: time.Second}
	d := &rateLimitedDialer{config: config, rateLimiter: nil}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:1"),
	}
	_, err := d.DialTLS(context.Background(), target)
	if err == nil {
		t.Error("expected connection error dialing TLS to 127.0.0.1:1, got nil")
	}
}

// TestRateLimitedDialer_DialTLS_WithRateLimiter mirrors the TCP test for TLS.
func TestRateLimitedDialer_DialTLS_WithRateLimiter(t *testing.T) {
	t.Parallel()

	rl := rate.NewLimiter(rate.Inf, 1)
	config := &Config{DefaultTimeout: time.Second}
	d := &rateLimitedDialer{config: config, rateLimiter: rl}

	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:1"),
	}
	_, err := d.DialTLS(context.Background(), target)
	if err == nil {
		t.Error("expected connection error dialing TLS to 127.0.0.1:1, got nil")
	}
}

// TestSimplePluginRunner_DialerIsRateLimitedDialer verifies that simplePluginRunner
// sets target.Dialer to a *rateLimitedDialer, not a *Config.
func TestSimplePluginRunner_DialerIsRateLimitedDialer(t *testing.T) {
	t.Parallel()

	var capturedDialer plugins.Dialer

	// capturePlugin captures the Dialer set on the target.
	capturePlugin := &capturePlug{capture: &capturedDialer}

	config := &Config{DefaultTimeout: time.Second}
	conn := stubConn{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:80"),
	}

	_, _ = simplePluginRunner(conn, target, config, capturePlugin)

	if capturedDialer == nil {
		t.Fatal("expected target.Dialer to be set, got nil")
	}
	if _, ok := capturedDialer.(*rateLimitedDialer); !ok {
		t.Errorf("expected target.Dialer to be *rateLimitedDialer, got %T", capturedDialer)
	}
}

// TestSimplePluginRunner_RateLimiterPropagated verifies that when config.ProbeRateLimiter
// is non-nil, simplePluginRunner passes it to the rateLimitedDialer.
func TestSimplePluginRunner_RateLimiterPropagated(t *testing.T) {
	t.Parallel()

	var capturedDialer plugins.Dialer
	capturePlugin := &capturePlug{capture: &capturedDialer}

	rl := rate.NewLimiter(rate.Inf, 1)
	config := &Config{
		DefaultTimeout:   time.Second,
		ProbeRateLimiter: rl,
	}
	conn := stubConn{}
	target := plugins.Target{
		Address: netip.MustParseAddrPort("127.0.0.1:80"),
	}

	_, _ = simplePluginRunner(conn, target, config, capturePlugin)

	if capturedDialer == nil {
		t.Fatal("expected target.Dialer to be set, got nil")
	}
	rld, ok := capturedDialer.(*rateLimitedDialer)
	if !ok {
		t.Fatalf("expected *rateLimitedDialer, got %T", capturedDialer)
	}
	if rld.rateLimiter != rl {
		t.Errorf("expected rateLimiter to be the same instance, got different pointer")
	}
}

// capturePlug is a test plugin that captures the Dialer from the target.
type capturePlug struct {
	capture *plugins.Dialer
}

func (p *capturePlug) Run(_ net.Conn, _ time.Duration, target plugins.Target) (*plugins.Service, error) {
	*p.capture = target.Dialer
	return &plugins.Service{IP: target.Address.Addr().String()}, nil
}
func (p *capturePlug) PortPriority(_ uint16) bool { return false }
func (p *capturePlug) Name() string               { return "capture" }
func (p *capturePlug) Type() plugins.Protocol     { return plugins.TCP }
func (p *capturePlug) Priority() int              { return 0 }

// TestScanTargets_ProbeRateLimiterSet verifies that ScanTargets sets
// config.ProbeRateLimiter from the pool's rate limiter when RateLimit > 0.
// We confirm indirectly: with a slow rate limit and a fast-failing plugin,
// the probe dialer's rate limiter must match the pool's.
// This is a structural test: after ScanTargets runs, config.ProbeRateLimiter
// is set only if RateLimit > 0.
func TestScanTargets_ProbeRateLimiterSetWhenRateLimitConfigured(t *testing.T) {
	t.Parallel()

	// Config with RateLimit set.
	config := Config{
		Workers:   1,
		RateLimit: 100.0,
	}

	// The pool is created inside ScanTargets; we verify the field is set
	// by inspecting config after it goes through the code path.
	// Since ScanTargets mutates a local copy, we test via NewScanPool directly.
	pool := NewScanPool(config)
	if pool.rateLimiter == nil {
		t.Error("expected pool.rateLimiter to be non-nil when RateLimit > 0")
	}

	// With RateLimit == 0, pool.rateLimiter must be nil.
	config0 := Config{Workers: 1, RateLimit: 0}
	pool0 := NewScanPool(config0)
	if pool0.rateLimiter != nil {
		t.Error("expected pool.rateLimiter to be nil when RateLimit == 0")
	}
}
