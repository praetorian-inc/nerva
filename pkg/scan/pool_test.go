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
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/praetorian-inc/nerva/pkg/plugins"
)

// makeTargets generates n targets with IP 127.0.0.1 and sequential ports starting at 1.
func makeTargets(n int) []plugins.Target {
	ip := netip.MustParseAddr("127.0.0.1")
	targets := make([]plugins.Target, n)
	for i := range targets {
		targets[i] = plugins.Target{
			Address: netip.AddrPortFrom(ip, uint16(i+1)),
		}
	}
	return targets
}

// TestScanPool_BasicParallel verifies that multiple workers scan targets concurrently.
func TestScanPool_BasicParallel(t *testing.T) {
	t.Parallel()

	var peakConcurrency int64
	var currentConcurrency int64

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		cur := atomic.AddInt64(&currentConcurrency, 1)
		defer atomic.AddInt64(&currentConcurrency, -1)

		for {
			peak := atomic.LoadInt64(&peakConcurrency)
			if cur <= peak {
				break
			}
			if atomic.CompareAndSwapInt64(&peakConcurrency, peak, cur) {
				break
			}
		}

		time.Sleep(50 * time.Millisecond)
		return []plugins.Service{{IP: target.Address.Addr().String(), Port: int(target.Address.Port())}}, nil
	}

	pool := NewScanPool(Config{Workers: 10})
	targets := makeTargets(20)

	results, err := pool.Run(context.Background(), targets, fn)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(results) != 20 {
		t.Errorf("expected 20 results, got %d", len(results))
	}
	if peakConcurrency <= 1 {
		t.Errorf("expected peak concurrency > 1 (parallelism), got %d", peakConcurrency)
	}
}

// TestScanPool_SequentialWithOneWorker verifies that a single-worker pool processes
// targets sequentially (peak concurrency == 1), preserving backward compatibility.
func TestScanPool_SequentialWithOneWorker(t *testing.T) {
	t.Parallel()

	var peakConcurrency int64
	var currentConcurrency int64

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		cur := atomic.AddInt64(&currentConcurrency, 1)
		defer atomic.AddInt64(&currentConcurrency, -1)

		for {
			peak := atomic.LoadInt64(&peakConcurrency)
			if cur <= peak {
				break
			}
			if atomic.CompareAndSwapInt64(&peakConcurrency, peak, cur) {
				break
			}
		}

		time.Sleep(5 * time.Millisecond)
		return []plugins.Service{{IP: target.Address.Addr().String(), Port: int(target.Address.Port())}}, nil
	}

	pool := NewScanPool(Config{Workers: 1})
	targets := makeTargets(5)

	_, err := pool.Run(context.Background(), targets, fn)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if peakConcurrency != 1 {
		t.Errorf("expected peak concurrency == 1 with single worker, got %d", peakConcurrency)
	}
}

// TestScanPool_ContinueOnError verifies that scan errors for individual targets do not
// abort the whole run — the pool continues processing remaining targets.
func TestScanPool_ContinueOnError(t *testing.T) {
	t.Parallel()

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		// Even ports fail, odd ports succeed.
		if target.Address.Port()%2 == 0 {
			return nil, errors.New("simulated scan error")
		}
		return []plugins.Service{{IP: target.Address.Addr().String(), Port: int(target.Address.Port())}}, nil
	}

	pool := NewScanPool(Config{Workers: 5})
	targets := makeTargets(10)

	results, err := pool.Run(context.Background(), targets, fn)

	if err != nil {
		t.Fatalf("expected no top-level error, got: %v", err)
	}
	// Ports 1,3,5,7,9 succeed → expect 5 results.
	if len(results) == 0 {
		t.Error("expected some results from successful (odd-port) targets, got none")
	}
}

// TestScanPool_EmptyTargets verifies that an empty target list returns nil, nil without panic.
func TestScanPool_EmptyTargets(t *testing.T) {
	t.Parallel()

	pool := NewScanPool(Config{Workers: 5})

	results, err := pool.Run(context.Background(), nil, func(plugins.Target) ([]plugins.Service, error) {
		return nil, nil
	})

	if err != nil {
		t.Fatalf("expected nil error for empty targets, got: %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results for empty targets, got: %v", results)
	}
}

// TestHostLimiter_BasicAcquireRelease verifies that Acquire increments ActiveCount and
// the returned release function decrements it correctly.
func TestHostLimiter_BasicAcquireRelease(t *testing.T) {
	t.Parallel()

	limiter := NewHostLimiter(2)
	ctx := context.Background()

	release1, err := limiter.Acquire(ctx, "host1")
	if err != nil {
		t.Fatalf("first Acquire failed: %v", err)
	}
	if got := limiter.ActiveCount("host1"); got != 1 {
		t.Errorf("after 1st acquire: expected ActiveCount==1, got %d", got)
	}

	release2, err := limiter.Acquire(ctx, "host1")
	if err != nil {
		t.Fatalf("second Acquire failed: %v", err)
	}
	if got := limiter.ActiveCount("host1"); got != 2 {
		t.Errorf("after 2nd acquire: expected ActiveCount==2, got %d", got)
	}

	release1()
	if got := limiter.ActiveCount("host1"); got != 1 {
		t.Errorf("after release1: expected ActiveCount==1, got %d", got)
	}

	release2()
	if got := limiter.ActiveCount("host1"); got != 0 {
		t.Errorf("after release2: expected ActiveCount==0, got %d", got)
	}
}

// TestHostLimiter_EnforcesConcurrencyLimit verifies that the per-host limit is respected
// under concurrent goroutine pressure.
func TestHostLimiter_EnforcesConcurrencyLimit(t *testing.T) {
	t.Parallel()

	const limit = 2
	limiter := NewHostLimiter(limit)

	var peakConcurrency int64
	var currentConcurrency int64
	var done atomic.Int64

	for i := 0; i < 10; i++ {
		go func() {
			release, err := limiter.Acquire(context.Background(), "host1")
			if err != nil {
				return
			}
			defer func() {
				release()
				done.Add(1)
			}()

			cur := atomic.AddInt64(&currentConcurrency, 1)
			defer atomic.AddInt64(&currentConcurrency, -1)

			for {
				peak := atomic.LoadInt64(&peakConcurrency)
				if cur <= peak {
					break
				}
				if atomic.CompareAndSwapInt64(&peakConcurrency, peak, cur) {
					break
				}
			}

			time.Sleep(50 * time.Millisecond)
		}()
	}

	// Wait for all goroutines to finish.
	deadline := time.Now().Add(5 * time.Second)
	for done.Load() < 10 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	if peak := atomic.LoadInt64(&peakConcurrency); peak > limit {
		t.Errorf("expected peak concurrency <= %d, got %d", limit, peak)
	}
}

// TestHostLimiter_IndependentHosts verifies that separate hosts have independent semaphores:
// a limit of 1 per host still allows simultaneous acquisition on distinct hosts.
func TestHostLimiter_IndependentHosts(t *testing.T) {
	t.Parallel()

	limiter := NewHostLimiter(1)
	ctx := context.Background()

	release1, err := limiter.Acquire(ctx, "host1")
	if err != nil {
		t.Fatalf("Acquire host1 failed: %v", err)
	}
	release2, err := limiter.Acquire(ctx, "host2")
	if err != nil {
		t.Fatalf("Acquire host2 failed (should not block): %v", err)
	}

	if got := limiter.ActiveCount("host1"); got != 1 {
		t.Errorf("expected host1 ActiveCount==1, got %d", got)
	}
	if got := limiter.ActiveCount("host2"); got != 1 {
		t.Errorf("expected host2 ActiveCount==1, got %d", got)
	}

	release1()
	release2()

	if got := limiter.ActiveCount("host1"); got != 0 {
		t.Errorf("after release: expected host1 ActiveCount==0, got %d", got)
	}
	if got := limiter.ActiveCount("host2"); got != 0 {
		t.Errorf("after release: expected host2 ActiveCount==0, got %d", got)
	}
}

// TestHostLimiter_ContextCancellation verifies that Acquire returns an error when the
// context is already cancelled (slot is full and no release is coming).
func TestHostLimiter_ContextCancellation(t *testing.T) {
	t.Parallel()

	limiter := NewHostLimiter(1)

	// Fill the single slot.
	release, err := limiter.Acquire(context.Background(), "host1")
	if err != nil {
		t.Fatalf("initial Acquire failed: %v", err)
	}
	defer release()

	// Try to acquire again with an already-cancelled context.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err = limiter.Acquire(ctx, "host1")
	if err == nil {
		t.Error("expected error from Acquire with cancelled context, got nil")
	}
}

// TestScanPool_WithHostLimiter verifies that when MaxHostConn is set, the pool
// never exceeds that many concurrent scans to the same host.
func TestScanPool_WithHostLimiter(t *testing.T) {
	t.Parallel()

	const maxHostConn = 2
	var peakConcurrency int64
	var currentConcurrency int64

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		cur := atomic.AddInt64(&currentConcurrency, 1)
		defer atomic.AddInt64(&currentConcurrency, -1)

		for {
			peak := atomic.LoadInt64(&peakConcurrency)
			if cur <= peak {
				break
			}
			if atomic.CompareAndSwapInt64(&peakConcurrency, peak, cur) {
				break
			}
		}

		time.Sleep(50 * time.Millisecond)
		return []plugins.Service{{IP: target.Address.Addr().String(), Port: int(target.Address.Port())}}, nil
	}

	pool := NewScanPool(Config{
		Workers:     10,
		MaxHostConn: maxHostConn,
	})
	targets := makeTargets(20) // all targets share IP 127.0.0.1

	_, err := pool.Run(context.Background(), targets, fn)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if peak := atomic.LoadInt64(&peakConcurrency); peak > maxHostConn {
		t.Errorf("expected peak concurrency <= %d (MaxHostConn), got %d", maxHostConn, peak)
	}
}

// TestScanPool_WithRateLimiter verifies that the global rate limiter enforces a per-second
// ceiling. 5 targets at 10/s should take at least ~350ms (4 intervals × 100ms).
func TestScanPool_WithRateLimiter(t *testing.T) {
	t.Parallel()

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		return []plugins.Service{{IP: target.Address.Addr().String(), Port: int(target.Address.Port())}}, nil
	}

	pool := NewScanPool(Config{
		Workers:   10,
		RateLimit: 10.0, // 10 per second → 100ms between tokens
	})
	targets := makeTargets(5)

	start := time.Now()
	_, err := pool.Run(context.Background(), targets, fn)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// 5 targets at 10/s: first is free, then 4 × 100ms ≈ 400ms minimum.
	// We allow a generous threshold of 350ms to avoid CI flakiness.
	const minElapsed = 350 * time.Millisecond
	if elapsed < minElapsed {
		t.Errorf("expected elapsed >= %v with RateLimit=10, got %v", minElapsed, elapsed)
	}
}

// TestScanPool_GracefulShutdown verifies that cancelling the context during a run
// results in partial (not zero, not complete) results and no error.
func TestScanPool_GracefulShutdown(t *testing.T) {
	t.Parallel()

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		time.Sleep(100 * time.Millisecond)
		return []plugins.Service{{IP: target.Address.Addr().String(), Port: int(target.Address.Port())}}, nil
	}

	pool := NewScanPool(Config{Workers: 10})
	targets := makeTargets(100)

	ctx, cancel := context.WithCancel(context.Background())
	// Cancel after 150ms: enough for ~10-20 targets to complete (workers × 1.5 cycles).
	time.AfterFunc(150*time.Millisecond, cancel)

	results, err := pool.Run(ctx, targets, fn)

	if err != nil {
		t.Fatalf("expected no error after cancellation, got: %v", err)
	}
	if len(results) == 0 {
		t.Error("expected some results before context cancellation, got none")
	}
	if len(results) >= 100 {
		t.Errorf("expected partial results (< 100), got %d — cancellation did not stop the scan", len(results))
	}
}

// TestScanPool_ProgressCounters verifies that after Run completes, the sum of
// completed + failed counters equals the total number of targets processed.
func TestScanPool_ProgressCounters(t *testing.T) {
	t.Parallel()

	const total = 10
	fn := func(target plugins.Target) ([]plugins.Service, error) {
		// Odd ports succeed, even ports fail.
		if target.Address.Port()%2 != 0 {
			return []plugins.Service{{IP: target.Address.Addr().String(), Port: int(target.Address.Port())}}, nil
		}
		return nil, errors.New("simulated failure")
	}

	pool := NewScanPool(Config{Workers: 5})
	targets := makeTargets(total)

	_, err := pool.Run(context.Background(), targets, fn)
	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	completed := pool.completed.Load()
	failed := pool.failed.Load()
	if completed+failed != total {
		t.Errorf("expected completed(%d) + failed(%d) == %d, got %d",
			completed, failed, total, completed+failed)
	}
}
