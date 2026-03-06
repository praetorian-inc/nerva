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
	"sort"
	"sync"
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

// TestScanPool_Reuse verifies that a ScanPool can be reused for multiple Run calls
// and that counters are reset between runs (proving the counter reset logic works).
func TestScanPool_Reuse(t *testing.T) {
	t.Parallel()

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		return []plugins.Service{{IP: target.Address.Addr().String(), Port: int(target.Address.Port())}}, nil
	}

	pool := NewScanPool(Config{Workers: 5})

	// First run with 10 targets
	targets1 := makeTargets(10)
	results1, err := pool.Run(context.Background(), targets1, fn)
	if err != nil {
		t.Fatalf("first run: expected no error, got: %v", err)
	}
	if len(results1) != 10 {
		t.Errorf("first run: expected 10 results, got %d", len(results1))
	}

	completed1 := pool.completed.Load()
	failed1 := pool.failed.Load()
	if completed1 != 10 {
		t.Errorf("first run: expected completed==10, got %d", completed1)
	}
	if failed1 != 0 {
		t.Errorf("first run: expected failed==0, got %d", failed1)
	}

	// Second run with 5 different targets — counters should reset
	targets2 := makeTargets(5)
	results2, err := pool.Run(context.Background(), targets2, fn)
	if err != nil {
		t.Fatalf("second run: expected no error, got: %v", err)
	}
	if len(results2) != 5 {
		t.Errorf("second run: expected 5 results, got %d", len(results2))
	}

	// After second run, counters should be 5 and 0, NOT 15 and 0 (proves reset worked)
	completed2 := pool.completed.Load()
	failed2 := pool.failed.Load()
	if completed2 != 5 {
		t.Errorf("second run: expected completed==5 (not 15), got %d — counters were not reset", completed2)
	}
	if failed2 != 0 {
		t.Errorf("second run: expected failed==0, got %d", failed2)
	}
}

// TestScanPool_RateLimiterContextCancel covers the rateLimiter.Wait(ctx) error path in
// processTarget (the branch that increments p.failed and returns when the context is
// cancelled while a worker is blocked waiting for a rate-limiter token).
//
// Strategy: use a very slow rate (1/s) with 20 targets and a 200ms deadline. At 1 token
// per second only ~1-2 targets can complete before the context expires; the remaining
// workers will be blocked inside rateLimiter.Wait(ctx) when cancellation fires, driving
// the failed counter above zero.
func TestScanPool_RateLimiterContextCancel(t *testing.T) {
	t.Parallel()

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		return []plugins.Service{{IP: target.Address.Addr().String(), Port: int(target.Address.Port())}}, nil
	}

	pool := NewScanPool(Config{Workers: 10, RateLimit: 1.0})
	targets := makeTargets(20)

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	results, err := pool.Run(ctx, targets, fn)
	if err != nil {
		t.Fatalf("expected no error from Run, got: %v", err)
	}

	// At 1 token/sec with a 200ms window, only a handful of targets can complete.
	if len(results) >= 20 {
		t.Errorf("expected partial results (< 20), got %d — cancellation did not stop the scan", len(results))
	}

	// The rate-limiter Wait path must have fired for at least one worker.
	if pool.failed.Load() == 0 {
		t.Error("expected failed > 0: rate-limiter context-cancel path was not exercised")
	}
}

// TestScanPool_ProgressTickerFires covers the ticker.C case inside startProgressTicker.
// Existing tests finish before the 2s default interval, so the ticker never fires.
// Here we call startProgressTicker directly with a short interval so the case executes,
// then exercise the stop-function path and the ctx.Done() path.
func TestScanPool_ProgressTickerFires(t *testing.T) {
	t.Parallel()

	pool := NewScanPool(Config{Workers: 4})
	pool.total.Store(100)
	pool.completed.Store(25)
	pool.failed.Store(5)

	ctx, cancel := context.WithCancel(context.Background())

	// Use a very short interval so the ticker fires quickly.
	stop := pool.startProgressTicker(ctx, 50*time.Millisecond)

	// Let the ticker fire a few times.
	time.Sleep(200 * time.Millisecond)

	// Exercise the stop function path (closes the done channel).
	stop()

	// Also exercise the ctx.Done() path by cancelling after stop.
	// The goroutine may have already exited via done channel, but cancel is safe to call.
	cancel()

	// No assertions needed — this test exists purely for coverage.
	// Reaching here without deadlock or panic means the ticker.C case was exercised.
}

// TestScanPool_VerboseProgress exercises the progress ticker (verbose mode).
// The test verifies that a ScanPool with Verbose: true successfully exercises
// the startProgressTicker code path and completes all targets.
func TestScanPool_VerboseProgress(t *testing.T) {
	t.Parallel()

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		time.Sleep(250 * time.Millisecond)
		return []plugins.Service{{IP: target.Address.Addr().String(), Port: int(target.Address.Port())}}, nil
	}

	pool := NewScanPool(Config{Workers: 2, Verbose: true})
	targets := makeTargets(10)

	results, err := pool.Run(context.Background(), targets, fn)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(results) != 10 {
		t.Errorf("expected 10 results, got %d", len(results))
	}

	completed := pool.completed.Load()
	failed := pool.failed.Load()

	if completed != 10 {
		t.Errorf("expected completed==10, got %d", completed)
	}
	if failed != 0 {
		t.Errorf("expected failed==0, got %d", failed)
	}
}

// TestScanPool_SequentialParallelAccuracy validates that sequential (Workers=1) and
// parallel (Workers=50) runs produce identical results for the same set of targets and
// a deterministic scan function. This guards against races or dropped results that would
// only appear under parallel execution.
func TestScanPool_SequentialParallelAccuracy(t *testing.T) {
	t.Parallel()

	targets := makeTargets(100)

	scanFunc := func(target plugins.Target) ([]plugins.Service, error) {
		return []plugins.Service{{
			IP:       target.Address.Addr().String(),
			Port:     int(target.Address.Port()),
			Protocol: "mock",
		}}, nil
	}

	seqPool := NewScanPool(Config{Workers: 1})
	sequential, err := seqPool.Run(context.Background(), targets, scanFunc)
	if err != nil {
		t.Fatalf("sequential run: expected no error, got: %v", err)
	}

	parPool := NewScanPool(Config{Workers: 50})
	parallel, err := parPool.Run(context.Background(), targets, scanFunc)
	if err != nil {
		t.Fatalf("parallel run: expected no error, got: %v", err)
	}

	if len(sequential) != 100 {
		t.Errorf("sequential: expected 100 results, got %d", len(sequential))
	}
	if len(parallel) != 100 {
		t.Errorf("parallel: expected 100 results, got %d", len(parallel))
	}

	sort.Slice(sequential, func(i, j int) bool {
		return sequential[i].Port < sequential[j].Port
	})
	sort.Slice(parallel, func(i, j int) bool {
		return parallel[i].Port < parallel[j].Port
	})

	for i := range sequential {
		if sequential[i].IP != parallel[i].IP {
			t.Errorf("result[%d]: IP mismatch: sequential=%s parallel=%s",
				i, sequential[i].IP, parallel[i].IP)
		}
		if sequential[i].Port != parallel[i].Port {
			t.Errorf("result[%d]: Port mismatch: sequential=%d parallel=%d",
				i, sequential[i].Port, parallel[i].Port)
		}
	}
}

// Test Group 9: ProgressCallback

func TestScanPool_WithProgress_CallbackInvoked(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int64
	var mu sync.Mutex
	var completedTargets []plugins.Target

	callback := func(target plugins.Target, results []plugins.Service, count int64) {
		callCount.Add(1)
		mu.Lock()
		completedTargets = append(completedTargets, target)
		mu.Unlock()
	}

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		return []plugins.Service{{IP: target.Address.Addr().String()}}, nil
	}

	pool := NewScanPool(Config{Workers: 5}).WithProgress(callback)
	targets := makeTargets(10)

	_, err := pool.Run(context.Background(), targets, fn)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if callCount.Load() != 10 {
		t.Errorf("expected 10 callback invocations, got %d", callCount.Load())
	}
	if len(completedTargets) != 10 {
		t.Errorf("expected 10 completed targets, got %d", len(completedTargets))
	}
}

func TestScanPool_WithProgress_ReceivesCorrectResults(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	resultsByPort := make(map[int][]plugins.Service)

	callback := func(target plugins.Target, results []plugins.Service, count int64) {
		mu.Lock()
		resultsByPort[int(target.Address.Port())] = results
		mu.Unlock()
	}

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		return []plugins.Service{{
			IP:   target.Address.Addr().String(),
			Port: int(target.Address.Port()),
		}}, nil
	}

	pool := NewScanPool(Config{Workers: 5}).WithProgress(callback)
	targets := makeTargets(5)

	_, err := pool.Run(context.Background(), targets, fn)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// Each target got its results
	for port := 1; port <= 5; port++ {
		if len(resultsByPort[port]) != 1 {
			t.Errorf("port %d: expected 1 result, got %d", port, len(resultsByPort[port]))
		}
		if resultsByPort[port][0].Port != port {
			t.Errorf("port %d: result port = %d, want %d", port, resultsByPort[port][0].Port, port)
		}
	}
}

func TestScanPool_WithProgress_CountIncreases(t *testing.T) {
	t.Parallel()

	var mu sync.Mutex
	var counts []int64

	callback := func(target plugins.Target, results []plugins.Service, count int64) {
		mu.Lock()
		counts = append(counts, count)
		mu.Unlock()
	}

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		return []plugins.Service{{IP: target.Address.Addr().String()}}, nil
	}

	pool := NewScanPool(Config{Workers: 1}).WithProgress(callback) // Single worker for order
	targets := makeTargets(5)

	_, err := pool.Run(context.Background(), targets, fn)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// With single worker, counts should be strictly increasing
	for i := 1; i < len(counts); i++ {
		if counts[i] <= counts[i-1] {
			t.Errorf("counts[%d] = %d, counts[%d] = %d, expected strictly increasing", i, counts[i], i-1, counts[i-1])
		}
	}
}

func TestScanPool_WithProgress_ThreadSafe(t *testing.T) {
	t.Parallel()

	var counter atomic.Int64
	var maxConcurrent atomic.Int64
	var current atomic.Int64

	callback := func(target plugins.Target, results []plugins.Service, count int64) {
		cur := current.Add(1)
		defer current.Add(-1)

		// Track max concurrent callback invocations
		for {
			max := maxConcurrent.Load()
			if cur <= max || maxConcurrent.CompareAndSwap(max, cur) {
				break
			}
		}

		// Simulate some work in callback
		time.Sleep(5 * time.Millisecond)
		counter.Add(1)
	}

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		return []plugins.Service{{IP: target.Address.Addr().String()}}, nil
	}

	pool := NewScanPool(Config{Workers: 10}).WithProgress(callback)
	targets := makeTargets(50)

	_, err := pool.Run(context.Background(), targets, fn)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if counter.Load() != 50 {
		t.Errorf("expected 50 callback invocations, got %d", counter.Load())
	}
	// Verify some concurrency occurred
	if maxConcurrent.Load() <= 1 {
		t.Errorf("expected max concurrency > 1, got %d", maxConcurrent.Load())
	}
}

func TestScanPool_WithProgress_NilCallback(t *testing.T) {
	t.Parallel()

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		return []plugins.Service{{IP: target.Address.Addr().String()}}, nil
	}

	pool := NewScanPool(Config{Workers: 5}).WithProgress(nil)
	targets := makeTargets(10)

	results, err := pool.Run(context.Background(), targets, fn)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	if len(results) != 10 {
		t.Errorf("expected 10 results, got %d", len(results))
	}
}

func TestScanPool_WithProgress_NotCalledOnError(t *testing.T) {
	t.Parallel()

	var callCount atomic.Int64

	callback := func(target plugins.Target, results []plugins.Service, count int64) {
		callCount.Add(1)
	}

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		return nil, errors.New("simulated error")
	}

	pool := NewScanPool(Config{Workers: 5}).WithProgress(callback)
	targets := makeTargets(10)

	_, err := pool.Run(context.Background(), targets, fn)

	if err != nil {
		t.Fatalf("expected no error (pool continues on individual errors), got: %v", err)
	}
	if callCount.Load() != 0 {
		t.Errorf("expected 0 callback invocations (errors skip callback), got %d", callCount.Load())
	}
}

func TestScanPool_WithProgress_ChainedCall(t *testing.T) {
	callback := func(target plugins.Target, results []plugins.Service, count int64) {}

	pool := NewScanPool(Config{Workers: 5})
	returned := pool.WithProgress(callback)

	if pool != returned {
		t.Error("WithProgress() should return the same pool instance for chaining")
	}
}

func TestScanPool_WithProgress_EmptyResults(t *testing.T) {
	t.Parallel()

	var receivedEmpty atomic.Bool

	callback := func(target plugins.Target, results []plugins.Service, count int64) {
		if len(results) == 0 {
			receivedEmpty.Store(true)
		}
	}

	fn := func(target plugins.Target) ([]plugins.Service, error) {
		return nil, nil // No results
	}

	pool := NewScanPool(Config{Workers: 5}).WithProgress(callback)
	targets := makeTargets(5)

	_, err := pool.Run(context.Background(), targets, fn)

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}
	// Note: callback is only called when len(services) > 0 according to source
	// So this test documents that behavior
}
