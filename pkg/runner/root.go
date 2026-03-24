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

package runner

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/scan"
)

var (
	config     cliConfig
	targetList []string
	userInput  string
	rootCmd    = &cobra.Command{
		Use: "nerva [flags]\nTARGET SPECIFICATION:\n\tRequires a host and port number or ip and port number. " +
			"The port is assumed to be open.\n\tHOST:PORT or IP:PORT\nEXAMPLES:\n\tnerva -t praetorian.com:80\n" +
			"\tnerva -l input-file.txt\n\tnerva --json -t praetorian.com:80,127.0.0.1:8000",
		RunE: runScan,
	}
)

// setupSignalContext creates a context that cancels on SIGINT/SIGTERM.
// Double-SIGINT within 3 seconds forces immediate exit.
func setupSignalContext() (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 2)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	var lastSigTime atomic.Int64
	var sigCount atomic.Int32

	go func() {
		for sig := range sigChan {
			now := time.Now().UnixNano()
			count := sigCount.Add(1)
			lastTime := lastSigTime.Swap(now)

			// Double-SIGINT within 3 seconds forces exit
			if count > 1 && (now-lastTime) < int64(3*time.Second) {
				fmt.Fprintln(os.Stderr, "\n[WRN] Force exit - state file may not be saved")
				os.Exit(130)
			}

			fmt.Fprintf(os.Stderr, "\n[INF] %v received: Initiating graceful shutdown...\n", sig)
			cancel()
		}
	}()

	cleanup := func() {
		signal.Stop(sigChan)
		close(sigChan)
		cancel()
	}

	return ctx, cleanup
}

func runScan(cmd *cobra.Command, args []string) error {
	if config.showCapabilities {
		printCapabilities()
		return nil
	}

	if err := checkConfig(config); err != nil {
		return err
	}

	ctx, cleanup := setupSignalContext()
	defer cleanup()

	// Load targets
	var targets []plugins.Target
	var originalCount int
	var existingResults []plugins.Service

	if config.resume && config.stateFile != "" {
		// Resume from state file
		state, err := LoadState(config.stateFile)
		if err != nil {
			return fmt.Errorf("failed to load state file: %w", err)
		}

		if config.verbose {
			log.Printf("[INF] Resuming scan: %d completed, %d pending\n",
				len(state.Targets.Completed), len(state.Targets.Pending))
		}

		targets = StringsToTargets(state.Targets.Pending, config.verbose)
		originalCount = state.Targets.OriginalCount
		existingResults = state.Results

		// Restore config from state if not overridden
		if config.timeout == 2000 { // default value
			config.timeout = state.Config.TimeoutMs
		}
		if !config.misconfigs {
			config.misconfigs = state.Config.Misconfigs
		}
	} else {
		// Read targets from input
		var err error
		targets, err = readTargets(inputFile, config.verbose)
		if err != nil {
			return err
		}
		originalCount = len(targets)
	}

	if len(targets) == 0 {
		if len(existingResults) > 0 {
			// All targets already completed
			return Report(existingResults)
		}
		return fmt.Errorf("no targets to scan")
	}

	// Thread-safe state tracking for progress callback
	var mu sync.Mutex
	var completedTargets []string
	var allResults []plugins.Service
	allResults = append(allResults, existingResults...)
	var lastSaveCount int

	// Async save channel to avoid blocking workers
	saveCh := make(chan *ScanState, 1)
	var saveWg sync.WaitGroup
	if config.stateFile != "" {
		saveWg.Add(1)
		go func() {
			defer saveWg.Done()
			for state := range saveCh {
				if err := SaveState(config.stateFile, state); err != nil {
					log.Printf("[WRN] Failed to save state: %v\n", err)
				} else if config.verbose {
					log.Printf("[INF] State saved: %d completed, %d pending\n",
						len(state.Targets.Completed), len(state.Targets.Pending))
				}
			}
		}()
	}

	// Create progress callback for state tracking
	scanConfig := createScanConfig(config)

	if config.stateFile != "" {
		scanConfig.OnProgress = func(target plugins.Target, results []plugins.Service, completedCount int64) {
			mu.Lock()
			defer mu.Unlock()

			completedTargets = append(completedTargets, TargetToString(target))
			allResults = append(allResults, results...)

			// Auto-save at intervals (non-blocking)
			if config.autoSave > 0 && len(completedTargets)-lastSaveCount >= config.autoSave {
				lastSaveCount = len(completedTargets)
				state := buildState(config, targets, completedTargets, allResults, originalCount)
				select {
				case saveCh <- state:
				default:
					// Previous save still in progress, skip this one
				}
			}
		}
	}

	// Run the scan
	results, err := scan.ScanTargets(ctx, targets, scanConfig)

	// Close save channel and wait for pending saves
	if config.stateFile != "" {
		close(saveCh)
		saveWg.Wait()
	}

	// Handle interruption - save state
	if ctx.Err() != nil && config.stateFile != "" {
		mu.Lock()
		state := buildState(config, targets, completedTargets, allResults, originalCount)
		mu.Unlock()

		if err := SaveState(config.stateFile, state); err != nil {
			log.Printf("[WRN] Failed to save state: %v\n", err)
		}

		fmt.Fprintf(os.Stderr, "[INF] State saved to %s. Resume with: nerva --resume --state-file %s\n",
			config.stateFile, config.stateFile)
		return ctx.Err()
	}

	if err != nil {
		return fmt.Errorf("failed running ScanTargets: %w", err)
	}

	// Combine existing results with new results
	finalResults := append(existingResults, results...)

	// Clean up state file on successful completion
	if config.stateFile != "" && config.resume {
		os.Remove(config.stateFile)
		if config.verbose {
			log.Printf("[INF] Scan completed, removed state file\n")
		}
	}

	return Report(finalResults)
}

func buildState(config cliConfig, targets []plugins.Target, completedTargets []string, results []plugins.Service, originalCount int) *ScanState {
	// Calculate pending safely
	completedSet := make(map[string]bool, len(completedTargets))
	for _, c := range completedTargets {
		completedSet[c] = true
	}

	var pending []string
	for _, t := range targets {
		s := TargetToString(t)
		if !completedSet[s] {
			pending = append(pending, s)
		}
	}

	return &ScanState{
		Version:   CurrentStateVersion,
		CreatedAt: time.Now().UTC(),
		Config: StateConfig{
			TimeoutMs:   config.timeout,
			FastMode:    config.fastMode,
			UDP:         config.useUDP,
			SCTP:        config.useSCTP,
			Verbose:     config.verbose,
			Workers:     config.workers,
			MaxHostConn: config.maxHostConn,
			RateLimit:   config.rateLimit,
			Proxy:       config.proxy,
			ProxyAuth:   config.proxyAuth,
			DNSOrder:    config.dnsOrder,
			Misconfigs:  config.misconfigs,
		},
		Targets: StateTargets{
			OriginalCount: originalCount,
			Completed:     completedTargets,
			Pending:       pending,
			InputFile:     inputFile,
		},
		Results: results,
	}
}

func init() {
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})

	rootCmd.PersistentFlags().StringVarP(&inputFile, "list", "l", "", "input file containing targets")
	rootCmd.PersistentFlags().StringSliceVarP(&targetList, "targets", "t", nil, "target or comma separated target list")
	rootCmd.PersistentFlags().StringVarP(&config.outputFile, "output", "o", "", "output file")
	rootCmd.PersistentFlags().BoolVarP(&config.outputJSON, "json", "", false, "output format in json")
	rootCmd.PersistentFlags().BoolVarP(&config.outputCSV, "csv", "", false, "output format in csv")

	rootCmd.PersistentFlags().BoolVarP(&config.fastMode, "fast", "f", false, "fast mode")
	rootCmd.PersistentFlags().BoolVarP(&config.useUDP, "udp", "U", false, "run UDP plugins")
	rootCmd.PersistentFlags().BoolVarP(&config.useSCTP, "sctp", "S", false, "run SCTP plugins (Linux only)")
	rootCmd.PersistentFlags().BoolVarP(&config.verbose, "verbose", "v", false, "verbose mode")
	rootCmd.PersistentFlags().IntVarP(&config.timeout, "timeout", "w", 2000, "timeout (milliseconds)")
	rootCmd.PersistentFlags().IntVarP(&config.workers, "workers", "W", 50, "number of concurrent scan workers")
	rootCmd.PersistentFlags().IntVarP(&config.maxHostConn, "max-host-conn", "H", 0, "max concurrent connections per host IP (0=unlimited)")
	rootCmd.PersistentFlags().Float64VarP(&config.rateLimit, "rate-limit", "R", 0, "max scans per second (0=unlimited)")
	rootCmd.PersistentFlags().BoolVarP(&config.showCapabilities, "capabilities", "c", false, "list available capabilities and exit")

	// Resume support
	rootCmd.PersistentFlags().IntVar(&config.autoSave, "auto-save", 0, "auto-save interval (number of targets)")
	rootCmd.PersistentFlags().BoolVar(&config.misconfigs, "misconfigs", false, "enable security misconfiguration detection")

	rootCmd.PersistentFlags().StringVar(&config.proxy, "proxy", "", "proxy URL (e.g. socks5://127.0.0.1:1080)")
	rootCmd.PersistentFlags().StringVar(&config.proxyAuth, "proxy-auth", "", "socks5 proxy authentication (username:password)")
	rootCmd.PersistentFlags().StringVar(&config.dnsOrder, "dns-order", "lp", "DNS resolution order: p, l, lp, pl")
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
