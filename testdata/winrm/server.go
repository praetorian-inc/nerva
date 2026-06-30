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

// Package main implements mock WinRM HTTP servers for integration testing.
// Three listeners simulate distinct WinRM configurations:
//   - Port 8985: unauthenticated WinRM (HTTP 200, no auth challenge)
//   - Port 8986: authenticated WinRM (HTTP 401, Negotiate challenge)
//   - Port 8080: generic HTTP server (nginx, no WinRM indicators)
package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func logRequest(status int, r *http.Request) {
	log.Printf("%d %s %s %s", status, r.Method, r.URL.Path, r.RemoteAddr)
}

// unauthenticatedMux returns a handler that responds to all paths with HTTP 200
// and WinRM headers, simulating a WinRM endpoint with no authentication required.
func unauthenticatedMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		w.WriteHeader(http.StatusOK)
		logRequest(http.StatusOK, r)
	})
	return mux
}

// authenticatedMux returns a handler that responds to all paths with HTTP 401
// and a Negotiate challenge, simulating a WinRM endpoint that requires auth.
func authenticatedMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "Microsoft-HTTPAPI/2.0")
		w.Header().Set("Content-Type", "application/soap+xml;charset=UTF-8")
		w.Header().Set("WWW-Authenticate", "Negotiate")
		w.WriteHeader(http.StatusUnauthorized)
		logRequest(http.StatusUnauthorized, r)
	})
	return mux
}

// genericMux returns a handler that responds like a plain nginx server,
// with no WinRM indicators, used to verify false-positive prevention.
func genericMux() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx/1.24.0")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body>Welcome to nginx!</body></html>")
		logRequest(http.StatusOK, r)
	})
	return mux
}

func newServer(addr string, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              addr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
}

func startServer(srv *http.Server) {
	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server %s error: %v", srv.Addr, err)
		}
	}()
}

func main() {
	unauthSrv := newServer(":8985", unauthenticatedMux())
	authSrv := newServer(":8986", authenticatedMux())
	genericSrv := newServer(":8080", genericMux())

	startServer(unauthSrv)
	log.Printf("WinRM unauthenticated mock listening on :8985")

	startServer(authSrv)
	log.Printf("WinRM authenticated mock listening on :8986")

	startServer(genericSrv)
	log.Printf("Generic HTTP mock listening on :8080")

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	sig := <-sigChan
	fmt.Printf("\nReceived signal %v, shutting down...\n", sig)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	for _, srv := range []*http.Server{unauthSrv, authSrv, genericSrv} {
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("Shutdown error for %s: %v", srv.Addr, err)
		}
	}
}
