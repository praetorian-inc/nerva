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

// Package main implements a mock APC Network Management Card (NMC) HTTP
// server for integration testing.
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

const DefaultPort = "8080"

// logonPage returns the HTML body for the APC NMC login page at /logon.htm
func logonPage() string {
	return `<html><head><title>APC | Log On</title></head>
<body>
<form name="frmLogin" method="POST" action="/Forms/login1">
<input name="login_username" type="text">
<input name="login_password" type="password">
<input type="submit" value="Log On">
</form>
</body></html>`
}

func main() {
	port := DefaultPort
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			notFoundHandler(w, r)
			return
		}
		log.Printf("GET / from %s — redirecting to /logon.htm", r.RemoteAddr)
		http.Redirect(w, r, "/logon.htm", http.StatusFound)
	})

	mux.HandleFunc("/logon.htm", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /logon.htm from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Set-Cookie", "C0=apc; path=/")
		fmt.Fprint(w, logonPage())
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("APC NMC mock server listening on port %s", port)

	// Setup signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	sig := <-sigChan
	fmt.Printf("\nReceived signal %v, shutting down...\n", sig)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
}

// notFoundHandler serves the APC-specific 404 response for unknown paths.
func notFoundHandler(w http.ResponseWriter, r *http.Request) {
	log.Printf("GET %s from %s — not found", r.URL.Path, r.RemoteAddr)
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(http.StatusNotFound)
	fmt.Fprint(w, `<html><body>The requested URL was not found on the APC Management Web Server.</body></html>`)
}
