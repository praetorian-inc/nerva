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

// Package main implements a mock PaperCut MF HTTP server for integration testing.
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

const DefaultPort = "9191"

func main() {
	port := DefaultPort
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/app", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET %s from %s", r.URL.Path, r.RemoteAddr)
		w.Header().Set("Set-Cookie", "JSESSIONID=xyz789; HttpOnly; Path=/")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <title>PaperCut Login</title>
</head>
<body>
  <h1>PaperCut MF</h1>
  <form action="/app?service=direct/1/Login/loginForm" method="post">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="submit" value="Log in">
  </form>
  <nav>
    <a href="/app?service=page/Dashboard">Dashboard</a>
    <a href="/app?service=page/PrinterList">Printers</a>
  </nav>
  <footer>PaperCut MF &copy; PaperCut Software Pty Ltd</footer>
</body>
</html>`)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET %s from %s (404)", r.URL.Path, r.RemoteAddr)
		http.NotFound(w, r)
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("PaperCut mock server listening on port %s", port)

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
