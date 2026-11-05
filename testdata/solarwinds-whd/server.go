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

// Package main implements a mock SolarWinds Web Help Desk HTTP server for integration testing.
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

const DefaultPort = "8081"

func main() {
	port := DefaultPort
	if envPort := os.Getenv("PORT"); envPort != "" {
		port = envPort
	}

	mux := http.NewServeMux()

	mux.HandleFunc("/helpdesk/WebObjects/Helpdesk.woa", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET %s from %s", r.URL.Path, r.RemoteAddr)
		w.Header().Set("Server", "Apache-Coyote/1.1")
		w.Header().Set("X-Webobjects-Loadaverage", "0.42")
		w.Header().Set("X-Webobjects-Servlet", "YES")
		w.Header().Set("Set-Cookie", "JSESSIONID=abc123; HttpOnly; Path=/helpdesk/")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<!DOCTYPE html>
<html lang="en">
<head>
  <title>Web Help Desk</title>
  <link rel="stylesheet" type="text/css" href="/helpdesk/css/whdStyles.css">
</head>
<body>
  <h1>Web Help Desk</h1>
  <form action="/helpdesk/WebObjects/Helpdesk.woa/wo/6.7" method="post">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="submit" value="Login">
  </form>
  <footer>SolarWinds WorldWide, LLC</footer>
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
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("SolarWinds Web Help Desk mock server listening on port %s", port)

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
