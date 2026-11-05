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

// Package main implements a mock Webmin (MiniServ) HTTP server for integration testing
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

const (
	DefaultPort  = "10000"
	MiniServ     = "MiniServ/2.104"
)

// loginPage returns the HTML body for the Webmin login page at /.
func loginPage() string {
	return `<html><head><title>Login to Webmin</title></head>
<body>
<form action="/session_login.cgi" method="post">
<input name="user" type="text" size="20">
<input name="pass" type="password" size="20">
<input type="submit" value="Login">
<input type="hidden" name="page" value="/">
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
		w.Header().Set("Server", MiniServ)
		w.Header().Set("Content-Type", "text/html; Charset=UTF-8")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Connection", "close")
		w.Header().Set("Set-Cookie", "testing=1; path=/")

		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "Document not found")
			return
		}

		log.Printf("GET / from %s", r.RemoteAddr)
		fmt.Fprint(w, loginPage())
	})

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("Webmin (MiniServ) mock server listening on port %s", port)

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
