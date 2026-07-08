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

// Package main implements a mock HTTP server exposing common admin paths for integration testing
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

func main() {
	mux := http.NewServeMux()

	mux.HandleFunc("/wp-admin/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /wp-admin/ from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Dashboard ‹ Test — WordPress</title></head><body><h1>WordPress Dashboard</h1></body></html>`)
	})

	mux.HandleFunc("/wp-login.php", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /wp-login.php from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Log In ‹ Test — WordPress</title></head><body><form id="loginform" action="/wp-login.php" method="post"><input type="text" name="log" /><input type="password" name="pwd" /><input type="submit" value="Log In" /></form></body></html>`)
	})

	mux.HandleFunc("/phpmyadmin/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /phpmyadmin/ from %s — redirecting to /phpmyadmin/index.php", r.RemoteAddr)
		http.Redirect(w, r, "/phpmyadmin/index.php", http.StatusFound)
	})

	mux.HandleFunc("/phpmyadmin/index.php", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /phpmyadmin/index.php from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>phpMyAdmin</title></head><body><h1>Welcome to phpMyAdmin</h1></body></html>`)
	})

	mux.HandleFunc("/administrator/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /administrator/ from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Administration - Joomla!</title></head><body><h1>Joomla Administrator</h1></body></html>`)
	})

	mux.HandleFunc("/users/sign_in", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /users/sign_in from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Sign in · GitLab</title></head><body><h1>GitLab Sign In</h1></body></html>`)
	})

	mux.HandleFunc("/adminer.php", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /adminer.php from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Adminer</title></head><body><h1>Adminer</h1></body></html>`)
	})

	mux.HandleFunc("/admin/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /admin/ from %s", r.RemoteAddr)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><head><title>Admin Dashboard</title></head><body><h1>Admin Dashboard</h1></body></html>`)
	})

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("GET /login from %s — redirecting to /auth/login", r.RemoteAddr)
		http.Redirect(w, r, "/auth/login", http.StatusFound)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	})

	srv := &http.Server{
		Addr:              ":8090",
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
	}

	log.Printf("Admin path mock server listening on port 8090")

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
