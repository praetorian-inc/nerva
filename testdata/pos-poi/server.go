// Independent HTTP identity mocks for POS/POI management UIs.
// Strings and paths are copied from public login pages cited in README.md.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}
	mode := strings.ToLower(os.Getenv("MODE"))
	if mode == "" {
		mode = "generic"
	}

	mux := http.NewServeMux()
	switch mode {
	case "verifone":
		registerVerifone(mux)
	case "ingenico-estate":
		registerIngenicoEstate(mux)
	case "ingenico-tms":
		registerIngenicoTMS(mux)
	case "generic":
		registerGeneric(mux)
	default:
		log.Fatalf("unknown MODE=%q (want verifone|ingenico-estate|ingenico-tms|generic)", mode)
	}

	srv := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Printf("pos-poi mock MODE=%s listening on %s", mode, srv.Addr)
		errCh <- srv.ListenAndServe()
	}()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	select {
	case err := <-errCh:
		if err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	case sig := <-sigCh:
		log.Printf("shutting down (%s)", sig)
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
	}
}

func writeHTML(w http.ResponseWriter, body string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(body))
}

func registerVerifone(mux *http.ServeMux) {
	page := vhqLoginHTML()
	serve := func(w http.ResponseWriter, r *http.Request) {
		writeHTML(w, page)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		serve(w, r)
	})
	mux.HandleFunc("/VHQ.Authentication.VHQFederationV1/Account/Login", serve)
	mux.HandleFunc("/VHQ.Authentication.Federation/Account/Login", serve)
}

func vhqLoginHTML() string {
	return `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>VHQ</title>
</head>
<body>
    <div class="version-text">Version 3.30.02.27</div>
    <form method="post" action="Account/Login" id="formTest">
        <span id="loginFailedMsg">Invalid user name or password</span>
        <input type="text" name="username" id="txtloginname" autocomplete="off">
        <input type="password" name="password" id="txtpassword" autocomplete="off">
        <button type="submit" id="Btnsubmit">Login</button>
    </form>
    <div class="login-footer">
        Copyright &copy; 2026, Verifone Systems, Inc.
        <img src="/VHQ.Authentication.VHQFederationV1/Content/images/verifone-b.png" alt="">
    </div>
</body>
</html>
`
}

func registerIngenicoEstate(mux *http.ServeMux) {
	page := estateHTML()
	serve := func(w http.ResponseWriter, r *http.Request) {
		writeHTML(w, page)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		serve(w, r)
	})
	mux.HandleFunc("/emgui/resetPassword.jsp", serve)
	mux.HandleFunc("/emgui/", serve)
}

func estateHTML() string {
	return `<!DOCTYPE html>
<html class="login-page">
<head>
    <meta charset="utf-8">
    <title>Ingenico Estate Management</title>
</head>
<body>
<div class="login-holder">
    <h1>Welcome to <span> The Estate Manager</span></h1>
    <form action="/emgui/login.jsp" method="post" class="form-login-user">
        <label for="login">Login</label>
        <input type="text" id="userName" name="userName">
        <button type="submit">Reset</button>
    </form>
    <img alt="Ingenico Group" src="/emgui/resources/common/img_content/ingenico-group-logo.png">
    <div class="mentions">Copyright 2021</div>
</div>
</body>
</html>
`
}

func registerIngenicoTMS(mux *http.ServeMux) {
	page := tmsHTML()
	serve := func(w http.ResponseWriter, r *http.Request) {
		writeHTML(w, page)
	}
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		serve(w, r)
	})
	mux.HandleFunc("/extranet/login.sm", serve)
}

func tmsHTML() string {
	return `<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">
<html>
<head>
  <title>TMS Web Access- Login</title>
</head>
<body>
<form name="fmLogin" method="POST" action="j_spring_security_check" autocomplete="off">
  <table>
    <tr><td>Web Site : <a href="http://www.ingenico.com">www.ingenico.com</a></td></tr>
    <tr><td>Please sign in to access the TMS</td></tr>
    <tr><td>User Name <input type="text" name="j_username" value=""></td></tr>
    <tr><td>Password <input type="password" name="j_password" value=""></td></tr>
    <tr><td><button type="submit" id="j_submit">Log In</button></td></tr>
  </table>
</form>
</body>
</html>
`
}

func registerGeneric(mux *http.ServeMux) {
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		writeHTML(w, `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><title>Hello</title></head>
<body>Hello</body>
</html>
`)
	})
}
