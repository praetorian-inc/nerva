// Mock Oracle OUAF/UTA server for integration testing.
//
// MODE env var controls what the container simulates:
//   "ouaf"     - OUAF login surface only (port 6501)
//   "uta"      - UTA login surface only (port 6500)
//   "both"     - OUAF + UTA on the same host (port 6501)
package main

import (
	"fmt"
	"net/http"
	"os"
)

func main() {
	mode := os.Getenv("MODE")
	if mode == "" {
		mode = "ouaf"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "6501"
	}

	mux := http.NewServeMux()

	if mode == "ouaf" || mode == "both" {
		mux.HandleFunc("/ouaf/loginPage.jsp", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.Header().Set("Server", "Oracle-Application-Server-11g")
			fmt.Fprint(w, ouafLoginPage)
		})
		mux.HandleFunc("/ouaf/cis.jsp", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			w.Header().Set("Server", "Oracle-Application-Server-11g")
			http.Redirect(w, r, "/ouaf/loginPage.jsp", http.StatusFound)
		})
		mux.HandleFunc("/ouaf/rest", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Server", "Oracle-Application-Server-11g")
			fmt.Fprint(w, `{"application":"Oracle Utilities Application Framework","version":"4.4.0.3.0"}`)
		})
	}

	if mode == "uta" || mode == "both" {
		mux.HandleFunc("/uta/login.html", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html; charset=UTF-8")
			fmt.Fprint(w, utaLoginPage)
		})
	}

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, "<html><body>404 Not Found</body></html>")
			return
		}
		if mode == "ouaf" || mode == "both" {
			http.Redirect(w, r, "/ouaf/loginPage.jsp", http.StatusFound)
			return
		}
		if mode == "uta" {
			http.Redirect(w, r, "/uta/login.html", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	})

	addr := ":" + port
	fmt.Printf("OUAF/UTA mock server starting (mode=%s) on %s\n", mode, addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

const ouafLoginPage = `<!DOCTYPE html>
<html>
<head>
    <title>Oracle Utilities Application Framework - Login</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body>
    <div id="loginContainer">
        <h1>Oracle Utilities Application Framework</h1>
        <p>Customer Care and Billing</p>
        <form name="loginForm" method="POST" action="j_security_check">
            <label for="j_username">User ID:</label>
            <input type="text" id="j_username" name="j_username">
            <label for="j_password">Password:</label>
            <input type="password" id="j_password" name="j_password">
            <input type="submit" value="Sign In">
        </form>
        <p class="version">Version 4.4.0.3.0</p>
    </div>
</body>
</html>`

const utaLoginPage = `<!DOCTYPE html>
<html>
<head>
    <title>Oracle Utilities Testing Accelerator</title>
    <meta http-equiv="Content-Type" content="text/html; charset=UTF-8">
</head>
<body>
    <div id="loginContainer">
        <h1>Oracle Utilities Testing Accelerator</h1>
        <p>Version 7.0.0.0</p>
        <form name="loginForm" method="POST" action="j_security_check">
            <label for="username">User ID:</label>
            <input type="text" id="username" name="username">
            <label for="password">Password:</label>
            <input type="password" id="password" name="password">
            <input type="submit" value="Sign In">
        </form>
    </div>
</body>
</html>`
