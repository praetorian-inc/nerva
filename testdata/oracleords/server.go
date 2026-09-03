// Mock Oracle REST Data Services (ORDS) server for integration testing.
//
// Responses are modelled on a live ORDS 26.2.3 standalone instance (the
// Oracle-published ords-latest.zip distribution) plus the Database Actions
// client config it ships in WEB-INF/lib/ords-sdw-client-26.2.3.237.1104.jar.
//
// MODE env var controls what the container simulates:
//
//	"modern"        - ORDS 24.x/26.x fronting APEX. No Server, X-ORDS-* or
//	                  X-Powered-By header at all; the version is only
//	                  obtainable from /ords/_sdw/js/config.js (LAB-5060).
//	"modern-noapex" - the same release without APEX installed.
//	"protected"     - modern ORDS whose /ords/_sdw/ surface answers 401, so no
//	                  version is obtainable and the plugin must degrade to a
//	                  detection-only result.
//	"legacy"        - ORDS 22.x/23.x, which still emits
//	                  "Server: Oracle-REST-Data-Services/<ver>".
package main

import (
	"fmt"
	"net/http"
	"os"
)

const (
	// sdwConfigJS is the Database Actions / SQL Developer Web client config as
	// shipped in ORDS 26.2.3. Its productVersion pins the patch component at
	// zero for the whole release train.
	sdwConfigJS = `define({"meta":{"productName":"SQL Developer","companyName":"Oracle",` +
		`"productVersion":"26.2.0","productPath":"_sdw/","signInPath":"sign-in/",` +
		`"signOutPath":"sign-out/","landingPath":"/sql-developer"},` +
		`"service":{"name":"Database Actions","version":""},` +
		`"session":{"username":null,"schema":null,"urlMapping":null}})`

	// legacyServerHeader is the Server token older ORDS releases emit.
	legacyServerHeader = "Oracle-REST-Data-Services/22.4.3"

	// notFoundBody is the application/problem+json body modern ORDS returns for
	// an unmapped request.
	notFoundBody = `{
    "code": "NotFound",
    "title": "Not Found",
    "message": "The request could not be mapped to any database. Check the request URL is correct, and that URL to database mappings have been correctly configured",
    "type": "tag:oracle.com,2020:error/NotFound",
    "instance": "tag:oracle.com,2020:ecid/aNRJXXFQmFfkOBAjKpaWcA"
}`
)

func main() {
	mode := os.Getenv("MODE")
	if mode == "" {
		mode = "modern"
	}
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	legacy := mode == "legacy"
	apex := mode != "modern-noapex"

	// setServerHeader mirrors the header behaviour of the simulated release:
	// modern ORDS emits no Server header at all.
	setServerHeader := func(w http.ResponseWriter) {
		if legacy {
			w.Header().Set("Server", legacyServerHeader)
			return
		}
		// Go's net/http adds no Server header of its own, but be explicit: the
		// absence of this header is the whole point of the modern modes.
		w.Header()["Server"] = nil
	}

	notFound := func(w http.ResponseWriter) {
		setServerHeader(w)
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, notFoundBody)
	}

	mux := http.NewServeMux()

	// The ORDS entry point. On a real instance this serves the APEX sign-in
	// page when APEX is installed, and otherwise redirects to the landing page.
	mux.HandleFunc("/ords/", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/ords/":
			setServerHeader(w)
			if !apex {
				http.Redirect(w, r, "/ords/_/landing", http.StatusFound)
				return
			}
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, apexSignInPage)
		case "/ords/_/landing":
			setServerHeader(w)
			w.Header().Set("Content-Type", "text/html")
			w.Header().Set("X-Frame-Options", "SAMEORIGIN")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, landingPage)
		case "/ords/_sdw/js/config.js":
			setServerHeader(w)
			if mode == "protected" {
				w.Header().Set("WWW-Authenticate", `Basic realm="Oracle REST Data Services"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("Cache-Control", "public,max-age=86400")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, sdwConfigJS)
		default:
			notFound(w)
		}
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			notFound(w)
			return
		}
		setServerHeader(w)
		http.Redirect(w, r, "/ords/", http.StatusFound)
	})

	addr := ":" + port
	fmt.Printf("ORDS mock (mode=%s) listening on %s\n", mode, addr)
	server := &http.Server{Addr: addr, Handler: mux}
	if err := server.ListenAndServe(); err != nil {
		fmt.Fprintf(os.Stderr, "server error: %v\n", err)
		os.Exit(1)
	}
}

// apexSignInPage is the shape of an APEX-rendered page: every static asset
// reference carries the APEX version as a "?v=" cache-busting parameter.
const apexSignInPage = `<!DOCTYPE html>
<html lang="en">
<head>
    <title>Sign In</title>
    <meta charset="UTF-8">
    <link rel="stylesheet" href="/i/24.1.5/app_ui/css/Core.min.css?v=24.1.5">
    <script src="/i/libraries/apex/minified/desktop.min.js?v=24.1.5"></script>
</head>
<body>
    <form action="wwv_flow.accept" method="post">
        <a href="f?p=4550:1:0::NO">Oracle APEX Administration Services</a>
        <input type="text" name="p_t01" id="P101_USERNAME">
        <input type="password" name="p_t02" id="P101_PASSWORD">
        <button type="submit">Sign In</button>
    </form>
</body>
</html>`

// landingPage is the ORDS standalone landing page introduced in ORDS 23.2. It
// carries no version string; its only "apex" reference is the font-apex icon
// stylesheet that ORDS ships for its own UI.
const landingPage = `<!DOCTYPE html>
<html lang="en">
<head>
    <title data-i18n data-i18n.inner-text="landing_page"></title>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <link rel="stylesheet" href="landing/css/style.css">
    <link rel="stylesheet" href="lib/css/font-apex/css/font-apex.min.css">
    <link rel="icon" href="landing/css/images/favicon.svg">
</head>
<body>
    <div id="landing-page">
        <h1 data-i18n data-i18n.inner-text="welcome"></h1>
        <p data-i18n data-i18n.inner-text="ords_description"></p>
    </div>
    <script src="jet/js/libs/3rdparty/require/require.js"></script>
    <script src="landing/js/main.js"></script>
</body>
</html>`
