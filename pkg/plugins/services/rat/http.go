// Copyright 2026 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0.
// See LICENSE for license information.

package rat

import (
	"net/http"
	"regexp"
	"strings"

	"github.com/praetorian-inc/nerva/pkg/plugins/fingerprinters"
)

// httpFingerprinter identifies remote-access HTTP services using
// their Server headers. Nerva's existing HTTP/HTTPS plugins supply the response.
// Source: Nmap nmap-service-probes, LogMeIn httpd / LogMeIn Web Gateway matches.
type httpFingerprinter struct{}

var logMeInServer = regexp.MustCompile(`(?i)^LogMeIn(?:/[^\s/]+)?$`)

func init() { fingerprinters.Register(&httpFingerprinter{}) }

func (f *httpFingerprinter) Name() string { return "rat-http" }

func (f *httpFingerprinter) Match(resp *http.Response) bool {
	return remoteAccessHTTPProduct(resp.Header.Get("Server")) != ""
}

func (f *httpFingerprinter) Fingerprint(resp *http.Response, _ []byte) (*fingerprinters.FingerprintResult, error) {
	server := strings.TrimSpace(resp.Header.Get("Server"))
	product := remoteAccessHTTPProduct(server)
	if product == "" {
		return nil, nil
	}
	return &fingerprinters.FingerprintResult{
		Technology: product,
		Metadata: map[string]any{
			"vendor":   "LogMeIn",
			"evidence": "Server: " + server,
		},
	}, nil
}

func remoteAccessHTTPProduct(server string) string {
	server = strings.TrimSpace(server)
	if strings.EqualFold(server, "LogMeIn Web Gateway") {
		return "logmein-web-gateway"
	}
	if logMeInServer.MatchString(server) {
		return "logmein"
	}
	return ""
}
