// Copyright 2026 Praetorian Security, Inc.
// Licensed under the Apache License, Version 2.0.
// See LICENSE for license information.

package rat

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRemoteAccessHTTPHeaders(t *testing.T) {
	fp := &httpFingerprinter{}
	for _, tc := range []struct {
		header, product string
		status          int
	}{
		{"LogMeIn", "logmein", 200},
		{"LogMeIn/4.1.0.2138", "logmein", 401},
		{"logmein/development", "logmein", 500},
		{"LogMeIn Web Gateway", "logmein-web-gateway", 403},
		{" logmein web gateway ", "logmein-web-gateway", 200},
	} {
		t.Run(tc.header, func(t *testing.T) {
			response := &http.Response{StatusCode: tc.status, Header: http.Header{"Server": {tc.header}}}
			require.True(t, fp.Match(response))
			result, err := fp.Fingerprint(response, nil)
			require.NoError(t, err)
			require.Equal(t, tc.product, result.Technology)
			require.Empty(t, result.Version)
			require.Empty(t, result.Severity, "fingerprinting must not assign severity")
			require.Empty(t, result.SecurityFindings)
			require.Contains(t, result.Metadata["evidence"], "Server:")
		})
	}
	for _, header := range []string{"", "nginx", "NotLogMeIn/4.1", "LogMeIn/", "LogMeInProxy", "logmein.example.com", "LogMeIn/4.1 unrelated", "Something LogMeIn Web Gateway"} {
		response := &http.Response{StatusCode: 200, Header: http.Header{"Server": {header}}}
		require.False(t, fp.Match(response), header)
		result, err := fp.Fingerprint(response, []byte("LogMeIn Web Gateway LogMeIn/4.1"))
		require.NoError(t, err)
		require.Nil(t, result, "body mentions must not identify the service")
	}
}
