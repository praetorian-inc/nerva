//go:build linux

package scan

import (
	"strings"
	"testing"
)

func TestDialSCTP(t *testing.T) {
	tests := []struct {
		name      string
		ip        string
		port      uint16
		wantErr   bool
		errSubstr string
	}{
		{
			name:      "invalid IP - empty string",
			ip:        "",
			port:      3868,
			wantErr:   true,
			errSubstr: "invalid IP address",
		},
		{
			name:      "invalid IP - malformed",
			ip:        "not.an.ip.address",
			port:      3868,
			wantErr:   true,
			errSubstr: "invalid IP address",
		},
		{
			name:      "invalid IP - partial",
			ip:        "192.168",
			port:      3868,
			wantErr:   true,
			errSubstr: "invalid IP address",
		},
		{
			name:      "valid IP - connection refused (no listener)",
			ip:        "127.0.0.1",
			port:      65535,
			wantErr:   true,
			errSubstr: "SCTP dial failed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := DialSCTP(tt.ip, tt.port)

			if tt.wantErr {
				if err == nil {
					t.Errorf("DialSCTP(%q, %d) expected error, got nil", tt.ip, tt.port)
					if conn != nil {
						conn.Close()
					}
					return
				}
				if !strings.Contains(err.Error(), tt.errSubstr) {
					t.Errorf("DialSCTP(%q, %d) error = %v, want containing %q",
						tt.ip, tt.port, err, tt.errSubstr)
				}
			} else {
				if err != nil {
					t.Errorf("DialSCTP(%q, %d) unexpected error: %v", tt.ip, tt.port, err)
				}
				if conn != nil {
					conn.Close()
				}
			}
		})
	}
}
