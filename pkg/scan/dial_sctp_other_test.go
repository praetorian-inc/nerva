//go:build !linux

package scan

import (
	"errors"
	"testing"
)

func TestDialSCTPNotSupported(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		port uint16
	}{
		{
			name: "returns error for any valid input",
			ip:   "127.0.0.1",
			port: 3868,
		},
		{
			name: "returns error for any IP",
			ip:   "10.0.0.1",
			port: 5060,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			conn, err := DialSCTP(tt.ip, tt.port)

			if conn != nil {
				t.Error("DialSCTP returned non-nil connection on non-Linux")
				conn.Close()
			}

			if err == nil {
				t.Error("DialSCTP expected error on non-Linux, got nil")
			}

			if !errors.Is(err, ErrSCTPNotSupported) {
				t.Errorf("DialSCTP error = %v, want ErrSCTPNotSupported", err)
			}
		})
	}
}

func TestErrSCTPNotSupportedMessage(t *testing.T) {
	expected := "SCTP scanning requires Linux; limited support on this platform"
	if ErrSCTPNotSupported.Error() != expected {
		t.Errorf("ErrSCTPNotSupported = %q, want %q",
			ErrSCTPNotSupported.Error(), expected)
	}
}
