//go:build linux

package scan

import (
	"testing"
)

func TestDialSCTPSignature(t *testing.T) {
	// Verify DialSCTP has correct signature
	var dialFunc func(string, uint16) (interface{}, error) = func(ip string, port uint16) (interface{}, error) {
		return DialSCTP(ip, port)
	}
	_ = dialFunc
}
