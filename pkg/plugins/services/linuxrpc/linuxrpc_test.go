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

package linuxrpc

import (
	"testing"

	"github.com/ory/dockertest/v3"

	"github.com/praetorian-inc/nerva/pkg/plugins"
	"github.com/praetorian-inc/nerva/pkg/test"
)

func TestRPC(t *testing.T) {
	testcases := []test.Testcase{
		{
			Description: "alpine-nfs",
			Port:        111,
			Protocol:    plugins.TCP,
			Expected: func(res *plugins.Service) bool {
				return res != nil
			},
			RunConfig: dockertest.RunOptions{
				Repository: "woahbase/alpine-nfs",
				Tag:        "x86_64",
				Privileged: true,
			},
		},
	}

	p := &RPCPlugin{}

	for _, tc := range testcases {
		tc := tc
		t.Run(tc.Description, func(t *testing.T) {
			t.Parallel()
			err := test.RunTest(t, tc, p)
			if err != nil {
				t.Error(err)
			}
		})
	}
}

// TestParseRPCInfoOversizedNetworkIDLenNoPanic is a regression test: a declared
// networkIDLen larger than the remaining bytes panicked at response[0:networkIDLen].
func TestParseRPCInfoOversizedNetworkIDLenNoPanic(t *testing.T) {
	resp := make([]byte, 0x20+0x20)
	// After the 0x20 header: program(4) version(4) networkIDLen(4) then 20 bytes remain.
	body := resp[0x20:]
	body[11] = 0x40 // networkIDLen = 64 > 20 remaining

	lookup := &plugins.ServiceRPC{}
	if err := parseRPCInfo(resp, lookup); err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if len(lookup.Entries) != 0 {
		t.Errorf("expected no entries, got %d", len(lookup.Entries))
	}
}
