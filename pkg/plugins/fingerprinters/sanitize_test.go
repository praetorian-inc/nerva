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

package fingerprinters

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// ── TestSanitizeHTTPHeaderValue ───────────────────────────────────────────────

func TestSanitizeHTTPHeaderValue(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "Empty string returns empty",
			input: "",
			want:  "",
		},
		{
			name:  "Printable ASCII preserved unchanged",
			input: "Cleo Harmony/5.8.0.21 (Linux)",
			want:  "Cleo Harmony/5.8.0.21 (Linux)",
		},
		{
			name:  "C0 NUL (U+0000) stripped",
			input: "before\x00after",
			want:  "beforeafter",
		},
		{
			name:  "C0 BEL (U+0007) stripped",
			input: "before\x07after",
			want:  "beforeafter",
		},
		{
			name:  "C0 ESC (U+001B) stripped",
			input: "before\x1bafter",
			want:  "beforeafter",
		},
		{
			name:  "DEL (U+007F) stripped",
			input: "before\x7fafter",
			want:  "beforeafter",
		},
		{
			name:  "C1 NEL (U+0085) stripped from middle of valid string",
			input: "CleoHarmony",
			want:  "CleoHarmony",
		},
		{
			name:  "C1 DCS (U+0090) stripped",
			input: "beforeafter",
			want:  "beforeafter",
		},
		{
			name:  "All C0/C1/DEL combined stripped, printables preserved",
			input: "A\x00B\x07C\x1bD\x7fEFG",
			want:  "ABCDEFG",
		},
		{
			name:  "257-byte ASCII input truncated to 256",
			input: strings.Repeat("a", 257),
			want:  strings.Repeat("a", 256),
		},
		{
			name: "UTF-8 boundary safety: multi-byte rune straddling byte 256 trimmed back",
			// 255 ASCII bytes + "é" (0xC3 0xA9, 2 bytes) = 257 bytes total.
			// Naive cap at 256 would split "é"; result must trim back to the
			// previous valid rune boundary (255 ASCII bytes only).
			input: strings.Repeat("a", 255) + "é",
			want:  strings.Repeat("a", 255),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sanitizeHTTPHeaderValue(tt.input)
			if got != tt.want {
				t.Errorf("sanitizeHTTPHeaderValue(%q) = %q, want %q", tt.input, got, tt.want)
			}
			// Defensive invariant: output must always be valid UTF-8 and
			// must never exceed the 256-byte cap, regardless of input.
			if !utf8.ValidString(got) {
				t.Errorf("sanitizeHTTPHeaderValue(%q) returned invalid UTF-8: %q", tt.input, got)
			}
			if len(got) > 256 {
				t.Errorf("sanitizeHTTPHeaderValue(%q) returned %d bytes, exceeds 256-byte cap", tt.input, len(got))
			}
		})
	}
}
