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
	"unicode"
	"unicode/utf8"
)

// sanitizeHTTPHeaderValue strips control characters (Unicode classes Cc/Cf,
// covering U+0000-U+001F, U+007F, and U+0080-U+009F) and bounds the result
// to 256 bytes. The byte cap is rune-boundary safe — if the cap would split
// a multi-byte UTF-8 rune, the result is trimmed back to the previous valid
// rune boundary.
//
// Used to defang attacker-controlled HTTP header values (e.g. Server header)
// before they are stored in result metadata or written to logs. Intended for
// short identifier-like values; large free-form text should use a dedicated
// formatter.
func sanitizeHTTPHeaderValue(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		if unicode.IsControl(r) {
			continue
		}
		b.WriteRune(r)
	}
	out := b.String()
	if len(out) <= 256 {
		return out
	}
	// Trim back to a valid UTF-8 rune boundary at or before byte 256.
	out = out[:256]
	for !utf8.ValidString(out) && len(out) > 0 {
		out = out[:len(out)-1]
	}
	return out
}
