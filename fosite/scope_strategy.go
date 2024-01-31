// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package fosite

import "strings"

// ScopeStrategy is a strategy for matching scopes.
type ScopeStrategy func(haystack []string, needle string) bool

func HierarchicScopeStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		// foo == foo -> true
		if this == needle {
			return true
		}

		// picture.read > picture -> false (scope picture includes read, write, ...)
		if len(this) > len(needle) {
			continue
		}

		needles := strings.Split(needle, ".")
		currentHaystack := strings.Split(this, ".")
		haystackLen := len(currentHaystack) - 1
		for k, currentNeedle := range needles {
			if haystackLen < k {
				return true
			}

			current := currentHaystack[k]
			if current != currentNeedle {
				break
			}
		}
	}

	return false
}

func ExactScopeStrategy(haystack []string, needle string) bool {
	for _, this := range haystack {
		if needle == this {
			return true
		}
	}

	return false
}

func WildcardScopeStrategy(haystack []string, needle string) bool {
	for _, pattern := range haystack {
		if matchPattern(pattern, needle) {
			return true
		}
	}

	return false
}

// matchPattern implements wildcard scope matching with segment semantics.
//
//   - Scopes are dot-separated segments.
//   - "+" matches exactly one non-empty segment.
//   - "*" matches zero or more segments (deep wildcard).
//   - Literal segments must match exactly.
//
// There are no allocations: we operate directly on the string with indices.
//
// Examples:
//
//	pattern: "a.+.c",  candidate: "a.b.c"         => true
//	pattern: "a.+.c",  candidate: "a..c"          => false (empty segment)
//	pattern: "a.*",    candidate: "a"             => true
//	pattern: "a.*",    candidate: "a.b.c.d"       => true
//	pattern: "a.b.*.d", candidate: "a.b.d"        => true  (* = zero segments)
//	pattern: "a.b.*.d", candidate: "a.b.c.d"      => true
//	pattern: "x.*.y",   candidate: "x.y"          => true
//	pattern: "x.*.y",   candidate: "x.a.b.y"      => true
func matchPattern(pattern, candidate string) bool {
	// Reject candidates with empty segments: leading '.', trailing '.', or ".."
	if hasEmptySegment(candidate) {
		return false
	}
	return matchFrom(pattern, 0, candidate, 0)
}

// hasEmptySegment returns true if s has any empty segment: leading '.', trailing '.',
// or two consecutive dots.
func hasEmptySegment(s string) bool {
	if len(s) == 0 {
		return false
	}
	if s[0] == '.' || s[len(s)-1] == '.' {
		return true
	}
	for i := 1; i < len(s); i++ {
		if s[i] == '.' && s[i-1] == '.' {
			return true
		}
	}
	return false
}

// matchFrom matches pattern[pi:] against candidate[ci:] with segment semantics.
func matchFrom(pattern string, pi int, candidate string, ci int) bool {
	// Both pattern and candidate consumed
	if pi >= len(pattern) && ci >= len(candidate) {
		return true
	}
	// Pattern consumed but candidate not
	if pi >= len(pattern) {
		return false
	}

	// Parse next pattern segment: [pStart, pEnd), and compute nextPi after optional '.'
	pStart := pi
	for pi < len(pattern) && pattern[pi] != '.' {
		pi++
	}
	pEnd := pi
	nextPi := pi
	if nextPi < len(pattern) && pattern[nextPi] == '.' {
		nextPi++
	}

	// Handle "*": deep wildcard, zero or more segments
	if pEnd-pStart == 1 && pattern[pStart] == '*' {
		// If "*" is the last pattern segment, we match any remaining candidate segments.
		if nextPi >= len(pattern) {
			return true
		}

		// Try to match the remainder of the pattern with candidate starting at:
		//   - the current segment (zero segments consumed by '*')
		//   - after consuming 1 segment
		//   - after consuming 2 segments
		//   - ...
		ciTry := ci
		for {
			if matchFrom(pattern, nextPi, candidate, ciTry) {
				return true
			}
			// Advance ciTry to the next segment boundary
			if ciTry >= len(candidate) {
				break
			}
			// Skip current segment
			for ciTry < len(candidate) && candidate[ciTry] != '.' {
				ciTry++
			}
			// Skip '.' if present
			if ciTry < len(candidate) && candidate[ciTry] == '.' {
				ciTry++
			}
		}
		return false
	}

	// For "+" or literal, we need a candidate segment available
	if ci >= len(candidate) {
		return false
	}
	// Candidate must not start on '.' (empty segment is already filtered, but this is safe)
	if candidate[ci] == '.' {
		return false
	}

	// Parse next candidate segment: [cStart, cEnd), and compute nextCi
	cStart := ci
	for ci < len(candidate) && candidate[ci] != '.' {
		ci++
	}
	cEnd := ci
	nextCi := ci
	if nextCi < len(candidate) && candidate[nextCi] == '.' {
		nextCi++
	}

	// "+" matches exactly one non-empty segment (any content)
	if pEnd-pStart == 1 && pattern[pStart] == '+' {
		// cStart..cEnd is guaranteed non-empty here
		return matchFrom(pattern, nextPi, candidate, nextCi)
	}

	// Literal segment: must match exactly in length and content
	if pEnd-pStart != cEnd-cStart {
		return false
	}
	for k := 0; k < pEnd-pStart; k++ {
		if pattern[pStart+k] != candidate[cStart+k] {
			return false
		}
	}
	return matchFrom(pattern, nextPi, candidate, nextCi)
}
