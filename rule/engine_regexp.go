// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"hash/crc64"
	"strings"

	"github.com/pkg/errors"

	"github.com/dlclark/regexp2"

	"github.com/ory/ladon/compiler"
)

type regexpMatchingEngine struct {
	compiled *regexp2.Regexp
	checksum uint64
	table    *crc64.Table
}

func (re *regexpMatchingEngine) compile(pattern string) error {
	if re.table == nil {
		re.table = crc64.MakeTable(polynomial)
	}
	if checksum := crc64.Checksum([]byte(pattern), re.table); checksum != re.checksum {
		startDelim := byte('<')
		endDelim := byte('>')
		if strings.Contains(pattern, "(?>") || strings.Contains(pattern, "(?<") {
			pattern = strings.ReplaceAll(pattern, "<<", "«")
			pattern = strings.ReplaceAll(pattern, ">>", "»")
			if strings.ContainsRune(pattern, '«') && strings.ContainsRune(pattern, '»') {
				startDelim = byte('«')
				endDelim = byte('»')
			} else {
				return errors.Errorf("attempted to use regex 'possessive match' or regex 'lookbehind' without changing delimiters from '<...>' to '<<...>>' in: %s", pattern)
			}
		}
		compiled, err := compiler.CompileRegex(pattern, startDelim, endDelim)
		if err != nil {
			return err
		}
		re.compiled = compiled
		re.checksum = checksum
	}
	return nil
}

// Checksum of a saved pattern.
func (re *regexpMatchingEngine) Checksum() uint64 {
	return re.checksum
}

// IsMatching determines whether the input matches the pattern.
func (re *regexpMatchingEngine) IsMatching(pattern, matchAgainst string) (bool, error) {
	if err := re.compile(pattern); err != nil {
		return false, err
	}
	return re.compiled.MatchString(matchAgainst)
}

// ReplaceAllString replaces all matches in `input` with `replacement`.
func (re *regexpMatchingEngine) ReplaceAllString(pattern, input, replacement string) (string, error) {
	if err := re.compile(pattern); err != nil {
		return "", err
	}
	return re.compiled.Replace(input, replacement, -1, -1)
}

// FindStringSubmatch returns all captures in matchAgainst following the pattern
func (re *regexpMatchingEngine) FindStringSubmatch(pattern, matchAgainst string) ([]string, error) {
	if err := re.compile(pattern); err != nil {
		return nil, err
	}

	m, _ := re.compiled.FindStringMatch(matchAgainst)
	if m == nil {
		return nil, errors.New("not match")
	}

	result := []string{}
	for _, group := range m.Groups()[1:] {
		result = append(result, group.String())
	}

	return result, nil
}
