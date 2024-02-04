// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package rule

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFindStringSubmatch(t *testing.T) {
	type args struct {
		pattern      string
		matchAgainst string
	}
	tests := []struct {
		name    string
		args    args
		want    []string
		wantErr bool
	}{
		{
			name: "bad pattern",
			args: args{
				pattern:      `urn:foo:<.?>`,
				matchAgainst: "urn:foo:user",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "bad lookbehind (wrong delimiters)",
			args: args{
				pattern:      `urn:foo:<(?<=foo:)foobar>`,
				matchAgainst: "urn:foo:foobar",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "one group",
			args: args{
				pattern:      `urn:foo:<.*>`,
				matchAgainst: "urn:foo:user",
			},
			want:    []string{"user"},
			wantErr: false,
		},
		{
			name: "several groups",
			args: args{
				pattern:      `urn:foo:<.*>:<.*>`,
				matchAgainst: "urn:foo:user:one",
			},
			want:    []string{"user", "one"},
			wantErr: false,
		},
		{
			name: "classic foo bar",
			args: args{
				pattern:      `urn:foo:<foo|bar>`,
				matchAgainst: "urn:foo:bar",
			},
			want:    []string{"bar"},
			wantErr: false,
		},
		{
			name: "positive lookbehind (?<=foo)bar",
			args: args{
				pattern:      `urn:foo:<<(?<=foo:)foobar>>`,
				matchAgainst: "urn:foo:foobar",
			},
			want:    []string{"foobar"},
			wantErr: false,
		},
		{
			name: "negative lookbehind (?<!boo)foobar",
			args: args{
				pattern:      `urn:foo:<<(?<!boo:)foobar>>`,
				matchAgainst: "urn:foo:foobar",
			},
			want:    []string{"foobar"},
			wantErr: false,
		},
		{
			name: "negative lookbehind (?<!boo)foobar, not match",
			args: args{
				pattern:      `urn:foo:<<(?<!boo:)foobar>>`,
				matchAgainst: "urn:boo:foobar",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "negative lookbehind (?<!boo)foobar, new delimiters",
			args: args{
				pattern:      `urn:foo:<<(?<!boo:)foobar>>`,
				matchAgainst: "urn:foo:foobar",
			},
			want:    []string{"foobar"},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regexpEngine := new(regexpMatchingEngine)
			got, err := regexpEngine.FindStringSubmatch(tt.args.pattern, tt.args.matchAgainst)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindStringSubmatch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.ElementsMatch(t, got, tt.want, "FindStringSubmatch() got = %v, want %v", got, tt.want)
		})
	}
}

func TestFindNamedStringSubmatch(t *testing.T) {
	type args struct {
		pattern      string
		matchAgainst string
	}
	tests := []struct {
		name    string
		args    args
		want    map[string]string
		wantErr bool
	}{
		{
			name: "bad pattern",
			args: args{
				pattern:      `urn:foo:<.?>`,
				matchAgainst: "urn:foo:user",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "bad lookbehind (wrong delimiters)",
			args: args{
				pattern:      `urn:foo:<(?<=foo:)foobar>`,
				matchAgainst: "urn:foo:foobar",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "one group",
			args: args{
				pattern:      `urn:foo:<.*>`,
				matchAgainst: "urn:foo:user",
			},
			want: map[string]string{
				"1": "user",
			},
			wantErr: false,
		},
		{
			name: "several groups",
			args: args{
				pattern:      `urn:foo:<.*>:<.*>`,
				matchAgainst: "urn:foo:user:one",
			},
			want: map[string]string{
				"1": "user",
				"2": "one",
			},
			wantErr: false,
		},
		{
			name: "several groups, some named",
			args: args{
				pattern:      `urn:foo:<<.*>>:<<.*>>:<<(?<named>.*)>>:<<(?<another>.*)>>`,
				matchAgainst: "urn:foo:user:one:ready:two",
			},
			want: map[string]string{
				"1":       "user",
				"2":       "one",
				"3":       "ready",
				"4":       "two",
				"named":   "ready",
				"another": "two",
			},
			wantErr: false,
		},
		{
			name: "classic foo bar",
			args: args{
				pattern:      `urn:foo:<foo|bar>`,
				matchAgainst: "urn:foo:bar",
			},
			want: map[string]string{
				"1": "bar",
			},
			wantErr: false,
		},
		{
			name: "positive lookbehind (?<=foo)bar",
			args: args{
				pattern:      `urn:foo:<<(?<=foo:)foobar>>`,
				matchAgainst: "urn:foo:foobar",
			},
			want:    map[string]string{"1": "foobar"},
			wantErr: false,
		},
		{
			name: "negative lookbehind (?<!boo)foobar",
			args: args{
				pattern:      `urn:foo:<<(?<!boo:)foobar>>`,
				matchAgainst: "urn:foo:foobar",
			},
			want:    map[string]string{"1": "foobar"},
			wantErr: false,
		},
		{
			name: "negative lookbehind (?<!boo)foobar, not match",
			args: args{
				pattern:      `urn:foo:<<(?<!boo:)foobar>>`,
				matchAgainst: "urn:boo:foobar",
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "negative lookbehind (?<!boo)foobar, new delimiters",
			args: args{
				pattern:      `urn:foo:<<(?<!boo:)foobar>>`,
				matchAgainst: "urn:foo:foobar",
			},
			want:    map[string]string{"1": "foobar"},
			wantErr: false,
		},
		{
			name: "complex capture",
			args: args{
				pattern:      `urn:foo:<<(?:(?<foo>abc))(?:\k<foo>.*)>>`,
				matchAgainst: "urn:foo:abcabcabc",
			},
			want: map[string]string{
				"1":   "abcabcabc",
				"foo": "abc",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			regexpEngine := new(regexpMatchingEngine)
			got, err := regexpEngine.FindNamedStringSubmatch(tt.args.pattern, tt.args.matchAgainst)
			if (err != nil) != tt.wantErr {
				t.Errorf("FindStringSubmatch() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.EqualValuesf(t, got, tt.want, "FindNamedStringSubmatch() got = %v, want %v", got, tt.want)
		})
	}
}
