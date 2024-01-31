// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package x

import (
	"net/url"
	"os"

	"github.com/ory/x/logrusx"
	"github.com/ory/x/urlx"
)

// ParseURLOrPanic parses a url or panics.
// This is the same function as urlx.ParseOrPanic() except that it uses
// urlx.Parse() instead of url.Parse()
func ParseURLOrPanic(in string) *url.URL {
	out, err := urlx.Parse(in)
	if err != nil {
		panic(err.Error())
	}
	return out
}

// ParseURLOrFatal parses a url or fatals.
// This is the same function as urlx.ParseOrFatal() except that it uses
// urlx.Parse() instead of url.Parse()
func ParseURLOrFatal(l *logrusx.Logger, in string) *url.URL {
	out, err := urlx.Parse(in)
	if err != nil {
		l.WithError(err).Fatalf("Unable to parse url: %s", in)
	}
	return out
}

// FileOrContent holds a file path or content.
type FileOrContent string

// String returns the FileOrContent in string format.
func (f FileOrContent) String() string {
	return string(f)
}

func (f FileOrContent) Mask() string {
	if len(f.String()) == 0 || len(f.MustReadString()) == 0 {
		return ""
	}

	return "***"
}

// IsPath returns true if the FileOrContent is a file path, otherwise returns false.
func (f FileOrContent) IsPath() bool {
	_, err := os.Stat(f.String())
	return err == nil
}

func (f FileOrContent) MustRead() []byte {
	content, _ := f.Read()
	return content
}

func (f FileOrContent) MustReadString() string {
	content, _ := f.Read()
	return string(content)
}

// Read returns the content after reading the FileOrContent variable.
func (f FileOrContent) Read() ([]byte, error) {
	var content []byte
	if f.IsPath() {
		var err error
		content, err = os.ReadFile(f.String())
		if err != nil {
			return nil, err
		}
	} else {
		content = []byte(f)
	}
	return content, nil
}
