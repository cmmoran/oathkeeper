// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"bytes"
	"cmp"
	"encoding/json"
	stderrors "errors"
	"fmt"
	regexp "github.com/dlclark/regexp2"
	"github.com/ory/herodot"
	"github.com/pkg/errors"
	"io"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/oklog/ulid"

	"github.com/ory/oathkeeper/credentials"
	"github.com/ory/oathkeeper/driver/configuration"
	"github.com/ory/oathkeeper/pipeline"
	"github.com/ory/x/otelx"
)

const (
	challenge              = "challenge"
	defaultSignatureHeader = "x-jwks-signature"
	defaultKidHeader       = "x-jwks-signature-kid"
	defaultIssuerHeader    = "x-jwks-issuer"
	regexPrefix            = "regex:"
	regexpPrefix           = "regexp:"
	insecurePrefix         = "http://"
)

type reusableReader struct {
	io.Reader
	readBuf *bytes.Buffer
	backBuf *bytes.Buffer
}

type Headers struct {
	Signature *string `json:"signature,omitempty"`
	Kid       *string `json:"kid,omitempty"`
	Issuer    *string `json:"issuer"`
}

type Authority struct {
	Headers             Headers  `json:"headers"`
	AllowedIssuers      []string `json:"allowed_issuers"`
	allowedIssuersRegex []*regexp.Regexp
}

type AuthenticatorPre9421Config struct {
	Authorities     []Authority `json:"authorities"`
	MaxChallengeAge string      `json:"max_challenge_age"`
	AllowInsecure   bool        `json:"allow_insecure"`
}

type AuthenticatorPre9421 struct {
	c               configuration.Provider
	r               AuthenticatorJWTRegistry
	maxChallengeAge time.Duration
}

func NewAuthenticatorPre9421(
	c configuration.Provider,
	r AuthenticatorJWTRegistry,
) *AuthenticatorPre9421 {
	return &AuthenticatorPre9421{
		c: c,
		r: r,
	}
}

func (x *AuthenticatorPre9421) Authenticate(r *http.Request, _ *AuthenticationSession, config json.RawMessage, _ pipeline.Rule) (err error) {
	ctx, span := x.r.Tracer().Start(r.Context(), "pipeline.authn.AuthenticatorPre9421.Authenticate")
	defer otelx.End(span, &err)
	*r = *(r.WithContext(ctx))

	cf, err := x.Config(config)
	if err != nil {
		return err
	}

	if len(cf.Authorities) == 0 {
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}

	body := new(bytes.Buffer)
	var (
		invalid bool
		id      *ulid.ULID
	)

	switch {
	case hasRequestBody(r):
		r.Body = io.NopCloser(newReusableReader(r.Body))
		if _, err = body.ReadFrom(r.Body); err != nil {
			invalid = true
		}
	case hasQueryParams(r):
		var uid ulid.ULID
		if r.URL != nil {
			if x.maxChallengeAge > 0 {
				if _, ok := r.URL.Query()[challenge]; ok {
					if uid, err = ulid.Parse(r.URL.Query().Get(challenge)); err == nil {
						id = &uid
					} else {
						id = nil
						invalid = true
					}
				} else {
					invalid = true
				}
			}
		}
		body = bytes.NewBufferString(r.URL.RawQuery)
	default:
		invalid = true
	}

	if invalid {
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}

	if id != nil {
		now := time.Now().UTC()
		idTime := ulid.Time(id.Time()).UTC()
		jitter := 30 * time.Second
		if x.maxChallengeAge > 0 && now.Sub(idTime) > x.maxChallengeAge+jitter {
			return errors.WithStack(ErrAuthenticatorNotResponsible)
		}
	}

	for _, authority := range cf.Authorities {
		var signature, issuer, kid string

		if authority.Headers.Signature == nil {
			signature = r.Header.Get(defaultSignatureHeader)
		} else {
			signature = r.Header.Get(cmp.Or(*authority.Headers.Signature, defaultSignatureHeader))
		}
		if len(signature) == 0 {
			continue
		}
		if authority.Headers.Kid == nil {
			kid = r.Header.Get(defaultKidHeader)
		} else {
			kid = r.Header.Get(cmp.Or(*authority.Headers.Kid, defaultKidHeader))
		}
		if len(kid) == 0 {
			continue
		}
		if authority.Headers.Issuer == nil {
			issuer = r.Header.Get(defaultIssuerHeader)
		} else {
			issuer = r.Header.Get(cmp.Or(*authority.Headers.Issuer, defaultIssuerHeader))
		}
		if len(issuer) == 0 {
			continue
		}

		if !cf.allowedIssuer(issuer) {
			continue
		}

		issuerUrl := fmt.Sprintf("%s/.well-known/jwks.json", issuer)
		jwksu, jerr := x.c.ParseURLs([]string{issuerUrl})
		if jerr != nil {
			err = stderrors.Join(err, jerr)
		}
		if err = x.r.CredentialsVerifier().VerifyPayload(r.Context(), &credentials.ValidationContext{
			KeyURLs: jwksu,
			Issuers: []string{issuer},
			KeyIDs:  []string{kid},
		}, signature, body.Bytes()); err == nil {
			return nil
		}
	}

	return herodot.ErrUnauthorized.WithTrace(err).WithDetail("payload", body.String())
}

func (x *AuthenticatorPre9421Config) allowedIssuer(issuer string) bool {
	if len(x.Authorities) == 0 {
		return false
	}
	if strings.HasPrefix(issuer, insecurePrefix) && !x.AllowInsecure {
		return false
	}
	for _, authority := range x.Authorities {
		if len(authority.AllowedIssuers) == 0 {
			continue
		}
		if len(authority.allowedIssuersRegex) == 0 {
			if slices.Contains(authority.AllowedIssuers, issuer) {
				return true
			}
		}
		for _, r := range authority.allowedIssuersRegex {
			if matches, err := r.MatchString(issuer); matches && err == nil {
				return true
			}
		}
	}

	return false
}

func newReusableReader(r io.Reader) io.Reader {
	readBuf := bytes.Buffer{}
	_, _ = readBuf.ReadFrom(r) // error handling ignored for brevity
	backBuf := bytes.Buffer{}

	return reusableReader{
		io.TeeReader(&readBuf, &backBuf),
		&readBuf,
		&backBuf,
	}
}

func (r reusableReader) reset() {
	_, _ = io.Copy(r.readBuf, r.backBuf) // nolint: errcheck
}

func (r reusableReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if err == io.EOF {
		r.reset()
	}
	return n, err
}

func hasRequestBody(r *http.Request) bool {
	if r == nil || r.Body == nil {
		return false
	}

	// Peek into the body safely
	buf := make([]byte, 1)
	n, err := r.Body.Read(buf)
	if n > 0 {
		// Body exists; restore it for further reading
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(buf[:n]), r.Body))
		return true
	}

	if err != nil && err != io.EOF {
		return false
	}
	return false
}

func hasQueryParams(r *http.Request) bool {
	return r != nil && r.URL != nil && r.URL.RawQuery != ""
}

func (x *AuthenticatorPre9421) GetID() string {
	return "http_message_signing_pre9421"
}

func (x *AuthenticatorPre9421) Validate(config json.RawMessage) error {
	if !x.c.AuthenticatorIsEnabled(x.GetID()) {
		return NewErrAuthenticatorNotEnabled(x)
	}

	_, err := x.Config(config)
	return err
}

func (x *AuthenticatorPre9421) Config(config json.RawMessage) (*AuthenticatorPre9421Config, error) {
	var c AuthenticatorPre9421Config
	if err := x.c.AuthenticatorConfig(x.GetID(), config, &c); err != nil {
		return nil, NewErrAuthenticatorMisconfigured(x, err)
	}
	var (
		err    error
		maxAge = 30 * time.Second
	)
	if c.MaxChallengeAge != "" {
		maxAge, err = time.ParseDuration(c.MaxChallengeAge)
		if err != nil {
			return nil, err
		}
	} else {
		c.MaxChallengeAge = "30s"
	}

	x.maxChallengeAge = maxAge

	for i, authority := range c.Authorities {
		c.Authorities[i].allowedIssuersRegex = make([]*regexp.Regexp, 0)
		for _, allowedIssuer := range authority.AllowedIssuers {
			hasRegexPrefix := strings.HasPrefix(allowedIssuer, regexPrefix)
			hasRegexpPrefix := strings.HasPrefix(allowedIssuer, regexpPrefix)
			if hasRegexPrefix {
				allowedIssuer = strings.TrimPrefix(allowedIssuer, regexPrefix)
			} else {
				allowedIssuer = strings.TrimPrefix(allowedIssuer, regexpPrefix)
			}
			if hasRegexPrefix || hasRegexpPrefix {
				if !strings.HasPrefix(allowedIssuer, "^") {
					allowedIssuer = fmt.Sprintf("^%s", allowedIssuer)
				}
				if !strings.HasSuffix(allowedIssuer, "$") {
					allowedIssuer = fmt.Sprintf("%s$", allowedIssuer)
				}
				if regex, regexpErr := regexp.Compile(allowedIssuer, regexp.RE2); regexpErr == nil {
					c.Authorities[i].allowedIssuersRegex = append(c.Authorities[i].allowedIssuersRegex, regex)
				}
			}
		}
	}

	return &c, nil
}
