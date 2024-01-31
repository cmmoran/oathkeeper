// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package authz

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/pkg/errors"

	"github.com/ory/oathkeeper/credentials"
	"github.com/ory/x/urlx"
)

func pipeRequestBody(r *http.Request, w io.Writer) error {
	if r.Body == nil {
		return nil
	}

	var body bytes.Buffer
	defer r.Body.Close() //nolint:errcheck
	_, err := io.Copy(w, io.TeeReader(r.Body, &body))
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(&body)
	return err
}

func signPayload(ctx context.Context, credSigner credentials.Signer, req *http.Request, body bytes.Buffer, header, sharedKey, jwksUrl, issuer string) (err error) {
	if (sharedKey != "") == (jwksUrl != "") {
		return errors.Wrap(err, "exactly one of hmac.shared_key or hmac.jwks_url must be specified")
	}

	if sharedKey != "" {
		sig := sign(body.Bytes(), []byte(sharedKey))
		if header == "" {
			header = "X-Request-Signature"
		}
		req.Header.Add(header, sig)
	} else if jwksUrl != "" {
		var (
			jwks                *url.URL
			sig, keyId, bodyStr string
		)
		if jwks, err = urlx.Parse(jwksUrl); err != nil {
			return errors.WithStack(err)
		}
		bodyStr = body.String()
		if sig, keyId, err = credSigner.SignPayload(ctx, jwks, bodyStr); err != nil {
			return errors.WithStack(err)
		} else {
			if header == "" {
				header = "X-Jwks-Signature"
			}
			req.Header.Add(header, sig)
			kidHeader := fmt.Sprintf("%s-Kid", header)
			req.Header.Add(kidHeader, keyId)
			if len(issuer) > 0 {
				header = "X-Jwks-Issuer"
				req.Header.Add(header, issuer)
			}
		}
	}
	return nil
}
