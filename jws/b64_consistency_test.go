package jws_test

import (
	"bytes"
	"io"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

func TestSignRejectsInconsistentB64(t *testing.T) {
	t.Parallel()

	payload := []byte("shared-payload")

	key1, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)
	key2, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	unencoded := func() jws.Headers {
		hdr := jws.NewHeaders()
		require.NoError(t, hdr.Set(jws.B64Key, false))
		require.NoError(t, hdr.Set(jws.CriticalKey, []string{jws.B64Key}))
		return hdr
	}

	orders := []struct {
		name  string
		first jws.Headers
		last  jws.Headers
	}{
		{name: "false then default", first: unencoded(), last: nil},
		{name: "default then false", first: nil, last: unencoded()},
	}

	for _, order := range orders {
		order := order
		t.Run(order.name, func(t *testing.T) {
			t.Parallel()

			signers := func() []jws.SignOption {
				opts := []jws.SignOption{jws.WithJSON()}
				if order.first != nil {
					opts = append(opts, jws.WithKey(jwa.HS256(), key1, jws.WithProtectedHeaders(order.first)))
				} else {
					opts = append(opts, jws.WithKey(jwa.HS256(), key1))
				}
				if order.last != nil {
					opts = append(opts, jws.WithKey(jwa.HS256(), key2, jws.WithProtectedHeaders(order.last)))
				} else {
					opts = append(opts, jws.WithKey(jwa.HS256(), key2))
				}
				return opts
			}

			t.Run("in-band", func(t *testing.T) {
				t.Parallel()

				signed, err := jws.Sign(payload, signers()...)
				require.Error(t, err)
				require.Nil(t, signed)
				require.ErrorIs(t, err, jws.SignError())
				require.ErrorContains(t, err, `"b64"`)
			})

			t.Run("detached payload", func(t *testing.T) {
				t.Parallel()

				signed, err := jws.Sign(nil, append(signers(), jws.WithDetachedPayload(payload))...)
				require.Error(t, err)
				require.Nil(t, signed)
				require.ErrorIs(t, err, jws.SignError())
				require.ErrorContains(t, err, `"b64"`)
			})

			t.Run("streaming detached payload", func(t *testing.T) {
				t.Parallel()

				reader := &b64TrackingReader{r: bytes.NewReader(payload)}
				signed, err := jws.Sign(nil, append(signers(), jws.WithDetachedPayloadReader(reader))...)
				require.Error(t, err)
				require.Nil(t, signed)
				require.ErrorIs(t, err, jws.SignError())
				require.ErrorContains(t, err, `"b64"`)
				require.False(t, reader.read, `Sign must reject inconsistent b64 before reading the payload`)
			})
		})
	}
}

func TestSignAcceptsDefaultAndExplicitTrueB64(t *testing.T) {
	t.Parallel()

	payload := []byte("shared-payload")

	key1, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)
	key2, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err)

	explicitTrue := jws.NewHeaders()
	require.NoError(t, explicitTrue.Set(jws.B64Key, true))

	signed, err := jws.Sign(payload,
		jws.WithJSON(),
		jws.WithKey(jwa.HS256(), key1, jws.WithProtectedHeaders(explicitTrue)),
		jws.WithKey(jwa.HS256(), key2),
	)
	require.NoError(t, err)

	for _, key := range []any{key1, key2} {
		got, err := jws.Verify(signed, jws.WithKey(jwa.HS256(), key))
		require.NoError(t, err)
		require.Equal(t, payload, got)
	}
}

type b64TrackingReader struct {
	r    io.Reader
	read bool
}

func (r *b64TrackingReader) Read(p []byte) (int, error) {
	r.read = true
	return r.r.Read(p)
}
