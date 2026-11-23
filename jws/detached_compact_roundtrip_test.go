package jws_test

import (
	"encoding/json"
	"testing"

	"github.com/lestrrat-go/jwx/v4/internal/jwxtest"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jws"
	"github.com/stretchr/testify/require"
)

// TestDetachedCompactRoundTrip pins the parse/serialize model for compact
// JWS messages whose middle segment is empty. That wire form is produced by
// jws.Sign with jws.WithDetachedPayload (RFC 7515 Appendix F); the compact
// serialization cannot distinguish it from an in-band JWS over an empty
// payload, so parse() must record it with the same detached state that
// UnmarshalJSON records when the "payload" member is omitted.
//
// Before the fix, parse() only tracked payload *presence* and left the
// detached flag false. A detached compact JWS parsed and re-marshaled to
// JSON therefore grew an in-band "payload":"" member, and a subsequent
// jws.Verify with jws.WithDetachedPayload rejected it with
// "can't specify detached payload for JWS with payload".
func TestDetachedCompactRoundTrip(t *testing.T) {
	t.Parallel()

	external := []byte("Lorem ipsum dolor sit amet")

	privkey, err := jwxtest.GenerateRsaKey()
	require.NoError(t, err, `jwxtest.GenerateRsaKey should succeed`)
	pubkey := &privkey.PublicKey

	compact, err := jws.Sign(nil, jws.WithKey(jwa.RS256(), privkey), jws.WithDetachedPayload(external))
	require.NoError(t, err, `jws.Sign (detached) should succeed`)

	t.Run("JSON marshal omits payload member", func(t *testing.T) {
		t.Parallel()
		msg, err := jws.Parse(compact)
		require.NoError(t, err, `jws.Parse should succeed`)

		jsonbuf, err := json.Marshal(msg)
		require.NoError(t, err, `json.Marshal should succeed`)

		var obj map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(jsonbuf, &obj), `json.Unmarshal should succeed`)
		_, present := obj["payload"]
		require.False(t, present, `parsed detached compact JWS must not gain a "payload" member on JSON marshal: %s`, jsonbuf)
	})

	t.Run("JSON round trip still verifies with detached payload", func(t *testing.T) {
		t.Parallel()
		msg, err := jws.Parse(compact)
		require.NoError(t, err, `jws.Parse should succeed`)

		jsonbuf, err := json.Marshal(msg)
		require.NoError(t, err, `json.Marshal should succeed`)

		payload, err := jws.Verify(jsonbuf, jws.WithKey(jwa.RS256(), pubkey), jws.WithDetachedPayload(external))
		require.NoError(t, err, `jws.Verify after JSON round trip should accept the detached payload`)
		require.Equal(t, external, payload, `verified payload should round-trip`)
	})

	t.Run("compact re-serialization is byte-identical", func(t *testing.T) {
		t.Parallel()
		msg, err := jws.Parse(compact)
		require.NoError(t, err, `jws.Parse should succeed`)

		out, err := jws.Compact(msg)
		require.NoError(t, err, `jws.Compact should succeed`)
		require.Equal(t, compact, out, `re-serialized compact JWS must keep its empty middle segment`)
	})

	t.Run("parsed message keeps verifying through compact form", func(t *testing.T) {
		t.Parallel()
		msg, err := jws.Parse(compact)
		require.NoError(t, err, `jws.Parse should succeed`)

		out, err := jws.Compact(msg)
		require.NoError(t, err, `jws.Compact should succeed`)

		payload, err := jws.Verify(out, jws.WithKey(jwa.RS256(), pubkey), jws.WithDetachedPayload(external))
		require.NoError(t, err, `jws.Verify after compact round trip should accept the detached payload`)
		require.Equal(t, external, payload, `verified payload should round-trip`)
	})

	t.Run("in-band compact payload keeps payload member after JSON marshal", func(t *testing.T) {
		t.Parallel()
		// A non-empty middle segment is unambiguously in-band and must keep
		// its "payload" member (and stay rejected when a detached payload is
		// supplied), guarding the fix against over-broad detachment marking.
		inband, err := jws.Sign(external, jws.WithKey(jwa.RS256(), privkey))
		require.NoError(t, err, `jws.Sign (in-band) should succeed`)

		msg, err := jws.Parse(inband)
		require.NoError(t, err, `jws.Parse should succeed`)

		jsonbuf, err := json.Marshal(msg)
		require.NoError(t, err, `json.Marshal should succeed`)

		var obj map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(jsonbuf, &obj), `json.Unmarshal should succeed`)
		_, present := obj["payload"]
		require.True(t, present, `in-band compact JWS must keep its "payload" member: %s`, jsonbuf)

		_, err = jws.Verify(inband, jws.WithKey(jwa.RS256(), pubkey), jws.WithDetachedPayload(external))
		require.Error(t, err, `jws.Verify must reject detached option for an in-band JWS`)
	})
}

// TestDetachedCompactRoundTripB64False covers the RFC 7797 b64=false variant:
// a detached compact JWS with an unencoded payload still parses with the
// detached state set, so JSON marshal omits "payload" and re-serialization
// preserves the empty middle segment.
func TestDetachedCompactRoundTripB64False(t *testing.T) {
	t.Parallel()

	external := []byte("unencoded detached payload")
	key, err := jwxtest.GenerateSymmetricJwk()
	require.NoError(t, err, `jwxtest.GenerateSymmetricJwk should succeed`)

	hdrs := jws.NewHeaders()
	require.NoError(t, hdrs.Set("b64", false))
	require.NoError(t, hdrs.Set(jws.CriticalKey, []string{"b64"}))

	compact, err := jws.Sign(nil,
		jws.WithKey(jwa.HS256(), key, jws.WithProtectedHeaders(hdrs)),
		jws.WithDetachedPayload(external),
	)
	require.NoError(t, err, `jws.Sign (detached, b64=false) should succeed`)

	msg, err := jws.Parse(compact)
	require.NoError(t, err, `jws.Parse should succeed`)

	jsonbuf, err := json.Marshal(msg)
	require.NoError(t, err, `json.Marshal should succeed`)

	var obj map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(jsonbuf, &obj), `json.Unmarshal should succeed`)
	_, present := obj["payload"]
	require.False(t, present, `b64=false detached compact JWS must not gain a "payload" member: %s`, jsonbuf)

	out, err := jws.Compact(msg)
	require.NoError(t, err, `jws.Compact should succeed`)
	require.Equal(t, compact, out, `b64=false compact re-serialization must stay detached`)

	payload, err := jws.Verify(out, jws.WithKey(jwa.HS256(), key), jws.WithDetachedPayload(external))
	require.NoError(t, err, `jws.Verify (detached, b64=false) should succeed`)
	require.Equal(t, external, payload, `verified payload should round-trip`)
}
