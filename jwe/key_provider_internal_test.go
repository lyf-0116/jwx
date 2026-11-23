package jwe

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwk"
	"github.com/stretchr/testify/require"
)

// TestKeySetProviderKeyOps verifies that key selection consults key_ops
// and maps the key-management algorithm to the right operation. In
// particular, key-wrapping algorithms require unwrapKey rather than
// decrypt.
func TestKeySetProviderKeyOps(t *testing.T) {
	t.Parallel()

	rsaRaw, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	newRSAKey := func(t *testing.T, ops jwk.KeyOperationList) jwk.Key {
		t.Helper()
		key, err := jwk.Import[jwk.Key](rsaRaw)
		require.NoError(t, err)
		require.NoError(t, key.Set(jwk.KeyIDKey, "encryption-kid"))
		require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.RSA_OAEP()))
		if ops != nil {
			require.NoError(t, key.Set(jwk.KeyOpsKey, ops))
		}
		return key
	}

	recipient := NewRecipient()
	require.NoError(t, recipient.Headers().Set(AlgorithmKey, jwa.RSA_OAEP()))

	t.Run("sign-only key rejected", func(t *testing.T) {
		t.Parallel()

		key := newRSAKey(t, jwk.KeyOperationList{jwk.KeyOpSign, jwk.KeyOpVerify})
		kp := &keySetProvider{}
		sink := &recordingKeySink{}

		err := kp.selectKey(sink, key, recipient, NewMessage())
		require.Error(t, err)
		require.Empty(t, sink.keys)
		require.Contains(t, err.Error(), `encryption-kid`)
		require.Contains(t, err.Error(), `key_ops=`)
		require.Contains(t, err.Error(), `not usable for decryption`)
		require.Contains(t, err.Error(), `unwrapKey`)
	})

	t.Run("unwrapKey accepted for wrapping algorithm", func(t *testing.T) {
		t.Parallel()

		key := newRSAKey(t, jwk.KeyOperationList{jwk.KeyOpWrapKey, jwk.KeyOpUnwrapKey})
		kp := &keySetProvider{}
		sink := &recordingKeySink{}

		require.NoError(t, kp.selectKey(sink, key, recipient, NewMessage()))
		require.Len(t, sink.keys, 1)
	})

	t.Run("decrypt rejected for wrapping algorithm", func(t *testing.T) {
		t.Parallel()

		key := newRSAKey(t, jwk.KeyOperationList{jwk.KeyOpEncrypt, jwk.KeyOpDecrypt})
		kp := &keySetProvider{}
		sink := &recordingKeySink{}

		err := kp.selectKey(sink, key, recipient, NewMessage())
		require.Error(t, err)
		require.Empty(t, sink.keys)
	})

	t.Run("missing key_ops accepted", func(t *testing.T) {
		t.Parallel()

		key := newRSAKey(t, nil)
		kp := &keySetProvider{}
		sink := &recordingKeySink{}

		require.NoError(t, kp.selectKey(sink, key, recipient, NewMessage()))
		require.Len(t, sink.keys, 1)
	})

	t.Run("direct mode requires decrypt", func(t *testing.T) {
		t.Parallel()

		key, err := jwk.Import[jwk.Key]([]byte("0123456789abcdef"))
		require.NoError(t, err)
		require.NoError(t, key.Set(jwk.AlgorithmKey, jwa.DIRECT()))

		rec := NewRecipient()
		require.NoError(t, rec.Headers().Set(AlgorithmKey, jwa.DIRECT()))
		kp := &keySetProvider{}

		require.NoError(t, key.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpEncrypt, jwk.KeyOpDecrypt}))
		sink := &recordingKeySink{}
		require.NoError(t, kp.selectKey(sink, key, rec, NewMessage()))
		require.Len(t, sink.keys, 1)

		require.NoError(t, key.Set(jwk.KeyOpsKey, jwk.KeyOperationList{jwk.KeyOpSign, jwk.KeyOpVerify}))
		sink = &recordingKeySink{}
		require.Error(t, kp.selectKey(sink, key, rec, NewMessage()))
		require.Empty(t, sink.keys)
	})
}
