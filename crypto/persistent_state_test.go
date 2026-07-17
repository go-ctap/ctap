package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/hkdf"
)

func encryptPersistentState(
	t *testing.T,
	pinUvAuthToken,
	iv,
	plaintext []byte,
	info string,
) []byte {
	t.Helper()

	key := make([]byte, aes.BlockSize)
	_, err := io.ReadFull(hkdf.New(
		sha256.New,
		pinUvAuthToken,
		make([]byte, sha256.Size),
		[]byte(info),
	), key)
	require.NoError(t, err)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	ciphertext := make([]byte, aes.BlockSize)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(ciphertext, plaintext)
	return append(bytes.Clone(iv), ciphertext...)
}

func TestDecryptPersistentState(t *testing.T) {
	token := bytes.Repeat([]byte{0x11}, 32)
	identifier := []byte("identifier-12345")
	state := []byte("store-state-1234")

	encryptedIdentifier := encryptPersistentState(
		t,
		token,
		bytes.Repeat([]byte{0x22}, aes.BlockSize),
		identifier,
		"encIdentifier",
	)
	encryptedState := encryptPersistentState(
		t,
		token,
		bytes.Repeat([]byte{0x33}, aes.BlockSize),
		state,
		"encCredStoreState",
	)

	gotIdentifier, err := DecryptAuthenticatorIdentifier(token, encryptedIdentifier)
	require.NoError(t, err)
	assert.Equal(t, identifier, gotIdentifier[:])

	gotState, err := DecryptCredentialStoreState(token, encryptedState)
	require.NoError(t, err)
	assert.Equal(t, state, gotState[:])

	wrongLabel, err := DecryptCredentialStoreState(token, encryptedIdentifier)
	require.NoError(t, err)
	assert.NotEqual(t, identifier, wrongLabel[:])
}

func TestDecryptPersistentStateAcceptsRegeneratedIV(t *testing.T) {
	token := bytes.Repeat([]byte{0x44}, 32)
	plaintext := []byte("store-state-1234")

	first, err := DecryptCredentialStoreState(token, encryptPersistentState(
		t,
		token,
		bytes.Repeat([]byte{0x55}, aes.BlockSize),
		plaintext,
		"encCredStoreState",
	))
	require.NoError(t, err)
	second, err := DecryptCredentialStoreState(token, encryptPersistentState(
		t,
		token,
		bytes.Repeat([]byte{0x66}, aes.BlockSize),
		plaintext,
		"encCredStoreState",
	))
	require.NoError(t, err)

	assert.Equal(t, first, second)
}

func TestDecryptPersistentStateValidatesInput(t *testing.T) {
	_, err := DecryptAuthenticatorIdentifier(nil, make([]byte, 32))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "must not be empty")

	_, err = DecryptAuthenticatorIdentifier(make([]byte, 32), make([]byte, 31))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exactly 32 bytes")
}
