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

func encryptGetInfoMember(
	t *testing.T,
	persistentPinUvAuthToken,
	iv,
	plaintext []byte,
	info string,
) []byte {
	t.Helper()

	key := make([]byte, aes.BlockSize)
	_, err := io.ReadFull(hkdf.New(
		sha256.New,
		persistentPinUvAuthToken,
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

func TestDecryptDeviceIdentifierAndCredentialStoreState(t *testing.T) {
	persistentPinUvAuthToken := bytes.Repeat([]byte{0x11}, 32)
	deviceIdentifier := []byte("identifier-12345")
	credentialStoreState := []byte("store-state-1234")

	encIdentifier := encryptGetInfoMember(
		t,
		persistentPinUvAuthToken,
		bytes.Repeat([]byte{0x22}, aes.BlockSize),
		deviceIdentifier,
		"encIdentifier",
	)
	encCredStoreState := encryptGetInfoMember(
		t,
		persistentPinUvAuthToken,
		bytes.Repeat([]byte{0x33}, aes.BlockSize),
		credentialStoreState,
		"encCredStoreState",
	)

	gotDeviceIdentifier, err := DecryptDeviceIdentifier(
		persistentPinUvAuthToken,
		encIdentifier,
	)
	require.NoError(t, err)
	assert.Equal(t, deviceIdentifier, gotDeviceIdentifier[:])

	gotCredentialStoreState, err := DecryptCredentialStoreState(
		persistentPinUvAuthToken,
		encCredStoreState,
	)
	require.NoError(t, err)
	assert.Equal(t, credentialStoreState, gotCredentialStoreState[:])

	wrongLabel, err := DecryptCredentialStoreState(persistentPinUvAuthToken, encIdentifier)
	require.NoError(t, err)
	assert.NotEqual(t, deviceIdentifier, wrongLabel[:])
}

func TestDecryptCredentialStoreStateAcceptsRegeneratedIV(t *testing.T) {
	persistentPinUvAuthToken := bytes.Repeat([]byte{0x44}, 32)
	credentialStoreState := []byte("store-state-1234")

	first, err := DecryptCredentialStoreState(
		persistentPinUvAuthToken,
		encryptGetInfoMember(
			t,
			persistentPinUvAuthToken,
			bytes.Repeat([]byte{0x55}, aes.BlockSize),
			credentialStoreState,
			"encCredStoreState",
		),
	)
	require.NoError(t, err)
	second, err := DecryptCredentialStoreState(
		persistentPinUvAuthToken,
		encryptGetInfoMember(
			t,
			persistentPinUvAuthToken,
			bytes.Repeat([]byte{0x66}, aes.BlockSize),
			credentialStoreState,
			"encCredStoreState",
		),
	)
	require.NoError(t, err)

	assert.Equal(t, first, second)
}

func TestDecryptGetInfoMembersValidateInput(t *testing.T) {
	_, err := DecryptDeviceIdentifier(nil, make([]byte, 32))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "persistentPinUvAuthToken must not be empty")

	_, err = DecryptDeviceIdentifier(make([]byte, 32), make([]byte, 31))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encIdentifier must be exactly 32 bytes")

	_, err = DecryptCredentialStoreState(make([]byte, 32), make([]byte, 31))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encCredStoreState must be exactly 32 bytes")
}
