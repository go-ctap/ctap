package protocoltwo

import (
	"bytes"
	"encoding/base64"
	"math/rand"
	"slices"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	derivedSecret             = "PDUkqZmuzEAsQobgnzyYCW/QhVluFMFskbCannzAxseuxtv3SzuMYIN4xCytczdff4ho2ZNHBrWM5WgVqYJ0Eg=="
	messageAuthenticationCode = "iFW3YmE8HVJs3Yyi6kZ3RMmR1Wkc7UBfIjkzTVl3630="
)

func TestKDF(t *testing.T) {
	// Create derived with zero material
	key1, err := KDF(nil)
	require.NoError(t, err)

	// Create a deterministic shared secret
	sharedSecret := make([]byte, 32)
	r := rand.New(rand.NewSource(0))
	_, err = r.Read(sharedSecret)
	require.NoError(t, err)
	wantSharedSecret := slices.Clone(sharedSecret)

	// Create derived with a shared secret
	key2, err := KDF(sharedSecret)
	require.NoError(t, err)
	assert.Equal(t, wantSharedSecret, sharedSecret)

	// Ensure key1 and key2 are different
	assert.NotEqual(t, key1, key2)

	// Compare it with reference
	savedKey, _ := base64.StdEncoding.DecodeString(derivedSecret)
	assert.Equal(t, key2, savedKey)
}

func TestEncryptDecrypt(t *testing.T) {
	key, _ := base64.StdEncoding.DecodeString(derivedSecret)
	badKey := append(key, 0)

	plaintext := []byte("16-byte block...")
	badPlaintext := []byte("17-byte block...!")
	longPlaintext := slices.Concat(plaintext, plaintext, plaintext, plaintext)

	// Encrypt with a 65-byte key
	_, err := Encrypt(badKey, plaintext)
	assert.Error(t, err)

	// Encrypt with a 17-byte block
	_, err = Encrypt(key, badPlaintext)
	assert.Error(t, err)

	// Test encrypt-decrypt with one block
	{
		ciphertext, err := Encrypt(key, plaintext)
		require.NoError(t, err)

		decrypted, err := Decrypt(key, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, plaintext, decrypted)
	}

	// Test encrypt-decrypt with multiple blocks
	{
		ciphertext, err := Encrypt(key, longPlaintext)
		require.NoError(t, err)

		decrypted, err := Decrypt(key, ciphertext)
		require.NoError(t, err)
		assert.Equal(t, longPlaintext, decrypted)
	}
}

func TestDecryptRejectsInvalidInputs(t *testing.T) {
	key, _ := base64.StdEncoding.DecodeString(derivedSecret)
	badKey := append(key, 0)
	iv := bytes.Repeat([]byte{0x01}, 16)

	_, err := Decrypt(badKey, slices.Concat(iv, []byte("16-byte block...")))
	assert.Error(t, err)

	_, err = Decrypt(key, []byte("short iv"))
	assert.Error(t, err)

	_, err = Decrypt(key, iv)
	assert.Error(t, err)

	_, err = Decrypt(key, slices.Concat(iv, []byte("not block aligned!")))
	assert.Error(t, err)
}

func TestAuthenticate(t *testing.T) {
	key, _ := base64.StdEncoding.DecodeString(derivedSecret)
	message := []byte("hello world!")

	mac := Authenticate(key, message)
	assert.Equal(t, 32, len(mac))
	assert.Equal(t, messageAuthenticationCode, base64.StdEncoding.EncodeToString(mac))
}
