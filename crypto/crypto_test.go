package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	mrand "math/rand"
	"slices"
	"testing"

	"github.com/go-ctap/ctap/cose"
	"github.com/go-ctap/ctap/protocol"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var origData = []byte("hello world!")

func TestEncryptDecryptLargeBlob(t *testing.T) {
	encKey := make([]byte, 32)
	r := mrand.New(mrand.NewSource(42))
	_, err := r.Read(encKey)
	require.NoError(t, err)

	encryptedBlob, err := EncryptLargeBlob(encKey, origData)
	require.NoError(t, err)
	assert.Equal(t, uint(len(origData)), encryptedBlob.OrigSize)
	assert.Len(t, encryptedBlob.Nonce, 12)
	assert.NotEmpty(t, encryptedBlob.Ciphertext)

	decryptedOrigData, err := DecryptLargeBlob(encKey, encryptedBlob)
	require.NoError(t, err)

	assert.Equal(t, decryptedOrigData, origData)

	compressed, err := OpenLargeBlob(encKey, encryptedBlob)
	require.NoError(t, err)
	openedOrigData, err := DecompressLargeBlobData(compressed, encryptedBlob.OrigSize)
	require.NoError(t, err)
	assert.Equal(t, origData, openedOrigData)
}

func TestDecryptLargeBlobRejectsTampering(t *testing.T) {
	encKey := deterministicBytes(t, 32, 42)
	encryptedBlob, err := EncryptLargeBlob(encKey, origData)
	require.NoError(t, err)

	wrongKey := deterministicBytes(t, 32, 43)
	_, err = DecryptLargeBlob(wrongKey, encryptedBlob)
	require.Error(t, err)

	tamperedNonce := cloneLargeBlob(encryptedBlob)
	tamperedNonce.Nonce[0] ^= 0xff
	_, err = DecryptLargeBlob(encKey, tamperedNonce)
	require.Error(t, err)

	tamperedCiphertext := cloneLargeBlob(encryptedBlob)
	tamperedCiphertext.Ciphertext[0] ^= 0xff
	_, err = DecryptLargeBlob(encKey, tamperedCiphertext)
	require.Error(t, err)

	tamperedOrigSize := cloneLargeBlob(encryptedBlob)
	tamperedOrigSize.OrigSize++
	_, err = DecryptLargeBlob(encKey, tamperedOrigSize)
	require.Error(t, err)
}

func TestLargeBlobRejectsInvalidKeyLength(t *testing.T) {
	shortKey := deterministicBytes(t, 16, 42)

	_, err := EncryptLargeBlob(shortKey, origData)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "large blob key length")

	_, err = DecryptLargeBlob(shortKey, protocol.LargeBlob{})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "large blob key length")
}

func TestDecryptLargeBlobRejectsInvalidNonceLength(t *testing.T) {
	encKey := deterministicBytes(t, 32, 42)
	encryptedBlob, err := EncryptLargeBlob(encKey, origData)
	require.NoError(t, err)
	encryptedBlob.Nonce = encryptedBlob.Nonce[:len(encryptedBlob.Nonce)-1]

	_, err = DecryptLargeBlob(encKey, encryptedBlob)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nonce length")
}

func TestDecryptLargeBlobRejectsMismatchedDecompressedSize(t *testing.T) {
	encKey := deterministicBytes(t, 32, 42)
	encryptedBlob := encryptLargeBlobWithOrigSize(t, encKey, origData, uint(len(origData)+1))

	_, err := DecryptLargeBlob(encKey, encryptedBlob)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "orig size mismatch")
}

func TestPinUvAuthProtocolEncapsulateAndEncryptDecrypt(t *testing.T) {
	for _, tc := range []struct {
		name            string
		protocol        protocol.PinUvAuthProtocol
		sharedSecretLen int
		ciphertextLen   int
	}{
		{name: "protocol one", protocol: protocol.PinUvAuthProtocolOne, sharedSecretLen: 32, ciphertextLen: 16},
		{name: "protocol two", protocol: protocol.PinUvAuthProtocolTwo, sharedSecretLen: 64, ciphertextLen: 32},
	} {
		t.Run(tc.name, func(t *testing.T) {
			platform, err := NewPinUvAuthProtocol(tc.protocol)
			require.NoError(t, err)
			authenticator, err := NewPinUvAuthProtocol(tc.protocol)
			require.NoError(t, err)

			platformPublicKey, sharedSecret, err := platform.Encapsulate(authenticator.platformCoseKey)
			require.NoError(t, err)
			require.Len(t, sharedSecret, tc.sharedSecretLen)
			assert.EqualValues(t, cose.AlgorithmECDHESHKDF256, platformPublicKey[cose.KeyParameterAlg])
			require.Len(t, platformPublicKey, 5)

			authenticatorSharedSecret, err := authenticator.ECDH(platformPublicKey)
			require.NoError(t, err)
			assert.Equal(t, sharedSecret, authenticatorSharedSecret)

			plaintext := []byte("16-byte block...")
			ciphertext, err := platform.Encrypt(sharedSecret, plaintext)
			require.NoError(t, err)
			require.Len(t, ciphertext, tc.ciphertextLen)

			decrypted, err := authenticator.Decrypt(authenticatorSharedSecret, ciphertext)
			require.NoError(t, err)
			assert.Equal(t, plaintext, decrypted)
		})
	}
}

func TestPinUvAuthProtocolRejectsInvalidProtocol(t *testing.T) {
	protocol := &PinUvAuthProtocol{Number: 99}

	_, err := protocol.KDF([]byte("shared secret"))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidAuthProtocol))

	_, err = protocol.Encrypt(make([]byte, 32), []byte("16-byte block..."))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidAuthProtocol))

	_, err = protocol.Decrypt(make([]byte, 32), []byte("16-byte block..."))
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrInvalidAuthProtocol))
}

func TestAuthenticateDispatchesByProtocol(t *testing.T) {
	message := []byte("hello world!")
	sharedSecret32 := deterministicBytes(t, 32, 42)
	sharedSecret64 := append(slices.Clone(sharedSecret32), deterministicBytes(t, 32, 43)...)

	protocolOneMAC := Authenticate(protocol.PinUvAuthProtocolOne, sharedSecret32, message)
	assert.Len(t, protocolOneMAC, 16)

	protocolTwoMAC := Authenticate(protocol.PinUvAuthProtocolTwo, sharedSecret64, message)
	assert.Len(t, protocolTwoMAC, 32)
	assert.Equal(t, Authenticate(protocol.PinUvAuthProtocolTwo, sharedSecret32, message), protocolTwoMAC)
}

func deterministicBytes(t *testing.T, n int, seed int64) []byte {
	t.Helper()

	b := make([]byte, n)
	r := mrand.New(mrand.NewSource(seed))
	_, err := r.Read(b)
	require.NoError(t, err)
	return b
}

func cloneLargeBlob(blob protocol.LargeBlob) protocol.LargeBlob {
	return protocol.LargeBlob{
		Ciphertext: slices.Clone(blob.Ciphertext),
		Nonce:      slices.Clone(blob.Nonce),
		OrigSize:   blob.OrigSize,
	}
}

func encryptLargeBlobWithOrigSize(t *testing.T, key []byte, origData []byte, origSize uint) protocol.LargeBlob {
	t.Helper()

	plaintext, err := compress(origData)
	require.NoError(t, err)

	block, err := aes.NewCipher(key)
	require.NoError(t, err)
	gcm, err := cipher.NewGCM(block)
	require.NoError(t, err)

	nonce := deterministicBytes(t, gcm.NonceSize(), 44)
	origSizeBin := make([]byte, 8)
	binary.LittleEndian.PutUint64(origSizeBin, uint64(origSize))

	return protocol.LargeBlob{
		Ciphertext: gcm.Seal(nil, nonce, plaintext, slices.Concat([]byte("blob"), origSizeBin)),
		Nonce:      nonce,
		OrigSize:   origSize,
	}
}
