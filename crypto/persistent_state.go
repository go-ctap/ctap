package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

const persistentStateSize = aes.BlockSize

// DecryptAuthenticatorIdentifier decrypts the device identifier returned in
// authenticatorGetInfo's encIdentifier member.
func DecryptAuthenticatorIdentifier(pinUvAuthToken, encrypted []byte) ([persistentStateSize]byte, error) {
	return decryptPersistentState(pinUvAuthToken, encrypted, "encIdentifier")
}

// DecryptCredentialStoreState decrypts the credential store state returned in
// authenticatorGetInfo's encCredStoreState member.
func DecryptCredentialStoreState(pinUvAuthToken, encrypted []byte) ([persistentStateSize]byte, error) {
	return decryptPersistentState(pinUvAuthToken, encrypted, "encCredStoreState")
}

func decryptPersistentState(
	pinUvAuthToken,
	encrypted []byte,
	info string,
) ([persistentStateSize]byte, error) {
	var plaintext [persistentStateSize]byte
	if len(pinUvAuthToken) == 0 {
		return plaintext, fmt.Errorf("pinUvAuthToken must not be empty")
	}
	if len(encrypted) != 2*persistentStateSize {
		return plaintext, fmt.Errorf("%s must be exactly %d bytes", info, 2*persistentStateSize)
	}

	key := make([]byte, persistentStateSize)
	kdf := hkdf.New(
		sha256.New,
		pinUvAuthToken,
		make([]byte, sha256.Size),
		[]byte(info),
	)
	if _, err := io.ReadFull(kdf, key); err != nil {
		return plaintext, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return plaintext, err
	}

	iv := encrypted[:persistentStateSize]
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plaintext[:], encrypted[persistentStateSize:])
	return plaintext, nil
}
