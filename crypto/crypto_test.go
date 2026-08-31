package crypto

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	mrand "math/rand"
	"slices"
	"strings"
	"testing"

	"github.com/telesma-app/ctap/cose"
	"github.com/telesma-app/ctap/protocol"
)

var origData = []byte("hello world!")
var origDataForCompress = []byte("hello world! hello world! hello world!")

func TestCompressDecompress(t *testing.T) {
	compressed, err := compress(origDataForCompress)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	decompressed, err := decompress(compressed)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := decompressed, origDataForCompress; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestCompressDecompressLargeBlobData(t *testing.T) {
	compressed, err := CompressLargeBlobData(origDataForCompress)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	decompressed, err := DecompressLargeBlobData(compressed, uint(len(origDataForCompress)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := decompressed, origDataForCompress; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	_, err = DecompressLargeBlobData(compressed, uint(len(origDataForCompress)-1))
	if err == nil {
		t.Fatalf("expected an error")
	}
	if container, element := err.Error(), "orig size mismatch"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}
}

func TestLargeBlobDataSizeLimit(t *testing.T) {
	_, err := CompressLargeBlobData(make([]byte, MaxLargeBlobDataSize+1))
	if err == nil {
		t.Fatalf("expected an error")
	}

	_, err = DecompressLargeBlobData(nil, MaxLargeBlobDataSize+1)
	if err == nil {
		t.Fatalf("expected an error")
	}
}

func TestEncryptDecryptLargeBlob(t *testing.T) {
	encKey := make([]byte, 32)
	r := mrand.New(mrand.NewSource(42))
	_, err := r.Read(encKey)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	encryptedBlob, err := EncryptLargeBlob(encKey, origData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := encryptedBlob.OrigSize, uint(len(origData)); got != want {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if got, want := len(encryptedBlob.Nonce), 12; got != want {
		t.Errorf("got length %d, want %d", got, want)
	}
	if got := encryptedBlob.Ciphertext; len(got) == 0 {
		t.Errorf("got empty value %#v, want non-empty", got)
	}

	decryptedOrigData, err := DecryptLargeBlob(encKey, encryptedBlob)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if got, want := origData, decryptedOrigData; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}

	compressed, err := OpenLargeBlob(encKey, encryptedBlob)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	openedOrigData, err := DecompressLargeBlobData(compressed, encryptedBlob.OrigSize)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got, want := openedOrigData, origData; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func TestDecryptLargeBlobRejectsTampering(t *testing.T) {
	encKey := deterministicBytes(t, 32, 42)
	encryptedBlob, err := EncryptLargeBlob(encKey, origData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	wrongKey := deterministicBytes(t, 32, 43)
	_, err = DecryptLargeBlob(wrongKey, encryptedBlob)
	if err == nil {
		t.Fatalf("expected an error")
	}

	tamperedNonce := cloneLargeBlob(encryptedBlob)
	tamperedNonce.Nonce[0] ^= 0xff
	_, err = DecryptLargeBlob(encKey, tamperedNonce)
	if err == nil {
		t.Fatalf("expected an error")
	}

	tamperedCiphertext := cloneLargeBlob(encryptedBlob)
	tamperedCiphertext.Ciphertext[0] ^= 0xff
	_, err = DecryptLargeBlob(encKey, tamperedCiphertext)
	if err == nil {
		t.Fatalf("expected an error")
	}

	tamperedOrigSize := cloneLargeBlob(encryptedBlob)
	tamperedOrigSize.OrigSize++
	_, err = DecryptLargeBlob(encKey, tamperedOrigSize)
	if err == nil {
		t.Fatalf("expected an error")
	}
}

func TestLargeBlobRejectsInvalidKeyLength(t *testing.T) {
	shortKey := deterministicBytes(t, 16, 42)

	_, err := EncryptLargeBlob(shortKey, origData)
	if err == nil {
		t.Fatalf("expected an error")
	}
	if container, element := err.Error(), "large blob key length"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}

	_, err = DecryptLargeBlob(shortKey, protocol.LargeBlob{})
	if err == nil {
		t.Fatalf("expected an error")
	}
	if container, element := err.Error(), "large blob key length"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}
}

func TestDecryptLargeBlobRejectsInvalidNonceLength(t *testing.T) {
	encKey := deterministicBytes(t, 32, 42)
	encryptedBlob, err := EncryptLargeBlob(encKey, origData)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	encryptedBlob.Nonce = encryptedBlob.Nonce[:len(encryptedBlob.Nonce)-1]

	_, err = DecryptLargeBlob(encKey, encryptedBlob)
	if err == nil {
		t.Fatalf("expected an error")
	}
	if container, element := err.Error(), "nonce length"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}
}

func TestDecryptLargeBlobRejectsMismatchedDecompressedSize(t *testing.T) {
	encKey := deterministicBytes(t, 32, 42)
	encryptedBlob := encryptLargeBlobWithOrigSize(t, encKey, origData, uint(len(origData)+1))

	_, err := DecryptLargeBlob(encKey, encryptedBlob)
	if err == nil {
		t.Fatalf("expected an error")
	}
	if container, element := err.Error(), "orig size mismatch"; !strings.Contains(container, element) {
		t.Errorf("value does not contain %#v", element)
	}
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
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			authenticator, err := NewPinUvAuthProtocol(tc.protocol)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			platformPublicKey, sharedSecret, err := platform.Encapsulate(authenticator.platformCoseKey)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, want := len(sharedSecret), tc.sharedSecretLen; got != want {
				t.Fatalf("got length %d, want %d", got, want)
			}
			algorithm, ok := platformPublicKey[cose.KeyParameterAlg].(cose.Algorithm)
			if !ok || algorithm != cose.AlgorithmECDHESHKDF256 {
				t.Errorf("got platform key algorithm %#v, want %d", platformPublicKey[cose.KeyParameterAlg], cose.AlgorithmECDHESHKDF256)
			}
			if got, want := len(platformPublicKey), 5; got != want {
				t.Fatalf("got length %d, want %d", got, want)
			}

			authenticatorSharedSecret, err := authenticator.ECDH(platformPublicKey)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, want := authenticatorSharedSecret, sharedSecret; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
				t.Errorf("got %#v, want %#v", got, want)
			}

			plaintext := []byte("16-byte block...")
			ciphertext, err := platform.Encrypt(sharedSecret, plaintext)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, want := len(ciphertext), tc.ciphertextLen; got != want {
				t.Fatalf("got length %d, want %d", got, want)
			}

			decrypted, err := authenticator.Decrypt(authenticatorSharedSecret, ciphertext)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got, want := decrypted, plaintext; (got == nil) != (want == nil) || !bytes.Equal(got, want) {
				t.Errorf("got %#v, want %#v", got, want)
			}
		})
	}
}

func TestPinUvAuthProtocolRejectsInvalidProtocol(t *testing.T) {
	protocol := &PinUvAuthProtocol{Number: 99}

	_, err := protocol.KDF([]byte("shared secret"))
	if err == nil {
		t.Fatalf("expected an error")
	}
	if got := errors.Is(err, ErrInvalidAuthProtocol); !got {
		t.Errorf("got false, want true")
	}

	_, err = protocol.Encrypt(make([]byte, 32), []byte("16-byte block..."))
	if err == nil {
		t.Fatalf("expected an error")
	}
	if got := errors.Is(err, ErrInvalidAuthProtocol); !got {
		t.Errorf("got false, want true")
	}

	_, err = protocol.Decrypt(make([]byte, 32), []byte("16-byte block..."))
	if err == nil {
		t.Fatalf("expected an error")
	}
	if got := errors.Is(err, ErrInvalidAuthProtocol); !got {
		t.Errorf("got false, want true")
	}
}

func TestAuthenticateDispatchesByProtocol(t *testing.T) {
	message := []byte("hello world!")
	sharedSecret32 := deterministicBytes(t, 32, 42)
	sharedSecret64 := append(slices.Clone(sharedSecret32), deterministicBytes(t, 32, 43)...)

	protocolOneMAC := Authenticate(protocol.PinUvAuthProtocolOne, sharedSecret32, message)
	if got, want := len(protocolOneMAC), 16; got != want {
		t.Errorf("got length %d, want %d", got, want)
	}

	protocolTwoMAC := Authenticate(protocol.PinUvAuthProtocolTwo, sharedSecret64, message)
	if got, want := len(protocolTwoMAC), 32; got != want {
		t.Errorf("got length %d, want %d", got, want)
	}
	if got, want := protocolTwoMAC, Authenticate(protocol.PinUvAuthProtocolTwo, sharedSecret32, message); (got == nil) != (want == nil) || !bytes.Equal(got, want) {
		t.Errorf("got %#v, want %#v", got, want)
	}
}

func deterministicBytes(t *testing.T, n int, seed int64) []byte {
	t.Helper()

	b := make([]byte, n)
	r := mrand.New(mrand.NewSource(seed))
	_, err := r.Read(b)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
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
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	nonce := deterministicBytes(t, gcm.NonceSize(), 44)
	origSizeBin := make([]byte, 8)
	binary.LittleEndian.PutUint64(origSizeBin, uint64(origSize))

	return protocol.LargeBlob{
		Ciphertext: gcm.Seal(nil, nonce, plaintext, slices.Concat([]byte("blob"), origSizeBin)),
		Nonce:      nonce,
		OrigSize:   origSize,
	}
}
