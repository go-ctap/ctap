package authenticator

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"iter"
	"slices"
	"sync"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/client"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/options"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/go-ctap/ctap/transport/ctaphid"
	"github.com/go-ctap/ctap/webauthn"
	"github.com/go-ctap/ctap/yubico"
	"github.com/ldclabs/cose/key"
	"github.com/samber/lo"
)

// Device represents a physical or virtual hardware device supporting CTAP communication protocols.
type Device struct {
	Path              string
	transport         ctaptransport.Device
	info              protocol.AuthenticatorGetInfoResponse
	pinUvAuthProtocol protocol.PinUvAuthProtocol
	ctapClient        *client.Client
	encMode           cbor.EncMode
	mu                sync.Mutex // global mutex to serialize requests to the device
}

type pinger interface {
	Ping(ctx context.Context, data []byte) ([]byte, error)
}

type winker interface {
	Wink(ctx context.Context) error
}

type locker interface {
	Lock(ctx context.Context, seconds uint8) error
}

func (d *Device) requirePinUvAuthProtocol() (protocol.PinUvAuthProtocol, error) {
	if d.pinUvAuthProtocol == 0 {
		return 0, newErrorMessage(ErrNotSupported, "device didn't report pinUvAuthProtocols")
	}

	return d.pinUvAuthProtocol, nil
}

func (d *Device) pinUvAuthProtocolWithKeyAgreement(ctx context.Context) (protocol.PinUvAuthProtocol, key.Key, error) {
	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return 0, nil, err
	}

	keyAgreement, err := d.ctapClient.GetKeyAgreement(ctx, pinUvAuthProtocol)
	if err != nil {
		return 0, nil, err
	}

	return pinUvAuthProtocol, keyAgreement, nil
}

func (d *Device) refreshInfoLocked(ctx context.Context) error {
	info, err := d.ctapClient.GetInfo(ctx)
	if err != nil {
		return err
	}

	d.info = info
	return nil
}

func (d *Device) maxFragmentLength() uint {
	return d.info.EffectiveMaxMsgSize() - 64
}

// New creates a Device over an initialized transport. The caller retains
// ownership of transport if New returns an error. The returned Device owns
// transport on success.
func New(ctx context.Context, transport ctaptransport.Device, opts ...options.Option) (*Device, error) {
	if transport == nil {
		return nil, errors.New("device: nil transport")
	}

	oo := options.NewOptions(opts...)
	clientOpts := append(slices.Clone(opts), options.WithTransport(transport))
	ctapClient, err := client.NewClient(clientOpts...)
	if err != nil {
		return nil, err
	}

	d := &Device{
		transport:  transport,
		ctapClient: ctapClient,
		encMode:    oo.EncMode,
	}
	info, err := d.ctapClient.GetInfo(ctx)
	if err != nil {
		return nil, err
	}
	d.info = info
	if len(info.PinUvAuthProtocols) > 0 {
		d.pinUvAuthProtocol = info.PinUvAuthProtocols[0]
	}

	return d, nil
}

// OpenHID opens a HID authenticator, allocates a CTAPHID channel, and takes
// ownership of the resulting connection.
func OpenHID(ctx context.Context, path string, opts ...options.Option) (*Device, error) {
	dev, err := OpenPath(ctx, path, opts...)
	if err != nil {
		return nil, err
	}
	transport, err := ctaphid.Open(ctx, dev)
	if err != nil {
		return nil, errors.Join(err, dev.Close())
	}
	d, err := New(ctx, transport, opts...)
	if err != nil {
		return nil, errors.Join(err, transport.Close())
	}
	d.Path = path
	return d, nil
}

// Close closes the underlying transport.
func (d *Device) Close() error {
	return d.transport.Close()
}

// Ping sends a ping message to the device and verifies the response matches the sent data.
// Returns an error on failure.
func (d *Device) Ping(ctx context.Context, ping []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	transport, ok := d.transport.(pinger)
	if !ok {
		return newErrorMessage(ErrNotSupported, "ping requires CTAPHID")
	}

	pong, err := transport.Ping(ctx, ping)
	if err != nil {
		return err
	}

	if !bytes.Equal(ping, pong) {
		return ErrPingPongMismatch
	}

	return nil
}

// Wink sends a blink command to the device to visually signal its presence to the user.
// It uses the CTAPHID_WINK command, which is optional and could be unsupported by some devices.
func (d *Device) Wink(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	transport, ok := d.transport.(winker)
	if !ok {
		return newErrorMessage(ErrNotSupported, "wink requires CTAPHID")
	}

	return transport.Wink(ctx)
}

// Lock places an exclusive lock for one channel to communicate with the device.
// As long as the lock is active, any other channel trying to send a message will fail.
// Send 0 seconds to unlock the channel.
func (d *Device) Lock(ctx context.Context, seconds uint) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	transport, ok := d.transport.(locker)
	if !ok {
		return newErrorMessage(ErrNotSupported, "lock requires CTAPHID")
	}

	if seconds > 10 {
		return newErrorMessage(SyntaxError, "lock seconds must be between 0 and 10")
	}

	return transport.Lock(ctx, uint8(seconds))
}

// MakeCredential initiates the process of creating a new credential on a device with specified parameters and options.
func (d *Device) MakeCredential(
	ctx context.Context,
	pinUvAuthToken []byte,
	clientData []byte,
	rp credential.PublicKeyCredentialRpEntity,
	user credential.PublicKeyCredentialUserEntity,
	pubKeyCredParams []credential.PublicKeyCredentialParameters,
	excludeList []credential.PublicKeyCredentialDescriptor,
	extInputs *webauthn.CreateAuthenticationExtensionsClientInputs,
	options map[protocol.Option]bool,
	enterpriseAttestation uint,
	attestationFormatsPreference []attestation.AttestationStatementFormatIdentifier,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	notRequired, ok := d.info.Options[protocol.OptionMakeCredentialUvNotRequired]
	if (!ok || !notRequired) && pinUvAuthToken == nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, ErrPinUvAuthTokenRequired
	}

	var (
		pinUvAuthProtocol protocol.PinUvAuthProtocol
		pinProtocol       *crypto.PinUvAuthProtocol
		sharedSecret      []byte
	)

	extensions := new(protocol.CreateExtensionInputs)
	if extInputs == nil {
		extInputs = &webauthn.CreateAuthenticationExtensionsClientInputs{}
	}

	if extInputs.LargeBlobInputs != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(SyntaxError, "largeBlob extension is not supported yet")
	}

	if extInputs.CreateHMACSecretMCInputs != nil && extInputs.PRFInputs != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(SyntaxError, "you cannot use hmac-secret and prf extensions at the same time")
	}

	// hmac-secret
	if extInputs.CreateHMACSecretInputs != nil {
		if !slices.Contains(d.info.Extensions, extension.ExtensionIdentifierHMACSecret) {
			return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support hmac-secret extension")
		}

		extensions.CreateHMACSecretInput = &protocol.CreateHMACSecretInput{
			HMACSecret: extInputs.HMACCreateSecret,
		}
	}

	// hmac-secret-mc
	if extInputs.CreateHMACSecretMCInputs != nil {
		if !slices.Contains(d.info.Extensions, extension.ExtensionIdentifierHMACSecretMC) {
			return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support hmac-secret-mc extension")
		}
		if err := validateHMACGetSecretSalts(extInputs.CreateHMACSecretMCInputs.HMACGetSecret); err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}
		var (
			err          error
			keyAgreement key.Key
		)
		pinUvAuthProtocol, keyAgreement, err = d.pinUvAuthProtocolWithKeyAgreement(ctx)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		salt := slices.Concat(
			extInputs.CreateHMACSecretMCInputs.HMACGetSecret.Salt1,
			extInputs.CreateHMACSecretMCInputs.HMACGetSecret.Salt2,
		)

		pinProtocol, err = crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		var platformCoseKey key.Key
		platformCoseKey, sharedSecret, err = pinProtocol.Encapsulate(keyAgreement)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		saltEnc, err := pinProtocol.Encrypt(sharedSecret, salt)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		saltAuth := crypto.Authenticate(
			pinUvAuthProtocol,
			sharedSecret,
			saltEnc,
		)

		extensions.CreateHMACSecretInput = &protocol.CreateHMACSecretInput{
			HMACSecret: true,
		}
		extensions.CreateHMACSecretMCInput = &protocol.CreateHMACSecretMCInput{
			HMACSecret: protocol.HMACSecret{
				KeyAgreement:      platformCoseKey,
				SaltEnc:           saltEnc,
				SaltAuth:          saltAuth,
				PinUvAuthProtocol: pinUvAuthProtocol,
			},
		}
	}

	// prf
	if extInputs.PRFInputs != nil {
		if !slices.Contains(d.info.Extensions, extension.ExtensionIdentifierHMACSecretMC) {
			return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support prf extension during registration")
		}

		if extInputs.PRF.EvalByCredential != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(ErrNotSupported, "evalByCredential is not supported during registration")
		}

		if extInputs.PRF.Eval == nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(SyntaxError, "eval is empty")
		}
		var (
			err          error
			keyAgreement key.Key
		)
		pinUvAuthProtocol, keyAgreement, err = d.pinUvAuthProtocolWithKeyAgreement(ctx)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		hasher := sha256.New()
		hasher.Write([]byte("WebAuthn PRF"))
		hasher.Write([]byte{0x00})
		hasher.Write(extInputs.PRF.Eval.First)
		salt := hasher.Sum(nil)

		if extInputs.PRF.Eval.Second != nil {
			hasher.Reset()
			hasher.Write([]byte("WebAuthn PRF"))
			hasher.Write([]byte{0x00})
			hasher.Write(extInputs.PRF.Eval.Second)
			salt = slices.Concat(salt, hasher.Sum(nil))
		}

		pinProtocol, err = crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		var platformCoseKey key.Key
		platformCoseKey, sharedSecret, err = pinProtocol.Encapsulate(keyAgreement)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		saltEnc, err := pinProtocol.Encrypt(sharedSecret, salt)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		saltAuth := crypto.Authenticate(
			pinUvAuthProtocol,
			sharedSecret,
			saltEnc,
		)

		extensions.CreateHMACSecretInput = &protocol.CreateHMACSecretInput{
			HMACSecret: true,
		}
		extensions.CreateHMACSecretMCInput = &protocol.CreateHMACSecretMCInput{
			HMACSecret: protocol.HMACSecret{
				KeyAgreement:      platformCoseKey,
				SaltEnc:           saltEnc,
				SaltAuth:          saltAuth,
				PinUvAuthProtocol: pinUvAuthProtocol,
			},
		}
	}

	if pinUvAuthToken != nil && pinUvAuthProtocol == 0 {
		var err error
		pinUvAuthProtocol, err = d.requirePinUvAuthProtocol()
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}
	}

	// credProtection
	if extInputs.CreateCredentialProtectionInputs != nil {
		var credProtect int

		switch extInputs.CredentialProtectionPolicy {
		case extension.CredentialProtectionPolicyUserVerificationOptional:
			credProtect = 0x01
		case extension.CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList:
			credProtect = 0x02
		case extension.CredentialProtectionPolicyUserVerificationRequired:
			credProtect = 0x03
		default:
			return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(ErrNotSupported, "invalid credential protection policy")
		}

		if extInputs.EnforceCredentialProtectionPolicy &&
			extInputs.CredentialProtectionPolicy != extension.CredentialProtectionPolicyUserVerificationOptional &&
			!slices.Contains(d.info.Extensions, extension.ExtensionIdentifierCredentialProtection) {
			return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support credProtect extension")
		}

		extensions.CreateCredProtectInput = &protocol.CreateCredProtectInput{
			CredProtect: credProtect,
		}
	}

	// credBlob
	if extInputs.CreateCredentialBlobInputs != nil {
		if !slices.Contains(d.info.Extensions, extension.ExtensionIdentifierCredentialBlob) {
			return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support credBlob extension")
		}

		maxCredBlobLength, ok := d.info.MaxCredBlobLengthValue()
		if !ok {
			return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(
				ErrNotSupported,
				"device reports credBlob extension without maxCredBlobLength",
			)
		}
		if uint(len(extInputs.CredBlob)) > maxCredBlobLength {
			return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(
				ErrNotSupported,
				fmt.Sprintf("credBlob length must be less than %d bytes", maxCredBlobLength),
			)
		}

		extensions.CreateCredBlobInput = &protocol.CreateCredBlobInput{
			CredBlob: extInputs.CredBlob,
		}
	}

	// minPinLength
	if extInputs.CreateMinPinLengthInputs != nil {
		if !slices.Contains(d.info.Extensions, extension.ExtensionIdentifierMinPinLength) {
			return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support minPinLength extension")
		}

		extensions.CreateMinPinLengthInput = &protocol.CreateMinPinLengthInput{
			MinPinLength: extInputs.MinPinLength,
		}
	}
	if extInputs.CreatePinComplexityPolicyInputs != nil {
		if !slices.Contains(d.info.Extensions, extension.ExtensionIdentifierPinComplexityPolicy) {
			return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support pinComplexityPolicy extension")
		}

		extensions.CreatePinComplexityPolicyInput = &protocol.CreatePinComplexityPolicyInput{
			PinComplexityPolicy: extInputs.PinComplexityPolicy,
		}
	}

	clientDataHash := sha256.Sum256(clientData)
	resp, err := d.ctapClient.MakeCredential(
		ctx,
		pinUvAuthProtocol,
		pinUvAuthToken,
		clientDataHash[:],
		rp,
		user,
		pubKeyCredParams,
		excludeList,
		extensions,
		options,
		enterpriseAttestation,
		attestationFormatsPreference,
	)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	extOutputs := new(webauthn.CreateAuthenticationExtensionsClientOutputs)
	resp.ExtensionOutputs = extOutputs

	if extInputs.CreateCredentialPropertiesInputs != nil && extInputs.CredentialProperties {
		extOutputs.CreateCredentialPropertiesOutputs = &webauthn.CreateCredentialPropertiesOutputs{
			CredentialProperties: webauthn.CredentialPropertiesOutput{
				ResidentKey: options[protocol.OptionResidentKeys],
			},
		}
	}

	if !resp.AuthData.Flags.ExtensionDataIncluded() {
		return resp, nil
	}

	// credBlob
	if resp.AuthData.Extensions.CreateCredBlobOutput != nil {
		extOutputs.CreateCredentialBlobOutputs = &webauthn.CreateCredentialBlobOutputs{
			CredBlob: resp.AuthData.Extensions.CreateCredBlobOutput.CredBlob,
		}
	}

	// hmac-secret
	if resp.AuthData.Extensions.CreateHMACSecretOutput != nil {
		extOutputs.CreateHMACSecretOutputs = &webauthn.CreateHMACSecretOutputs{
			HMACCreateSecret: resp.AuthData.Extensions.CreateHMACSecretOutput.HMACSecret,
		}
	}

	// hmac-secret-mc (it needs tests, thought I cannot find any devices that support it yet)
	if resp.AuthData.Extensions.CreateHMACSecretMCOutput != nil {
		salt, err := pinProtocol.Decrypt(sharedSecret, resp.AuthData.Extensions.CreateHMACSecretMCOutput.HMACSecret)
		if err != nil {
			return protocol.AuthenticatorMakeCredentialResponse{}, err
		}

		switch len(salt) {
		case 32:
			extOutputs.PRFOutputs = &webauthn.PRFOutputs{
				PRF: webauthn.AuthenticationExtensionsPRFOutputs{
					Enabled: true,
					Results: webauthn.AuthenticationExtensionsPRFValues{
						First: salt[:32],
					},
				},
			}
		case 64:
			extOutputs.PRFOutputs = &webauthn.PRFOutputs{
				PRF: webauthn.AuthenticationExtensionsPRFOutputs{
					Enabled: true,
					Results: webauthn.AuthenticationExtensionsPRFValues{
						First:  salt[:32],
						Second: salt[32:],
					},
				},
			}
		default:
			return protocol.AuthenticatorMakeCredentialResponse{}, newErrorMessage(ErrInvalidSaltSize, "salt must be 32 or 64 bytes")
		}
	}

	return resp, nil
}

// GetAssertion provides a generator function to iterate over assertions stored on the device
// for the specified Relying Party, clientData, and allowed list (in case of non-discoverable credentials).
// It yields results via a callback function.
func (d *Device) GetAssertion(
	ctx context.Context,
	pinUvAuthToken []byte,
	rpID string,
	clientData []byte,
	allowList []credential.PublicKeyCredentialDescriptor,
	extInputs *webauthn.GetAuthenticationExtensionsClientInputs,
	options map[protocol.Option]bool,
) iter.Seq2[protocol.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(protocol.AuthenticatorGetAssertionResponse, error) bool) {
		d.mu.Lock()
		defer d.mu.Unlock()

		var (
			pinUvAuthProtocol protocol.PinUvAuthProtocol
			pinProtocol       *crypto.PinUvAuthProtocol
			sharedSecret      []byte
		)

		extensions := new(protocol.GetExtensionInputs)
		if extInputs == nil {
			extInputs = &webauthn.GetAuthenticationExtensionsClientInputs{}
		}

		if extInputs.LargeBlobInputs != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, newErrorMessage(SyntaxError, "largeBlob extension is not supported yet"))
			return
		}

		if extInputs.PRFInputs != nil && extInputs.GetHMACSecretInputs != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, newErrorMessage(SyntaxError, "you cannot use hmac-secret and prf extensions at the same time"))
			return
		}

		// hmac-secret
		if extInputs.GetHMACSecretInputs != nil {
			if err := validateHMACGetSecretSalts(extInputs.GetHMACSecretInputs.HMACGetSecret); err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}
			var (
				err          error
				keyAgreement key.Key
			)
			pinUvAuthProtocol, keyAgreement, err = d.pinUvAuthProtocolWithKeyAgreement(ctx)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}
			salt := slices.Concat(
				extInputs.GetHMACSecretInputs.HMACGetSecret.Salt1,
				extInputs.GetHMACSecretInputs.HMACGetSecret.Salt2,
			)

			pinProtocol, err = crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			var platformCoseKey key.Key
			platformCoseKey, sharedSecret, err = pinProtocol.Encapsulate(keyAgreement)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			saltEnc, err := pinProtocol.Encrypt(sharedSecret, salt)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			saltAuth := crypto.Authenticate(
				pinUvAuthProtocol,
				sharedSecret,
				saltEnc,
			)

			extensions.GetHMACSecretInput = &protocol.GetHMACSecretInput{
				HMACSecret: protocol.HMACSecret{
					KeyAgreement:      platformCoseKey,
					SaltEnc:           saltEnc,
					SaltAuth:          saltAuth,
					PinUvAuthProtocol: pinUvAuthProtocol,
				},
			}
		}

		// prf
		if extInputs.PRFInputs != nil {
			if extInputs.PRF.EvalByCredential != nil && (allowList == nil || len(allowList) == 0) {
				yield(protocol.AuthenticatorGetAssertionResponse{}, newErrorMessage(ErrNotSupported, "evalByCredential works only in conjunction with allowList"))
				return
			}

			var ev *webauthn.AuthenticationExtensionsPRFValues
			var ids [][]byte
			for idStr := range extInputs.PRF.EvalByCredential {
				id, err := base64.URLEncoding.DecodeString(idStr)
				if err != nil {
					yield(protocol.AuthenticatorGetAssertionResponse{}, newErrorMessage(SyntaxError, "invalid credential id"))
					return
				}

				ids = append(ids, id)
			}

			for _, id := range ids {
				desc, found := lo.Find(allowList, func(descriptor credential.PublicKeyCredentialDescriptor) bool {
					if slices.Equal(descriptor.ID, id) {
						return true
					}
					return false
				})
				if found {
					v, ok := extInputs.PRF.EvalByCredential[base64.URLEncoding.EncodeToString(desc.ID)]
					if ok {
						ev = &v
					}
				}
			}

			if ev == nil && extInputs.PRF.Eval != nil {
				ev = extInputs.PRF.Eval
			}
			if ev == nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, newErrorMessage(SyntaxError, "eval is empty"))
				return
			}
			var (
				err          error
				keyAgreement key.Key
			)
			pinUvAuthProtocol, keyAgreement, err = d.pinUvAuthProtocolWithKeyAgreement(ctx)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			hasher := sha256.New()
			hasher.Write([]byte("WebAuthn PRF"))
			hasher.Write([]byte{0x00})
			hasher.Write(ev.First)
			salt := hasher.Sum(nil)

			if ev.Second != nil {
				hasher.Reset()
				hasher.Write([]byte("WebAuthn PRF"))
				hasher.Write([]byte{0x00})
				hasher.Write(ev.Second)
				salt = slices.Concat(salt, hasher.Sum(nil))
			}

			pinProtocol, err = crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			var platformCoseKey key.Key
			platformCoseKey, sharedSecret, err = pinProtocol.Encapsulate(keyAgreement)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			saltEnc, err := pinProtocol.Encrypt(sharedSecret, salt)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			saltAuth := crypto.Authenticate(
				pinUvAuthProtocol,
				sharedSecret,
				saltEnc,
			)

			extensions.GetHMACSecretInput = &protocol.GetHMACSecretInput{
				HMACSecret: protocol.HMACSecret{
					KeyAgreement:      platformCoseKey,
					SaltEnc:           saltEnc,
					SaltAuth:          saltAuth,
					PinUvAuthProtocol: pinUvAuthProtocol,
				},
			}
		}

		// credBlob
		if extInputs.GetCredentialBlobInputs != nil {
			extensions.GetCredBlobInput = &protocol.GetCredBlobInput{
				CredBlob: extInputs.GetCredBlob,
			}
		}

		if pinUvAuthToken != nil && pinUvAuthProtocol == 0 {
			var err error
			pinUvAuthProtocol, err = d.requirePinUvAuthProtocol()
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}
		}

		clientDataHash := sha256.Sum256(clientData)
		for assertion, err := range d.ctapClient.GetAssertion(
			ctx,
			pinUvAuthProtocol,
			pinUvAuthToken,
			rpID,
			clientDataHash[:],
			allowList,
			extensions,
			options,
		) {
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}

			assertion.ExtensionOutputs = new(webauthn.GetAuthenticationExtensionsClientOutputs)

			// Yield assertions without extension data
			if !assertion.AuthData.Flags.ExtensionDataIncluded() {
				if !yield(assertion, nil) {
					return
				}
				continue
			}

			// credBlob
			if assertion.AuthData.Extensions.GetCredBlobOutput != nil {
				assertion.ExtensionOutputs.GetCredentialBlobOutputs = &webauthn.GetCredentialBlobOutputs{
					GetCredBlob: assertion.AuthData.Extensions.GetCredBlobOutput.CredBlob,
				}
			}

			// hmac-secret or prf
			if assertion.AuthData.Extensions.GetHMACSecretOutput != nil {
				salt, err := pinProtocol.Decrypt(sharedSecret, assertion.AuthData.Extensions.HMACSecret)
				if err != nil {
					yield(protocol.AuthenticatorGetAssertionResponse{}, err)
					return
				}

				switch len(salt) {
				case 32:
					if extInputs.GetHMACSecretInputs != nil {
						assertion.ExtensionOutputs.GetHMACSecretOutputs = &webauthn.GetHMACSecretOutputs{
							HMACGetSecret: webauthn.HMACGetSecretOutput{
								Output1: salt[:32],
							},
						}
					}
					if extInputs.PRFInputs != nil {
						assertion.ExtensionOutputs.PRFOutputs = &webauthn.PRFOutputs{
							PRF: webauthn.AuthenticationExtensionsPRFOutputs{
								Enabled: true,
								Results: webauthn.AuthenticationExtensionsPRFValues{
									First: salt[:32],
								},
							},
						}
					}
				case 64:
					if extInputs.GetHMACSecretInputs != nil {
						assertion.ExtensionOutputs.GetHMACSecretOutputs = &webauthn.GetHMACSecretOutputs{
							HMACGetSecret: webauthn.HMACGetSecretOutput{
								Output1: salt[:32],
								Output2: salt[32:],
							},
						}
					}
					if extInputs.PRFInputs != nil {
						assertion.ExtensionOutputs.PRFOutputs = &webauthn.PRFOutputs{
							PRF: webauthn.AuthenticationExtensionsPRFOutputs{
								Enabled: true,
								Results: webauthn.AuthenticationExtensionsPRFValues{
									First:  salt[:32],
									Second: salt[32:],
								},
							},
						}
					}
				default:
					yield(protocol.AuthenticatorGetAssertionResponse{}, newErrorMessage(ErrInvalidSaltSize, "salt must be 32 or 64 bytes"))
					return
				}
			}

			if !yield(assertion, nil) {
				return
			}
		}
	}
}

// GetInfo returns the struct containing metadata and capabilities of the device.
func (d *Device) GetInfo() protocol.AuthenticatorGetInfoResponse {
	return d.info
}

// GetYubiKeyDeviceInfo returns Yubico-specific device metadata using the
// vendor HID command 0xc2. Non-Yubico authenticators will normally return a
// CTAPHID invalid-command error.
func (d *Device) GetYubiKeyDeviceInfo(ctx context.Context) (yubico.DeviceInfo, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	transport, ok := d.transport.(yubico.VendorTransport)
	if !ok {
		return yubico.DeviceInfo{}, newErrorMessage(ErrNotSupported, "Yubico device info requires CTAPHID")
	}

	return yubico.GetDeviceInfo(ctx, transport)
}

// GetPINRetries retrieves the number of PIN retries remaining for the device, and if it requires a power cycle
// (after reaching the limit, you can reset remaining tries by re-connecting the token).
func (d *Device) GetPINRetries(ctx context.Context) (uint, *bool, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	clientPin, ok := d.info.Options[protocol.OptionClientPIN]
	if !ok {
		return 0, nil, newErrorMessage(ErrNotSupported, "device doesn't support clientPin option")
	}
	if !clientPin {
		return 0, nil, newErrorMessage(ErrPinNotSet, "please set PIN first")
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return 0, nil, err
	}

	return d.ctapClient.GetPINRetries(ctx, pinUvAuthProtocol)
}

// SetPIN sets a new PIN on the device if the clientPin option is supported and no PIN exists.
// Returns an error if the device does not support clientPin or if it was already set with PIN.
func (d *Device) SetPIN(ctx context.Context, pin string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	clientPin, ok := d.info.Options[protocol.OptionClientPIN]
	if !ok {
		return newErrorMessage(ErrNotSupported, "device doesn't support clientPin option")
	}
	if clientPin {
		return newErrorMessage(ErrPinAlreadySet, "pin already set, use changePin instead")
	}

	pin, err := d.normalizeAndValidateNewPIN(pin)
	if err != nil {
		return err
	}

	pinUvAuthProtocol, keyAgreement, err := d.pinUvAuthProtocolWithKeyAgreement(ctx)
	if err != nil {
		return err
	}

	if err := d.ctapClient.SetPIN(ctx, pinUvAuthProtocol, keyAgreement, pin); err != nil {
		return err
	}

	return d.refreshInfoLocked(ctx)
}

// ChangePIN updates the device's PIN by using the provided current PIN and new PIN.
// Returns an error if the device does not support clientPin or if the PIN change process fails.
func (d *Device) ChangePIN(ctx context.Context, currentPin, newPin string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	clientPin, ok := d.info.Options[protocol.OptionClientPIN]
	if !ok {
		return newErrorMessage(ErrNotSupported, "device doesn't support clientPin option")
	}
	if !clientPin {
		return newErrorMessage(ErrPinNotSet, "please set PIN first")
	}

	currentPin, err := d.normalizeAndValidateCurrentPIN(currentPin)
	if err != nil {
		return err
	}
	newPin, err = d.normalizeAndValidateNewPIN(newPin)
	if err != nil {
		return err
	}

	pinUvAuthProtocol, keyAgreement, err := d.pinUvAuthProtocolWithKeyAgreement(ctx)
	if err != nil {
		return err
	}

	if err := d.ctapClient.ChangePIN(
		ctx,
		pinUvAuthProtocol,
		keyAgreement,
		currentPin,
		newPin,
	); err != nil {
		return err
	}

	return d.refreshInfoLocked(ctx)
}

// GetPinUvAuthTokenUsingPIN obtains a pinUvAuthToken using a given PIN, permission, and in some cases optional
// Relying Party ID. Returns a token as a byte slice or an error if the operation fails.
// Checks device capabilities and permissions before proceeding.
func (d *Device) GetPinUvAuthTokenUsingPIN(
	ctx context.Context,
	pin string,
	permission protocol.Permission,
	rpID string,
) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	pin, err := d.normalizeAndValidateCurrentPIN(pin)
	if err != nil {
		return nil, err
	}

	noMcGaPermission, ok := d.info.Options[protocol.OptionNoMcGaPermissionsWithClientPin]
	if ok && noMcGaPermission && (permission&protocol.PermissionMakeCredential != 0 || permission&protocol.PermissionGetAssertion != 0) {
		return nil, newErrorMessage(
			ErrNotSupported,
			"you cannot get a pinUvAuthToken using PIN with MakeCredential or GetAssertion permissions if device has noMcGaPermissionsWithClientPin option",
		)
	}

	clientPIN, ok := d.info.Options[protocol.OptionClientPIN]
	if !ok {
		return nil, newErrorMessage(
			ErrNotSupported,
			"you cannot get a pinUvAuthToken using PIN if device hasn't clientPin option",
		)
	}
	if !clientPIN {
		return nil, newErrorMessage(
			ErrPinNotSet,
			"please set PIN first",
		)
	}

	if _, ok := d.info.Options[protocol.OptionBioEnroll]; !ok && permission&protocol.PermissionBioEnrollment != 0 {
		return nil, newErrorMessage(
			ErrNotSupported,
			"you cannot set be BioEnrollment permission if device doesn't support bioEnroll option",
		)
	}

	authnrCfg, ok := d.info.Options[protocol.OptionAuthenticatorConfig]
	if (!ok || !authnrCfg) && permission&protocol.PermissionAuthenticatorConfiguration != 0 {
		return nil, newErrorMessage(
			ErrNotSupported,
			"you cannot set be AuthenticatorConfiguration permission if device doesn't support uv option")
	}

	pinUvAuthProtocol, keyAgreement, err := d.pinUvAuthProtocolWithKeyAgreement(ctx)
	if err != nil {
		return nil, err
	}

	token, ok := d.info.Options[protocol.OptionPinUvAuthToken]
	if !ok || !token {
		return d.ctapClient.GetPinToken(
			ctx,
			pinUvAuthProtocol,
			keyAgreement,
			pin,
		)
	}

	return d.ctapClient.GetPinUvAuthTokenUsingPinWithPermissions(
		ctx,
		pinUvAuthProtocol,
		keyAgreement,
		pin,
		permission,
		rpID,
	)
}

// GetPinUvAuthTokenUsingUV obtains a pinUvAuthToken by performing user verification (UV) on a compatible device.
// Returns an error if the device does not support pinUvAuthToken or user verification features.
// Requires the permission type and optionally Relying Party ID (rpID) in some cases to execute successfully.
func (d *Device) GetPinUvAuthTokenUsingUV(ctx context.Context, permission protocol.Permission, rpID string) ([]byte, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	token, ok := d.info.Options[protocol.OptionPinUvAuthToken]
	if !ok || !token {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support pinUvAuthToken")
	}

	uv, ok := d.info.Options[protocol.OptionUserVerification]
	if !ok {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support user verification")
	}
	if !uv {
		return nil, newErrorMessage(ErrUvNotConfigured, "please configure UV first (e.g. enroll biometry)")
	}

	pinUvAuthProtocol, keyAgreement, err := d.pinUvAuthProtocolWithKeyAgreement(ctx)
	if err != nil {
		return nil, err
	}

	return d.ctapClient.GetPinUvAuthTokenUsingUvWithPermissions(
		ctx,
		pinUvAuthProtocol,
		keyAgreement,
		permission,
		rpID,
	)
}

// GetUVRetries retrieves the number of remaining user verification retries from the device.
// Returns an error if the device does not support user verification.
func (d *Device) GetUVRetries(ctx context.Context) (uint, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	uv, ok := d.info.Options[protocol.OptionUserVerification]
	if !ok {
		return 0, newErrorMessage(ErrNotSupported, "device doesn't support user verification")
	}
	if !uv {
		return 0, newErrorMessage(ErrUvNotConfigured, "please configure UV first (e.g. enroll biometry)")
	}

	return d.ctapClient.GetUVRetries(ctx)
}

// Reset performs a factory reset on the device, clearing all stored user data and resetting it to its default state.
// Some devices require doing reset within 10 seconds after you connected the token.
func (d *Device) Reset(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if err := d.ctapClient.Reset(ctx); err != nil {
		return err
	}

	return d.refreshInfoLocked(ctx)
}

// GetBioModality returns bio modality of authenticator.
// Currently, only fingerprint modality is defined in the FIDO 2.2 specification.
func (d *Device) GetBioModality(ctx context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[protocol.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[protocol.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return protocol.AuthenticatorBioEnrollmentResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.GetBioModality(
		ctx,
		d.info.Versions.IsPreviewOnly(),
	)
}

// GetFingerprintSensorInfo returns three properties:
//
//		FingerprintKind: For touch type fingerprints, its value is 1. For swipe type fingerprints, its value is 2.
//		MaxCaptureSamplesRequiredForEnroll: Indicates the maximum good samples required for enrollment.
//	 	MaxTemplateFriendlyName: Indicates the maximum number of bytes the authenticator will accept as a templateFriendlyName.
func (d *Device) GetFingerprintSensorInfo(ctx context.Context) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[protocol.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[protocol.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return protocol.AuthenticatorBioEnrollmentResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.GetFingerprintSensorInfo(
		ctx,
		d.info.Versions.IsPreviewOnly(),
	)
}

// EnrollBegin begins a fingerprint enrollment process and returns TemplateID, LastEnrollSampleStatus,
// and RemainingSamples properties. Use those properties to continue to capture the next samples or cancel it.
func (d *Device) EnrollBegin(
	ctx context.Context,
	pinUvAuthToken []byte,
	timeoutMilliseconds uint,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[protocol.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[protocol.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return protocol.AuthenticatorBioEnrollmentResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	resp, err := d.ctapClient.EnrollBegin(
		ctx,
		d.info.Versions.IsPreviewOnly(),
		pinUvAuthProtocol,
		pinUvAuthToken,
		timeoutMilliseconds,
	)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	if resp.RemainingSamples == nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, newErrorMessage(ErrSpecViolation, "device must return remaining samples")
	}

	if len(resp.TemplateID) > 0 && *resp.RemainingSamples == 0 {
		if err := d.refreshInfoLocked(ctx); err != nil {
			return protocol.AuthenticatorBioEnrollmentResponse{}, err
		}
	}

	return resp, nil
}

// EnrollCaptureNextSample continues capturing samples from an already started enrollment process.
func (d *Device) EnrollCaptureNextSample(
	ctx context.Context,
	pinUvAuthToken []byte,
	templateID []byte,
	timeoutMilliseconds uint,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[protocol.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[protocol.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return protocol.AuthenticatorBioEnrollmentResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	resp, err := d.ctapClient.EnrollCaptureNextSample(
		ctx,
		d.info.Versions.IsPreviewOnly(),
		pinUvAuthProtocol,
		pinUvAuthToken,
		templateID,
		timeoutMilliseconds,
	)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	if resp.RemainingSamples == nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, newErrorMessage(ErrSpecViolation, "device must return remaining samples")
	}

	if len(resp.TemplateID) > 0 && *resp.RemainingSamples == 0 {
		if err := d.refreshInfoLocked(ctx); err != nil {
			return protocol.AuthenticatorBioEnrollmentResponse{}, err
		}
	}

	return resp, nil
}

// CancelCurrentEnrollment cancels a current enrollment process.
func (d *Device) CancelCurrentEnrollment(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[protocol.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[protocol.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	return d.ctapClient.CancelCurrentEnrollment(
		ctx,
		d.info.Versions.IsPreviewOnly(),
	)
}

// EnumerateEnrollments enumerates enrollments by returning TemplateInfos property with an array of TemplateInfo
// for all the enrollments available on the authenticator.
func (d *Device) EnumerateEnrollments(ctx context.Context, pinUvAuthToken []byte) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[protocol.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[protocol.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return protocol.AuthenticatorBioEnrollmentResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return d.ctapClient.EnumerateEnrollments(
		ctx,
		d.info.Versions.IsPreviewOnly(),
		pinUvAuthProtocol,
		pinUvAuthToken,
	)
}

// SetFriendlyName allows renaming/setting of a friendly fingerprint name.
func (d *Device) SetFriendlyName(ctx context.Context, pinUvAuthToken []byte, templateID []byte, friendlyName string) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[protocol.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[protocol.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return err
	}

	return d.ctapClient.SetFriendlyName(
		ctx,
		d.info.Versions.IsPreviewOnly(),
		pinUvAuthProtocol,
		pinUvAuthToken,
		templateID,
		friendlyName,
	)
}

// RemoveEnrollment removes existing enrollment.
func (d *Device) RemoveEnrollment(ctx context.Context, pinUvAuthToken []byte, templateID []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	bioEnroll, ok := d.info.Options[protocol.OptionBioEnroll]
	if d.info.Versions.IsPreviewOnly() {
		bioEnroll, ok = d.info.Options[protocol.OptionUserVerificationMgmtPreview]
	}
	if !ok || !bioEnroll {
		return newErrorMessage(ErrNotSupported, "device doesn't support biometric enrollment")
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return err
	}

	if err := d.ctapClient.RemoveEnrollment(
		ctx,
		d.info.Versions.IsPreviewOnly(),
		pinUvAuthProtocol,
		pinUvAuthToken,
		templateID,
	); err != nil {
		return err
	}

	return d.refreshInfoLocked(ctx)
}

// GetCredsMetadata retrieves credential management metadata if the device supports it.
// Mainly ExistingResidentCredentialsCount and MaxPossibleRemainingResidentCredentialsCount.
func (d *Device) GetCredsMetadata(ctx context.Context, pinUvAuthToken []byte) (protocol.AuthenticatorCredentialManagementResponse, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	credMgmt, ok := d.info.Options[protocol.OptionCredentialManagement]
	if d.info.Versions.IsPreviewOnly() {
		credMgmt, ok = d.info.Options[protocol.OptionCredentialManagementPreview]
	}
	if !ok || !credMgmt {
		return protocol.AuthenticatorCredentialManagementResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support credential management")
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return protocol.AuthenticatorCredentialManagementResponse{}, err
	}

	return d.ctapClient.GetCredsMetadata(
		ctx,
		d.info.Versions.IsPreviewOnly(),
		pinUvAuthProtocol,
		pinUvAuthToken,
	)
}

// EnumerateRPs provides a generator function to iterate over Relying Parties stored on the device.
// It utilizes the Credential Management extension and yields results via a callback function.
// If the device does not support credential management, an error is yielded.
//
// IMPORTANT: Fully consume this iterator before invoking any other Device
// method. Authenticators keep enumeration state internally, and Device holds
// its request mutex while yielding. In particular, collect all RPs first and
// only then call EnumerateCredentials; nesting the iterators will deadlock and
// would invalidate the authenticator's active enumeration state.
func (d *Device) EnumerateRPs(ctx context.Context, pinUvAuthToken []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		d.mu.Lock()
		defer d.mu.Unlock()

		credMgmt, ok := d.info.Options[protocol.OptionCredentialManagement]
		if d.info.Versions.IsPreviewOnly() {
			credMgmt, ok = d.info.Options[protocol.OptionCredentialManagementPreview]
		}
		if !ok || !credMgmt {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support credential management"))
			return
		}

		pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		for rp, err := range d.ctapClient.EnumerateRPs(
			ctx,
			d.info.Versions.IsPreviewOnly(),
			pinUvAuthProtocol,
			pinUvAuthToken,
		) {
			if !yield(rp, err) {
				return
			}
		}
	}
}

// EnumerateCredentials provides a generator function to iterate over Credentials stored on the device
// for the specified Relying Party. It utilizes the Credential Management extension and yields results
// via a callback function. If the device does not support credential management, an error is yielded.
//
// IMPORTANT: Fully consume this iterator before invoking any other Device
// method. Authenticators keep enumeration state internally, and Device holds
// its request mutex while yielding. Do not nest this iterator inside
// EnumerateRPs; finish and materialize the RP enumeration first.
func (d *Device) EnumerateCredentials(ctx context.Context, pinUvAuthToken []byte, rpIDHash []byte) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		d.mu.Lock()
		defer d.mu.Unlock()

		credMgmt, ok := d.info.Options[protocol.OptionCredentialManagement]
		if d.info.Versions.IsPreviewOnly() {
			credMgmt, ok = d.info.Options[protocol.OptionCredentialManagementPreview]
		}
		if !ok || !credMgmt {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, newErrorMessage(ErrNotSupported, "device doesn't support credential management"))
			return
		}

		pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		for rp, err := range d.ctapClient.EnumerateCredentials(
			ctx,
			d.info.Versions.IsPreviewOnly(),
			pinUvAuthProtocol,
			pinUvAuthToken,
			rpIDHash,
		) {
			if !yield(rp, err) {
				return
			}
		}
	}
}

// DeleteCredential removes a specified credential from the device using the given authentication token.
// It returns an error if credential management is not supported or the operation fails.
func (d *Device) DeleteCredential(
	ctx context.Context,
	pinUvAuthToken []byte,
	credentialID credential.PublicKeyCredentialDescriptor,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	credMgmt, ok := d.info.Options[protocol.OptionCredentialManagement]
	if d.info.Versions.IsPreviewOnly() {
		credMgmt, ok = d.info.Options[protocol.OptionCredentialManagementPreview]
	}
	if !ok || !credMgmt {
		return newErrorMessage(ErrNotSupported, "device doesn't support credential management")
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return err
	}

	return d.ctapClient.DeleteCredential(
		ctx,
		d.info.Versions.IsPreviewOnly(),
		pinUvAuthProtocol,
		pinUvAuthToken,
		credentialID,
	)
}

// UpdateUserInformation updates information of an existing user credential on the device.
// Requires the device to support credential management features.
// Returns an error if the operation is not supported or fails.
func (d *Device) UpdateUserInformation(
	ctx context.Context,
	pinUvAuthToken []byte,
	credentialID credential.PublicKeyCredentialDescriptor,
	user credential.PublicKeyCredentialUserEntity,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	credMgmt, ok := d.info.Options[protocol.OptionCredentialManagement]
	if d.info.Versions.IsPreviewOnly() {
		credMgmt, ok = d.info.Options[protocol.OptionCredentialManagementPreview]
	}
	if !ok || !credMgmt {
		return newErrorMessage(ErrNotSupported, "device doesn't support credential management")
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return err
	}

	return d.ctapClient.UpdateUserInformation(
		ctx,
		d.info.Versions.IsPreviewOnly(),
		pinUvAuthProtocol,
		pinUvAuthToken,
		credentialID,
		user,
	)
}

// GetLargeBlobs retrieves a list of large blobs from the device that supports the large blobs option.
// Returns an error if the device does not support large blobs or if there is an issue with the retrieval process.
// Ensures integrity by validating computed and actual hashes of the retrieved data.
func (d *Device) GetLargeBlobs(ctx context.Context) ([]protocol.LargeBlob, error) {
	d.mu.Lock()
	defer d.mu.Unlock()

	largeBlobs, ok := d.info.Options[protocol.OptionLargeBlobs]
	if !ok || !largeBlobs {
		return nil, newErrorMessage(ErrNotSupported, "device doesn't support largeBlobs")
	}

	maxFragmentLength := d.maxFragmentLength()

	resp, err := d.ctapClient.LargeBlobs(
		ctx,
		0,
		nil,
		maxFragmentLength,
		nil,
		0,
		0,
	)
	if err != nil {
		return nil, err
	}

	config := resp.Config
	offset := maxFragmentLength

	// Continue to read
	for uint(len(config)) == maxFragmentLength {
		respNext, err := d.ctapClient.LargeBlobs(
			ctx,
			0,
			nil,
			maxFragmentLength,
			nil,
			offset,
			0,
		)
		if err != nil {
			return nil, err
		}

		config = slices.Concat(config, respNext.Config)
		offset += uint(len(respNext.Config))
	}
	if len(config) < 16 {
		return nil, newErrorMessage(ErrLargeBlobsIntegrityCheck, "invalid large blobs response length")
	}

	bLargeBlobs := config[:len(config)-16]
	hash := config[len(config)-16:]

	hasher := sha256.New()
	hasher.Write(bLargeBlobs)
	if !slices.Equal(hash, hasher.Sum(nil)[:16]) {
		return []protocol.LargeBlob{}, nil
	}

	var blobs []protocol.LargeBlob
	if err := cbor.Unmarshal(bLargeBlobs, &blobs); err != nil {
		return nil, SyntaxError
	}

	return blobs, nil
}

// SetLargeBlobs stores large blobs on the device, ensuring compatibility with its supported capabilities and limits.
// It validates device support, fragments the blob data if needed, and sends it in chunks to the device.
// Returns an error if the device does not support large blobs, the data exceeds size limits, or if any other failure occurs.
func (d *Device) SetLargeBlobs(ctx context.Context, pinUvAuthToken []byte, blobs []protocol.LargeBlob) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	largeBlobs, ok := d.info.Options[protocol.OptionLargeBlobs]
	if !ok || !largeBlobs {
		return newErrorMessage(ErrNotSupported, "device doesn't support largeBlobs")
	}

	set, err := d.encMode.Marshal(blobs)
	if err != nil {
		return err
	}

	hasher := sha256.New()
	hasher.Write(set)
	hash := hasher.Sum(nil)

	set = slices.Concat(set, hash[:16])

	maxSerializedLargeBlobArray, ok := d.info.MaxSerializedLargeBlobArrayValue()
	if !ok {
		return newErrorMessage(ErrNotSupported, "device reports largeBlobs without maxSerializedLargeBlobArray")
	}
	if uint(len(set)) > maxSerializedLargeBlobArray {
		return newErrorMessage(
			ErrLargeBlobsTooBig,
			fmt.Sprintf(
				"this device max serialized large blob size is %db while you are trying to save %db",
				maxSerializedLargeBlobArray,
				len(set),
			),
		)
	}

	maxFragmentLength := d.maxFragmentLength()
	offset := uint(0)
	length := uint(len(set))

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return err
	}

	setChunks := lo.Chunk(set, int(maxFragmentLength))
	for i, chunk := range setChunks {
		if i > 0 {
			length = 0
		}

		if _, err := d.ctapClient.LargeBlobs(
			ctx,
			pinUvAuthProtocol,
			pinUvAuthToken,
			0,
			chunk,
			offset,
			length,
		); err != nil {
			return err
		}

		offset += uint(len(chunk))
	}

	return nil
}

// EnableEnterpriseAttestation enables enterprise attestation on the device if supported, using the provided token.
func (d *Device) EnableEnterpriseAttestation(ctx context.Context, pinUvAuthToken []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if authnrCfg, ok := d.info.Options[protocol.OptionAuthenticatorConfig]; !ok || !authnrCfg {
		return newErrorMessage(ErrNotSupported, "device doesn't support authnrCfg")
	}
	if _, ok := d.info.Options[protocol.OptionEnterpriseAttestation]; !ok {
		return newErrorMessage(ErrNotSupported, "device doesn't support ep")
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return err
	}

	if err := d.ctapClient.EnableEnterpriseAttestation(
		ctx,
		pinUvAuthProtocol,
		pinUvAuthToken,
	); err != nil {
		return err
	}

	return d.refreshInfoLocked(ctx)
}

// ToggleAlwaysUV toggles the always UV (User Verification) setting on the device if supported, using the provided token.
func (d *Device) ToggleAlwaysUV(ctx context.Context, pinUvAuthToken []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if authnrCfg, ok := d.info.Options[protocol.OptionAuthenticatorConfig]; !ok || !authnrCfg {
		return newErrorMessage(ErrNotSupported, "device doesn't support authnrCfg")
	}
	if _, ok := d.info.Options[protocol.OptionAlwaysUv]; !ok {
		return newErrorMessage(ErrNotSupported, "device doesn't support alwaysUv")
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return err
	}

	if err := d.ctapClient.ToggleAlwaysUV(
		ctx,
		pinUvAuthProtocol,
		pinUvAuthToken,
	); err != nil {
		return err
	}

	return d.refreshInfoLocked(ctx)
}

func (d *Device) SetMinPINLength(
	ctx context.Context,
	pinUvAuthToken []byte,
	newMinPINLength uint,
	minPinLengthRPIDs []string,
	forceChangePin bool,
	pinComplexityPolicy bool,
) error {
	d.mu.Lock()
	defer d.mu.Unlock()

	if authnrCfg, ok := d.info.Options[protocol.OptionAuthenticatorConfig]; !ok || !authnrCfg {
		return newErrorMessage(ErrNotSupported, "device doesn't support authnrCfg")
	}

	pinUvAuthProtocol, err := d.requirePinUvAuthProtocol()
	if err != nil {
		return err
	}

	if err := d.ctapClient.SetMinPINLength(
		ctx,
		pinUvAuthProtocol,
		pinUvAuthToken,
		newMinPINLength,
		minPinLengthRPIDs,
		forceChangePin,
		pinComplexityPolicy,
	); err != nil {
		return err
	}

	return d.refreshInfoLocked(ctx)
}

// Selection is a higher-level version of ctap.Selection. CTAPHID commands are
// canceled when the context is canceled; other transports check the context
// before starting the command.
func (d *Device) Selection(ctx context.Context) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.ctapClient.Selection(ctx)
}
