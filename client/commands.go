package client

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"iter"
	"log/slog"
	"slices"

	"github.com/fxamacker/cbor/v2"
	"github.com/go-ctap/ctap/attestation"
	"github.com/go-ctap/ctap/credential"
	"github.com/go-ctap/ctap/crypto"
	"github.com/go-ctap/ctap/options"
	"github.com/go-ctap/ctap/protocol"
	ctaptransport "github.com/go-ctap/ctap/transport"
	"github.com/ldclabs/cose/key"
)

type Client struct {
	logger    *slog.Logger
	encMode   cbor.EncMode
	transport ctaptransport.CBOR
}

// ErrTransportNotConfigured is returned by commands on an unbound client.
var ErrTransportNotConfigured = errors.New("client: transport not configured")

func (cl *Client) cbor(data []byte) (ctaptransport.CBORResponse, error) {
	if cl.transport == nil {
		return ctaptransport.CBORResponse{}, ErrTransportNotConfigured
	}

	return cl.transport.CBOR(data)
}

func NewClient(opts ...options.Option) (*Client, error) {
	oo := options.NewOptions(opts...)
	if oo.Transport == nil {
		return nil, ErrTransportNotConfigured
	}

	return &Client{
		logger:    oo.Logger,
		encMode:   oo.EncMode,
		transport: oo.Transport,
	}, nil
}

func (cl *Client) MakeCredential(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	clientDataHash []byte,
	rp credential.PublicKeyCredentialRpEntity,
	user credential.PublicKeyCredentialUserEntity,
	pubKeyCredParams []credential.PublicKeyCredentialParameters,
	excludeList []credential.PublicKeyCredentialDescriptor,
	extensions *protocol.CreateExtensionInputs,
	options map[protocol.Option]bool,
	enterpriseAttestation uint,
	attestationFormatsPreference []attestation.AttestationStatementFormatIdentifier,
) (protocol.AuthenticatorMakeCredentialResponse, error) {
	if err := ValidateClientDataHash(clientDataHash); err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}

	req := &protocol.AuthenticatorMakeCredentialRequest{
		ClientDataHash:               clientDataHash,
		RP:                           rp,
		User:                         user,
		PubKeyCredParams:             pubKeyCredParams,
		ExcludeList:                  excludeList,
		Extensions:                   extensions,
		Options:                      options,
		EnterpriseAttestation:        enterpriseAttestation,
		AttestationFormatsPreference: attestationFormatsPreference,
	}

	if pinUvAuthToken != nil {
		pinUvAuthParam := crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			clientDataHash,
		)

		req.PinUvAuthParam = pinUvAuthParam
		req.PinUvAuthProtocol = pinUvAuthProtocol
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, fmt.Errorf("cannot marshal MakeCredential CBOR request: %w", err)
	}
	cl.logger.Debug("MakeCredential CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorMakeCredential)}, b))
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}
	cl.logger.Debug("MakeCredential CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp protocol.AuthenticatorMakeCredentialResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}
	authData, err := protocol.ParseMakeCredentialAuthData(resp.AuthDataRaw)
	if err != nil {
		return protocol.AuthenticatorMakeCredentialResponse{}, err
	}
	resp.AuthData = &authData

	return resp, nil
}

func (cl *Client) GetAssertion(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	rpID string,
	clientDataHash []byte,
	allowList []credential.PublicKeyCredentialDescriptor,
	extensions *protocol.GetExtensionInputs,
	options map[protocol.Option]bool,
) iter.Seq2[protocol.AuthenticatorGetAssertionResponse, error] {
	return func(yield func(protocol.AuthenticatorGetAssertionResponse, error) bool) {
		if err := ValidateClientDataHash(clientDataHash); err != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, err)
			return
		}

		req := &protocol.AuthenticatorGetAssertionRequest{
			RPID:           rpID,
			ClientDataHash: clientDataHash,
			AllowList:      allowList,
			Extensions:     extensions,
			Options:        options,
		}

		if pinUvAuthToken != nil {
			pinUvAuthParamBegin := crypto.Authenticate(
				pinUvAuthProtocol,
				pinUvAuthToken,
				clientDataHash,
			)

			req.PinUvAuthParam = pinUvAuthParamBegin
			req.PinUvAuthProtocol = pinUvAuthProtocol
		}

		bBegin, err := cl.encMode.Marshal(req)
		if err != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, err)
			return
		}
		cl.logger.Debug("GetAssertion CBOR request", "hex", hex.EncodeToString(bBegin))

		respRawBegin, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorGetAssertion)}, bBegin))
		if err != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, err)
			return
		}
		cl.logger.Debug("GetAssertion CBOR response", "hex", hex.EncodeToString(respRawBegin.Data))

		var respBegin protocol.AuthenticatorGetAssertionResponse
		if err := cbor.Unmarshal(respRawBegin.Data, &respBegin); err != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, err)
			return
		}
		authData, err := protocol.ParseGetAssertionAuthData(respBegin.AuthDataRaw)
		if err != nil {
			yield(protocol.AuthenticatorGetAssertionResponse{}, err)
			return
		}
		respBegin.AuthData = &authData

		if !yield(respBegin, nil) {
			return
		}

		if respBegin.NumberOfCredentials == nil {
			return
		}

		for i := uint(1); i < *respBegin.NumberOfCredentials; i++ {
			respRaw, err := cl.cbor([]byte{byte(protocol.AuthenticatorGetNextAssertion)})
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}
			cl.logger.Debug("GetNextAssertion CBOR response", "hex", hex.EncodeToString(respRaw.Data))

			var resp protocol.AuthenticatorGetAssertionResponse
			if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}
			authData, err := protocol.ParseGetAssertionAuthData(resp.AuthDataRaw)
			if err != nil {
				yield(protocol.AuthenticatorGetAssertionResponse{}, err)
				return
			}
			resp.AuthData = &authData

			if !yield(resp, nil) {
				return
			}
		}
	}
}

func (cl *Client) GetInfo() (protocol.AuthenticatorGetInfoResponse, error) {
	respRaw, err := cl.cbor([]byte{byte(protocol.AuthenticatorGetInfo)})
	if err != nil {
		return protocol.AuthenticatorGetInfoResponse{}, err
	}

	var resp protocol.AuthenticatorGetInfoResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorGetInfoResponse{}, err
	}

	return resp, nil
}

func (cl *Client) GetPINRetries(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
) (uint, *bool, error) {
	req := &protocol.AuthenticatorClientPINRequest{
		// While this parameter is unnecessary, SoloKeys Solo 2 requires it for some reason.
		PinUvAuthProtocol: pinUvAuthProtocol,
		SubCommand:        protocol.ClientPINSubCommandGetPINRetries,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return 0, nil, err
	}
	cl.logger.Debug("getPINRetries CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b))
	if err != nil {
		return 0, nil, err
	}
	cl.logger.Debug("getPINRetries CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *protocol.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return 0, nil, err
	}

	if resp.PinRetries == nil {
		return 0, nil, errors.New("spec violation: pinRetries is nil")
	}

	return *resp.PinRetries, resp.PowerCycleState, nil
}

func (cl *Client) GetKeyAgreement(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
) (key.Key, error) {
	req := &protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinUvAuthProtocol,
		SubCommand:        protocol.ClientPINSubCommandGetKeyAgreement,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("cannot marshal keyAgreement CBOR request: %w", err)
	}
	cl.logger.Debug("getKeyAgreement CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, fmt.Errorf("keyAgreement CBOR request failed: %w", err)
	}
	cl.logger.Debug("getKeyAgreement CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *protocol.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, fmt.Errorf("cannot unmarshal keyAgreement CBOR response: %w", err)
	}

	return resp.KeyAgreement, nil
}

func (cl *Client) SetPIN(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	keyAgreement key.Key,
	pin string,
) error {
	pin, err := normalizeAndValidatePIN(pin)
	if err != nil {
		return err
	}

	pinProtocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return err
	}

	platformCoseKey, sharedSecret, err := pinProtocol.Encapsulate(keyAgreement)
	if err != nil {
		return err
	}

	pinBytes := make([]byte, 64)
	copy(pinBytes, pin)

	ciphertext, err := pinProtocol.Encrypt(sharedSecret, pinBytes)
	if err != nil {
		return err
	}

	req := &protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinProtocol.Number,
		SubCommand:        protocol.ClientPINSubCommandSetPIN,
		KeyAgreement:      platformCoseKey,
		NewPinEnc:         ciphertext,
		PinUvAuthParam: crypto.Authenticate(
			pinUvAuthProtocol,
			sharedSecret,
			ciphertext,
		),
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("setPIN CBOR request", "hex", hex.EncodeToString(b))

	if _, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) ChangePIN(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	keyAgreement key.Key,
	currentPin string,
	newPin string,
) error {
	currentPin, err := normalizeAndValidatePIN(currentPin)
	if err != nil {
		return err
	}
	newPin, err = normalizeAndValidatePIN(newPin)
	if err != nil {
		return err
	}

	pinProtocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return err
	}

	platformCoseKey, sharedSecret, err := pinProtocol.Encapsulate(keyAgreement)
	if err != nil {
		return err
	}

	// Hash PIN and return the first 16 bytes of hash
	hasher := sha256.New()
	hasher.Write([]byte(currentPin))
	pinHash := hasher.Sum(nil)[:16]

	pinHashEnc, err := pinProtocol.Encrypt(sharedSecret, pinHash)
	if err != nil {
		return err
	}

	newPinBytes := make([]byte, 64)
	copy(newPinBytes, newPin)

	newPinEnc, err := pinProtocol.Encrypt(sharedSecret, newPinBytes)
	if err != nil {
		return err
	}

	req := &protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinProtocol.Number,
		SubCommand:        protocol.ClientPINSubCommandChangePIN,
		KeyAgreement:      platformCoseKey,
		PinHashEnc:        pinHashEnc,
		NewPinEnc:         newPinEnc,
		PinUvAuthParam: crypto.Authenticate(
			pinUvAuthProtocol,
			sharedSecret,
			slices.Concat(newPinEnc, pinHashEnc),
		),
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("changePIN CBOR request", "hex", hex.EncodeToString(b))

	if _, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b)); err != nil {
		return err
	}

	return nil
}

// GetPinToken allows getting a PinUvAuthToken (superseded by GetPinUvAuthTokenUsingUvWithPermissions or
// GetPinUvAuthTokenUsingPinWithPermissions, thus for backwards compatibility only).
func (cl *Client) GetPinToken(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	keyAgreement key.Key,
	pin string,
) ([]byte, error) {
	pin, err := normalizeAndValidatePIN(pin)
	if err != nil {
		return nil, err
	}

	pinProtocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return nil, err
	}

	platformCoseKey, sharedSecret, err := pinProtocol.Encapsulate(keyAgreement)
	if err != nil {
		return nil, err
	}

	hasher := sha256.New()
	hasher.Write([]byte(pin))
	pinHash := hasher.Sum(nil)[:16]

	pinHashEnc, err := pinProtocol.Encrypt(sharedSecret, pinHash)
	if err != nil {
		return nil, err
	}

	req := &protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinProtocol.Number,
		SubCommand:        protocol.ClientPINSubCommandGetPinToken,
		KeyAgreement:      platformCoseKey,
		PinHashEnc:        pinHashEnc,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getPinToken CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getPinToken CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *protocol.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	pinUvAuthToken, err := pinProtocol.Decrypt(sharedSecret, resp.PinUvAuthToken)
	if err != nil {
		return nil, err
	}

	return pinUvAuthToken, nil
}

// GetPinUvAuthTokenUsingUvWithPermissions allows getting a PinUvAuthToken with specific permissions using User Verification.
func (cl *Client) GetPinUvAuthTokenUsingUvWithPermissions(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	keyAgreement key.Key,
	permissions protocol.Permission,
	rpID string,
) ([]byte, error) {
	pinProtocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return nil, err
	}

	platformCoseKey, sharedSecret, err := pinProtocol.Encapsulate(keyAgreement)
	if err != nil {
		return nil, err
	}

	req := &protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinProtocol.Number,
		SubCommand:        protocol.ClientPINSubCommandGetPinUvAuthTokenUsingUvWithPermissions,
		KeyAgreement:      platformCoseKey,
		Permissions:       permissions,
		RPID:              rpID,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getPinUvAuthTokenUsingUvWithPermissions CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getPinUvAuthTokenUsingUvWithPermissions CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *protocol.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	pinUvAuthToken, err := pinProtocol.Decrypt(sharedSecret, resp.PinUvAuthToken)
	if err != nil {
		return nil, err
	}

	return pinUvAuthToken, nil
}

func (cl *Client) GetUVRetries() (uint, error) {
	req := &protocol.AuthenticatorClientPINRequest{
		SubCommand: protocol.ClientPINSubCommandGetUVRetries,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return 0, err
	}
	cl.logger.Debug("getUVRetries CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b))
	if err != nil {
		return 0, err
	}
	cl.logger.Debug("getUVRetries CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *protocol.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return 0, err
	}

	if resp.UvRetries == nil {
		return 0, errors.New("spec violation: uvRetries is nil")
	}

	return *resp.UvRetries, err
}

// GetPinUvAuthTokenUsingPinWithPermissions allows getting a PinUvAuthToken with specific permissions using PIN.
func (cl *Client) GetPinUvAuthTokenUsingPinWithPermissions(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	keyAgreement key.Key,
	pin string,
	permissions protocol.Permission,
	rpID string,
) ([]byte, error) {
	pin, err := normalizeAndValidatePIN(pin)
	if err != nil {
		return nil, err
	}

	pinProtocol, err := crypto.NewPinUvAuthProtocol(pinUvAuthProtocol)
	if err != nil {
		return nil, err
	}

	platformCoseKey, sharedSecret, err := pinProtocol.Encapsulate(keyAgreement)
	if err != nil {
		return nil, err
	}

	hasher := sha256.New()
	hasher.Write([]byte(pin))
	pinHash := hasher.Sum(nil)[:16]

	pinHashEnc, err := pinProtocol.Encrypt(sharedSecret, pinHash)
	if err != nil {
		return nil, err
	}

	req := &protocol.AuthenticatorClientPINRequest{
		PinUvAuthProtocol: pinProtocol.Number,
		SubCommand:        protocol.ClientPINSubCommandGetPinUvAuthTokenUsingPinWithPermissions,
		KeyAgreement:      platformCoseKey,
		PinHashEnc:        pinHashEnc,
		Permissions:       permissions,
		RPID:              rpID,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getPinUvAuthTokenUsingPinWithPermissions CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorClientPIN)}, b))
	if err != nil {
		return nil, err
	}
	cl.logger.Debug("getPinUvAuthTokenUsingPinWithPermissions CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp *protocol.AuthenticatorClientPINResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return nil, err
	}

	pinUvAuthToken, err := pinProtocol.Decrypt(sharedSecret, resp.PinUvAuthToken)
	if err != nil {
		return nil, err
	}

	return pinUvAuthToken, nil
}

// Reset sends an authenticatorReset command through the configured transport.
func (cl *Client) Reset() error {
	_, err := cl.cbor([]byte{byte(protocol.AuthenticatorReset)})
	return err
}

func (cl *Client) GetBioModality(
	preview bool,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	req := &protocol.AuthenticatorBioEnrollmentRequest{GetModality: true}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}
	cl.logger.Debug("getBioModality CBOR request", "hex", hex.EncodeToString(b))

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}
	cl.logger.Debug("getBioModality CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp protocol.AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return resp, nil
}

func (cl *Client) GetFingerprintSensorInfo(
	preview bool,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:   protocol.BioModalityFingerprint,
		SubCommand: protocol.BioEnrollmentSubCommandGetFingerprintSensorInfo,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}
	cl.logger.Debug("getFingerprintSensorInfo CBOR request", "hex", hex.EncodeToString(b))

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}
	cl.logger.Debug("getFingerprintSensorInfo CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp protocol.AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return resp, nil
}

func (cl *Client) EnrollBegin(
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	timeoutMilliseconds uint,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	bSubCommandParams, err := cl.encMode.Marshal(protocol.BioEnrollmentSubCommandParams{
		TimeoutMilliseconds: timeoutMilliseconds,
	})
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}
	if timeoutMilliseconds == 0 {
		bSubCommandParams = nil
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandEnrollBegin)},
			bSubCommandParams,
		),
	)

	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:   protocol.BioModalityFingerprint,
		SubCommand: protocol.BioEnrollmentSubCommandEnrollBegin,
		SubCommandParams: protocol.BioEnrollmentSubCommandParams{
			TimeoutMilliseconds: timeoutMilliseconds,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}
	cl.logger.Debug("enrollBegin CBOR request", "hex", hex.EncodeToString(b))

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}
	cl.logger.Debug("enrollBegin CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp protocol.AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return resp, nil
}

func (cl *Client) EnrollCaptureNextSample(
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	templateID []byte,
	timeoutMilliseconds uint,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	bSubCommandParams, err := cl.encMode.Marshal(protocol.BioEnrollmentSubCommandParams{
		TemplateID:          templateID,
		TimeoutMilliseconds: timeoutMilliseconds,
	})
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandEnrollCaptureNextSample)},
			bSubCommandParams,
		),
	)

	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:   protocol.BioModalityFingerprint,
		SubCommand: protocol.BioEnrollmentSubCommandEnrollCaptureNextSample,
		SubCommandParams: protocol.BioEnrollmentSubCommandParams{
			TemplateID:          templateID,
			TimeoutMilliseconds: timeoutMilliseconds,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}
	cl.logger.Debug("enrollCaptureNextSample CBOR request", "hex", hex.EncodeToString(b))

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}
	cl.logger.Debug("enrollCaptureNextSample CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp protocol.AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return resp, nil
}

func (cl *Client) CancelCurrentEnrollment(
	preview bool,
) error {
	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:   protocol.BioModalityFingerprint,
		SubCommand: protocol.BioEnrollmentSubCommandCancelCurrentEnrollment,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("cancelCurrentEnrollment CBOR request", "hex", hex.EncodeToString(b))

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	if _, err := cl.cbor(slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) EnumerateEnrollments(
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) (protocol.AuthenticatorBioEnrollmentResponse, error) {
	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		[]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandEnumerateEnrollments)},
	)

	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:          protocol.BioModalityFingerprint,
		SubCommand:        protocol.BioEnrollmentSubCommandEnumerateEnrollments,
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}
	cl.logger.Debug("enumerateEnrollments CBOR request", "hex", hex.EncodeToString(b))

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}
	cl.logger.Debug("enumerateEnrollments CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp protocol.AuthenticatorBioEnrollmentResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorBioEnrollmentResponse{}, err
	}

	return resp, nil
}

func (cl *Client) SetFriendlyName(
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	templateID []byte,
	friendlyName string,
) error {
	bSubCommandParams, err := cl.encMode.Marshal(protocol.BioEnrollmentSubCommandParams{
		TemplateID:           templateID,
		TemplateFriendlyName: friendlyName,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandSetFriendlyName)},
			bSubCommandParams,
		),
	)

	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:   protocol.BioModalityFingerprint,
		SubCommand: protocol.BioEnrollmentSubCommandSetFriendlyName,
		SubCommandParams: protocol.BioEnrollmentSubCommandParams{
			TemplateID:           templateID,
			TemplateFriendlyName: friendlyName,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("setFriendlyName CBOR request", "hex", hex.EncodeToString(b))

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	if _, err := cl.cbor(slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) RemoveEnrollment(
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	templateID []byte,
) error {
	bSubCommandParams, err := cl.encMode.Marshal(protocol.BioEnrollmentSubCommandParams{
		TemplateID: templateID,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(protocol.BioModalityFingerprint), byte(protocol.BioEnrollmentSubCommandRemoveEnrollment)},
			bSubCommandParams,
		),
	)

	req := &protocol.AuthenticatorBioEnrollmentRequest{
		Modality:   protocol.BioModalityFingerprint,
		SubCommand: protocol.BioEnrollmentSubCommandRemoveEnrollment,
		SubCommandParams: protocol.BioEnrollmentSubCommandParams{
			TemplateID: templateID,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("removeEnrollment CBOR request", "hex", hex.EncodeToString(b))

	command := protocol.AuthenticatorBioEnrollment
	if preview {
		command = protocol.PrototypeAuthenticatorBioEnrollment
	}

	if _, err := cl.cbor(slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) GetCredsMetadata(
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) (protocol.AuthenticatorCredentialManagementResponse, error) {
	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		[]byte{byte(protocol.CredentialManagementSubCommandGetCredsMetadata)},
	)

	req := &protocol.AuthenticatorCredentialManagementRequest{
		SubCommand:        protocol.CredentialManagementSubCommandGetCredsMetadata,
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorCredentialManagementResponse{}, err
	}
	cl.logger.Debug("getCredsMetadata CBOR request", "hex", hex.EncodeToString(b))

	command := protocol.AuthenticatorCredentialManagement
	if preview {
		command = protocol.PrototypeAuthenticatorCredentialManagement
	}

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(command)}, b))
	if err != nil {
		return protocol.AuthenticatorCredentialManagementResponse{}, err
	}
	cl.logger.Debug("getCredsMetadata CBOR response", "hex", hex.EncodeToString(respRaw.Data))

	var resp protocol.AuthenticatorCredentialManagementResponse
	if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
		return protocol.AuthenticatorCredentialManagementResponse{}, err
	}

	return resp, nil
}

// EnumerateRPs yields all Relying Parties from one authenticator enumeration.
//
// IMPORTANT: Fully consume this iterator before invoking any other Client
// method. Sending another command invalidates the authenticator's active
// enumeration state. Collect all RPs before starting EnumerateCredentials.
func (cl *Client) EnumerateRPs(
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		pinUvAuthParamBegin := crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			[]byte{byte(protocol.CredentialManagementSubCommandEnumerateRPsBegin)},
		)

		reqBegin := &protocol.AuthenticatorCredentialManagementRequest{
			SubCommand:        protocol.CredentialManagementSubCommandEnumerateRPsBegin,
			PinUvAuthProtocol: pinUvAuthProtocol,
			PinUvAuthParam:    pinUvAuthParamBegin,
		}

		bBegin, err := cl.encMode.Marshal(reqBegin)
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}
		cl.logger.Debug("enumerateRPsBegin CBOR request", "hex", hex.EncodeToString(bBegin))

		command := protocol.AuthenticatorCredentialManagement
		if preview {
			command = protocol.PrototypeAuthenticatorCredentialManagement
		}

		respRawBegin, err := cl.cbor(
			slices.Concat(
				[]byte{byte(command)},
				bBegin,
			),
		)
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}
		cl.logger.Debug("enumerateRPsBegin CBOR response", "hex", hex.EncodeToString(respRawBegin.Data))

		var respBegin protocol.AuthenticatorCredentialManagementResponse
		if err := cbor.Unmarshal(respRawBegin.Data, &respBegin); err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		if respBegin.TotalRPs == 0 {
			return
		}

		if !yield(respBegin, nil) {
			return
		}

		for i := uint(1); i < respBegin.TotalRPs; i++ {
			reqNext := &protocol.AuthenticatorCredentialManagementRequest{
				SubCommand: protocol.CredentialManagementSubCommandEnumerateRPsGetNextRP,
			}

			bNext, err := cl.encMode.Marshal(reqNext)
			if err != nil {
				yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
				return
			}
			cl.logger.Debug("enumerateRPsGetNextRP CBOR request", "hex", hex.EncodeToString(bNext))

			respRawNext, err := cl.cbor(slices.Concat([]byte{byte(command)}, bNext))
			if err != nil {
				yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
				return
			}
			cl.logger.Debug("enumerateRPsGetNextRP CBOR response", "hex", hex.EncodeToString(respRawNext.Data))

			var respNext protocol.AuthenticatorCredentialManagementResponse
			if err := cbor.Unmarshal(respRawNext.Data, &respNext); err != nil {
				yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
				return
			}

			if !yield(respNext, nil) {
				return
			}
		}
	}
}

// EnumerateCredentials yields all credentials for one Relying Party.
//
// IMPORTANT: Fully consume this iterator before invoking any other Client
// method. Sending another command invalidates the authenticator's active
// enumeration state. Do not nest it inside EnumerateRPs.
func (cl *Client) EnumerateCredentials(
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	rpIDHash []byte,
) iter.Seq2[protocol.AuthenticatorCredentialManagementResponse, error] {
	return func(yield func(protocol.AuthenticatorCredentialManagementResponse, error) bool) {
		bSubCommandParams, err := cl.encMode.Marshal(protocol.CredentialManagementSubCommandParams{RPIDHash: rpIDHash})
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		pinUvAuthParamBegin := crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			slices.Concat(
				[]byte{byte(protocol.CredentialManagementSubCommandEnumerateCredentialsBegin)},
				bSubCommandParams,
			),
		)

		reqBegin := &protocol.AuthenticatorCredentialManagementRequest{
			SubCommand:        protocol.CredentialManagementSubCommandEnumerateCredentialsBegin,
			SubCommandParams:  protocol.CredentialManagementSubCommandParams{RPIDHash: rpIDHash},
			PinUvAuthProtocol: pinUvAuthProtocol,
			PinUvAuthParam:    pinUvAuthParamBegin,
		}

		bBegin, err := cl.encMode.Marshal(reqBegin)
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}
		cl.logger.Debug("enumerateCredentialsBegin CBOR request", "hex", hex.EncodeToString(bBegin))

		command := protocol.AuthenticatorCredentialManagement
		if preview {
			command = protocol.PrototypeAuthenticatorCredentialManagement
		}

		respRawBegin, err := cl.cbor(
			slices.Concat(
				[]byte{byte(command)},
				bBegin,
			),
		)
		if err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}
		cl.logger.Debug("enumerateCredentialsBegin CBOR response", "hex", hex.EncodeToString(respRawBegin.Data))

		var respBegin protocol.AuthenticatorCredentialManagementResponse
		if err := cbor.Unmarshal(respRawBegin.Data, &respBegin); err != nil {
			yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
			return
		}

		if respBegin.TotalCredentials == 0 {
			return
		}

		if !yield(respBegin, nil) {
			return
		}

		for i := uint(1); i < respBegin.TotalCredentials; i++ {
			reqNext := &protocol.AuthenticatorCredentialManagementRequest{
				SubCommand: protocol.CredentialManagementSubCommandEnumerateCredentialsGetNextCredential,
			}

			bNext, err := cl.encMode.Marshal(reqNext)
			if err != nil {
				yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
				return
			}
			cl.logger.Debug("enumerateCredentialsGetNextCredential CBOR request", "hex", hex.EncodeToString(bNext))

			respRawNext, err := cl.cbor(slices.Concat([]byte{byte(command)}, bNext))
			if err != nil {
				yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
				return
			}
			cl.logger.Debug("enumerateCredentialsGetNextCredential CBOR response", "hex", hex.EncodeToString(respRawNext.Data))

			var respNext protocol.AuthenticatorCredentialManagementResponse
			if err := cbor.Unmarshal(respRawNext.Data, &respNext); err != nil {
				yield(protocol.AuthenticatorCredentialManagementResponse{}, err)
				return
			}

			if !yield(respNext, nil) {
				return
			}
		}
	}
}

func (cl *Client) DeleteCredential(
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	credentialID credential.PublicKeyCredentialDescriptor,
) error {
	bSubCommandParams, err := cl.encMode.Marshal(protocol.CredentialManagementSubCommandParams{
		CredentialID: credentialID,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(protocol.CredentialManagementSubCommandDeleteCredential)},
			bSubCommandParams,
		),
	)

	req := &protocol.AuthenticatorCredentialManagementRequest{
		SubCommand:        protocol.CredentialManagementSubCommandDeleteCredential,
		SubCommandParams:  protocol.CredentialManagementSubCommandParams{CredentialID: credentialID},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("deleteCredential CBOR request", "hex", hex.EncodeToString(b))

	command := protocol.AuthenticatorCredentialManagement
	if preview {
		command = protocol.PrototypeAuthenticatorCredentialManagement
	}

	if _, err := cl.cbor(slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) UpdateUserInformation(
	preview bool,
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	credentialID credential.PublicKeyCredentialDescriptor,
	user credential.PublicKeyCredentialUserEntity,
) error {
	bSubCommandParams, err := cl.encMode.Marshal(protocol.CredentialManagementSubCommandParams{
		CredentialID: credentialID,
		User:         user,
	})
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			[]byte{byte(protocol.CredentialManagementSubCommandUpdateUserInformation)},
			bSubCommandParams,
		),
	)

	req := &protocol.AuthenticatorCredentialManagementRequest{
		SubCommand: protocol.CredentialManagementSubCommandUpdateUserInformation,
		SubCommandParams: protocol.CredentialManagementSubCommandParams{
			CredentialID: credentialID,
			User:         user,
		},
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("updateUserInformation CBOR request", "hex", hex.EncodeToString(b))

	command := protocol.AuthenticatorCredentialManagement
	if preview {
		command = protocol.PrototypeAuthenticatorCredentialManagement
	}

	if _, err := cl.cbor(slices.Concat([]byte{byte(command)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) LargeBlobs(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	get uint,
	set []byte,
	offset uint,
	length uint,
) (protocol.AuthenticatorLargeBlobsResponse, error) {
	req := &protocol.AuthenticatorLargeBlobsRequest{
		Get:    get,
		Set:    set,
		Offset: offset,
		Length: length,
	}

	if pinUvAuthToken != nil {
		padding := make([]byte, 32)
		for i := range padding {
			padding[i] = 0xff
		}

		offsetBin := make([]byte, 4)
		binary.LittleEndian.PutUint32(offsetBin, uint32(offset))

		hasher := sha256.New()
		hasher.Reset()
		hasher.Write(set)
		hash := hasher.Sum(nil)

		pinUvAuthParam := crypto.Authenticate(
			pinUvAuthProtocol,
			pinUvAuthToken,
			slices.Concat(
				padding,
				[]byte{0x0c, 0x00},
				offsetBin,
				hash,
			),
		)

		req.PinUvAuthParam = pinUvAuthParam
		req.PinUvAuthProtocol = pinUvAuthProtocol
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return protocol.AuthenticatorLargeBlobsResponse{}, err
	}
	cl.logger.Debug("largeBlobs set CBOR request", "hex", hex.EncodeToString(b))

	respRaw, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorLargeBlobs)}, b))
	if err != nil {
		return protocol.AuthenticatorLargeBlobsResponse{}, err
	}

	var resp protocol.AuthenticatorLargeBlobsResponse
	if get > 0 {
		if err := cbor.Unmarshal(respRaw.Data, &resp); err != nil {
			return protocol.AuthenticatorLargeBlobsResponse{}, err
		}
	}

	return resp, nil
}

func (cl *Client) EnableEnterpriseAttestation(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) error {
	padding := make([]byte, 32)
	for i := range padding {
		padding[i] = 0xff
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			padding,
			[]byte{0x0d, byte(protocol.ConfigSubCommandEnableEnterpriseAttestation)},
		),
	)

	req := &protocol.AuthenticatorConfigRequest{
		SubCommand:        protocol.ConfigSubCommandEnableEnterpriseAttestation,
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("enableEnterpriseAttestation CBOR request", "hex", hex.EncodeToString(b))

	if _, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorConfig)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) ToggleAlwaysUV(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
) error {
	padding := make([]byte, 32)
	for i := range padding {
		padding[i] = 0xff
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			padding,
			[]byte{0x0d, byte(protocol.ConfigSubCommandToggleAlwaysUv)},
		),
	)

	req := &protocol.AuthenticatorConfigRequest{
		SubCommand:        protocol.ConfigSubCommandToggleAlwaysUv,
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("toggleAlwaysUv CBOR request", "hex", hex.EncodeToString(b))

	if _, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorConfig)}, b)); err != nil {
		return err
	}

	return nil
}

func (cl *Client) SetMinPINLength(
	pinUvAuthProtocol protocol.PinUvAuthProtocol,
	pinUvAuthToken []byte,
	newMinPINLength uint,
	minPinLengthRPIDs []string,
	forceChangePin bool,
	pinComplexityPolicy bool,
) error {
	padding := make([]byte, 32)
	for i := range padding {
		padding[i] = 0xff
	}

	subCommandParams := &protocol.SetMinPINLengthConfigSubCommandParams{
		NewMinPINLength:     newMinPINLength,
		MinPinLengthRPIDs:   minPinLengthRPIDs,
		ForceChangePin:      forceChangePin,
		PinComplexityPolicy: pinComplexityPolicy,
	}
	bSubCommandParams, err := cl.encMode.Marshal(subCommandParams)
	if err != nil {
		return err
	}

	pinUvAuthParam := crypto.Authenticate(
		pinUvAuthProtocol,
		pinUvAuthToken,
		slices.Concat(
			padding,
			[]byte{0x0d, byte(protocol.ConfigSubCommandSetMinPINLength)},
			bSubCommandParams,
		),
	)

	req := &protocol.AuthenticatorConfigRequest{
		SubCommand:        protocol.ConfigSubCommandSetMinPINLength,
		SubCommandParams:  subCommandParams,
		PinUvAuthProtocol: pinUvAuthProtocol,
		PinUvAuthParam:    pinUvAuthParam,
	}

	b, err := cl.encMode.Marshal(req)
	if err != nil {
		return err
	}
	cl.logger.Debug("SetMinPINLength CBOR request", "hex", hex.EncodeToString(b))

	if _, err := cl.cbor(slices.Concat([]byte{byte(protocol.AuthenticatorConfig)}, b)); err != nil {
		return err
	}

	return nil
}

// Selection blocks execution until the user will confirm his presence or operation will be canceled.
func (cl *Client) Selection() error {
	_, err := cl.cbor([]byte{byte(protocol.AuthenticatorSelection)})
	if err != nil {
		var ctapError *ctaptransport.CTAPError
		if !errors.As(err, &ctapError) || ctapError.StatusCode != ctaptransport.CTAP2_ERR_KEEPALIVE_CANCEL {
			return err
		}
	}

	return nil
}
