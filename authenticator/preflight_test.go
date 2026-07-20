package authenticator

import (
	"errors"
	"testing"

	"github.com/go-ctap/ctap/extension"
	"github.com/go-ctap/ctap/internal/testhid"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/ctap/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBioEnrollmentMode(t *testing.T) {
	tests := []struct {
		name        string
		info        protocol.AuthenticatorGetInfoResponse
		wantCommand protocol.Command
	}{
		{
			name: "FIDO 2.1",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionBioEnroll: false,
				},
			},
			wantCommand: protocol.AuthenticatorBioEnrollment,
		},
		{
			name: "FIDO 2.1 preview with enrollment",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerificationMgmtPreview: true,
				},
			},
			wantCommand: protocol.PrototypeAuthenticatorBioEnrollment,
		},
		{
			name: "FIDO 2.1 preview without enrollment",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerificationMgmtPreview: false,
				},
			},
			wantCommand: protocol.PrototypeAuthenticatorBioEnrollment,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorBioEnrollmentResponse{}))
			d := newTestDevice(fake, tt.info)

			_, err := d.GetBioModality(testContext)
			require.NoError(t, err)

			command, _ := fake.FirstCTAPPayload(t)
			assert.Equal(t, tt.wantCommand, command)
		})
	}
}

func TestBioEnrollmentPreviewAbsentIsNotSupported(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		Options:  map[protocol.Option]bool{},
	})

	_, err := d.GetBioModality(testContext)
	require.ErrorIs(t, err, ErrNotSupported)
	assert.Empty(t, fake.Writes())
}

func TestProtectedSubcommandsRejectMissingOrMalformedTokenBeforeCommand(t *testing.T) {
	t.Run("BioEnrollment requires token", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionBioEnroll: false,
			},
		})

		_, err := d.EnrollBegin(testContext, nil, 0)
		require.ErrorIs(t, err, ErrPinUvAuthTokenRequired)
		assert.Empty(t, fake.Writes())
	})

	t.Run("CredentialManagement requires token", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagement: true,
			},
		})

		_, err := d.GetCredsMetadata(testContext, nil)
		require.ErrorIs(t, err, ErrPinUvAuthTokenRequired)
		assert.Empty(t, fake.Writes())
	})

	t.Run("protocol 2 rejects short token without panic", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagement: true,
			},
		})

		_, err := d.GetCredsMetadata(testContext, make([]byte, 16))
		require.ErrorIs(t, err, SyntaxError)
		assert.Empty(t, fake.Writes())
	})
}

func TestPinUvAuthTokenLengthUsesCTAPVersion(t *testing.T) {
	t.Run("FIDO 2.0 accepts a longer protocol 1 token", func(t *testing.T) {
		d := newTestDevice(testhid.NewCBORDevice(t, testCID), protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_0},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		})

		got, err := d.pinUvAuthProtocolForRequest(make([]byte, 48), true)
		require.NoError(t, err)
		assert.Equal(t, protocol.PinUvAuthProtocolOne, got)
	})

	t.Run("FIDO 2.1 rejects a longer protocol 1 token", func(t *testing.T) {
		d := newTestDevice(testhid.NewCBORDevice(t, testCID), protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_1},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		})

		_, err := d.pinUvAuthProtocolForRequest(make([]byte, 48), true)
		require.ErrorIs(t, err, SyntaxError)
	})
}

func TestSelectPinTokenFlowUsingPIN(t *testing.T) {
	baseOptions := map[protocol.Option]bool{
		protocol.OptionClientPIN:      true,
		protocol.OptionPinUvAuthToken: true,
	}

	tests := []struct {
		name       string
		info       protocol.AuthenticatorGetInfoResponse
		permission protocol.Permission
		rpID       string
		wantFlow   pinTokenFlow
		wantErr    error
	}{
		{
			name: "permissioned mc requires RP ID",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options:  baseOptions,
			},
			permission: protocol.PermissionMakeCredential,
			wantErr:    SyntaxError,
		},
		{
			name: "legacy mc binds RP on first use",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			permission: protocol.PermissionMakeCredential,
			wantFlow:   pinTokenFlowLegacy,
		},
		{
			name: "FIDO 2.0 legacy token allows zero permission",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			permission: protocol.PermissionNone,
			wantFlow:   pinTokenFlowLegacy,
		},
		{
			name: "FIDO 2.0 ignores unknown pinUvAuthToken option",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:      true,
					protocol.OptionPinUvAuthToken: true,
				},
			},
			permission: protocol.PermissionMakeCredential,
			wantFlow:   pinTokenFlowLegacy,
		},
		{
			name: "standard bio false still grants be",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:      true,
					protocol.OptionPinUvAuthToken: true,
					protocol.OptionBioEnroll:      false,
				},
			},
			permission: protocol.PermissionBioEnrollment,
			wantFlow:   pinTokenFlowWithPermissions,
		},
		{
			name: "preview bio without enrollment uses legacy token",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionPinUvAuthToken:              true,
					protocol.OptionUserVerificationMgmtPreview: false,
				},
			},
			permission: protocol.PermissionBioEnrollment,
			wantFlow:   pinTokenFlowLegacy,
		},
		{
			name: "legacy token cannot grant standard cm",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:            true,
					protocol.OptionCredentialManagement: true,
				},
			},
			permission: protocol.PermissionCredentialManagement,
			wantErr:    ErrNotSupported,
		},
		{
			name: "pcmr cannot be combined",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options:  baseOptions,
			},
			permission: protocol.PermissionPersistentCredentialManagementReadOnly |
				protocol.PermissionCredentialManagement,
			wantErr: SyntaxError,
		},
		{
			name: "zero permission",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options:  baseOptions,
			},
			permission: protocol.PermissionNone,
			wantErr:    SyntaxError,
		},
		{
			name: "FIDO 2.1 rejects zero permission even with legacy token flow",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			permission: protocol.PermissionNone,
			wantErr:    SyntaxError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flow, err := selectPinTokenFlowUsingPIN(tt.info, tt.permission, tt.rpID)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantFlow, flow)
		})
	}
}

func TestValidatePinUvAuthTokenUsingUVPermissions(t *testing.T) {
	baseInfo := protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_3},
		Options: map[protocol.Option]bool{
			protocol.OptionPinUvAuthToken:   true,
			protocol.OptionUserVerification: true,
		},
	}

	t.Run("be requires uvBioEnroll", func(t *testing.T) {
		info := baseInfo
		info.Options = map[protocol.Option]bool{
			protocol.OptionPinUvAuthToken:   true,
			protocol.OptionUserVerification: true,
			protocol.OptionBioEnroll:        false,
		}

		err := validatePinUvAuthTokenUsingUV(info, protocol.PermissionBioEnrollment, "")
		require.ErrorIs(t, err, ErrNotSupported)

		info.Options[protocol.OptionUvBioEnroll] = true
		require.NoError(t, validatePinUvAuthTokenUsingUV(info, protocol.PermissionBioEnrollment, ""))
	})

	t.Run("acfg requires uvAcfg and authnrCfg", func(t *testing.T) {
		info := baseInfo
		info.Options = map[protocol.Option]bool{
			protocol.OptionPinUvAuthToken:   true,
			protocol.OptionUserVerification: true,
			protocol.OptionUvAcfg:           true,
		}

		err := validatePinUvAuthTokenUsingUV(info, protocol.PermissionAuthenticatorConfiguration, "")
		require.ErrorIs(t, err, ErrNotSupported)

		info.Options[protocol.OptionAuthenticatorConfig] = true
		require.NoError(t, validatePinUvAuthTokenUsingUV(info, protocol.PermissionAuthenticatorConfiguration, ""))
	})

	t.Run("ga requires RP ID", func(t *testing.T) {
		err := validatePinUvAuthTokenUsingUV(baseInfo, protocol.PermissionGetAssertion, "")
		require.ErrorIs(t, err, SyntaxError)
		require.NoError(t, validatePinUvAuthTokenUsingUV(baseInfo, protocol.PermissionGetAssertion, "example.com"))
	})

	t.Run("FIDO 2.0 ignores unknown pinUvAuthToken option", func(t *testing.T) {
		info := baseInfo
		info.Versions = protocol.Versions{protocol.FIDO_2_0}

		err := validatePinUvAuthTokenUsingUV(info, protocol.PermissionGetAssertion, "example.com")
		require.ErrorIs(t, err, ErrNotSupported)
	})
}

func TestConditionalAuthorizationUsesCTAPVersion(t *testing.T) {
	tests := []struct {
		name string
		info protocol.AuthenticatorGetInfoResponse
		want bool
	}{
		{
			name: "FIDO 2.0 ignores unknown alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv: true,
				},
			},
		},
		{
			name: "FIDO 2.1 honors alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv: true,
				},
			},
			want: true,
		},
		{
			name: "FIDO 2.3 honors alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv: true,
				},
			},
			want: true,
		},
		{
			name: "configured PIN protects every version",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, largeBlobsAuthorizationRequired(tt.info))
		})
	}
}

func TestSetLargeBlobsConditionalAuthorization(t *testing.T) {
	baseInfo := protocol.AuthenticatorGetInfoResponse{
		Versions:                    protocol.Versions{protocol.FIDO_2_1},
		MaxSerializedLargeBlobArray: 2048,
		Options: map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
		},
	}

	t.Run("unprotected authenticator omits auth", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, nil)
		d := newTestDevice(fake, baseInfo)

		require.NoError(t, d.SetLargeBlobs(testContext, nil, nil))

		command, request := fake.FirstCTAPRequestMap(t)
		assert.Equal(t, protocol.AuthenticatorLargeBlobs, command)
		assert.NotContains(t, request, uint64(5))
		assert.NotContains(t, request, uint64(6))
	})

	t.Run("protected authenticator requires auth", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		info := baseInfo
		info.Options = map[protocol.Option]bool{
			protocol.OptionLargeBlobs: true,
			protocol.OptionClientPIN:  true,
		}
		d := newTestDevice(fake, info)

		err := d.SetLargeBlobs(testContext, nil, nil)
		require.ErrorIs(t, err, ErrPinUvAuthTokenRequired)
		assert.Empty(t, fake.Writes())
	})
}

func TestAuthenticatorConfigCapabilityAndAuthorization(t *testing.T) {
	t.Run("unprotected SetMinPINLength omits auth", func(t *testing.T) {
		info := protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_3},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
			AuthenticatorConfigCommands: []protocol.ConfigSubCommand{protocol.ConfigSubCommandSetMinPINLength},
		}
		fake := testhid.NewCBORDevice(t, testCID, nil, encodeCBOR(t, info))
		d := newTestDevice(fake, info)

		require.NoError(t, d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(8)),
		}))

		command, request := fake.FirstCTAPRequestMap(t)
		assert.Equal(t, protocol.AuthenticatorConfig, command)
		assert.NotContains(t, request, uint64(3))
		assert.NotContains(t, request, uint64(4))
	})

	t.Run("protected config requires auth", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
				protocol.OptionClientPIN:           true,
			},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(8)),
		})
		require.ErrorIs(t, err, ErrPinUvAuthTokenRequired)
		assert.Empty(t, fake.Writes())
	})

	t.Run("setMinPINLength option is required", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
			},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(8)),
		})
		require.ErrorIs(t, err, ErrNotSupported)
		assert.Empty(t, fake.Writes())
	})

	t.Run("FIDO 2.3 command list is authoritative", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_3},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
			AuthenticatorConfigCommands: []protocol.ConfigSubCommand{},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(8)),
		})
		require.ErrorIs(t, err, ErrNotSupported)
		assert.Empty(t, fake.Writes())
	})

	t.Run("FIDO 2.3 missing command list rejects subcommands", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_3},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(8)),
		})
		require.ErrorIs(t, err, ErrNotSupported)
		assert.Empty(t, fake.Writes())
	})

	t.Run("FIDO 2.1 ignores unknown command list field", func(t *testing.T) {
		info := protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
			AuthenticatorConfigCommands: []protocol.ConfigSubCommand{},
		}
		fake := testhid.NewCBORDevice(t, testCID, nil, encodeCBOR(t, info))
		d := newTestDevice(fake, info)

		require.NoError(t, d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(8)),
		}))
	})

	t.Run("unprotected alwaysUv can be disabled without auth", func(t *testing.T) {
		info := protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_3},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionAlwaysUv:            true,
			},
			AuthenticatorConfigCommands: []protocol.ConfigSubCommand{protocol.ConfigSubCommandToggleAlwaysUv},
		}
		fake := testhid.NewCBORDevice(t, testCID, nil, encodeCBOR(t, info))
		d := newTestDevice(fake, info)

		require.NoError(t, d.ToggleAlwaysUV(testContext, nil))

		_, request := fake.FirstCTAPRequestMap(t)
		assert.NotContains(t, request, uint64(3))
		assert.NotContains(t, request, uint64(4))
	})

	t.Run("enables long touch without requesting getInfo", func(t *testing.T) {
		info := protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_3},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
			},
			LongTouchForReset: new(false),
			AuthenticatorConfigCommands: []protocol.ConfigSubCommand{
				protocol.ConfigSubCommandEnableLongTouchForReset,
			},
		}
		fake := testhid.NewCBORDevice(t, testCID, nil)
		d := newTestDevice(fake, info)

		require.NoError(t, d.EnableLongTouchForReset(testContext, nil))

		requests := fake.Requests(t)
		require.Len(t, requests, 1)
		command, request := requests[0].CTAPRequestMap(t)
		assert.Equal(t, protocol.AuthenticatorConfig, command)
		assert.Len(t, request, 1)
		assert.Contains(t, request, uint64(1))
	})

	t.Run("long touch requires feature field", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_3},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
			},
			AuthenticatorConfigCommands: []protocol.ConfigSubCommand{
				protocol.ConfigSubCommandEnableLongTouchForReset,
			},
		})

		err := d.EnableLongTouchForReset(testContext, nil)
		require.ErrorIs(t, err, ErrNotSupported)
		assert.Empty(t, fake.Writes())
	})

	t.Run("setMinPINLength rejects decreasing minimum", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Versions:     protocol.Versions{protocol.FIDO_2_1},
			MinPINLength: 8,
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(7)),
		})
		require.ErrorIs(t, err, SyntaxError)
		assert.Empty(t, fake.Writes())
	})

	t.Run("setMinPINLength validates RP ID limit", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Versions:                   protocol.Versions{protocol.FIDO_2_1},
			Extensions:                 []extension.ExtensionIdentifier{extension.ExtensionIdentifierMinPinLength},
			MaxRPIDsForSetMinPINLength: new(uint(1)),
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			MinPINLengthRPIDs: []string{"one.example", "two.example"},
		})
		require.ErrorIs(t, err, SyntaxError)
		assert.Empty(t, fake.Writes())
	})

	t.Run("setMinPINLength requires complexity feature", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
				protocol.OptionSetMinPINLength:     true,
			},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			PINComplexityPolicy: true,
		})
		require.ErrorIs(t, err, ErrNotSupported)
		assert.Empty(t, fake.Writes())
	})
}

func TestGetAssertionRejectsUnadvertisedExtensions(t *testing.T) {
	tests := []struct {
		name      string
		extInputs *webauthn.GetAuthenticationExtensionsClientInputs
	}{
		{
			name: "hmac-secret",
			extInputs: &webauthn.GetAuthenticationExtensionsClientInputs{
				GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{
					HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 32)},
				},
			},
		},
		{
			name: "credBlob",
			extInputs: &webauthn.GetAuthenticationExtensionsClientInputs{
				GetCredentialBlobInputs: &webauthn.GetCredentialBlobInputs{GetCredBlob: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fake := testhid.NewCBORDevice(t, testCID)
			d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
				Extensions: []extension.ExtensionIdentifier{},
			})

			var gotErr error
			for _, err := range d.GetAssertion(
				testContext,
				nil,
				"example.com",
				[]byte("client-data"),
				nil,
				tt.extInputs,
				nil,
			) {
				gotErr = err
			}

			require.Error(t, gotErr)
			assert.True(t, errors.Is(gotErr, ErrNotSupported))
			assert.Empty(t, fake.Writes())
		})
	}
}

func TestGetAssertionRejectsMalformedTokenBeforeExtensionKeyAgreement(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
		Versions:           protocol.Versions{protocol.FIDO_2_3},
		Extensions:         []extension.ExtensionIdentifier{extension.ExtensionIdentifierHMACSecret},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
		Options: map[protocol.Option]bool{
			protocol.OptionClientPIN: true,
		},
	})
	extInputs := &webauthn.GetAuthenticationExtensionsClientInputs{
		GetHMACSecretInputs: &webauthn.GetHMACSecretInputs{
			HMACGetSecret: webauthn.HMACGetSecretInput{Salt1: make([]byte, 32)},
		},
	}

	var gotErr error
	for _, err := range d.GetAssertion(
		testContext,
		make([]byte, 16),
		"example.com",
		[]byte("client-data"),
		nil,
		extInputs,
		nil,
	) {
		gotErr = err
	}

	require.ErrorIs(t, gotErr, SyntaxError)
	assert.Empty(t, fake.Writes())
}

func TestRetryQueriesWorkBeforePINOrUVConfiguration(t *testing.T) {
	t.Run("PIN", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
			PinRetries: new(uint(8)),
		}))
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			Options: map[protocol.Option]bool{
				protocol.OptionClientPIN: false,
			},
		})

		retries, _, err := d.GetPINRetries(testContext)
		require.NoError(t, err)
		assert.Equal(t, uint(8), retries)
	})

	t.Run("UV", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
			UvRetries: new(uint(5)),
		}))
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Options: map[protocol.Option]bool{
				protocol.OptionUserVerification: false,
			},
		})

		retries, err := d.GetUVRetries(testContext)
		require.NoError(t, err)
		assert.Equal(t, uint(5), retries)
	})
}

func TestFIDO20RejectsCTAP21OnlyCommands(t *testing.T) {
	t.Run("getUVRetries", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_0},
			Options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
		})

		_, err := d.GetUVRetries(testContext)
		require.ErrorIs(t, err, ErrNotSupported)
		assert.Empty(t, fake.Writes())
	})

	t.Run("authenticatorSelection", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_0},
		})

		err := d.Selection(testContext)
		require.ErrorIs(t, err, ErrNotSupported)
		assert.Empty(t, fake.Writes())
	})
}
