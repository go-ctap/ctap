package authenticator

import (
	"errors"
	"maps"
	"testing"

	"github.com/telesma-app/ctap/extension"
	"github.com/telesma-app/ctap/internal/testhid"
	"github.com/telesma-app/ctap/protocol"
	"github.com/telesma-app/ctap/webauthn"
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
			d := newTestDevice(t, fake, tt.info)

			_, err := d.GetBioModality(testContext)
			require.NoError(t, err)

			command, _ := fake.FirstCTAPPayload(t)
			assert.Equal(t, tt.wantCommand, command)
		})
	}
}

func TestBioEnrollmentPreviewAbsentIsNotSupported(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		Options:  map[protocol.Option]bool{},
	})

	_, err := d.GetBioModality(testContext)
	require.ErrorIs(t, err, ErrNotSupported)
	assertNoAuthenticatorIO(t, fake)
}

func TestProtectedSubcommandsRejectMissingOrMalformedTokenBeforeCommand(t *testing.T) {
	t.Run("BioEnrollment requires token", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionBioEnroll: false,
			},
		})

		_, err := d.EnrollBegin(testContext, nil, 0)
		require.ErrorIs(t, err, ErrPinUvAuthTokenRequired)
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("CredentialManagement requires token", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagement: true,
			},
		})

		_, err := d.GetCredsMetadata(testContext, nil)
		require.ErrorIs(t, err, ErrPinUvAuthTokenRequired)
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("protocol 2 rejects short token without panic", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo},
			Options: map[protocol.Option]bool{
				protocol.OptionCredentialManagement: true,
			},
		})

		_, err := d.GetCredsMetadata(testContext, make([]byte, 16))
		require.ErrorIs(t, err, SyntaxError)
		assertNoAuthenticatorIO(t, fake)
	})
}

func TestPinUvAuthTokenLengthUsesCTAPVersion(t *testing.T) {
	t.Run("FIDO 2.0 accepts a longer protocol 1 token", func(t *testing.T) {
		d := newTestDevice(t, testhid.NewCBORDevice(t, testCID), protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_0},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		})

		got, err := d.pinUvAuthProtocolForRequest(make([]byte, 48), true)
		require.NoError(t, err)
		assert.Equal(t, protocol.PinUvAuthProtocolOne, got)
	})

	t.Run("FIDO 2.1 rejects a longer protocol 1 token", func(t *testing.T) {
		d := newTestDevice(t, testhid.NewCBORDevice(t, testCID), protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_1},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		})

		_, err := d.pinUvAuthProtocolForRequest(make([]byte, 48), true)
		require.ErrorIs(t, err, SyntaxError)
	})

	t.Run("FIDO 2.1 Preview accepts a longer protocol 1 token", func(t *testing.T) {
		d := newTestDevice(t, testhid.NewCBORDevice(t, testCID), protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
		})

		got, err := d.pinUvAuthProtocolForRequest(make([]byte, 48), true)
		require.NoError(t, err)
		assert.Equal(t, protocol.PinUvAuthProtocolOne, got)
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

func TestSelectPinUvAuthTokenFlowUsingUV(t *testing.T) {
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

		_, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionBioEnrollment, "")
		require.ErrorIs(t, err, ErrNotSupported)

		info.Options[protocol.OptionUvBioEnroll] = true
		flow, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionBioEnrollment, "")
		require.NoError(t, err)
		assert.Equal(t, uvTokenFlowWithPermissions, flow)
	})

	t.Run("acfg requires uvAcfg and authnrCfg", func(t *testing.T) {
		info := baseInfo
		info.Options = map[protocol.Option]bool{
			protocol.OptionPinUvAuthToken:   true,
			protocol.OptionUserVerification: true,
			protocol.OptionUvAcfg:           true,
		}

		_, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionAuthenticatorConfiguration, "")
		require.ErrorIs(t, err, ErrNotSupported)

		info.Options[protocol.OptionAuthenticatorConfig] = true
		flow, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionAuthenticatorConfiguration, "")
		require.NoError(t, err)
		assert.Equal(t, uvTokenFlowWithPermissions, flow)
	})

	t.Run("ga requires RP ID", func(t *testing.T) {
		_, err := selectPinUvAuthTokenFlowUsingUV(baseInfo, protocol.PermissionGetAssertion, "")
		require.ErrorIs(t, err, SyntaxError)

		flow, err := selectPinUvAuthTokenFlowUsingUV(baseInfo, protocol.PermissionGetAssertion, "example.com")
		require.NoError(t, err)
		assert.Equal(t, uvTokenFlowWithPermissions, flow)
	})

	t.Run("FIDO 2.0 ignores unknown pinUvAuthToken option", func(t *testing.T) {
		info := baseInfo
		info.Versions = protocol.Versions{protocol.FIDO_2_0}

		_, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionGetAssertion, "example.com")
		require.ErrorIs(t, err, ErrNotSupported)
	})

	previewInfo := protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
		PinUvAuthProtocols: []protocol.PinUvAuthProtocol{
			protocol.PinUvAuthProtocolOne,
		},
		Options: map[protocol.Option]bool{
			protocol.OptionUserVerification:            true,
			protocol.OptionUvToken:                     true,
			protocol.OptionCredentialManagementPreview: true,
			protocol.OptionUserVerificationMgmtPreview: false,
		},
	}

	t.Run("preview bio enrollment uses legacy UV token", func(t *testing.T) {
		flow, err := selectPinUvAuthTokenFlowUsingUV(
			previewInfo,
			protocol.PermissionBioEnrollment,
			"",
		)
		require.NoError(t, err)
		assert.Equal(t, uvTokenFlowPreview, flow)
	})

	t.Run("preview credential management uses legacy UV token", func(t *testing.T) {
		flow, err := selectPinUvAuthTokenFlowUsingUV(
			previewInfo,
			protocol.PermissionCredentialManagement,
			"",
		)
		require.NoError(t, err)
		assert.Equal(t, uvTokenFlowPreview, flow)
	})

	t.Run("preview get assertion does not require RP ID", func(t *testing.T) {
		flow, err := selectPinUvAuthTokenFlowUsingUV(
			previewInfo,
			protocol.PermissionGetAssertion,
			"",
		)
		require.NoError(t, err)
		assert.Equal(t, uvTokenFlowPreview, flow)
	})

	t.Run("preview requires uvToken option", func(t *testing.T) {
		info := previewInfo
		info.Options = maps.Clone(previewInfo.Options)
		delete(info.Options, protocol.OptionUvToken)

		_, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionBioEnrollment, "")
		require.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("preview requires protocol one", func(t *testing.T) {
		info := previewInfo
		info.PinUvAuthProtocols = []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolTwo}

		_, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionBioEnrollment, "")
		require.ErrorIs(t, err, ErrNotSupported)
	})

	t.Run("preview allows omitted optional protocol list", func(t *testing.T) {
		info := previewInfo
		info.PinUvAuthProtocols = nil

		flow, err := selectPinUvAuthTokenFlowUsingUV(info, protocol.PermissionBioEnrollment, "")
		require.NoError(t, err)
		assert.Equal(t, uvTokenFlowPreview, flow)
	})

	t.Run("preview rejects permissions not granted by getUvToken", func(t *testing.T) {
		_, err := selectPinUvAuthTokenFlowUsingUV(previewInfo, protocol.PermissionLargeBlobWrite, "")
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
		d := newTestDevice(t, fake, baseInfo)

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
		d := newTestDevice(t, fake, info)

		err := d.SetLargeBlobs(testContext, nil, nil)
		require.ErrorIs(t, err, ErrPinUvAuthTokenRequired)
		assertNoAuthenticatorIO(t, fake)
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
		d := newTestDevice(t, fake, info)

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
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("setMinPINLength option is required", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
			Options: map[protocol.Option]bool{
				protocol.OptionAuthenticatorConfig: true,
			},
		})

		err := d.SetMinPINLength(testContext, nil, protocol.SetMinPINLengthConfigSubCommandParams{
			NewMinPINLength: new(uint(8)),
		})
		require.ErrorIs(t, err, ErrNotSupported)
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("FIDO 2.3 command list is authoritative", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("FIDO 2.3 missing command list rejects subcommands", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
		assertNoAuthenticatorIO(t, fake)
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
		d := newTestDevice(t, fake, info)

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
		d := newTestDevice(t, fake, info)

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
		d := newTestDevice(t, fake, info)

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
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("setMinPINLength rejects decreasing minimum", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("setMinPINLength validates RP ID limit", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("setMinPINLength requires complexity feature", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
		assertNoAuthenticatorIO(t, fake)
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
			d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
			assertNoAuthenticatorIO(t, fake)
		})
	}
}

func TestGetAssertionRejectsMalformedTokenBeforeExtensionKeyAgreement(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
	assertNoAuthenticatorIO(t, fake)
}

func TestRetryQueriesWorkBeforePINOrUVConfiguration(t *testing.T) {
	t.Run("PIN", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
			PinRetries: new(uint(8)),
		}))
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
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
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions:           protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
			PinUvAuthProtocols: []protocol.PinUvAuthProtocol{protocol.PinUvAuthProtocolOne},
			Options: map[protocol.Option]bool{
				protocol.OptionUserVerification: false,
			},
		})

		retries, err := d.GetUVRetries(testContext)
		require.NoError(t, err)
		assert.Equal(t, uint(5), retries)

		command, request := fake.FirstCTAPRequestMap(t)
		assert.Equal(t, protocol.AuthenticatorClientPIN, command)
		assert.Equal(t, uint64(protocol.PinUvAuthProtocolOne), request[uint64(1)])
		assert.Equal(t, uint64(protocol.ClientPINSubCommandGetUVRetries), request[uint64(2)])
	})

	t.Run("UV without pinUvAuthProtocol", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID, encodeCBOR(t, protocol.AuthenticatorClientPINResponse{
			UvRetries: new(uint(5)),
		}))
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_1},
			Options: map[protocol.Option]bool{
				protocol.OptionUserVerification: false,
			},
		})

		retries, err := d.GetUVRetries(testContext)
		require.NoError(t, err)
		assert.Equal(t, uint(5), retries)

		_, request := fake.FirstCTAPRequestMap(t)
		_, present := request[uint64(1)]
		assert.False(t, present)
	})
}

func TestFIDO20RejectsCTAP21OnlyCommands(t *testing.T) {
	t.Run("getUVRetries", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_0},
			Options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
		})

		_, err := d.GetUVRetries(testContext)
		require.ErrorIs(t, err, ErrNotSupported)
		assertNoAuthenticatorIO(t, fake)
	})

	t.Run("authenticatorSelection", func(t *testing.T) {
		fake := testhid.NewCBORDevice(t, testCID)
		d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
			Versions: protocol.Versions{protocol.FIDO_2_0},
		})

		err := d.Selection(testContext)
		require.ErrorIs(t, err, ErrNotSupported)
		assertNoAuthenticatorIO(t, fake)
	})
}

func TestValidateMakeCredentialAuthorization(t *testing.T) {
	tests := []struct {
		name    string
		info    protocol.AuthenticatorGetInfoResponse
		token   []byte
		options map[protocol.Option]bool
		wantErr error
	}{
		{
			name: "FIDO 2.0 unprotected authenticator",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
			},
		},
		{
			name: "FIDO 2.0 configured PIN requires authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.0 configured built-in UV requires authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.0 token satisfies authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			token: []byte("token"),
		},
		{
			name: "FIDO 2.0 built-in UV satisfies authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
		},
		{
			name: "FIDO 2.0 ignores makeCredUvNotRqd",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.0 ignores alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv: true,
				},
			},
		},
		{
			name: "FIDO 2.1 configured PIN requires authorization by default",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.1 token satisfies default requirement",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
			token: []byte("token"),
		},
		{
			name: "FIDO 2.1 non-discoverable credential may omit authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "FIDO 2.1 discoverable credential still requires authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionResidentKeys: true,
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.1 always UV requires authorization without built-in UV",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.1 always UV implicitly uses configured built-in UV",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:         true,
					protocol.OptionUserVerification: true,
				},
			},
		},
		{
			name: "FIDO 2.3 uses modern makeCredUvNotRqd semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "FIDO 2.3 discoverable credential still requires authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionResidentKeys: true,
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "device supporting FIDO 2.0 and 2.1 uses modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "FIDO 2.1 preview uses modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1_PRE},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "unknown future FIDO version uses modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.Version("FIDO_2_4")},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "missing versions preserves modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN:                   true,
					protocol.OptionMakeCredentialUvNotRequired: true,
				},
			},
		},
		{
			name: "built-in UV unsupported",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: ErrNotSupported,
		},
		{
			name: "built-in UV not configured",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: false,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: ErrUvNotConfigured,
		},
		{
			name:  "token and built-in UV are mutually exclusive",
			token: []byte("token"),
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: SyntaxError,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateMakeCredentialAuthorization(test.info, test.token, test.options)
			if test.wantErr == nil {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

func TestValidateGetAssertionAuthorization(t *testing.T) {
	tests := []struct {
		name    string
		info    protocol.AuthenticatorGetInfoResponse
		token   []byte
		options map[protocol.Option]bool
		wantErr error
	}{
		{
			name: "FIDO 2.0 configured PIN does not require authorization",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
		},
		{
			name: "FIDO 2.0 ignores alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.U2F_V2},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
		},
		{
			name: "configured PIN without alwaysUv permits UP-only assertion",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionClientPIN: true,
				},
			},
		},
		{
			name: "token and built-in UV are mutually exclusive",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: true,
				},
			},
			token: []byte("token"),
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: SyntaxError,
		},
		{
			name: "built-in UV unsupported",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: ErrNotSupported,
		},
		{
			name: "built-in UV not configured",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionUserVerification: false,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
			wantErr: ErrUvNotConfigured,
		},
		{
			name: "rk is unsupported even when false",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
			},
			options: map[protocol.Option]bool{
				protocol.OptionResidentKeys: false,
			},
			wantErr: ErrNotSupported,
		},
		{
			name: "FIDO 2.1 alwaysUv requires token for PIN-only authenticator",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "FIDO 2.3 token satisfies alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			token: []byte("token"),
		},
		{
			name: "explicit built-in UV satisfies alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:         true,
					protocol.OptionUserVerification: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserVerification: true,
			},
		},
		{
			name: "configured built-in UV is used implicitly for alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:         true,
					protocol.OptionUserVerification: true,
				},
			},
		},
		{
			name: "up false bypasses alwaysUv requirement",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			options: map[protocol.Option]bool{
				protocol.OptionUserPresence: false,
			},
		},
		{
			name: "alwaysUv reports unconfigured built-in UV",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:         true,
					protocol.OptionUserVerification: false,
				},
			},
			wantErr: ErrUvNotConfigured,
		},
		{
			name: "alwaysUv without available UV mechanism requires built-in UV",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv: true,
				},
			},
			wantErr: ErrBuiltInUVRequired,
		},
		{
			name: "client PIN without GetAssertion permission cannot satisfy alwaysUv",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_3},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:                       true,
					protocol.OptionClientPIN:                      true,
					protocol.OptionNoMcGaPermissionsWithClientPin: true,
				},
			},
			wantErr: ErrBuiltInUVRequired,
		},
		{
			name: "device supporting FIDO 2.0 and 2.1 uses modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Versions: protocol.Versions{protocol.FIDO_2_0, protocol.FIDO_2_1},
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
		{
			name: "missing versions preserves modern semantics",
			info: protocol.AuthenticatorGetInfoResponse{
				Options: map[protocol.Option]bool{
					protocol.OptionAlwaysUv:  true,
					protocol.OptionClientPIN: true,
				},
			},
			wantErr: ErrPinUvAuthTokenRequired,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validateGetAssertionAuthorization(test.info, test.token, test.options)
			if test.wantErr == nil {
				require.NoError(t, err)
				return
			}

			require.ErrorIs(t, err, test.wantErr)
		})
	}
}

func TestGetAssertionValidatesAuthorizationBeforeCommand(t *testing.T) {
	fake := testhid.NewCBORDevice(t, testCID)
	d := newTestDevice(t, fake, protocol.AuthenticatorGetInfoResponse{
		Versions: protocol.Versions{protocol.FIDO_2_3},
		Options: map[protocol.Option]bool{
			protocol.OptionAlwaysUv:  true,
			protocol.OptionClientPIN: true,
		},
	})

	var count int
	for assertion, err := range d.GetAssertion(
		testContext,
		nil,
		"example.com",
		[]byte("client-data"),
		nil,
		nil,
		nil,
	) {
		count++
		assert.Equal(t, protocol.AuthenticatorGetAssertionResponse{}, assertion)
		require.ErrorIs(t, err, ErrPinUvAuthTokenRequired)
	}

	assert.Equal(t, 1, count)
	assertNoAuthenticatorIO(t, fake)
}
