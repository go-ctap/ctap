package webauthn

import (
	"encoding/json"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestCreateAuthenticationExtensionsClientInputsJSON(t *testing.T) {
	encoded, err := json.Marshal(CreateAuthenticationExtensionsClientInputs{
		CreateCredentialPropertiesInputs: &CreateCredentialPropertiesInputs{CredentialProperties: true},
		PRFInputs:                        &PRFInputs{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"credProps":true,"prf":{}}`; got != want {
		t.Fatalf("JSON = %s, want %s", got, want)
	}
}

func TestLargeBlobOutputsPreserveOptionalPresence(t *testing.T) {
	for name, decode := range map[string]func([]byte, any) error{
		"CBOR": cbor.Unmarshal,
		"JSON": json.Unmarshal,
	} {
		t.Run(name, func(t *testing.T) {
			var absent AuthenticationExtensionsLargeBlobOutputs
			require.NoError(t, decode([]byte(largeBlobOutputEncoding(name, false)), &absent))
			require.Nil(t, absent.Supported)
			require.Nil(t, absent.Written)
			require.Nil(t, absent.Blob)

			var present AuthenticationExtensionsLargeBlobOutputs
			require.NoError(t, decode([]byte(largeBlobOutputEncoding(name, true)), &present))
			require.NotNil(t, present.Supported)
			require.False(t, *present.Supported)
			require.NotNil(t, present.Written)
			require.False(t, *present.Written)
			require.NotNil(t, present.Blob)
			require.Empty(t, present.Blob)
		})
	}
}

func TestLargeBlobOutputsPreservePresentEmptyBlob(t *testing.T) {
	for name, encode := range map[string]func(any) ([]byte, error){
		"CBOR": cbor.Marshal,
		"JSON": json.Marshal,
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := encode(AuthenticationExtensionsLargeBlobOutputs{Blob: []byte{}})
			require.NoError(t, err)

			var present map[string]any
			if name == "CBOR" {
				require.NoError(t, cbor.Unmarshal(encoded, &present))
			} else {
				require.NoError(t, json.Unmarshal(encoded, &present))
			}
			require.Contains(t, present, "blob")

			encoded, err = encode(AuthenticationExtensionsLargeBlobOutputs{})
			require.NoError(t, err)
			var absent map[string]any
			if name == "CBOR" {
				require.NoError(t, cbor.Unmarshal(encoded, &absent))
			} else {
				require.NoError(t, json.Unmarshal(encoded, &absent))
			}
			require.NotContains(t, absent, "blob")
		})
	}
}

func TestLargeBlobInputsPreservePresentEmptyWrite(t *testing.T) {
	for name, encode := range map[string]func(any) ([]byte, error){
		"CBOR": cbor.Marshal,
		"JSON": json.Marshal,
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := encode(AuthenticationExtensionsLargeBlobInputs{Write: []byte{}})
			require.NoError(t, err)

			var present map[string]any
			if name == "CBOR" {
				require.NoError(t, cbor.Unmarshal(encoded, &present))
			} else {
				require.NoError(t, json.Unmarshal(encoded, &present))
			}
			require.Contains(t, present, "write")

			encoded, err = encode(AuthenticationExtensionsLargeBlobInputs{})
			require.NoError(t, err)
			var absent map[string]any
			if name == "CBOR" {
				require.NoError(t, cbor.Unmarshal(encoded, &absent))
			} else {
				require.NoError(t, json.Unmarshal(encoded, &absent))
			}
			require.NotContains(t, absent, "write")
		})
	}
}

func TestLargeBlobInputsPreservePresentFalseRead(t *testing.T) {
	for name, encode := range map[string]func(any) ([]byte, error){
		"CBOR": cbor.Marshal,
		"JSON": json.Marshal,
	} {
		t.Run(name, func(t *testing.T) {
			read := false
			encoded, err := encode(AuthenticationExtensionsLargeBlobInputs{Read: &read})
			require.NoError(t, err)

			var fields map[string]any
			if name == "CBOR" {
				require.NoError(t, cbor.Unmarshal(encoded, &fields))
			} else {
				require.NoError(t, json.Unmarshal(encoded, &fields))
			}
			require.Contains(t, fields, "read")
			require.Equal(t, false, fields["read"])

			var decoded AuthenticationExtensionsLargeBlobInputs
			if name == "CBOR" {
				require.NoError(t, cbor.Unmarshal(encoded, &decoded))
			} else {
				require.NoError(t, json.Unmarshal(encoded, &decoded))
			}
			require.NotNil(t, decoded.Read)
			require.False(t, *decoded.Read)
		})
	}
}

func largeBlobOutputEncoding(format string, present bool) string {
	if format == "JSON" {
		if present {
			return `{"supported":false,"written":false,"blob":""}`
		}
		return `{}`
	}
	if present {
		return string([]byte{
			0xa3,
			0x69, 's', 'u', 'p', 'p', 'o', 'r', 't', 'e', 'd', 0xf4,
			0x67, 'w', 'r', 'i', 't', 't', 'e', 'n', 0xf4,
			0x64, 'b', 'l', 'o', 'b', 0x40,
		})
	}
	return string([]byte{0xa0})
}

func TestAuthenticationExtensionsPRFValuesJSONPreservesPresentEmptySecond(t *testing.T) {
	encoded, err := json.Marshal(AuthenticationExtensionsPRFValues{
		First:  []byte{},
		Second: []byte{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(encoded), `{"first":"","second":""}`; got != want {
		t.Fatalf("JSON = %s, want %s", got, want)
	}
}

func TestAuthenticationExtensionsPRFOutputsJSONFollowCeremony(t *testing.T) {
	create, err := json.Marshal(CreatePRFOutputs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(create), `{"prf":{"enabled":false}}`; got != want {
		t.Fatalf("create JSON = %s, want %s", got, want)
	}

	get, err := json.Marshal(GetPRFOutputs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(get), `{"prf":{}}`; got != want {
		t.Fatalf("get JSON = %s, want %s", got, want)
	}
}

func TestCredentialPropertiesOutputJSONDistinguishesFalseFromUnknown(t *testing.T) {
	residentKey := false
	known, err := json.Marshal(CreateCredentialPropertiesOutputs{
		CredentialProperties: CredentialPropertiesOutput{ResidentKey: &residentKey},
	})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(known), `{"credProps":{"rk":false}}`; got != want {
		t.Fatalf("known JSON = %s, want %s", got, want)
	}

	unknown, err := json.Marshal(CreateCredentialPropertiesOutputs{})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(unknown), `{"credProps":{}}`; got != want {
		t.Fatalf("unknown JSON = %s, want %s", got, want)
	}
}
