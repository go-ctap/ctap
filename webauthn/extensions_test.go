package webauthn

import (
	"encoding/json"
	"testing"
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
