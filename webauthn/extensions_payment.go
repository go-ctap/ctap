package webauthn

import "github.com/telesma-app/ctap/credential"

type PaymentEntityLogo struct {
	URL   string `cbor:"url" json:"url"`
	Label string `cbor:"label" json:"label"`
}

type PaymentCurrencyAmount struct {
	Currency string `cbor:"currency" json:"currency"`
	Value    string `cbor:"value" json:"value"`
}

type PaymentCredentialInstrument struct {
	DisplayName     string `cbor:"displayName" json:"displayName"`
	Icon            string `cbor:"icon" json:"icon"`
	IconMustBeShown string `cbor:"iconMustBeShown,omitempty" json:"iconMustBeShown,omitempty"` // should default to true
	Details         string `cbor:"details,omitempty" json:"details,omitempty"`
}

type AuthenticationExtensionsPaymentInputs struct {
	IsPayment                    bool                                       `cbor:"payment" json:"payment"`
	BrowserBoundPubKeyCredParams []credential.PublicKeyCredentialParameters `cbor:"browserBoundPubKeyCredParams" json:"browserBoundPubKeyCredParams"`

	RPID                 string                       `cbor:"rpId" json:"rpId"`
	TopOrigin            string                       `cbor:"topOrigin" json:"topOrigin"`
	PayeeName            string                       `cbor:"payeeName" json:"payeeName"`
	PayeeOrigin          string                       `cbor:"payeeOrigin" json:"payeeOrigin"`
	PaymentEntitiesLogos []PaymentEntityLogo          `cbor:"paymentEntitiesLogos" json:"paymentEntitiesLogos"`
	Total                *PaymentCurrencyAmount       `cbor:"total" json:"total"`
	Instrument           *PaymentCredentialInstrument `cbor:"instrument" json:"instrument"`
}

type PaymentInputs struct {
	Payment AuthenticationExtensionsPaymentInputs `cbor:"payment" json:"payment,omitempty"`
}

type BrowserBoundSignature struct {
	Signature []byte `cbor:"signature" json:"signature"`
}

type AuthenticationExtensionsPaymentOutputs struct {
	BrowserBoundSignature *BrowserBoundSignature `cbor:"browserBoundSignature,omitempty" json:"browserBoundSignature,omitempty"`
}

type PaymentOutputs struct {
	Payment AuthenticationExtensionsPaymentOutputs `cbor:"payment" json:"payment"`
}
