package protocol

type AuthenticatorBioEnrollmentRequest struct {
	Modality          BioModality                   `cbor:"1,keyasint,omitempty"`
	SubCommand        BioEnrollmentSubCommand       `cbor:"2,keyasint,omitempty"`
	SubCommandParams  BioEnrollmentSubCommandParams `cbor:"3,keyasint,omitzero"`
	PinUvAuthProtocol PinUvAuthProtocol             `cbor:"4,keyasint,omitempty"`
	PinUvAuthParam    []byte                        `cbor:"5,keyasint,omitempty"`
	GetModality       bool                          `cbor:"6,keyasint,omitempty"`
}

type BioEnrollmentSubCommandParams struct {
	TemplateID           []byte  `cbor:"1,keyasint,omitempty"`
	TemplateFriendlyName *string `cbor:"2,keyasint,omitzero"`
	TimeoutMilliseconds  uint    `cbor:"3,keyasint,omitempty"`
}

type AuthenticatorBioEnrollmentResponse struct {
	Modality                           BioModality             `cbor:"1,keyasint,omitzero"`
	FingerprintKind                    uint                    `cbor:"2,keyasint,omitzero"`
	MaxCaptureSamplesRequiredForEnroll *uint                   `cbor:"3,keyasint,omitempty"`
	TemplateID                         []byte                  `cbor:"4,keyasint,omitempty"`
	LastEnrollSampleStatus             *LastEnrollSampleStatus `cbor:"5,keyasint,omitempty"`
	RemainingSamples                   *uint                   `cbor:"6,keyasint,omitempty"`
	TemplateInfos                      []TemplateInfo          `cbor:"7,keyasint,omitzero"`
	MaxTemplateFriendlyName            *uint                   `cbor:"8,keyasint,omitempty"`
}

type TemplateInfo struct {
	TemplateID           []byte `cbor:"1,keyasint"`
	TemplateFriendlyName string `cbor:"2,keyasint,omitempty"`
}
