package protocol

type AuthenticatorLargeBlobsRequest struct {
	Get               uint              `cbor:"1,keyasint,omitempty"`
	Set               []byte            `cbor:"2,keyasint,omitempty"`
	Offset            uint              `cbor:"3,keyasint"`
	Length            uint              `cbor:"4,keyasint,omitempty"`
	PinUvAuthParam    []byte            `cbor:"5,keyasint,omitempty"`
	PinUvAuthProtocol PinUvAuthProtocol `cbor:"6,keyasint,omitempty"`
}

type AuthenticatorLargeBlobsResponse struct {
	Config []byte `cbor:"1,keyasint"`
}

type LargeBlob struct {
	Ciphertext []byte `cbor:"1,keyasint"`
	Nonce      []byte `cbor:"2,keyasint"`
	OrigSize   uint   `cbor:"3,keyasint"`
}
