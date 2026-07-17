package client

import "fmt"

const clientDataHashSize = 32

func validateClientDataHash(clientDataHash []byte) error {
	if len(clientDataHash) != clientDataHashSize {
		return fmt.Errorf("clientDataHash must be exactly %d bytes", clientDataHashSize)
	}

	return nil
}
