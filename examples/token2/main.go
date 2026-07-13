package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/protocol"
	"github.com/go-ctap/ctap/transport/token2"
	"github.com/go-ctap/pcsc"
)

func main() {
	ctx := context.Background()
	readerName := findReader(os.Getenv("PCSC_READER"))
	card, err := pcsc.Open(readerName)
	if err != nil {
		log.Fatal(err)
	}

	transport, err := token2.New(ctx, card)
	if err != nil {
		_ = card.Close()
		log.Fatal(err)
	}

	device, err := authenticator.New(ctx, transport)
	if err != nil {
		log.Fatal(err)
	}
	defer device.Close()

	pin := os.Getenv("FIDO2_PIN")
	if pin == "" {
		log.Fatal("FIDO2_PIN is not set")
	}

	token, err := device.GetPinUvAuthTokenUsingPIN(
		ctx,
		pin,
		protocol.PermissionCredentialManagement,
		"",
	)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("PC/SC reader: %s\n", readerName)
	printCredentials(ctx, device, token)
}

func findReader(filter string) string {
	for reader, err := range pcsc.Enumerate() {
		if err != nil {
			log.Fatal(err)
		}
		if filter == "" {
			return reader.Name
		}
		if strings.Contains(reader.Name, filter) {
			return reader.Name
		}
	}
	log.Fatalf("no PC/SC reader matching %q", filter)
	return ""
}

func printCredentials(ctx context.Context, device *authenticator.Device, token []byte) {
	metadata, err := device.GetCredsMetadata(ctx, token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf(
		"Passkeys: %d (%d slots left)\n",
		metadata.ExistingResidentCredentialsCount,
		metadata.MaxPossibleRemainingResidentCredentialsCount,
	)

	rps := make([]protocol.AuthenticatorCredentialManagementResponse, 0)
	for rp, err := range device.EnumerateRPs(ctx, token) {
		if err != nil {
			log.Fatal(err)
		}
		rps = append(rps, rp)
	}

	index := 1
	for _, rp := range rps {
		for credential, err := range device.EnumerateCredentials(ctx, token, rp.RPIDHash) {
			if err != nil {
				log.Fatal(err)
			}
			fmt.Printf(
				"%d) %s: %s / %s / %s\n",
				index,
				rp.RP.ID,
				string(credential.User.ID),
				credential.User.Name,
				credential.User.DisplayName,
			)
			index++
		}
	}
}
