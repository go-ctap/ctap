package main

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"

	"github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/discover"
	"github.com/go-ctap/ctap/options"
	"github.com/go-ctap/ctap/protocol"
)

func main() {
	device, err := discover.SelectDevice(options.WithUseNamedPipes())
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = device.Close()
	}()

	ping := make([]byte, 32)
	if _, err := rand.Read(ping); err != nil {
		log.Fatal(err)
	}
	if err := device.Ping(ping); err != nil {
		log.Fatal(err)
	}

	info := device.GetInfo()
	fmt.Printf("path: %s\n", device.Path)
	fmt.Printf("versions: %v\n", info.Versions)
	fmt.Printf("AAGUID: %s\n", info.AAGUID)
	fmt.Println("named-pipe CTAPHID ping: OK")

	pin := os.Getenv("FIDO2_PIN")
	if pin == "" {
		log.Fatal("FIDO2_PIN is not set")
	}

	token, err := device.GetPinUvAuthTokenUsingPIN(
		pin,
		protocol.PermissionCredentialManagement,
		"",
	)
	if err != nil {
		log.Fatal(err)
	}

	printCredentials(device, token)
}

func printCredentials(device *authenticator.Device, token []byte) {
	metadata, err := device.GetCredsMetadata(token)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf(
		"Passkeys: %d (%d slots left)\n",
		metadata.ExistingResidentCredentialsCount,
		metadata.MaxPossibleRemainingResidentCredentialsCount,
	)

	rps := make([]protocol.AuthenticatorCredentialManagementResponse, 0)
	for rp, err := range device.EnumerateRPs(token) {
		if err != nil {
			log.Fatal(err)
		}
		rps = append(rps, rp)
	}

	index := 1
	for _, rp := range rps {
		for credential, err := range device.EnumerateCredentials(token, rp.RPIDHash) {
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
