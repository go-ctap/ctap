package main

import (
	"fmt"
	"log"

	"github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/discover"
	"github.com/go-ctap/ctap/protocol"
)

func main() {
	device, err := discover.SelectDevice()
	if err != nil {
		log.Fatal(err)
	}
	defer func() {
		_ = device.Close()
	}()

	retries, err := device.GetUVRetries()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Printf("UV retries: %d\n", retries)

	token, err := device.GetPinUvAuthTokenUsingUV(
		protocol.PermissionCredentialManagement|protocol.PermissionBioEnrollment,
		"",
	)
	if err != nil {
		log.Fatal(err)
	}

	printFingerprints(device, token)
	printCredentials(device, token)
}

func printFingerprints(device *authenticator.Device, token []byte) {
	response, err := device.EnumerateEnrollments(token)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Printf("Fingerprints: %d\n", len(response.TemplateInfos))
	for i, template := range response.TemplateInfos {
		fmt.Printf(
			"%d) %s (template ID: %x)\n",
			i+1,
			template.TemplateFriendlyName,
			template.TemplateID,
		)
	}
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
