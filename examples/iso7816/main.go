package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/transport/iso7816"
	"github.com/go-ctap/pcsc"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) (err error) {
	readerName, err := findReader(os.Getenv("PCSC_READER"))
	if err != nil {
		return err
	}

	card, err := pcsc.Open(
		readerName,
		pcsc.WithShareMode(pcsc.ShareModeExclusive),
	)
	if err != nil {
		return fmt.Errorf("open PC/SC reader %q: %w", readerName, err)
	}

	isoTransport, err := iso7816.New(ctx, card)
	if err != nil {
		// iso7816.New does not take ownership on failure.
		return errors.Join(
			fmt.Errorf("initialize FIDO applet on %q: %w", readerName, err),
			card.Close(),
		)
	}

	device, err := authenticator.New(ctx, isoTransport)
	if err != nil {
		return errors.Join(
			fmt.Errorf("initialize authenticator: %w", err),
			isoTransport.Close(),
		)
	}
	defer func() {
		err = errors.Join(err, device.Close())
	}()

	info, valid := device.GetInfoCached()
	if !valid {
		return errors.New("authenticator info cache is unexpectedly invalid")
	}

	fmt.Printf("PC/SC reader: %s\n", readerName)
	fmt.Printf("Selected applet version: %s\n", isoTransport.Version())
	fmt.Printf("CTAP versions: %v\n", info.Versions)
	fmt.Printf("AAGUID: %s\n", info.AAGUID)
	fmt.Printf("Options: %v\n", info.Options)
	return nil
}

func findReader(filter string) (string, error) {
	for reader, err := range pcsc.Enumerate() {
		if err != nil {
			return "", fmt.Errorf("enumerate PC/SC readers: %w", err)
		}
		if filter == "" || strings.Contains(reader.Name, filter) {
			return reader.Name, nil
		}
	}

	if filter == "" {
		return "", errors.New("no PC/SC readers found")
	}
	return "", fmt.Errorf("no PC/SC reader matching %q", filter)
}
