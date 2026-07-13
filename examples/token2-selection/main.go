package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/go-ctap/ctap/authenticator"
	"github.com/go-ctap/ctap/discover"
	"github.com/go-ctap/ctap/transport/token2"
	"github.com/go-ctap/pcsc"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) (err error) {
	discover.SelectDevice()

	readerName, err := findReader(os.Getenv("PCSC_READER"))
	if err != nil {
		return err
	}
	card, err := pcsc.Open(readerName)
	if err != nil {
		return fmt.Errorf("open PC/SC reader %q: %w", readerName, err)
	}

	tokenTransport, err := token2.New(ctx, card)
	if err != nil {
		// token2.New did not take ownership on failure.
		return errors.Join(
			fmt.Errorf("initialize Token2 on %q: %w", readerName, err),
			card.Close(),
		)
	}

	device, err := authenticator.New(ctx, tokenTransport)
	if err != nil {
		// authenticator.New owns and closes tokenTransport even on failure.
		return fmt.Errorf("initialize authenticator: %w", err)
	}
	defer func() {
		err = errors.Join(err, device.Close())
	}()

	fmt.Printf("PC/SC reader: %s\n", readerName)
	fmt.Printf("CTAP versions: %v\n", device.GetInfo().Versions)
	fmt.Println("Touch the Token2 now. Waiting for authenticatorSelection...")
	fmt.Println("The Token2 APDU transport cannot interrupt an in-flight command with a context deadline.")

	if err := device.Selection(ctx); err != nil {
		return fmt.Errorf("authenticatorSelection: %w", err)
	}

	fmt.Println("Token2 confirmed user presence.")
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
