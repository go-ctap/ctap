package main

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/go-ctap/ctap/authenticator"
	ctappcsc "github.com/go-ctap/ctap/backend/pcsc"
)

func main() {
	if err := run(context.Background()); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context) (err error) {
	device, err := authenticator.Select(ctx, ctappcsc.Enumerate)
	if err != nil {
		return err
	}
	defer func() {
		err = errors.Join(err, device.Close())
	}()

	info, valid := device.GetInfoCached()
	if !valid {
		return errors.New("authenticator info cache is unexpectedly invalid")
	}

	fmt.Printf("CTAP versions: %v\n", info.Versions)
	fmt.Printf("AAGUID: %s\n", info.AAGUID)
	fmt.Printf("Options: %v\n", info.Options)
	return nil
}
