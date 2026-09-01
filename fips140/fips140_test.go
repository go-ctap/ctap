package fips140_test

import (
	cryptofips140 "crypto/fips140"
	"errors"
	"strings"
	"testing"

	ctapfips140 "github.com/telesma-app/ctap/fips140"
)

func TestRequiredFollowsGoFIPS140Mode(t *testing.T) {
	if got, want := ctapfips140.Required(), cryptofips140.Enabled(); got != want {
		t.Fatalf("Required() = %v, want %v", got, want)
	}
}

func TestNotAllowedError(t *testing.T) {
	err := &ctapfips140.NotAllowedError{Operation: "verify COSE algorithm -47"}

	if !strings.Contains(err.Error(), "verify COSE algorithm -47") {
		t.Fatalf("Error() = %q, want operation", err.Error())
	}
	if !strings.Contains(err.Error(), "FIPS 140-3 mode") {
		t.Fatalf("Error() = %q, want FIPS 140-3 mode", err.Error())
	}
	if !errors.Is(err, ctapfips140.ErrNotAllowed) {
		t.Fatal("errors.Is did not match ErrNotAllowed")
	}

	var target *ctapfips140.NotAllowedError
	if !errors.As(err, &target) {
		t.Fatal("errors.As did not match NotAllowedError")
	}
	if target.Operation != err.Operation {
		t.Fatalf("errors.As operation = %q, want %q", target.Operation, err.Operation)
	}
}

func TestNotAllowedErrorWithoutOperation(t *testing.T) {
	err := &ctapfips140.NotAllowedError{}
	if got, want := err.Error(), ctapfips140.ErrNotAllowed.Error(); got != want {
		t.Fatalf("Error() = %q, want %q", got, want)
	}
}
