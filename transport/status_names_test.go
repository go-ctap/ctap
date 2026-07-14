package transport

import "testing"

func TestStatusCodeName(t *testing.T) {
	name, ok := CTAP2_ERR_NOT_ALLOWED.Name()
	if !ok || name != CTAP2_ERR_NOT_ALLOWED.String() {
		t.Fatalf("known status Name() = %q, %v", name, ok)
	}

	for _, status := range []StatusCode{0x41, 0xe1, 0xf1} {
		if name, ok := status.Name(); ok || name != "" {
			t.Errorf("unknown StatusCode(0x%02x).Name() = %q, %v, want empty, false", byte(status), name, ok)
		}
	}
}
