package discover

import (
	"testing"

	ghid "github.com/go-ctap/hid"
)

func TestIsFIDOEvent(t *testing.T) {
	tests := []struct {
		name  string
		event ghid.DeviceEvent
		want  bool
	}{
		{"connected", ghid.DeviceEvent{Type: ghid.DeviceEventConnected, DeviceInfo: &ghid.DeviceInfo{UsagePage: 0xf1d0, Usage: 0x01}}, true},
		{"disconnected", ghid.DeviceEvent{Type: ghid.DeviceEventDisconnected, DeviceInfo: &ghid.DeviceInfo{UsagePage: 0xf1d0, Usage: 0x01}}, true},
		{"missing metadata", ghid.DeviceEvent{Type: ghid.DeviceEventConnected}, true},
		{"other HID", ghid.DeviceEvent{Type: ghid.DeviceEventConnected, DeviceInfo: &ghid.DeviceInfo{UsagePage: 0x01, Usage: 0x02}}, false},
		{"unknown event", ghid.DeviceEvent{Type: "changed"}, false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isFIDOEvent(test.event); got != test.want {
				t.Fatalf("isFIDOEvent() = %v, want %v", got, test.want)
			}
		})
	}
}
