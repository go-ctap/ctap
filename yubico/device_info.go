// Package yubico implements Yubico-specific commands and data formats.
package yubico

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/go-ctap/ctap/transport/ctaphid"
)

//go:generate go run golang.org/x/tools/cmd/stringer@v0.47.0 -type=Capability -output=capability_string.go

// Capability is a bitmap of applications exposed by a YubiKey interface.
type Capability uint16

const (
	CapabilityOTP     Capability = 0x0001
	CapabilityU2F     Capability = 0x0002
	CapabilityCCID    Capability = 0x0004
	CapabilityOpenPGP Capability = 0x0008
	CapabilityPIV     Capability = 0x0010
	CapabilityOATH    Capability = 0x0020
	CapabilityCTAP2   Capability = 0x0200
)

// FirmwareVersion is the major.minor.build version reported by the device.
type FirmwareVersion struct {
	Major byte
	Minor byte
	Build byte
}

//go:generate go run golang.org/x/tools/cmd/stringer@v0.47.0 -type=FormFactor -output=form_factor_string.go

// FormFactor describes the physical shape and connector type of a YubiKey.
type FormFactor byte

const (
	FormFactorUnknown               FormFactor = 0
	FormFactorUSBAKeychain          FormFactor = 1
	FormFactorUSBANano              FormFactor = 2
	FormFactorUSBCKeychain          FormFactor = 3
	FormFactorUSBCNano              FormFactor = 4
	FormFactorUSBCLightning         FormFactor = 5
	FormFactorUSBABiometricKeychain FormFactor = 6
	FormFactorUSBCBiometricKeychain FormFactor = 7
)

// DeviceInfo is returned by Yubico's GET DEVICE INFORMATION command.
// UnknownFields preserves tags introduced by newer firmware.
type DeviceInfo struct {
	SupportedUSBCapabilities Capability
	Serial                   *uint32
	EnabledUSBCapabilities   Capability
	FormFactor               FormFactor
	IsFIPS                   bool
	IsSecurityKey            bool
	FirmwareVersion          FirmwareVersion
	AutoEjectTimeout         uint16
	ChallengeResponseTimeout byte
	DeviceFlags              byte
	Locked                   bool
	SupportedNFCCapabilities *Capability
	EnabledNFCCapabilities   *Capability
	UnknownFields            map[byte][]byte
}

var ErrInvalidDeviceInfo = errors.New("invalid Yubico device information")

// CommandGetDeviceInfo is Yubico's GET DEVICE INFORMATION command. Its
// logical CTAPHID value is 0x42; the transport adds the INIT bit, resulting in
// the on-wire command byte 0xc2.
const CommandGetDeviceInfo ctaphid.Command = ctaphid.CTAPHID_VENDOR_FIRST + 2

// GetDeviceInfo sends Yubico's CTAPHID command 0xc2 (0x42 without the INIT
// packet bit) and parses its TLV response.
func GetDeviceInfo(device io.ReadWriter, cid ctaphid.ChannelID) (DeviceInfo, error) {
	response, err := ctaphid.Vendor(device, cid, CommandGetDeviceInfo, nil)
	if err != nil {
		return DeviceInfo{}, err
	}
	return ParseDeviceInfo(response.Data)
}

// ParseDeviceInfo parses TOTAL-LENGTH followed by TAG-LENGTH-VALUE fields.
func ParseDeviceInfo(data []byte) (DeviceInfo, error) {
	if len(data) == 0 || int(data[0]) != len(data)-1 {
		return DeviceInfo{}, fmt.Errorf("%w: total length does not match payload", ErrInvalidDeviceInfo)
	}

	info := DeviceInfo{UnknownFields: make(map[byte][]byte)}
	for fields := data[1:]; len(fields) > 0; {
		if len(fields) < 2 || int(fields[1]) > len(fields)-2 {
			return DeviceInfo{}, fmt.Errorf("%w: truncated TLV", ErrInvalidDeviceInfo)
		}
		tag, length := fields[0], int(fields[1])
		value := fields[2 : 2+length]
		fields = fields[2+length:]

		switch tag {
		case 0x01:
			v, err := capability(tag, value)
			if err != nil {
				return DeviceInfo{}, err
			}
			info.SupportedUSBCapabilities = v
		case 0x02:
			if len(value) != 4 {
				return DeviceInfo{}, fieldLengthError(tag, 4, len(value))
			}
			v := binary.BigEndian.Uint32(value)
			info.Serial = &v
		case 0x03:
			v, err := capability(tag, value)
			if err != nil {
				return DeviceInfo{}, err
			}
			info.EnabledUSBCapabilities = v
		case 0x04:
			if len(value) != 1 {
				return DeviceInfo{}, fieldLengthError(tag, 1, len(value))
			}
			info.FormFactor = FormFactor(value[0] & 0x0f)
			info.IsFIPS = value[0]&0x80 != 0
			info.IsSecurityKey = value[0]&0x40 != 0
		case 0x05:
			if len(value) != 3 {
				return DeviceInfo{}, fieldLengthError(tag, 3, len(value))
			}
			v := FirmwareVersion{value[0], value[1], value[2]}
			info.FirmwareVersion = v
		case 0x06:
			if len(value) != 2 {
				return DeviceInfo{}, fieldLengthError(tag, 2, len(value))
			}
			v := binary.BigEndian.Uint16(value)
			info.AutoEjectTimeout = v
		case 0x07:
			if len(value) != 1 {
				return DeviceInfo{}, fieldLengthError(tag, 1, len(value))
			}
			v := value[0]
			info.ChallengeResponseTimeout = v
		case 0x08:
			if len(value) != 1 {
				return DeviceInfo{}, fieldLengthError(tag, 1, len(value))
			}
			v := value[0]
			info.DeviceFlags = v
		case 0x0a:
			if len(value) != 1 || value[0] > 1 {
				return DeviceInfo{}, fmt.Errorf("%w: invalid locked field", ErrInvalidDeviceInfo)
			}
			v := value[0] == 1
			info.Locked = v
		case 0x0d:
			v, err := capability(tag, value)
			if err != nil {
				return DeviceInfo{}, err
			}
			info.SupportedNFCCapabilities = &v
		case 0x0e:
			v, err := capability(tag, value)
			if err != nil {
				return DeviceInfo{}, err
			}
			info.EnabledNFCCapabilities = &v
		default:
			info.UnknownFields[tag] = append([]byte(nil), value...)
		}
	}
	return info, nil
}

func capability(tag byte, value []byte) (Capability, error) {
	if len(value) != 2 {
		return 0, fieldLengthError(tag, 2, len(value))
	}
	return Capability(binary.BigEndian.Uint16(value)), nil
}

func fieldLengthError(tag byte, want, got int) error {
	return fmt.Errorf("%w: tag 0x%02x length is %d, want %d", ErrInvalidDeviceInfo, tag, got, want)
}
