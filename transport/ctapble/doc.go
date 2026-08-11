// Package ctapble implements the CTAP Bluetooth Low Energy transport binding.
//
// CTAP requires a conforming authenticator to protect its FIDO GATT
// characteristics. This package relies on the operating system to pair when
// necessary and establish the encrypted link when those characteristics are
// accessed. Open waits for the protected GATT operations used to initialize
// the transport, including acknowledgement of the fidoStatus subscription.
// It does not manage pairing or bonds itself.
package ctapble
