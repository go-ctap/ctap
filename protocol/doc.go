// Package protocol defines CTAP commands, constants, and wire data structures.
//
// Wire types model operational CTAP semantics rather than the optional/required
// spelling of a specification table. A scalar field is a pointer only when an
// omitted CBOR map member and an explicitly encoded zero value (0, false, or an
// empty value) cause observably different protocol behavior. Otherwise, the
// field uses its Go value type and its zero value is omitted on the wire.
//
// For example, newMinPINLength is a pointer because omission means using the
// current minimum while an explicit zero is rejected. An optional boolean for
// which false and omission perform the same operation is not a pointer. Slices
// and maps use nil versus non-nil empty values when presence itself is
// significant. Any presence-sensitive field should have a wire-encoding test
// demonstrating the distinction required by the CTAP specification.
package protocol
