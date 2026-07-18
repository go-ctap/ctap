package client

import (
	"reflect"
	"sort"
	"strings"

	"github.com/fxamacker/cbor/v2"
	ctapdiag "github.com/go-ctap/ctap/diagnostic"
)

const diagnosticRedacted = "[REDACTED]"

func renderDiagnostic(
	decoder cbor.DecMode,
	encoder cbor.EncMode,
	raw []byte,
	schema reflect.Type,
) (ctapdiag.Message, uint64) {
	message := ctapdiag.Message{Bytes: len(raw)}
	if len(raw) == 0 {
		return message, 0
	}
	if schema = dereferenceType(schema); schema == nil {
		message.Error = "diagnostic schema unavailable"
		return message, 0
	}

	value := reflect.New(schema)
	if err := decoder.Unmarshal(raw, value.Interface()); err != nil {
		message.Error = err.Error()
		return message, 0
	}
	var subCommand uint64
	if field := value.Elem().FieldByName("SubCommand"); field.IsValid() &&
		field.CanUint() && field.Uint() != 0 {
		subCommand = field.Uint()
	}
	redactDiagnostic(value.Elem(), "", &message.RedactedFields)

	safeCBOR, err := encoder.Marshal(value.Interface())
	if err != nil {
		message.Error = err.Error()
		return message, 0
	}
	diagnosticMode, err := cbor.DiagOptions{ByteStringText: true}.DiagMode()
	if err != nil {
		message.Error = err.Error()
		return message, 0
	}
	message.Notation, err = diagnosticMode.Diagnose(safeCBOR)
	if err != nil {
		message.Error = err.Error()
		return message, 0
	}
	sort.Strings(message.RedactedFields)

	return message, subCommand
}

func redactDiagnostic(value reflect.Value, path string, redacted *[]string) {
	for value.IsValid() && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		if value.IsNil() {
			return
		}
		value = value.Elem()
	}
	if !value.IsValid() || value.Kind() != reflect.Struct {
		return
	}

	typeInfo := value.Type()
	for index := range value.NumField() {
		fieldInfo := typeInfo.Field(index)
		if fieldInfo.PkgPath != "" || fieldInfo.Tag.Get("cbor") == "-" {
			continue
		}

		field := value.Field(index)
		fieldPath := joinDiagnosticPath(path, fieldInfo.Name)
		if fieldInfo.Tag.Get("ctapdiag") == "redact" && !omittedDiagnosticField(field, fieldInfo.Tag.Get("cbor")) {
			setDiagnosticRedacted(field)
			*redacted = append(*redacted, fieldPath)
			continue
		}
		if fieldInfo.Anonymous && fieldInfo.Tag.Get("cbor") == "" {
			fieldPath = path
		}
		redactDiagnostic(field, fieldPath, redacted)
	}
}

func setDiagnosticRedacted(value reflect.Value) {
	switch value.Kind() {
	case reflect.Interface:
		value.Set(reflect.ValueOf(diagnosticRedacted))
	case reflect.Map:
		result := reflect.MakeMap(value.Type())
		if value.Type().Key().Kind() == reflect.String && value.Type().Elem().Kind() == reflect.Interface {
			key := reflect.ValueOf(diagnosticRedacted).Convert(value.Type().Key())
			result.SetMapIndex(key, reflect.ValueOf(diagnosticRedacted))
		}
		value.Set(result)
	case reflect.Slice:
		if value.Type().Elem().Kind() == reflect.Uint8 {
			value.SetBytes([]byte(diagnosticRedacted))
		} else {
			value.SetZero()
		}
	case reflect.String:
		value.SetString(diagnosticRedacted)
	default:
		value.SetZero()
	}
}

func omittedDiagnosticField(value reflect.Value, tag string) bool {
	return value.IsZero() && (strings.Contains(","+tag+",", ",omitempty,") ||
		strings.Contains(","+tag+",", ",omitzero,"))
}

func dereferenceType(value reflect.Type) reflect.Type {
	for value != nil && (value.Kind() == reflect.Interface || value.Kind() == reflect.Pointer) {
		value = value.Elem()
	}

	return value
}

func joinDiagnosticPath(parent, child string) string {
	if parent == "" {
		return child
	}

	return parent + "." + child
}
