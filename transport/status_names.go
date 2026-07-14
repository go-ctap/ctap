package transport

// Name returns the stable symbolic name for s. Unknown status bytes have no
// name; callers must retain the numeric byte as the authoritative value.
func (s StatusCode) Name() (string, bool) {
	name, ok := _StatusCode_map[s]
	return name, ok
}
