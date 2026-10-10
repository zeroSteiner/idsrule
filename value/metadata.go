package value

// MetadataEntry is one "key value" entry of a metadata value.
type MetadataEntry struct {
	// Key is the first word of the entry.
	Key string
	// Value is the rest of the entry, trimmed; it may be empty.
	Value string
}

// Metadata is a decoded metadata value.
type Metadata struct {
	// Entries are the entries in the order written.
	Entries []MetadataEntry
}

// ParseMetadata decodes a metadata value: comma-separated entries, each a
// key, the first blank-separated word, followed by an optional value, the
// rest of the entry. Blanks around the entries are allowed; an empty entry
// is an error.
func ParseMetadata(s string) (Metadata, error) {
	var m Metadata
	for _, p := range splitComma(s) {
		p = trim(p)
		if p.text == "" {
			return Metadata{}, errAt(p.off, "empty metadata entry")
		}
		key, val := keyValue(p)
		m.Entries = append(m.Entries, MetadataEntry{Key: key.text, Value: val.text})
	}
	return m, nil
}
