package hpack

// SetFirefoxEncoding selects the measured Firefox 151 HPACK policy. It keeps
// the current dynamic table, so callers must use one policy consistently for a
// connection when reproducing a browser's compression history. The zero value
// and false retain the encoder's original behaviour.
func (e *Encoder) SetFirefoxEncoding(enabled bool) {
	e.firefox = enabled
}

func (e *Encoder) writeFirefoxField(f HeaderField) {
	f.Sensitive = f.Sensitive || f.Name == "authorization" || (f.Name == "cookie" && len(f.Value) < 20)
	noLocalIndex := f.Name == ":path"
	idx, exact := e.searchFirefoxTable(f)
	if exact && !noLocalIndex && !f.Sensitive {
		e.buf = appendIndexed(e.buf, idx)
		return
	}
	// Firefox leaves large fields out of the table even when they would fit.
	indexing := !f.Sensitive && !noLocalIndex && e.dynTab.maxSize >= 128 && f.Size() <= e.dynTab.maxSize/2
	if indexing {
		e.dynTab.add(f)
	}
	if idx == 0 {
		e.buf = append(e.buf, encodeTypeByte(indexing, f.Sensitive))
		e.buf = appendFirefoxString(e.buf, f.Name)
	} else {
		prefix := byte(4)
		if indexing {
			prefix = 6
		}
		first := len(e.buf)
		e.buf = appendVarInt(e.buf, prefix, idx)
		e.buf[first] |= encodeTypeByte(indexing, f.Sensitive)
	}
	e.buf = appendFirefoxString(e.buf, f.Value)
}

func (e *Encoder) searchFirefoxTable(f HeaderField) (uint64, bool) {
	var nameIndex uint64
	// Firefox uses the first exact match, but the last matching name. In
	// particular a dynamic cookie name can take precedence over static index 32.
	for i, entry := range staticTable.ents {
		if entry.Name == f.Name {
			nameIndex = uint64(i + 1)
			if entry.Value == f.Value {
				return nameIndex, true
			}
		}
	}
	entries := e.dynTab.table.ents
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		if entry.Name == f.Name {
			nameIndex = uint64(staticTable.len() + len(entries) - i)
			if entry.Value == f.Value {
				return nameIndex, true
			}
		}
	}
	return nameIndex, false
}

func appendFirefoxString(dst []byte, value string) []byte {
	// Firefox Huffman-encodes even when the encoded length is not shorter.
	first := len(dst)
	dst = appendVarInt(dst, 7, HuffmanEncodeLength(value))
	dst[first] |= 0x80
	return AppendHuffmanString(dst, value)
}
