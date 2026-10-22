package hpack

import (
	"bytes"
	"strings"
	"testing"
)

func TestFirefoxEncodingPolicy(t *testing.T) {
	for _, tc := range []struct {
		name      string
		field     HeaderField
		sensitive bool
		literal   bool
	}{
		{name: "19 byte cookie", field: HeaderField{Name: "cookie", Value: "n19=aaaaaaaaaaaaaaa"}, sensitive: true},
		{name: "20 byte cookie", field: HeaderField{Name: "cookie", Value: "n20=aaaaaaaaaaaaaaaa"}},
		{name: "authorization", field: HeaderField{Name: "authorization", Value: "synthetic"}, sensitive: true},
		{name: "static path", field: HeaderField{Name: ":path", Value: "/"}, literal: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b bytes.Buffer
			e := NewEncoder(&b)
			e.SetFirefoxEncoding(true)
			decoder := NewDecoder(initialHeaderTableSize, nil)
			for range 2 {
				b.Reset()
				if err := e.WriteField(tc.field); err != nil {
					t.Fatal(err)
				}
				fields, err := decoder.DecodeFull(b.Bytes())
				if err != nil || len(fields) != 1 {
					t.Fatalf("decode: %v, %v", fields, err)
				}
				got := fields[0]
				if got.Name != tc.field.Name || got.Value != tc.field.Value || got.Sensitive != tc.sensitive {
					t.Fatalf("field: %#v", got)
				}
				if tc.literal && b.Bytes()[0]&0xf0 != 0 {
					t.Fatalf("path must remain a plain literal: %x", b.Bytes())
				}
			}
		})
	}
}

func TestFirefoxEncodingSmallTables(t *testing.T) {
	for _, tc := range []struct {
		maxSize uint32
		value   string
	}{
		{maxSize: 64, value: "x"},
		{maxSize: 128, value: strings.Repeat("x", 40)},
	} {
		var b bytes.Buffer
		e := NewEncoder(&b)
		e.SetFirefoxEncoding(true)
		e.SetMaxDynamicTableSize(tc.maxSize)
		if err := e.WriteField(HeaderField{Name: ":method", Value: "GET"}); err != nil {
			t.Fatal(err)
		}
		b.Reset()
		if err := e.WriteField(HeaderField{Name: "small", Value: tc.value}); err != nil {
			t.Fatal(err)
		}
		if b.Bytes()[0]&0xf0 != 0 {
			t.Fatalf("table %d must not index field: %x", tc.maxSize, b.Bytes())
		}
	}
}

func TestFirefoxEncodingOldestNameReference(t *testing.T) {
	var b bytes.Buffer
	e := NewEncoder(&b)
	e.SetFirefoxEncoding(true)
	for _, value := range []string{"A", "B", "C"} {
		b.Reset()
		if err := e.WriteField(HeaderField{Name: "custom", Value: value}); err != nil {
			t.Fatal(err)
		}
	}
	// The third value refers to the oldest matching name: static length 61 + 2.
	if !bytes.HasPrefix(b.Bytes(), []byte{0x7f, 0}) {
		t.Fatalf("oldest name reference: %x", b.Bytes())
	}
}
