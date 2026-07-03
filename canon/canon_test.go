package canon

import (
	"encoding/hex"
	"errors"
	"testing"
)

func TestEncodeCapsuleSortsFields(t *testing.T) {
	got, err := EncodeCapsule(Capsule{
		Type:    1,
		Version: 1,
		Fields: []Field{
			{ID: 7, Value: []byte{0xaa}},
			{ID: 2, Value: []byte{0xbb, 0xcc}},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "0001000100000002000200000002bbcc000700000001aa"
	if hex.EncodeToString(got) != want {
		t.Fatalf("wire = %x, want %s", got, want)
	}
}

func TestDecodeRejectsDuplicateAndUnknownCritical(t *testing.T) {
	dup, err := EncodeCapsule(Capsule{Fields: []Field{{ID: 1}, {ID: 1}}})
	if err == nil || !errors.Is(err, ErrDuplicateField) {
		t.Fatalf("duplicate encode err = %v, want ErrDuplicateField", err)
	}
	_ = dup

	wire, err := EncodeCapsule(Capsule{Type: 2, Version: 1, Fields: []Field{{ID: 99, Value: []byte("x")}}})
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodeCapsule(wire, DecodeOptions{IsCritical: func(id uint16) bool { return id >= 64 }})
	if err == nil {
		t.Fatal("unknown critical field decoded successfully")
	}
}
