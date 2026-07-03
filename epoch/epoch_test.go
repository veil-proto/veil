package epoch

import "testing"

func TestDeriveKeysAndAdvance(t *testing.T) {
	var root [32]byte
	for i := range root {
		root[i] = byte(i)
	}
	ctx := Context([]byte("session"), 7, 9, []byte("tokens"), [32]byte{1})
	keys, err := DeriveKeys(root, ctx)
	if err != nil {
		t.Fatal(err)
	}
	if keys.TXAEADKey == keys.RXAEADKey {
		t.Fatal("tx/rx AEAD keys should differ")
	}
	next, err := Advance(root, ctx, []byte("pq"))
	if err != nil {
		t.Fatal(err)
	}
	if next == root {
		t.Fatal("epoch root did not advance")
	}
}
