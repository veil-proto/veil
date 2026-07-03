package recordv1

import (
	"bytes"
	"errors"
	"testing"
)

func testKeys() DirectionKeys {
	var k DirectionKeys
	for i := 0; i < 32; i++ {
		k.AEADKey[i] = byte(i)
		k.HPKey[i] = byte(32 - i)
	}
	copy(k.NoncePrefix[:], []byte{1, 2, 3, 4})
	k.RecordContext = []byte("record-context")
	return k
}

func TestRecordSealOpenRoundTrip(t *testing.T) {
	keys := testKeys()
	token := [16]byte{9, 8, 7}
	pt := []byte("secret inner frame")
	wire, err := Seal(keys, token, 42, pt)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(wire[16:24], []byte{0, 0, 0, 0, 0, 0, 0, 42}) {
		t.Fatal("sequence was not header-protected")
	}
	gotToken, seq, got, err := Open(keys, NewReplayWindow(), wire)
	if err != nil {
		t.Fatal(err)
	}
	if gotToken != token || seq != 42 || !bytes.Equal(got, pt) {
		t.Fatalf("open = token %x seq %d pt %q", gotToken, seq, got)
	}
}

func TestReplayCommitsOnlyAfterAEADSuccess(t *testing.T) {
	keys := testKeys()
	token := [16]byte{1}
	wire, err := Seal(keys, token, 7, []byte("ok"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), wire...)
	tampered[len(tampered)-1] ^= 1
	rw := NewReplayWindow()
	if _, _, _, err := Open(keys, rw, tampered); err == nil {
		t.Fatal("tampered packet opened")
	}
	if _, _, _, err := Open(keys, rw, wire); err != nil {
		t.Fatalf("valid packet after tamper failed: %v", err)
	}
	if _, _, _, err := Open(keys, rw, wire); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay err = %v, want ErrReplay", err)
	}
}

func TestFrameMarshalParse(t *testing.T) {
	wire, err := MarshalFrame(Frame{Type: FrameControl, Flags: 1, Body: []byte{2, 3}, Padding: []byte{0, 0, 0}})
	if err != nil {
		t.Fatal(err)
	}
	f, err := ParseFrame(wire)
	if err != nil {
		t.Fatal(err)
	}
	if f.Type != FrameControl || f.Flags != 1 || !bytes.Equal(f.Body, []byte{2, 3}) || len(f.Padding) != 3 {
		t.Fatalf("frame = %+v", f)
	}
	wire[len(wire)-1] = 9
	if _, err := ParseFrame(wire); !errors.Is(err, ErrMalformedFrame) {
		t.Fatalf("malformed err = %v", err)
	}
}
