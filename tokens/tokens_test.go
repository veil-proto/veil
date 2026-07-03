package tokens

import (
	"bytes"
	"testing"
	"time"
)

func TestTokenDerivationBindsFields(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	a := Route(key, 1, 2, 3, DirectionC2S)
	b := Route(key, 1, 2, 4, DirectionC2S)
	c := Route(key, 1, 2, 3, DirectionS2C)
	if a == b || a == c {
		t.Fatal("route token did not bind slot or direction")
	}
}

func TestWindowPromoteAndExpire(t *testing.T) {
	now := time.Unix(100, 0)
	w := NewWindow()
	cur := [16]byte{1}
	next := [16]byte{2}
	w.Install(cur, StateCurrent, time.Time{})
	w.Install(next, StateNext, now.Add(time.Hour))
	w.Promote(now, time.Second)
	if ent, ok := w.Lookup(cur, now); !ok || ent.State != StatePrevious {
		t.Fatalf("current token after promote = %+v ok=%v", ent, ok)
	}
	if ent, ok := w.Lookup(next, now); !ok || ent.State != StateCurrent {
		t.Fatalf("next token after promote = %+v ok=%v", ent, ok)
	}
	w.Expire(now.Add(2 * time.Second))
	if _, ok := w.Lookup(cur, now.Add(2*time.Second)); ok {
		t.Fatal("expired previous token still accepted")
	}
}
